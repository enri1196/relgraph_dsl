//! Axum and Tower middleware for enforcing a validated route policy.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::authz::policy::{
    PathParameters, PolicyError, PolicyInputError, RoutePolicy, ValidatedRoutePolicy,
};
use crate::authz::{
    AuthorizationDecision, AuthorizationError, Bound, CheckRequest, FgaAuthz, ModelIdentity,
    ObjectRef, RelationName, RelationshipStore, StoreErrorKind, Subject,
};
use axum::body::Body;
use axum::extract::{FromRequestParts, Path, Request};
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use tower::{Layer, Service, ServiceExt};

/// Metadata attached to a request after its fixed route policy allows access.
///
/// The values describe the exact subject, object, and relation checked by the
/// middleware. No relationship tuples or condition values are exposed.
#[derive(Clone, Debug)]
pub struct Authorized {
    subject: Subject,
    object: ObjectRef,
    relation: RelationName,
    model_identity: ModelIdentity,
}

impl Authorized {
    /// Returns the authenticated subject used for the successful check.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// Returns the exact object reference used for the successful check.
    pub fn object(&self) -> &ObjectRef {
        &self.object
    }

    /// Returns the fixed relation checked for this route.
    pub fn relation(&self) -> &RelationName {
        &self.relation
    }

    /// Returns the identity of the compiled model that authorized this request.
    pub fn model_identity(&self) -> &ModelIdentity {
        &self.model_identity
    }
}

/// Cloneable Tower layer created by [`FgaAuthz::middleware`].
pub struct FgaAuthzLayer<S> {
    authz: FgaAuthz<Bound<S>>,
    policy: Arc<ValidatedRoutePolicy>,
}

impl<S: RelationshipStore> Clone for FgaAuthzLayer<S> {
    fn clone(&self) -> Self {
        Self {
            authz: self.authz.clone(),
            policy: Arc::clone(&self.policy),
        }
    }
}

impl<S: RelationshipStore + 'static, Inner> Layer<Inner> for FgaAuthzLayer<S> {
    type Service = FgaAuthzService<S, Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        FgaAuthzService {
            inner,
            authz: self.authz.clone(),
            policy: Arc::clone(&self.policy),
        }
    }
}

/// Tower service that authorizes request parts before forwarding the request.
pub struct FgaAuthzService<S, Inner> {
    inner: Inner,
    authz: FgaAuthz<Bound<S>>,
    policy: Arc<ValidatedRoutePolicy>,
}

impl<S: RelationshipStore, Inner: Clone> Clone for FgaAuthzService<S, Inner> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            authz: self.authz.clone(),
            policy: Arc::clone(&self.policy),
        }
    }
}

impl<S, Inner> Service<Request> for FgaAuthzService<S, Inner>
where
    S: RelationshipStore + 'static,
    Inner: Service<Request, Response = Response<Body>, Error = Infallible> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Axum route services are always ready. The cloned inner service is
        // polled with `oneshot` after the authorization check succeeds.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let authz = self.authz.clone();
        let policy = Arc::clone(&self.policy);
        let inner = self.inner.clone();

        Box::pin(async move {
            match authorize_request(&authz, &policy, request).await {
                Ok((mut request, authorized)) => {
                    request.extensions_mut().insert(authorized);
                    match inner.oneshot(request).await {
                        Ok(response) => Ok(response),
                        Err(never) => match never {},
                    }
                }
                Err(rejection) => Ok(rejection.into_response()),
            }
        })
    }
}

impl<S: RelationshipStore + 'static> FgaAuthz<Bound<S>> {
    /// Validates a fixed route policy and returns its Axum-compatible Tower layer.
    pub fn middleware(&self, policy: RoutePolicy) -> Result<FgaAuthzLayer<S>, PolicyError> {
        let policy = self.validate_policy(policy)?;
        Ok(FgaAuthzLayer {
            authz: self.clone(),
            policy: Arc::new(policy),
        })
    }
}

/// Resolves trusted and client-bound route inputs, then runs one model check.
async fn authorize_request<S: RelationshipStore>(
    authz: &FgaAuthz<Bound<S>>,
    policy: &ValidatedRoutePolicy,
    request: Request,
) -> Result<(Request, Authorized), Rejection> {
    let (mut parts, body) = request.into_parts();

    // Resolve authentication before client-controlled route inputs so missing
    // authentication follows the application's established 401 contract.
    let subject = policy
        .resolve_principal(&parts)
        .map_err(Rejection::from_principal_error)?;
    let tenant = policy
        .resolve_tenant(&parts)
        .map_err(|_| Rejection::Internal)?;

    if policy.requires_path_params() {
        let Path(parameters) =
            <Path<HashMap<String, String>> as FromRequestParts<()>>::from_request_parts(
                &mut parts,
                &(),
            )
            .await
            .map_err(|_| Rejection::BadRequest)?;
        parts
            .extensions
            .insert(PathParameters::new(parameters.into_iter().collect()));
    }

    let object_id = policy
        .resolve_object_id(&parts)
        .map_err(Rejection::from_object_input_error)?;
    let context = policy
        .resolve_context(&parts)
        .await
        .map_err(Rejection::from_context_input_error)?;

    let object = ObjectRef::new(policy.object_type(), object_id.as_str())
        .map_err(|_| Rejection::Internal)?;
    let relation = RelationName::new(policy.relation()).map_err(|_| Rejection::Internal)?;
    let mut check = CheckRequest::new(tenant, subject.clone(), object.clone(), relation.clone());
    for (condition, values) in context {
        check = check.with_condition_context(condition, values);
    }

    let authorized = Authorized {
        subject,
        object,
        relation,
        model_identity: authz.model_identity(),
    };

    match authz.check(check).await {
        Ok(AuthorizationDecision::Allow) => Ok((Request::from_parts(parts, body), authorized)),
        Ok(AuthorizationDecision::Deny) => Err(Rejection::Forbidden),
        Err(error) => Err(Rejection::from_authorization_error(error)),
    }
}

/// An HTTP outcome selected without exposing internal authorization details.
#[derive(Clone, Copy)]
enum Rejection {
    /// The route had no authenticated principal extension.
    Unauthorized,
    /// A client-controlled path or context input was malformed.
    BadRequest,
    /// The relationship model denied access.
    Forbidden,
    /// A store or evaluation resource limit prevented a decision.
    Unavailable,
    /// Trusted application state or an internal invariant was invalid.
    Internal,
}

impl Rejection {
    /// Maps principal extraction failures to the authentication contract.
    fn from_principal_error(error: PolicyInputError) -> Self {
        match error {
            PolicyInputError::MissingExtension(_) => Self::Unauthorized,
            _ => Self::Internal,
        }
    }

    /// Maps object identifier extraction failures to a client input response.
    fn from_object_input_error(error: PolicyInputError) -> Self {
        match error {
            PolicyInputError::MissingPathParameter(_) | PolicyInputError::InvalidObjectId(_) => {
                Self::BadRequest
            }
            _ => Self::Internal,
        }
    }

    /// Maps condition provider failures while keeping trusted failures internal.
    fn from_context_input_error(error: PolicyInputError) -> Self {
        match error {
            PolicyInputError::InvalidContextValue { .. } => Self::BadRequest,
            _ => Self::Internal,
        }
    }

    /// Maps check failures to bounded HTTP outcomes without exposing details.
    fn from_authorization_error(error: AuthorizationError) -> Self {
        match error {
            AuthorizationError::EvaluationLimitExceeded { .. }
            | AuthorizationError::RelationDepthExceeded { .. }
            | AuthorizationError::StoreCallLimitExceeded { .. }
            | AuthorizationError::WorkLimitExceeded { .. }
            | AuthorizationError::ConditionCostLimitExceeded { .. } => Self::Unavailable,
            AuthorizationError::Store(error) => match error.kind() {
                StoreErrorKind::Unavailable
                | StoreErrorKind::IncompleteRead
                | StoreErrorKind::TupleLimitExceeded => Self::Unavailable,
                // Conflict and InvalidInput describe writes; a read reporting
                // them is an adapter fault rather than a client error.
                StoreErrorKind::CorruptData
                | StoreErrorKind::Internal
                | StoreErrorKind::Conflict
                | StoreErrorKind::InvalidInput => Self::Internal,
            },
            AuthorizationError::InvalidConditionContext {
                source: crate::authz::ConditionContextSource::Request,
                ..
            } => Self::BadRequest,
            _ => Self::Internal,
        }
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response<Body> {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "authentication_required"),
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_authorization_input"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "access_denied"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "authorization_error"),
        };
        let payload = serde_json::json!({ "error": code });
        let bytes = serde_json::to_vec(&payload)
            .unwrap_or_else(|_| b"{\"error\":\"authorization_error\"}".to_vec());
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
    }
}
