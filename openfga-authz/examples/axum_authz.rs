use std::{collections::BTreeMap, error::Error};

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use openfga_authz::{
    ConditionContext, ContextBinding, ContextValue, ContextValueProvider, ContextValueType,
    EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ObjectIdSource, ObjectRef,
    PolicyInputError, PrincipalIdentity, PrincipalSource, RelationName, RelationshipTuple,
    RoutePolicy, Subject, TenantId, TenantIdentity, TenantSource,
};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone)]
struct AuthenticatedPrincipal(Subject);

impl PrincipalIdentity for AuthenticatedPrincipal {
    fn subject(&self) -> &Subject {
        &self.0
    }
}

#[derive(Clone)]
struct AuthenticatedTenant(TenantId);

impl TenantIdentity for AuthenticatedTenant {
    fn tenant_id(&self) -> &TenantId {
        &self.0
    }
}

fn server_current_time(_: &Parts) -> Result<ContextValue, PolicyInputError> {
    let current_time = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| PolicyInputError::ResolverFailure(error.to_string()))?;
    ContextValue::new(ContextValueType::Timestamp, json!(current_time))
}

async fn authenticate(mut request: Request<Body>, next: Next) -> Response {
    // Demo credentials stand in for a real authentication layer. The client
    // cannot choose a subject ID directly; each accepted token maps to one.
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let subject_id = match token {
        Some("anne-demo") => "anne",
        Some("bob-demo") => "bob",
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    request.extensions_mut().insert(AuthenticatedPrincipal(
        Subject::new("user", subject_id).expect("static subject is valid"),
    ));
    request.extensions_mut().insert(AuthenticatedTenant(
        TenantId::new("demo").expect("static tenant is valid"),
    ));
    next.run(request).await
}

async fn read_document() -> &'static str {
    "document access allowed"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let store = InMemoryRelationshipStore::new();
    store.insert(RelationshipTuple::new(
        TenantId::new("demo")?,
        ObjectRef::new("document", "42")?,
        RelationName::new("viewer")?,
        Subject::new("user", "anne")?,
    ))?;

    let grant_time = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let grant_context = ConditionContext::new(
        "valid_grant",
        BTreeMap::from([
            ("grant_time".to_owned(), json!(grant_time)),
            ("grant_duration".to_owned(), json!("30m")),
        ]),
    )?;
    store.insert(
        RelationshipTuple::new(
            TenantId::new("demo")?,
            ObjectRef::new("document", "42")?,
            RelationName::new("time_limited_viewer")?,
            Subject::new("user", "bob")?,
        )
        .with_condition(grant_context),
    )?;

    let authz = FgaAuthz::new(include_str!("authorization.fga"))?
        .with_store(store, EvaluationLimits::default());
    let view_document = authz.middleware(
        RoutePolicy::new("document", "can_view")
            .principal(PrincipalSource::extension::<AuthenticatedPrincipal>())
            .tenant(TenantSource::extension::<AuthenticatedTenant>())
            .object_id(ObjectIdSource::path("document_id"))
            .bind_context(ContextBinding::new(
                "valid_grant",
                "current_time",
                ContextValueProvider::from_request_parts(
                    ContextValueType::Timestamp,
                    server_current_time,
                ),
            )),
    )?;

    let app = Router::new()
        .route(
            "/documents/{document_id}",
            get(read_document).route_layer(view_document),
        )
        .layer(middleware::from_fn(authenticate));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;
    Ok(())
}
