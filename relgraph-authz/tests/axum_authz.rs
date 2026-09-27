#![cfg(feature = "axum")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::extract::{Extension, State};
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use relgraph_authz::axum_authz::{Authorized, FgaAuthzLayer};
use relgraph_authz::{
    Bound, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ModelIdentity, ObjectIdSource,
    ObjectRef, PrincipalIdentity, PrincipalSource, RelationName, RelationshipPage,
    RelationshipReadSession, RelationshipStore, RelationshipTuple, RoutePolicy, StoreCursor,
    StoreError, StoreErrorKind, StoreFuture, Subject, TenantId, TenantIdentity, TenantSource,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const MODEL: &str = r#"
model
  schema 1.1

type user

type document
  relations
    define viewer: [user]
"#;

#[derive(Clone)]
struct Identity {
    subject: Subject,
    tenant: TenantId,
    calls: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct PrincipalExtension(Subject);

#[derive(Clone)]
struct TenantExtension(TenantId);

impl Identity {
    fn new(subject_id: &str) -> Self {
        Self {
            subject: Subject::new("user", subject_id).unwrap(),
            tenant: TenantId::new("tenant-a").unwrap(),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl PrincipalIdentity for PrincipalExtension {
    fn subject(&self) -> &Subject {
        &self.0
    }
}

impl TenantIdentity for TenantExtension {
    fn tenant_id(&self) -> &TenantId {
        &self.0
    }
}

#[derive(Clone)]
struct AppState {
    calls: Arc<AtomicUsize>,
    model_identity: ModelIdentity,
}

impl AppState {
    fn new(model_identity: ModelIdentity) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            model_identity,
        }
    }
}

fn route_policy() -> RoutePolicy {
    RoutePolicy::new("document", "viewer")
        .principal(PrincipalSource::extension::<PrincipalExtension>())
        .tenant(TenantSource::extension::<TenantExtension>())
        .object_id(ObjectIdSource::path("document_id"))
}

fn authz_with_allow_tuple() -> FgaAuthz<Bound<InMemoryRelationshipStore>> {
    let store = InMemoryRelationshipStore::new();
    store
        .insert(RelationshipTuple::new(
            TenantId::new("tenant-a").unwrap(),
            ObjectRef::new("document", "42").unwrap(),
            RelationName::new("viewer").unwrap(),
            Subject::new("user", "anne").unwrap(),
        ))
        .unwrap();
    FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default())
}

fn allow_layer() -> FgaAuthzLayer<InMemoryRelationshipStore> {
    authz_with_allow_tuple().middleware(route_policy()).unwrap()
}

fn authed(app: Router, subject: &str) -> Router {
    let identity = Identity::new(subject);
    app.layer(Extension(PrincipalExtension(identity.subject)))
        .layer(Extension(TenantExtension(identity.tenant)))
}

fn request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

async fn protected_handler(
    State(state): State<AppState>,
    Extension(authorized): Extension<Authorized>,
) -> String {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let same_model = authorized.model_identity() == &state.model_identity;
    format!(
        "{}:{}:{}:{same_model}",
        authorized.object().id().as_str(),
        authorized.subject().id().as_str(),
        authorized.relation().as_str(),
    )
}

async fn body_handler(
    State(state): State<AppState>,
    Extension(authorized): Extension<Authorized>,
    Json(value): Json<Value>,
) -> Json<Value> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "body": value,
        "checked_object": authorized.object().id().as_str(),
    }))
}

async fn public_handler() -> &'static str {
    "public"
}

#[tokio::test]
async fn allowed_request_attaches_authorized_and_supports_custom_nested_state() {
    let authz = authz_with_allow_tuple();
    let expected_identity = authz.model_identity();
    let state = AppState::new(expected_identity);
    let calls = Arc::clone(&state.calls);
    let api: Router<AppState> = Router::new().route(
        "/documents/{document_id}",
        get(protected_handler).route_layer(authz.middleware(route_policy()).unwrap()),
    );
    let app = Router::new().nest("/api", api).with_state(state);
    let app = authed(app, "anne");

    let response = app
        .oneshot(request(Method::GET, "/api/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "42:anne:viewer:true"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn protected_handler_receives_the_original_request_body() {
    let authz = authz_with_allow_tuple();
    let state = AppState::new(authz.model_identity());
    let calls = Arc::clone(&state.calls);
    let app = Router::new()
        .route(
            "/documents/{document_id}",
            post(body_handler).route_layer(authz.middleware(route_policy()).unwrap()),
        )
        .with_state(state);
    let app = authed(app, "anne");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/documents/42")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"intact"}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"body":{"name":"intact"},"checked_object":"42"})
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn denials_missing_auth_and_bad_path_input_never_call_the_handler() {
    let state = AppState::new(authz_with_allow_tuple().model_identity());
    let calls = Arc::clone(&state.calls);
    let app = Router::new()
        .route(
            "/documents/{document_id}",
            get(protected_handler).route_layer(allow_layer()),
        )
        .with_state(state);

    let response = authed(app.clone(), "bob")
        .oneshot(request(Method::GET, "/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let response = app
        .clone()
        .oneshot(request(Method::GET, "/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let principal_only = app.clone().layer(Extension(PrincipalExtension(
        Subject::new("user", "anne").unwrap(),
    )));
    let response = principal_only
        .oneshot(request(Method::GET, "/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let response = authed(app, "anne")
        .oneshot(request(Method::GET, "/documents/%20"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body, json!({"error":"invalid_authorization_input"}));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

struct UnavailableStore;

struct UnavailableReadSession;

impl RelationshipStore for UnavailableStore {
    type ReadSession = UnavailableReadSession;

    fn begin_read<'a>(
        &'a self,
        _tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        Box::pin(async { Ok(UnavailableReadSession) })
    }
}

impl RelationshipReadSession for UnavailableReadSession {
    fn tuples<'a>(
        &'a self,
        _object: &'a ObjectRef,
        _relation: &'a RelationName,
        _maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        Box::pin(async {
            Err(StoreError::new(
                StoreErrorKind::Unavailable,
                "test store outage",
            ))
        })
    }

    fn tuples_page<'a>(
        &'a self,
        _object: &'a ObjectRef,
        _relation: &'a RelationName,
        _cursor: Option<StoreCursor>,
        _maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
        Box::pin(async {
            Err(StoreError::new(
                StoreErrorKind::Unavailable,
                "test store outage",
            ))
        })
    }
}

#[tokio::test]
async fn store_outage_returns_503_without_calling_the_handler() {
    let authz = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(UnavailableStore, EvaluationLimits::default());
    let state = AppState::new(authz.model_identity());
    let calls = Arc::clone(&state.calls);
    let app = Router::new()
        .route(
            "/documents/{document_id}",
            get(protected_handler).route_layer(authz.middleware(route_policy()).unwrap()),
        )
        .with_state(state);
    let app = authed(app, "anne");

    let response = app
        .oneshot(request(Method::GET, "/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

async fn authenticate(
    State(identity): State<Identity>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    identity.calls.fetch_add(1, Ordering::SeqCst);
    request
        .extensions_mut()
        .insert(PrincipalExtension(identity.subject.clone()));
    request
        .extensions_mut()
        .insert(TenantExtension(identity.tenant.clone()));
    next.run(request).await
}

#[tokio::test]
async fn authentication_layer_runs_before_authorization() {
    let authz = authz_with_allow_tuple();
    let identity = Identity::new("anne");
    let authentication_calls = Arc::clone(&identity.calls);
    let state = AppState::new(authz.model_identity());
    let app = Router::new()
        .route(
            "/documents/{document_id}",
            get(protected_handler).route_layer(authz.middleware(route_policy()).unwrap()),
        )
        .layer(middleware::from_fn_with_state(identity, authenticate))
        .with_state(state);

    let response = app
        .oneshot(request(Method::GET, "/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(authentication_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn only_protected_routes_are_authorized_and_axum_preserves_route_method_results() {
    let state = AppState::new(authz_with_allow_tuple().model_identity());
    let calls = Arc::clone(&state.calls);
    let app = Router::new()
        .route(
            "/documents/{document_id}",
            get(protected_handler).route_layer(allow_layer()),
        )
        .route("/public", get(public_handler))
        .with_state(state);

    let response = app
        .clone()
        .oneshot(request(Method::GET, "/public"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "public"
    );

    let response = app
        .clone()
        .oneshot(request(Method::GET, "/missing"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = app
        .clone()
        .oneshot(request(Method::POST, "/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let response = app
        .clone()
        .oneshot(request(Method::OPTIONS, "/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let response = authed(app, "anne")
        .oneshot(request(Method::HEAD, "/documents/42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn middleware_layer_clones_keep_the_compiled_model_identity() {
    let authz = authz_with_allow_tuple();
    let original = authz.model_identity();
    let cloned = authz.clone().model_identity();
    assert_eq!(original, cloned);
    assert!(original.identifies_same_model(&cloned));

    let separate = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(
            InMemoryRelationshipStore::new(),
            EvaluationLimits::default(),
        )
        .model_identity();
    assert_ne!(original, separate);
}

#[test]
fn route_policy_references_are_validated_when_middleware_is_built() {
    let authz = authz_with_allow_tuple();
    let result = authz.middleware(
        RoutePolicy::new("document", "missing")
            .principal(PrincipalSource::extension::<PrincipalExtension>())
            .tenant(TenantSource::extension::<TenantExtension>())
            .object_id(ObjectIdSource::path("document_id")),
    );
    assert!(result.is_err());
}

#[derive(Clone)]
struct FixedObjectId;

impl relgraph_authz::RequestPartsExtractor<relgraph_authz::EntityId> for FixedObjectId {
    fn extract(
        &self,
        _parts: &http::request::Parts,
    ) -> Result<relgraph_authz::EntityId, relgraph_authz::PolicyInputError> {
        Ok(relgraph_authz::EntityId::new("42").unwrap())
    }
}

#[derive(Clone)]
struct PendingStore {
    dropped_read: Arc<std::sync::atomic::AtomicBool>,
}

struct PendingSession {
    dropped_read: Arc<std::sync::atomic::AtomicBool>,
}

struct PendingTupleRead {
    dropped_read: Arc<std::sync::atomic::AtomicBool>,
}

struct PendingTupleListRead {
    dropped_read: Arc<std::sync::atomic::AtomicBool>,
}

impl std::future::Future for PendingTupleRead {
    type Output = Result<relgraph_authz::RelationshipPage, relgraph_authz::StoreError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

impl Drop for PendingTupleRead {
    fn drop(&mut self) {
        self.dropped_read
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl std::future::Future for PendingTupleListRead {
    type Output = Result<Vec<relgraph_authz::RelationshipTuple>, relgraph_authz::StoreError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

impl Drop for PendingTupleListRead {
    fn drop(&mut self) {
        self.dropped_read
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl relgraph_authz::RelationshipStore for PendingStore {
    type ReadSession = PendingSession;

    fn begin_read<'a>(
        &'a self,
        _tenant: &'a TenantId,
    ) -> relgraph_authz::StoreFuture<'a, Result<Self::ReadSession, relgraph_authz::StoreError>>
    {
        Box::pin(async move {
            Ok(PendingSession {
                dropped_read: Arc::clone(&self.dropped_read),
            })
        })
    }
}

impl relgraph_authz::RelationshipReadSession for PendingSession {
    fn tuples<'a>(
        &'a self,
        _object: &'a ObjectRef,
        _relation: &'a RelationName,
        _maximum: usize,
    ) -> relgraph_authz::StoreFuture<
        'a,
        Result<Vec<relgraph_authz::RelationshipTuple>, relgraph_authz::StoreError>,
    > {
        Box::pin(PendingTupleListRead {
            dropped_read: Arc::clone(&self.dropped_read),
        })
    }

    fn tuples_page<'a>(
        &'a self,
        _object: &'a ObjectRef,
        _relation: &'a RelationName,
        _cursor: Option<relgraph_authz::StoreCursor>,
        _maximum: usize,
    ) -> relgraph_authz::StoreFuture<
        'a,
        Result<relgraph_authz::RelationshipPage, relgraph_authz::StoreError>,
    > {
        Box::pin(PendingTupleRead {
            dropped_read: Arc::clone(&self.dropped_read),
        })
    }
}

#[tokio::test]
async fn tower_readiness_is_immediate_and_cancelling_authorization_never_runs_handler() {
    use tower::{Layer, Service, ServiceExt};

    let dropped_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let store = PendingStore {
        dropped_read: Arc::clone(&dropped_read),
    };
    let authz = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default());
    let policy = RoutePolicy::new("document", "viewer")
        .principal(PrincipalSource::extension::<PrincipalExtension>())
        .tenant(TenantSource::extension::<TenantExtension>())
        .object_id(ObjectIdSource::from_request_parts(
            "fixed_document_id",
            FixedObjectId,
        ));
    let layer = authz.middleware(policy).unwrap();
    let handler_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler_counter = Arc::clone(&handler_calls);
    let inner = tower::service_fn(move |_request: Request<Body>| {
        let handler_counter = Arc::clone(&handler_counter);
        async move {
            handler_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
        }
    });
    let mut service = layer.layer(inner);

    tokio::time::timeout(std::time::Duration::from_secs(1), service.ready())
        .await
        .expect("authorization service readiness should not wait for a request")
        .expect("authorization service should be ready");

    let mut request = Request::new(Body::empty());
    request
        .extensions_mut()
        .insert(PrincipalExtension(Subject::new("user", "anne").unwrap()));
    request
        .extensions_mut()
        .insert(TenantExtension(TenantId::new("tenant-a").unwrap()));
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(25), service.call(request)).await;

    assert!(
        result.is_err(),
        "the pending store read should be cancelled by the timeout"
    );
    assert!(
        dropped_read.load(std::sync::atomic::Ordering::SeqCst),
        "the in-flight store future should be dropped"
    );
    assert_eq!(handler_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}
