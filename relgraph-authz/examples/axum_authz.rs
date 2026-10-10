//! # Axum authorization example
//!
//! Run it with `cargo run -p relgraph-authz --example axum_authz --features axum`.
//! The adjacent `authorization.fga` file defines the authorization rules; this
//! Rust program provides demo grants, maps demo bearer tokens to trusted
//! identities, and protects the document route with those rules.
//!
//! At startup, [`main`] inserts Anne's direct viewer grant and Bob's
//! time-limited grant, then compiles the model and builds a route policy. For
//! each request, [`authenticate`] adds a principal and tenant to the request
//! extensions. The policy reads the document ID from the path, supplies the
//! server's current time to the condition, and runs `document#can_view`. Axum
//! calls [`read_document`] only when that check allows access. Missing or
//! unknown demo tokens receive `401`; a valid token without an active grant
//! receives `403`.
//!
//! The tokens and in-memory relationship store are demonstration fixtures.

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
use relgraph_authz::{
    ConditionContext, ContextBinding, ContextValue, ContextValueProvider, ContextValueType,
    EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ObjectIdSource, ObjectRef,
    PolicyInputError, PrincipalIdentity, PrincipalSource, RelationName, RelationshipTuple,
    RoutePolicy, Subject, TenantId, TenantIdentity, TenantSource,
};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone)]
/// Principal extension inserted by the example authentication middleware.
struct AuthenticatedPrincipal(Subject);

impl PrincipalIdentity for AuthenticatedPrincipal {
    fn subject(&self) -> &Subject {
        &self.0
    }
}

#[derive(Clone)]
/// Tenant extension inserted by the example authentication middleware.
struct AuthenticatedTenant(TenantId);

impl TenantIdentity for AuthenticatedTenant {
    fn tenant_id(&self) -> &TenantId {
        &self.0
    }
}

/// Resolve the condition's current time from the server clock, never the URL.
fn server_current_time(_: &Parts) -> Result<ContextValue, PolicyInputError> {
    let current_time = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| PolicyInputError::ResolverFailure(error.to_string()))?;
    ContextValue::new(ContextValueType::Timestamp, json!(current_time))
}

/// Map a fixed demo bearer token to trusted request extensions.
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

/// Return the protected resource after its route policy has allowed access.
async fn read_document() -> &'static str {
    "document access allowed"
}

#[tokio::main]
/// Seed the demo store, build the authorization layer, and serve one route.
async fn main() -> Result<(), Box<dyn Error>> {
    // Seed one direct grant for Anne on document:42 in the demo tenant.
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
    // Bob's grant carries its start time and duration with the tuple. The
    // route supplies only current_time when it evaluates valid_grant.
    store.insert(
        RelationshipTuple::new(
            TenantId::new("demo")?,
            ObjectRef::new("document", "42")?,
            RelationName::new("time_limited_viewer")?,
            Subject::new("user", "bob")?,
        )
        .with_condition(grant_context),
    )?;

    // Compile the adjacent model once, then bind the relationship store.
    let authz = FgaAuthz::new(include_str!("authorization.fga"))?
        .with_store(store, EvaluationLimits::default());
    // Fix the check to document#can_view. Identity comes from trusted
    // extensions, the object ID from the named path segment, and current_time
    // from the server clock.
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

    // The app-wide authentication middleware supplies extensions before the
    // route policy runs; the handler runs only after the policy allows.
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
