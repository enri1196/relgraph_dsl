//! Authentication supplies the trusted tenant and subject for every check.

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use relgraph_authz::{Subject, TenantId};

use crate::error::ApiError;

/// An application identity obtained from a fixed demo token, never from JSON.
#[derive(Clone)]
pub struct Identity {
    pub tenant: TenantId,
    pub user: &'static str,
    pub subject: Subject,
}

/// Maps demo credentials to identities before handlers inspect any resources.
pub async fn authenticate(mut request: Request, next: Next) -> Result<Response, ApiError> {
    let token = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    let (tenant, user) = match token {
        Some("Bearer alice-demo") => ("acme", "alice"),
        Some("Bearer bob-demo") => ("acme", "bob"),
        Some("Bearer carol-demo") => ("acme", "carol"),
        Some("Bearer eve-demo") => ("other", "eve"),
        _ => {
            return Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "valid bearer token required",
            ));
        }
    };
    request.extensions_mut().insert(Identity {
        tenant: TenantId::new(tenant).map_err(ApiError::unavailable)?,
        user,
        subject: Subject::new("user", user).map_err(ApiError::unavailable)?,
    });
    Ok(next.run(request).await)
}
