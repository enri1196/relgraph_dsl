//! Public HTTP errors deliberately exclude store and evaluator internals.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// A status and safe, static description suitable for an API client.
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str);

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    /// Reports invalid application input.
    pub fn bad_request(message: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, message)
    }

    /// Conceals both absent resources and resources belonging to another tenant.
    pub fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "resource not found")
    }

    /// Records internal diagnostics while returning a safe service error.
    pub fn unavailable(error: impl std::fmt::Display) -> Self {
        eprintln!("drive service error: {error}");
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization service unavailable",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
