//! Resource handlers authorize domain operations against trusted identities.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    middleware,
    routing::get,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    auth::{Identity, authenticate},
    drive::{Drive, Grantee, Item, Kind, Role, Share},
    error::ApiError,
};

/// Cloned Axum state retains one repository and authorization/write lock.
pub type AppState = Arc<Mutex<Drive>>;

/// Builds the API; authentication wraps all resource handlers.
pub fn router(drive: Drive) -> Router {
    Router::new()
        .route("/items", get(list_items).post(create_item))
        .route("/items/{id}", get(read_item))
        .route("/items/{id}/content", get(read_content).put(write_content))
        .route("/items/{id}/shares", get(list_shares).post(create_share))
        .route(
            "/items/{id}/shares/{share_id}",
            axum::routing::delete(revoke_share),
        )
        .route_layer(middleware::from_fn(authenticate))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .with_state(Arc::new(Mutex::new(drive)))
        .route("/health", get(|| async { "ok" }))
        .route(
            "/",
            get(|| async { "Relgraph Drive API: see examples/drive-api/README.md\n" }),
        )
}

/// An optional folder/workspace filter; an omitted filter returns visible items.
#[derive(Deserialize)]
pub struct ListQuery {
    parent_id: Option<String>,
}

/// Filters every candidate through authorization instead of leaking metadata.
async fn list_items(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<Item>>, ApiError> {
    let drive = state.lock().await;
    // A shared child may be visible even when its parent is private. This query
    // therefore checks children individually rather than requiring parent access.
    let mut visible = Vec::new();
    for item in drive.items.values().filter(|item| {
        item.tenant == identity.tenant
            && query
                .parent_id
                .as_ref()
                .is_none_or(|id| item.parent_id.as_ref() == Some(id))
    }) {
        if drive.allowed(&identity, item, "can_view").await? {
            visible.push(item.clone());
        }
    }
    Ok(Json(visible))
}

/// Returns metadata only after checking view access.
async fn read_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
) -> Result<Json<Item>, ApiError> {
    let drive = state.lock().await;
    let item = drive.item(&identity, &id)?;
    drive.require(&identity, &item, "can_view").await?;
    Ok(Json(item))
}

/// Creation input excludes tenant, owner, relation, and caller-supplied IDs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateItem {
    kind: Kind,
    name: String,
    parent_id: String,
    #[serde(default)]
    content: String,
}

/// Creates a folder or file under a parent that the caller may edit.
async fn create_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(input): Json<CreateItem>,
) -> Result<(StatusCode, Json<Item>), ApiError> {
    validate_name(&input.name)?;
    validate_content(&input.content)?;
    let expected_parent = match input.kind {
        Kind::Folder if input.content.is_empty() => Kind::Workspace,
        Kind::File => Kind::Folder,
        _ => {
            return Err(ApiError::bad_request(
                "create a folder without content or a file; workspace provisioning is server-owned",
            ));
        }
    };
    let mut drive = state.lock().await;
    let parent = drive.item(&identity, &input.parent_id)?;
    drive.require(&identity, &parent, "can_edit").await?;
    if parent.kind != expected_parent {
        return Err(ApiError::bad_request(
            "folders require a workspace parent; files require a folder parent",
        ));
    }
    let id = drive.allocate_id(input.kind.model_type());
    let item = drive
        .add_item(
            identity.tenant,
            identity.user,
            id,
            input.kind,
            input.name,
            Some(input.parent_id),
            input.content,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(item)))
}

/// File content is served separately from metadata and carries a revision.
#[derive(Serialize)]
pub struct Content {
    content: String,
    revision: u64,
}

/// Reads a text file after a view check.
async fn read_content(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
) -> Result<Json<Content>, ApiError> {
    let drive = state.lock().await;
    let item = drive.item(&identity, &id)?;
    drive.require(&identity, &item, "can_view").await?;
    require_file(&item)?;
    Ok(Json(Content {
        content: item.content,
        revision: item.revision,
    }))
}

/// A mandatory expected revision prevents silent lost updates between editors.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteContent {
    content: String,
    expected_revision: u64,
}

/// Updates content only if both edit access and the expected revision still hold.
async fn write_content(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
    Json(input): Json<WriteContent>,
) -> Result<Json<Item>, ApiError> {
    validate_content(&input.content)?;
    let mut drive = state.lock().await;
    let item = drive.item(&identity, &id)?;
    drive.require(&identity, &item, "can_edit").await?;
    require_file(&item)?;
    if item.revision != input.expected_revision {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "revision conflict; read the file again",
        ));
    }
    let stored = drive.items.get_mut(&id).ok_or_else(ApiError::not_found)?;
    stored.content = input.content;
    stored.revision += 1;
    Ok(Json(stored.clone()))
}

/// Share mutations accept only explicit roles and tenant-local known recipients.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateShare {
    grantee: Grantee,
    role: Role,
}

/// Lists direct grants for managers; inherited grants are not duplicated here.
async fn list_shares(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
) -> Result<Json<Vec<Share>>, ApiError> {
    let drive = state.lock().await;
    let item = drive.item(&identity, &id)?;
    drive.require(&identity, &item, "can_manage").await?;
    Ok(Json(drive.shares.get(&id).cloned().unwrap_or_default()))
}

/// Requires management access before publishing a relationship grant.
async fn create_share(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path(id): Path<String>,
    Json(input): Json<CreateShare>,
) -> Result<(StatusCode, Json<Share>), ApiError> {
    let mut drive = state.lock().await;
    let item = drive.item(&identity, &id)?;
    drive.require(&identity, &item, "can_manage").await?;
    let share = drive.add_share(&item, input.grantee, input.role).await?;
    Ok((StatusCode::CREATED, Json(share)))
}

/// Revokes one direct grant; other direct or inherited access remains effective.
async fn revoke_share(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Path((id, share_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let mut drive = state.lock().await;
    let item = drive.item(&identity, &id)?;
    drive.require(&identity, &item, "can_manage").await?;
    drive.revoke_share(&item, &share_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Restricts names to nonempty, printable labels within a small byte limit.
fn validate_name(name: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 200 || name.chars().any(char::is_control) {
        Err(ApiError::bad_request(
            "name must contain 1–200 bytes without control characters",
        ))
    } else {
        Ok(())
    }
}

/// Keeps this text-storage demonstration bounded independently of JSON overhead.
fn validate_content(content: &str) -> Result<(), ApiError> {
    if content.len() > 64 * 1024 {
        Err(ApiError::bad_request("content exceeds 64 KiB"))
    } else {
        Ok(())
    }
}

/// Prevents treating folders or workspaces as file blobs.
fn require_file(item: &Item) -> Result<(), ApiError> {
    if item.kind == Kind::File {
        Ok(())
    } else {
        Err(ApiError::bad_request("content belongs only to files"))
    }
}
