//! Application metadata and relationship writes share a process-local lock.
//!
//! Handlers retain this lock across checks and mutations so revocation cannot
//! race an authorized write. A database implementation needs an equivalent
//! consistency design spanning metadata and authorization relationships.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use relgraph_authz::{
    AuthorizationDecision, Bound, CheckRequest, EvaluationLimits, FgaAuthz,
    InMemoryRelationshipStore, ObjectRef, RelationName, RelationshipTuple, Subject, TenantId,
    TupleSubject, WriteError,
};
use serde::{Deserialize, Serialize};

use crate::{auth::Identity, error::ApiError};

/// Supported resource kinds enforce an acyclic workspace → folder → file tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Workspace,
    Folder,
    File,
}

impl Kind {
    /// Returns the corresponding object type in the embedded model.
    pub fn model_type(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Folder => "folder",
            Self::File => "file",
        }
    }

    /// Describes the single supported parent level.
    fn parent_kind(self) -> Option<Self> {
        match self {
            Self::Workspace => None,
            Self::Folder => Some(Self::Workspace),
            Self::File => Some(Self::Folder),
        }
    }
}

/// Metadata returned by list and read endpoints; tenant selection stays internal.
#[derive(Clone, Serialize)]
pub struct Item {
    pub id: String,
    pub kind: Kind,
    pub name: String,
    pub parent_id: Option<String>,
    pub owner: String,
    pub revision: u64,
    #[serde(skip_serializing)]
    pub tenant: TenantId,
    #[serde(skip_serializing)]
    pub content: String,
}

/// Explicit share roles cannot grant ownership or choose an arbitrary relation.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Editor,
}

impl Role {
    /// Maps a validated role to a direct relationship.
    fn relation(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
        }
    }
}

/// Share targets distinguish concrete users from team membership usersets.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Grantee {
    User(String),
    Team(String),
}

/// A share stores its full tuple so removal revokes that exact grant.
#[derive(Clone, Serialize)]
pub struct Share {
    pub id: String,
    pub grantee: Grantee,
    pub role: Role,
    #[serde(skip_serializing)]
    pub tuple: RelationshipTuple,
}

/// The local repository, authorizer, and grant ledger owned by this application.
///
/// Relationship writes go through the authorizer's validating write methods,
/// so every stored tuple fits the model that checks read it with.
pub struct Drive {
    pub items: BTreeMap<String, Item>,
    pub shares: BTreeMap<String, Vec<Share>>,
    authz: FgaAuthz<Bound<InMemoryRelationshipStore>>,
    next_id: u64,
}

impl Drive {
    /// Compiles the model and seeds two tenants with independent root workspaces.
    pub async fn seeded() -> Result<Self, Box<dyn std::error::Error>> {
        let authz = FgaAuthz::new(include_str!("../authorization.fga"))?.with_store(
            InMemoryRelationshipStore::new(),
            EvaluationLimits::default(),
        );
        let mut drive = Self {
            items: BTreeMap::new(),
            shares: BTreeMap::new(),
            authz,
            next_id: 1,
        };
        for (tenant, user, root) in [
            ("acme", "alice", "acme-drive"),
            ("other", "eve", "other-drive"),
        ] {
            drive
                .add_item(
                    TenantId::new(tenant)?,
                    user,
                    root.into(),
                    Kind::Workspace,
                    "Company drive".into(),
                    None,
                    String::new(),
                )
                .await?;
        }
        let acme = TenantId::new("acme")?;
        drive
            .authz
            .write_tuple(
                &acme,
                &RelationshipTuple::new(
                    acme.clone(),
                    ObjectRef::new("team", "design")?,
                    RelationName::new("member")?,
                    Subject::new("user", "bob")?,
                ),
            )
            .await?;
        drive
            .add_item(
                acme.clone(),
                "alice",
                "design-folder".into(),
                Kind::Folder,
                "Design".into(),
                Some("acme-drive".into()),
                String::new(),
            )
            .await?;
        drive
            .add_item(
                acme,
                "alice",
                "roadmap-file".into(),
                Kind::File,
                "Roadmap.txt".into(),
                Some("design-folder".into()),
                "Ship the shared drive MVP.\n".into(),
            )
            .await?;
        let folder = drive.items["design-folder"].clone();
        drive
            .add_share(&folder, Grantee::Team("design".into()), Role::Editor)
            .await?;
        Ok(drive)
    }

    /// Allocates a server-owned identifier; callers cannot overwrite existing IDs.
    pub fn allocate_id(&mut self, prefix: &str) -> String {
        let id = format!("{prefix}-{}", self.next_id);
        self.next_id += 1;
        id
    }

    /// Looks up metadata only inside the authenticated tenant.
    pub fn item(&self, identity: &Identity, id: &str) -> Result<Item, ApiError> {
        self.items
            .get(id)
            .filter(|item| item.tenant == identity.tenant)
            .cloned()
            .ok_or_else(ApiError::not_found)
    }

    /// Checks a fixed application capability and preserves evaluation errors.
    pub async fn allowed(
        &self,
        identity: &Identity,
        item: &Item,
        capability: &str,
    ) -> Result<bool, ApiError> {
        let request = CheckRequest::new(
            identity.tenant.clone(),
            identity.subject.clone(),
            ObjectRef::new(item.kind.model_type(), item.id.clone())
                .map_err(ApiError::unavailable)?,
            RelationName::new(capability).map_err(ApiError::unavailable)?,
        );
        self.authz
            .check(request)
            .await
            .map(|decision| decision == AuthorizationDecision::Allow)
            .map_err(ApiError::unavailable)
    }

    /// Requires an allow before the caller reads content or changes application state.
    pub async fn require(
        &self,
        identity: &Identity,
        item: &Item,
        capability: &str,
    ) -> Result<(), ApiError> {
        if self.allowed(identity, item, capability).await? {
            Ok(())
        } else {
            Err(ApiError(StatusCode::FORBIDDEN, "permission denied"))
        }
    }

    /// Creates metadata after atomically writing its owner and parent tuples.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_item(
        &mut self,
        tenant: TenantId,
        owner: &str,
        id: String,
        kind: Kind,
        name: String,
        parent_id: Option<String>,
        content: String,
    ) -> Result<Item, ApiError> {
        let object =
            ObjectRef::new(kind.model_type(), id.clone()).map_err(ApiError::unavailable)?;
        let owner_tuple = RelationshipTuple::new(
            tenant.clone(),
            object.clone(),
            RelationName::new("owner").map_err(ApiError::unavailable)?,
            Subject::new("user", owner).map_err(ApiError::unavailable)?,
        );
        let mut tuples = vec![owner_tuple];
        if let (Some(parent), Some(parent_kind)) = (&parent_id, kind.parent_kind()) {
            tuples.push(RelationshipTuple::new(
                tenant.clone(),
                object,
                RelationName::new("parent").map_err(ApiError::unavailable)?,
                Subject::new(parent_kind.model_type(), parent.clone())
                    .map_err(ApiError::unavailable)?,
            ));
        }
        self.authz
            .apply_changes(&tenant, &tuples, &[])
            .await
            .map_err(write_failed)?;
        let item = Item {
            id: id.clone(),
            kind,
            name,
            parent_id,
            owner: owner.into(),
            revision: 1,
            tenant,
            content,
        };
        self.items.insert(id, item.clone());
        Ok(item)
    }

    /// Adds a direct grant after the handler has checked management permission.
    pub async fn add_share(
        &mut self,
        item: &Item,
        grantee: Grantee,
        role: Role,
    ) -> Result<Share, ApiError> {
        let known = match &grantee {
            Grantee::User(id) => match item.tenant.as_str() {
                "acme" => ["alice", "bob", "carol"].contains(&id.as_str()),
                "other" => id == "eve",
                _ => false,
            },
            Grantee::Team(id) => item.tenant.as_str() == "acme" && id == "design",
        };
        if !known {
            return Err(ApiError::bad_request("unknown grantee in this tenant"));
        }
        if self.shares.get(&item.id).is_some_and(|shares| {
            shares
                .iter()
                .any(|share| share.grantee == grantee && share.role == role)
        }) {
            return Err(ApiError(StatusCode::CONFLICT, "share already exists"));
        }
        let subject = match &grantee {
            Grantee::User(id) => TupleSubject::Direct(
                Subject::new("user", id.clone()).map_err(ApiError::unavailable)?,
            ),
            Grantee::Team(id) => TupleSubject::Userset {
                object: ObjectRef::new("team", id.clone()).map_err(ApiError::unavailable)?,
                relation: RelationName::new("member").map_err(ApiError::unavailable)?,
            },
        };
        let tuple = RelationshipTuple::new(
            item.tenant.clone(),
            ObjectRef::new(item.kind.model_type(), item.id.clone())
                .map_err(ApiError::unavailable)?,
            RelationName::new(role.relation()).map_err(ApiError::unavailable)?,
            subject,
        );
        self.authz
            .write_tuple(&item.tenant, &tuple)
            .await
            .map_err(write_failed)?;
        let share = Share {
            id: self.allocate_id("share"),
            grantee,
            role,
            tuple,
        };
        self.shares
            .entry(item.id.clone())
            .or_default()
            .push(share.clone());
        Ok(share)
    }

    /// Removes a ledger entry only after its exact relationship has been removed.
    pub async fn revoke_share(&mut self, item: &Item, share_id: &str) -> Result<(), ApiError> {
        let shares = self
            .shares
            .get_mut(&item.id)
            .ok_or_else(ApiError::not_found)?;
        let index = shares
            .iter()
            .position(|share| share.id == share_id)
            .ok_or_else(ApiError::not_found)?;
        self.authz
            .delete_tuple(&item.tenant, &shares[index].tuple)
            .await
            .map_err(write_failed)?;
        shares.remove(index);
        Ok(())
    }
}

/// Reports a rejected or failed relationship write as a safe service error.
///
/// The application builds every tuple itself, so a validation failure is a
/// server bug rather than client input.
fn write_failed(error: WriteError) -> ApiError {
    ApiError::unavailable(error)
}
