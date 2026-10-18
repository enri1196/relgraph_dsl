//! Model-validating relationship writes for stores that support mutation.

use super::request::{AuthorizationError, TenantId};
use super::store::{RelationshipTuple, RelationshipWriteStore, StoreError, StoreErrorKind};
use super::{Bound, FgaAuthz};

/// A rejected or failed validating write.
#[derive(Debug)]
pub enum WriteError {
    /// The tuple does not fit the bound authorization model.
    Validation(AuthorizationError),
    /// The tenant check or the relationship store rejected or failed the write.
    Store(StoreError),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => write!(f, "relationship write rejected: {error}"),
            Self::Store(error) => write!(f, "relationship write failed: {error}"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(error) => Some(error),
            Self::Store(error) => Some(error),
        }
    }
}

/// Writes that validate tuples against the bound model before reaching the store.
///
/// These methods only keep stored tuples consistent with the model so checks
/// can read them. They do not authorize the caller to write: applications must
/// still decide who may create or remove each relationship.
impl<S: RelationshipWriteStore> FgaAuthz<Bound<S>> {
    /// Validates one tuple for `tenant` against this model, then inserts it.
    ///
    /// A tuple owned by another tenant returns [`StoreErrorKind::InvalidInput`]
    /// and an existing tuple returns [`StoreErrorKind::Conflict`], both as
    /// [`WriteError::Store`].
    pub async fn write_tuple(
        &self,
        tenant: &TenantId,
        tuple: &RelationshipTuple,
    ) -> Result<(), WriteError> {
        self.validate_write(tenant, tuple)?;
        self.state
            .store
            .insert_tuple(tenant, tuple)
            .await
            .map_err(WriteError::Store)
    }

    /// Validates one exact tuple for `tenant` against this model, then removes it.
    ///
    /// Returns `false` when no exact tuple exists. A stored tuple that no
    /// longer fits this model fails validation here; remove it through the
    /// store's [`RelationshipWriteStore::remove_tuple`] instead.
    pub async fn delete_tuple(
        &self,
        tenant: &TenantId,
        tuple: &RelationshipTuple,
    ) -> Result<bool, WriteError> {
        self.validate_write(tenant, tuple)?;
        self.state
            .store
            .remove_tuple(tenant, tuple)
            .await
            .map_err(WriteError::Store)
    }

    fn validate_write(
        &self,
        tenant: &TenantId,
        tuple: &RelationshipTuple,
    ) -> Result<(), WriteError> {
        if tuple.tenant() != tenant {
            return Err(WriteError::Store(StoreError::new(
                StoreErrorKind::InvalidInput,
                "relationship tuple tenant does not match write tenant",
            )));
        }
        self.compiled
            .validate_tuple(tuple)
            .map_err(WriteError::Validation)
    }
}
