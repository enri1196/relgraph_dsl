//! Authorization model construction and lifecycle state types.

mod evaluator;
mod model;
mod request;
mod store;

pub use request::{
    AuthorizationDecision, AuthorizationError, CapabilityDiagnostic, CheckRequest, ConditionName,
    ConstructionError, EntityId, EvaluationLimits, EvaluationLimitsError, IdentifierError,
    ObjectRef, RelationExpressionKind, RelationLocation, RelationName, RuntimeCapability, Subject,
    TenantId, TypeName,
};
pub use store::{
    ConditionContext, InMemoryReadSession, InMemoryRelationshipStore, RelationshipPage,
    RelationshipReadSession, RelationshipStore, RelationshipTuple, StoreError, StoreErrorKind,
    StoreFuture, TupleSubject,
};

use std::fmt;
use std::sync::Arc;

use evaluator::check as evaluate_check;
use model::CompiledModel;

/// Marker for a compiled authorization model that has no relationship store.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unbound;

/// Marker for a compiled authorization model after it is bound to a store.
///
/// Its private fields prevent callers from manufacturing a bound model without
/// going through [`FgaAuthz::with_store`]. Clones share the relationship store.
pub struct Bound<S> {
    store: Arc<S>,
    limits: EvaluationLimits,
}

impl<S> Clone for Bound<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            limits: self.limits,
        }
    }
}

/// A validated, compiled OpenFGA model in a typed lifecycle state.
///
/// Cloning this value shares its immutable compiled model through an `Arc`.
#[must_use = "constructing an authorization model has no effect until it is used"]
pub struct FgaAuthz<State = Unbound> {
    pub(crate) compiled: Arc<CompiledModel>,
    state: State,
}

impl FgaAuthz<Unbound> {
    /// Parses, semantically validates, checks runtime capabilities, and compiles
    /// an authorization definition synchronously without accessing a store.
    pub fn new(definition: &str) -> Result<Self, ConstructionError> {
        let schema = openfga_dsl::parse_fga_schema(definition).map_err(ConstructionError::Parse)?;
        let compiled = CompiledModel::compile(schema)?;
        Ok(Self {
            compiled: Arc::new(compiled),
            state: Unbound,
        })
    }

    /// Binds an explicit relationship source and bounded evaluation profile.
    pub fn with_store<S: RelationshipStore>(
        self,
        store: S,
        limits: EvaluationLimits,
    ) -> FgaAuthz<Bound<S>> {
        FgaAuthz {
            compiled: self.compiled,
            state: Bound {
                store: Arc::new(store),
                limits,
            },
        }
    }
}

impl<State> FgaAuthz<State> {
    /// Returns the validated syntax tree used to build this model.
    pub fn schema(&self) -> &openfga_dsl::Schema {
        self.compiled.schema()
    }
}

impl<S: RelationshipStore> FgaAuthz<Bound<S>> {
    /// Checks unconditional direct membership for a concrete subject.
    pub async fn check(
        &self,
        request: CheckRequest,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        evaluate_check(
            &self.compiled,
            self.state.store.as_ref(),
            self.state.limits,
            &request,
        )
        .await
    }
}

impl<State: Clone> Clone for FgaAuthz<State> {
    fn clone(&self) -> Self {
        Self {
            compiled: Arc::clone(&self.compiled),
            state: self.state.clone(),
        }
    }
}

impl<State> fmt::Debug for FgaAuthz<State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FgaAuthz")
            .field("types", &self.compiled.type_count())
            .field("relations", &self.compiled.relation_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::FgaAuthz;
    use std::sync::Arc;

    #[test]
    fn cloning_shares_the_compiled_model() {
        let model = FgaAuthz::new("model\nschema 1.1\ntype user\n").unwrap();
        let clone = model.clone();

        assert!(Arc::ptr_eq(&model.compiled, &clone.compiled));
    }
}
