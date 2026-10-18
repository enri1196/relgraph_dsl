//! Authorization model construction and lifecycle state types.

mod conditions;
mod evaluator;
mod model;
mod parameter_profile;
pub mod policy;
mod request;
mod store;
mod write;

pub use request::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, CapabilityDiagnostic,
    CheckRequest, ConditionContextSource, ConditionName, ConstructionError, ContextualTupleError,
    EntityId, EvaluationLimits, EvaluationLimitsError, FilteredObjects, IdentifierError,
    MAX_CONTEXTUAL_TUPLES, ObjectRef, RelationExpressionKind, RelationLocation, RelationName,
    RuntimeCapability, Subject, TenantId, TypeName,
};
pub use store::{
    ConditionContext, InMemoryReadSession, InMemoryRelationshipStore,
    MAX_CONDITION_CONTEXT_ELEMENTS, MAX_CONDITION_CONTEXT_SERIALIZED_BYTES, RelationshipPage,
    RelationshipReadSession, RelationshipStore, RelationshipTuple, RelationshipWriteStore,
    StoreCursor, StoreError, StoreErrorKind, StoreFuture, TupleSubject,
};
pub use write::WriteError;

use std::fmt;
use std::sync::Arc;

use evaluator::{batch_check as evaluate_batch_check, check as evaluate_check};
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
    model_identity: ModelIdentity,
    state: State,
}

/// Opaque identity shared by clones of one compiled authorization model.
///
/// This identifies a compiled model instance within the running process. It is
/// useful for tying request authorization metadata to the model that produced
/// it; it is not a persistent model version or a security credential.
#[derive(Clone)]
pub struct ModelIdentity(Arc<()>);

impl ModelIdentity {
    /// Creates an identity token for a newly compiled model instance.
    fn new() -> Self {
        Self(Arc::new(()))
    }

    /// Returns whether both values identify the same compiled model instance.
    pub fn identifies_same_model(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for ModelIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModelIdentity").finish_non_exhaustive()
    }
}

impl PartialEq for ModelIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.identifies_same_model(other)
    }
}

impl Eq for ModelIdentity {}

impl FgaAuthz<Unbound> {
    /// Parses, semantically validates, checks runtime capabilities, and compiles
    /// an authorization definition synchronously without accessing a store.
    pub fn new(definition: &str) -> Result<Self, ConstructionError> {
        let schema =
            relgraph_dsl::parse_fga_schema(definition).map_err(ConstructionError::Parse)?;
        let compiled = CompiledModel::compile(schema)?;
        Ok(Self {
            compiled: Arc::new(compiled),
            model_identity: ModelIdentity::new(),
            state: Unbound,
        })
    }

    /// Constructs an authorizer from an assembled modular model.
    ///
    /// The model is semantically revalidated before its composed schema is
    /// consumed, preserving module and file locations in validation errors.
    /// Runtime capability checks and CEL compilation then run as they do for
    /// [`FgaAuthz::new`].
    pub fn from_modular_model(
        model: relgraph_dsl::ModularModel,
    ) -> Result<Self, ConstructionError> {
        relgraph_dsl::validate_modular_model(&model).map_err(ConstructionError::Validation)?;
        let schema = model.into_schema();
        let compiled = CompiledModel::compile_validated(schema)?;
        Ok(Self {
            compiled: Arc::new(compiled),
            model_identity: ModelIdentity::new(),
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
            model_identity: self.model_identity,
            state: Bound {
                store: Arc::new(store),
                limits,
            },
        }
    }
}

impl<State> FgaAuthz<State> {
    /// Returns the validated syntax tree used to build this model.
    pub fn schema(&self) -> &relgraph_dsl::Schema {
        self.compiled.schema()
    }

    /// Validates a relationship tuple against this model before it is written.
    ///
    /// Checks reject a whole page of tuples when any tuple in it does not fit
    /// the model, so writers should call this before inserting a tuple. It
    /// verifies that the object type and relation exist, that the relation
    /// accepts directly assigned tuples, that the subject and condition match
    /// one of the relation's declared targets, and that a stored condition
    /// context converts to the declared parameter types. It does not check the
    /// tuple's tenant or authorize the write.
    pub fn validate_tuple(&self, tuple: &RelationshipTuple) -> Result<(), AuthorizationError> {
        self.compiled.validate_tuple(tuple)
    }

    /// Returns an opaque identity shared by clones of this compiled model.
    pub fn model_identity(&self) -> ModelIdentity {
        self.model_identity.clone()
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

    /// Checks many `(object, relation)` pairs for one subject and context.
    ///
    /// All items read one tenant snapshot, so a write made while the batch
    /// runs is not observed by later items, and they share memoized relation
    /// decisions and converted request values. Each item gets fresh tuple,
    /// store-call, and work budgets, and its error stays in its own slot.
    /// Results follow item order. The outer error reports a batch larger than
    /// [`EvaluationLimits::max_batch_items`], an unknown subject type, invalid
    /// contextual tuples, or a failure to open the read session. A backend may
    /// hold one connection and transaction for the whole batch.
    ///
    /// ```no_run
    /// use relgraph_authz::{
    ///     AuthorizationDecision, BatchCheckRequest, EvaluationLimits, FgaAuthz,
    ///     InMemoryRelationshipStore, ObjectRef, RelationName, Subject, TenantId,
    /// };
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let authorizer = FgaAuthz::new(
    ///     "model\n  schema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n",
    /// )?
    /// .with_store(InMemoryRelationshipStore::new(), EvaluationLimits::default());
    /// let viewer = RelationName::new("viewer")?;
    /// let request = BatchCheckRequest::new(
    ///     TenantId::new("acme")?,
    ///     Subject::new("user", "anne")?,
    ///     [
    ///         (ObjectRef::new("document", "1")?, viewer.clone()),
    ///         (ObjectRef::new("document", "2")?, viewer),
    ///     ],
    /// );
    /// for result in authorizer.batch_check(&request).await? {
    ///     let _allowed = result? == AuthorizationDecision::Allow;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn batch_check(
        &self,
        request: &BatchCheckRequest,
    ) -> Result<Vec<Result<AuthorizationDecision, AuthorizationError>>, AuthorizationError> {
        evaluate_batch_check(
            &self.compiled,
            self.state.store.as_ref(),
            self.state.limits,
            request,
        )
        .await
    }

    /// Returns the candidates on which `subject` holds `relation`.
    ///
    /// Candidates may mix object types that define `relation`. This is one
    /// [`Self::batch_check`] without request context or contextual tuples:
    /// allowed candidates and per-candidate errors are returned separately, in
    /// candidate order, and denied candidates are omitted. Use `batch_check`
    /// directly when conditions need request context or the check needs
    /// contextual tuples.
    pub async fn filter_objects(
        &self,
        tenant: TenantId,
        subject: Subject,
        relation: RelationName,
        candidates: Vec<ObjectRef>,
    ) -> Result<FilteredObjects, AuthorizationError> {
        let request = BatchCheckRequest::new(
            tenant,
            subject,
            candidates
                .into_iter()
                .map(|object| (object, relation.clone())),
        );
        let results = self.batch_check(&request).await?;
        let mut filtered = FilteredObjects::default();
        for ((object, _), result) in request.items().iter().zip(results) {
            match result {
                Ok(AuthorizationDecision::Allow) => filtered.allowed.push(object.clone()),
                Ok(AuthorizationDecision::Deny) => {}
                Err(error) => filtered.errors.push((object.clone(), error)),
            }
        }
        Ok(filtered)
    }
}

impl<State: Clone> Clone for FgaAuthz<State> {
    fn clone(&self) -> Self {
        Self {
            compiled: Arc::clone(&self.compiled),
            model_identity: self.model_identity.clone(),
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
