//! In-memory authorization quick start.
//!
//! The default authorization crate needs no database or optional feature. An
//! application supplies its Tokio runtime and can keep relationships in the
//! in-memory reference store for tests, examples, and small local deployments.
//!
//! ```no_run
//! use std::error::Error;
//!
//! use relgraph_authz::{
//!     CheckRequest, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore,
//!     ObjectRef, RelationName, RelationshipTuple, Subject, TenantId,
//! };
//!
//! const MODEL: &str = r#"
//! model
//!   schema 1.1
//!
//! type user
//!
//! type document
//!   relations
//!     define viewer: [user]
//! "#;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     let tenant = TenantId::new("acme")?;
//!     let subject = Subject::new("user", "anne")?;
//!     let object = ObjectRef::new("document", "42")?;
//!     let relation = RelationName::new("viewer")?;
//!
//!     let store = InMemoryRelationshipStore::new();
//!     store.insert(RelationshipTuple::new(
//!         tenant.clone(),
//!         object.clone(),
//!         relation.clone(),
//!         subject.clone(),
//!     ))?;
//!
//!     let authorizer = FgaAuthz::new(MODEL)?
//!         .with_store(store, EvaluationLimits::default());
//!     let request = CheckRequest::new(tenant, subject, object, relation);
//!     let _decision = authorizer.check(request).await?;
//!     Ok(())
//! }
//! ```
//!
//! Authorization runtime built on top of the `relgraph_dsl` parser.
//! Local OpenFGA authorization runtime.
//!
//! The [`relgraph_dsl`] crate remains a parser and semantic validator. This crate
//! owns runtime compilation and authorization APIs built on top of that parser.

mod authz;

pub use authz::ModelIdentity;

pub use authz::policy::{
    AssignmentRequirement, AsyncContextResolver, AuthorizationRequirements,
    ConditionParameterRequirement, ConditionRequirement, ContextBinding, ContextResolverFuture,
    ContextValue, ContextValueProvider, ContextValueType, ObjectIdSource, PathParameters,
    PolicyError, PolicyInputError, PrincipalIdentity, PrincipalSource, RelationKey,
    RelationRequirements, RequestPartsExtractor, RequirementExpression, RoutePolicy,
    TenantIdentity, TenantSource, ValidatedRoutePolicy,
};
pub use authz::{
    AuthorizationDecision, AuthorizationError, Bound, CapabilityDiagnostic, CheckRequest,
    ConditionContext, ConditionContextSource, ConditionName, ConstructionError, EntityId,
    EvaluationLimits, EvaluationLimitsError, FgaAuthz, IdentifierError, InMemoryReadSession,
    InMemoryRelationshipStore, MAX_CONDITION_CONTEXT_ELEMENTS,
    MAX_CONDITION_CONTEXT_SERIALIZED_BYTES, ObjectRef, RelationExpressionKind, RelationLocation,
    RelationName, RelationshipPage, RelationshipReadSession, RelationshipStore, RelationshipTuple,
    RelationshipWriteStore, RuntimeCapability, StoreCursor, StoreError, StoreErrorKind,
    StoreFuture, Subject, TenantId, TupleSubject, TypeName, Unbound,
};
#[cfg(feature = "axum")]
pub mod axum_authz;
