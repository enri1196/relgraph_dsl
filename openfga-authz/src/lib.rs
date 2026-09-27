//! Authorization runtime built on top of the `openfga_dsl` parser.
//! Local OpenFGA authorization runtime.
//!
//! The [`openfga_dsl`] crate remains a parser and semantic validator. This crate
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
    InMemoryRelationshipStore, ObjectRef, RelationExpressionKind, RelationLocation, RelationName,
    RelationshipPage, RelationshipReadSession, RelationshipStore, RelationshipTuple,
    RelationshipWriteStore, RuntimeCapability, StoreCursor, StoreError, StoreErrorKind,
    StoreFuture, Subject, TenantId, TupleSubject, TypeName, Unbound,
};
#[cfg(feature = "axum")]
pub mod axum_authz;
