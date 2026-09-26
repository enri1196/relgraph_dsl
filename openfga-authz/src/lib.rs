//! Authorization runtime built on top of the `openfga_dsl` parser.
//! Local OpenFGA authorization runtime.
//!
//! The [`openfga_dsl`] crate remains a parser and semantic validator. This crate
//! owns runtime compilation and authorization APIs built on top of that parser.

mod authz;

pub use authz::{
    AuthorizationDecision, AuthorizationError, Bound, CapabilityDiagnostic, CheckRequest,
    ConditionContext, ConditionName, ConstructionError, EntityId, EvaluationLimits,
    EvaluationLimitsError, FgaAuthz, IdentifierError, InMemoryReadSession,
    InMemoryRelationshipStore, ObjectRef, RelationExpressionKind, RelationLocation, RelationName,
    RelationshipReadSession, RelationshipStore, RelationshipTuple, RuntimeCapability, StoreError,
    StoreErrorKind, StoreFuture, Subject, TenantId, TupleSubject, TypeName, Unbound,
};
