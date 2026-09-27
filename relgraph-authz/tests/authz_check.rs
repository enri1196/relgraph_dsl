mod common;

use common::{DIRECT_MODEL, block_on, object, relation, request, subject, tenant};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, EvaluationLimits, FgaAuthz,
    InMemoryRelationshipStore, ObjectRef, RelationshipReadSession, RelationshipStore,
    RelationshipTuple, StoreError, StoreErrorKind, StoreFuture, TenantId,
};

#[test]
fn matching_direct_tuple_allows_and_missing_tuple_denies() {
    let store = InMemoryRelationshipStore::new();
    store
        .insert(RelationshipTuple::new(
            tenant("tenant-a"),
            object("document", "42"),
            relation("viewer"),
            subject("user", "anne"),
        ))
        .unwrap();
    let authz = FgaAuthz::new(DIRECT_MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    assert_eq!(
        block_on(authz.check(request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        block_on(authz.check(request(
            "tenant-a", "user", "bea", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
}

#[test]
fn identical_subject_and_object_ids_are_isolated_by_tenant() {
    let store = InMemoryRelationshipStore::new();
    store
        .insert(RelationshipTuple::new(
            tenant("tenant-a"),
            object("document", "42"),
            relation("viewer"),
            subject("user", "anne"),
        ))
        .unwrap();
    let authz = FgaAuthz::new(DIRECT_MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    assert_eq!(
        block_on(authz.check(request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        block_on(authz.check(request(
            "tenant-b", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
}

#[test]
fn unknown_object_type_subject_type_and_relation_are_errors() {
    let authz = FgaAuthz::new(DIRECT_MODEL).unwrap().with_store(
        InMemoryRelationshipStore::new(),
        EvaluationLimits::default(),
    );

    assert!(matches!(
        block_on(authz.check(request(
            "tenant-a", "user", "anne", "folder", "42", "viewer",
        ))),
        Err(AuthorizationError::UnknownObjectType(_))
    ));
    assert!(matches!(
        block_on(authz.check(request(
            "tenant-a", "person", "anne", "document", "42", "viewer",
        ))),
        Err(AuthorizationError::UnknownSubjectType(_))
    ));
    assert!(matches!(
        block_on(authz.check(request(
            "tenant-a", "user", "anne", "document", "42", "editor",
        ))),
        Err(AuthorizationError::UnknownRelation { .. })
    ));
}

#[test]
fn incompatible_persisted_tuple_is_an_error() {
    let tuple = RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation("viewer"),
        subject("group", "writers"),
    );
    let authz = FgaAuthz::new(DIRECT_MODEL)
        .unwrap()
        .with_store(FixedTupleStore(tuple), EvaluationLimits::default());

    assert!(matches!(
        block_on(authz.check(request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        ))),
        Err(AuthorizationError::InvalidTuple(_))
    ));
}

#[test]
fn store_failure_is_not_a_denial() {
    let authz = FgaAuthz::new(DIRECT_MODEL)
        .unwrap()
        .with_store(FailingStore, EvaluationLimits::default());

    assert!(matches!(
        block_on(authz.check(request(
            "tenant-a",
            "user",
            "anne",
            "document",
            "42",
            "viewer",
        ))),
        Err(AuthorizationError::Store(error)) if error.kind() == StoreErrorKind::Unavailable
    ));
}

#[test]
fn tuple_limit_exhaustion_is_an_error() {
    let store = InMemoryRelationshipStore::new();
    for id in ["anne", "bea"] {
        store
            .insert(RelationshipTuple::new(
                tenant("tenant-a"),
                object("document", "42"),
                relation("viewer"),
                subject("user", id),
            ))
            .unwrap();
    }
    let limits = EvaluationLimits::new(1).unwrap();
    let authz = FgaAuthz::new(DIRECT_MODEL)
        .unwrap()
        .with_store(store, limits);

    assert!(matches!(
        block_on(authz.check(request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        ))),
        Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples: 1 })
    ));
    assert!(EvaluationLimits::new(0).is_err());
    assert!(EvaluationLimits::new(EvaluationLimits::MAX_TUPLES_SCANNED + 1).is_err());
}

#[test]
fn cloning_bound_authz_keeps_the_shared_relationship_store() {
    let store = InMemoryRelationshipStore::new();
    let authz = FgaAuthz::new(DIRECT_MODEL)
        .unwrap()
        .with_store(store.clone(), EvaluationLimits::default());
    let clone = authz.clone();
    store
        .insert(RelationshipTuple::new(
            tenant("tenant-a"),
            object("document", "42"),
            relation("viewer"),
            subject("user", "anne"),
        ))
        .unwrap();

    assert_eq!(
        block_on(clone.check(request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
}

struct FixedTupleStore(RelationshipTuple);

struct FixedTupleSession(RelationshipTuple);

impl RelationshipStore for FixedTupleStore {
    type ReadSession = FixedTupleSession;

    fn begin_read<'a>(
        &'a self,
        _: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let tuple = self.0.clone();
        Box::pin(async move { Ok(FixedTupleSession(tuple)) })
    }
}

impl RelationshipReadSession for FixedTupleSession {
    fn tuples<'a>(
        &'a self,
        _: &'a ObjectRef,
        _: &'a relgraph_authz::RelationName,
        _: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        let tuple = self.0.clone();
        Box::pin(async move { Ok(vec![tuple]) })
    }
}

struct FailingStore;

struct UnusedSession;

impl RelationshipStore for FailingStore {
    type ReadSession = UnusedSession;

    fn begin_read<'a>(
        &'a self,
        _: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        Box::pin(async {
            Err(StoreError::new(
                StoreErrorKind::Unavailable,
                "test store unavailable",
            ))
        })
    }
}

impl RelationshipReadSession for UnusedSession {
    fn tuples<'a>(
        &'a self,
        _: &'a ObjectRef,
        _: &'a relgraph_authz::RelationName,
        _: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}
