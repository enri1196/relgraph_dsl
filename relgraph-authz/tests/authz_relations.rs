#[allow(dead_code)]
mod common;

use common::{block_on, request as check_request};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, EvaluationLimits, FgaAuthz, InMemoryReadSession,
    InMemoryRelationshipStore, ObjectRef, RelationName, RelationshipReadSession, RelationshipStore,
    RelationshipTuple, StoreError, StoreErrorKind, StoreFuture, Subject, TenantId, TupleSubject,
    TypeName,
};
use std::collections::HashSet;
use std::future::{Future, pending};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).unwrap()
}

fn object(type_name: &str, id: &str) -> ObjectRef {
    ObjectRef::new(type_name, id).unwrap()
}

fn subject(type_name: &str, id: &str) -> Subject {
    Subject::new(type_name, id).unwrap()
}

fn relation(value: &str) -> RelationName {
    RelationName::new(value).unwrap()
}

fn tuple(
    object_type: &str,
    object_id: &str,
    relation_name: &str,
    tuple_subject: impl Into<TupleSubject>,
) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant("tenant-a"),
        object(object_type, object_id),
        relation(relation_name),
        tuple_subject,
    )
}

#[test]
fn computed_usersets_union_intersection_and_difference_evaluate() {
    let definition = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define owner: [user]\n    define editor: [user]\n    define blocked: [user]\n    define inherited: owner\n    define union_viewer: owner or editor\n    define shared_viewer: owner and editor\n    define unblocked_owner: owner but not blocked\n    define nested_viewer: [user] or editor\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple("document", "42", "owner", subject("user", "anne")))
        .unwrap();
    store
        .insert(tuple("document", "42", "owner", subject("user", "charlie")))
        .unwrap();
    store
        .insert(tuple("document", "42", "editor", subject("user", "anne")))
        .unwrap();
    store
        .insert(tuple(
            "document",
            "42",
            "blocked",
            subject("user", "charlie"),
        ))
        .unwrap();
    store
        .insert(tuple(
            "document",
            "42",
            "nested_viewer",
            subject("user", "charlie"),
        ))
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    for relation_name in [
        "inherited",
        "union_viewer",
        "shared_viewer",
        "nested_viewer",
    ] {
        assert_eq!(
            block_on(authz.check(check_request(
                "tenant-a",
                "user",
                "anne",
                "document",
                "42",
                relation_name,
            )))
            .unwrap(),
            AuthorizationDecision::Allow,
            "expected allow for {relation_name}"
        );
    }
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a",
            "user",
            "bea",
            "document",
            "42",
            "union_viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a",
            "user",
            "charlie",
            "document",
            "42",
            "nested_viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a",
            "user",
            "charlie",
            "document",
            "42",
            "shared_viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a",
            "user",
            "anne",
            "document",
            "42",
            "unblocked_owner",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a",
            "user",
            "charlie",
            "document",
            "42",
            "unblocked_owner",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
}

#[test]
fn nested_group_usersets_reach_direct_members() {
    let definition = "model\nschema 1.1\ntype user\ntype subgroup\n  relations\n    define member: [user]\ntype group\n  relations\n    define member: [subgroup#member]\ntype document\n  relations\n    define viewer: [group#member]\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple(
            "document",
            "42",
            "viewer",
            TupleSubject::Userset {
                object: object("group", "8"),
                relation: relation("member"),
            },
        ))
        .unwrap();
    store
        .insert(tuple(
            "group",
            "8",
            "member",
            TupleSubject::Userset {
                object: object("subgroup", "3"),
                relation: relation("member"),
            },
        ))
        .unwrap();
    store
        .insert(tuple("subgroup", "3", "member", subject("user", "anne")))
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "bea", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
}

#[test]
fn typed_wildcards_match_only_the_declared_subject_type() {
    let definition = "model\nschema 1.1\ntype user\ntype team\ntype document\n  relations\n    define viewer: [user:*]\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple(
            "document",
            "42",
            "viewer",
            TupleSubject::TypedWildcard(TypeName::new("user").unwrap()),
        ))
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "team", "ops", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
}

#[test]
fn tuple_to_userset_inherits_access_from_parent_objects() {
    let definition = "model\nschema 1.1\ntype user\ntype folder\n  relations\n    define viewer: [user]\ntype document\n  relations\n    define parent: [folder]\n    define viewer: viewer from parent\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple("document", "42", "parent", subject("folder", "7")))
        .unwrap();
    store
        .insert(tuple("folder", "7", "viewer", subject("user", "anne")))
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "bea", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
}

#[test]
fn tuple_to_userset_skips_targets_without_the_computed_relation() {
    let definition = "model\nschema 1.1\ntype user\ntype folder\n  relations\n    define viewer: [user]\ntype team\ntype document\n  relations\n    define parent: [folder, team]\n    define viewer: viewer from parent\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple("document", "42", "parent", subject("team", "ops")))
        .unwrap();
    store
        .insert(tuple("document", "42", "parent", subject("folder", "docs")))
        .unwrap();
    store
        .insert(tuple("folder", "docs", "viewer", subject("user", "bea")))
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "bea", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
}

#[test]
fn difference_store_failures_never_grant_and_boolean_errors_are_branch_order_invariant() {
    let difference_model = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define owner: [user]\n    define blocked: [user]\n    define viewer: owner but not blocked\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple("document", "42", "owner", subject("user", "anne")))
        .unwrap();
    let authz = FgaAuthz::new(difference_model).unwrap().with_store(
        ErroringStore::new(store, ["blocked"]),
        EvaluationLimits::default(),
    );
    assert!(matches!(
        block_on(authz.check(check_request(
            "tenant-a",
            "user",
            "anne",
            "document",
            "42",
            "viewer",
        ))),
        Err(AuthorizationError::Store(error)) if error.kind() == StoreErrorKind::Unavailable
    ));

    let branches = [
        ("broken or owner", true),
        ("owner or broken", true),
        ("broken or other", false),
        ("other or broken", false),
        ("broken and other", false),
        ("other and broken", false),
    ];
    for (expression, should_allow) in branches {
        let definition = format!(
            "model\nschema 1.1\ntype user\ntype document\n  relations\n    define broken: [user]\n    define owner: [user]\n    define other: [user]\n    define viewer: {expression}\n"
        );
        let inner = InMemoryRelationshipStore::new();
        if expression.contains("owner") {
            inner
                .insert(tuple("document", "42", "owner", subject("user", "anne")))
                .unwrap();
        }
        let authz = FgaAuthz::new(&definition).unwrap().with_store(
            ErroringStore::new(inner, ["broken"]),
            EvaluationLimits::default(),
        );
        let result = block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )));
        if should_allow {
            assert_eq!(
                result.unwrap(),
                AuthorizationDecision::Allow,
                "{expression}"
            );
        } else if expression.contains("and") {
            assert!(
                matches!(result, Ok(AuthorizationDecision::Deny)),
                "{expression}"
            );
        } else {
            assert!(
                matches!(result, Err(AuthorizationError::Store(_))),
                "{expression}"
            );
        }
    }
}

#[test]
fn paged_reads_complete_within_the_tuple_budget_and_respect_store_call_limits() {
    let definition =
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n";
    let store = InMemoryRelationshipStore::new();
    for index in 0..129 {
        store
            .insert(tuple(
                "document",
                "42",
                "viewer",
                subject("user", &format!("user-{index}")),
            ))
            .unwrap();
    }
    store
        .insert(tuple("document", "42", "viewer", subject("user", "anne")))
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store.clone(), EvaluationLimits::new(1_000).unwrap());
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );

    let tuple_limited = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store.clone(), EvaluationLimits::new(128).unwrap());
    assert!(matches!(
        block_on(tuple_limited.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        ))),
        Err(AuthorizationError::EvaluationLimitExceeded {
            maximum_tuples: 128
        })
    ));

    let one_page = EvaluationLimits::new(1_000)
        .unwrap()
        .with_max_store_calls(1)
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, one_page);
    assert!(matches!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        ))),
        Err(AuthorizationError::StoreCallLimitExceeded { maximum_calls: 1 })
    ));
}

#[test]
fn relation_depth_work_and_mistyped_tuple_cycles_fail_safely() {
    let definition = "model\nschema 1.1\ntype user\ntype subgroup\n  relations\n    define member: [user]\ntype group\n  relations\n    define member: [subgroup#member]\ntype document\n  relations\n    define viewer: [group#member]\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple(
            "document",
            "42",
            "viewer",
            TupleSubject::Userset {
                object: object("group", "8"),
                relation: relation("member"),
            },
        ))
        .unwrap();
    store
        .insert(tuple(
            "group",
            "8",
            "member",
            TupleSubject::Userset {
                object: object("subgroup", "3"),
                relation: relation("member"),
            },
        ))
        .unwrap();
    store
        .insert(tuple("subgroup", "3", "member", subject("user", "anne")))
        .unwrap();
    let depth_limited = EvaluationLimits::default()
        .with_max_relation_depth(1)
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store.clone(), depth_limited);
    assert!(matches!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        ))),
        Err(AuthorizationError::RelationDepthExceeded { maximum_depth: 1 })
    ));

    let work_limited = EvaluationLimits::default().with_max_work_units(1).unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store.clone(), work_limited);
    assert!(matches!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        ))),
        Err(AuthorizationError::WorkLimitExceeded {
            maximum_work_units: 1
        })
    ));

    let cycle_store = InMemoryRelationshipStore::new();
    cycle_store
        .insert(tuple(
            "document",
            "42",
            "viewer",
            TupleSubject::Userset {
                object: object("group", "8"),
                relation: relation("member"),
            },
        ))
        .unwrap();
    cycle_store
        .insert(tuple(
            "group",
            "8",
            "member",
            TupleSubject::Userset {
                object: object("group", "8"),
                relation: relation("member"),
            },
        ))
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(cycle_store, EvaluationLimits::default());
    assert!(matches!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        ))),
        Err(AuthorizationError::InvalidTuple(_))
    ));
}

#[test]
fn completed_relation_decisions_are_memoized_for_one_check() {
    let definition = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define member: [user]\n    define editor: member\n    define viewer: member or editor\n";
    let calls = Arc::new(AtomicUsize::new(0));
    let authz = FgaAuthz::new(definition).unwrap().with_store(
        CountingStore {
            inner: InMemoryRelationshipStore::new(),
            calls: Arc::clone(&calls),
        },
        EvaluationLimits::default(),
    );
    assert_eq!(
        block_on(authz.check(check_request(
            "tenant-a", "user", "anne", "document", "42", "viewer",
        )))
        .unwrap(),
        AuthorizationDecision::Deny
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn cancelling_a_pending_store_read_drops_its_in_flight_future() {
    let definition =
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n";
    let active = Arc::new(AtomicUsize::new(0));
    let authz = FgaAuthz::new(definition).unwrap().with_store(
        PendingStore(Arc::clone(&active)),
        EvaluationLimits::default(),
    );
    let mut future = Box::pin(authz.check(check_request(
        "tenant-a", "user", "anne", "document", "42", "viewer",
    )));
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(active.load(Ordering::SeqCst), 1);
    drop(future);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[derive(Clone)]
struct ErroringStore {
    inner: InMemoryRelationshipStore,
    failures: HashSet<String>,
}

impl ErroringStore {
    fn new<const N: usize>(inner: InMemoryRelationshipStore, failures: [&str; N]) -> Self {
        Self {
            inner,
            failures: failures.into_iter().map(str::to_owned).collect(),
        }
    }
}

struct ErroringSession {
    inner: InMemoryReadSession,
    failures: HashSet<String>,
}

impl RelationshipStore for ErroringStore {
    type ReadSession = ErroringSession;

    fn begin_read<'a>(
        &'a self,
        tenant_id: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let inner =
            <InMemoryRelationshipStore as RelationshipStore>::begin_read(&self.inner, tenant_id);
        let failures = self.failures.clone();
        Box::pin(async move {
            Ok(ErroringSession {
                inner: inner.await?,
                failures,
            })
        })
    }
}

impl RelationshipReadSession for ErroringSession {
    fn tuples<'a>(
        &'a self,
        object_ref: &'a ObjectRef,
        relation_name: &'a RelationName,
        maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        if self.failures.contains(relation_name.as_str()) {
            return Box::pin(async {
                Err(StoreError::new(
                    StoreErrorKind::Unavailable,
                    "configured relation read failure",
                ))
            });
        }
        self.inner.tuples(object_ref, relation_name, maximum)
    }
}

#[derive(Clone)]
struct CountingStore {
    inner: InMemoryRelationshipStore,
    calls: Arc<AtomicUsize>,
}

struct CountingSession {
    inner: InMemoryReadSession,
    calls: Arc<AtomicUsize>,
}

impl RelationshipStore for CountingStore {
    type ReadSession = CountingSession;

    fn begin_read<'a>(
        &'a self,
        tenant_id: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let inner =
            <InMemoryRelationshipStore as RelationshipStore>::begin_read(&self.inner, tenant_id);
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            Ok(CountingSession {
                inner: inner.await?,
                calls,
            })
        })
    }
}

impl RelationshipReadSession for CountingSession {
    fn tuples<'a>(
        &'a self,
        object_ref: &'a ObjectRef,
        relation_name: &'a RelationName,
        maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.tuples(object_ref, relation_name, maximum)
    }
}

#[derive(Clone)]
struct PendingStore(Arc<AtomicUsize>);

struct PendingSession(Arc<AtomicUsize>);

struct ActiveRead(Arc<AtomicUsize>);

impl Drop for ActiveRead {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl RelationshipStore for PendingStore {
    type ReadSession = PendingSession;

    fn begin_read<'a>(
        &'a self,
        _: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let active = Arc::clone(&self.0);
        Box::pin(async move { Ok(PendingSession(active)) })
    }
}

impl RelationshipReadSession for PendingSession {
    fn tuples<'a>(
        &'a self,
        _: &'a ObjectRef,
        _: &'a RelationName,
        _: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        let active = Arc::clone(&self.0);
        Box::pin(async move {
            active.fetch_add(1, Ordering::SeqCst);
            let _read = ActiveRead(Arc::clone(&active));
            pending::<Result<Vec<RelationshipTuple>, StoreError>>().await
        })
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}
