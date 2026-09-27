use openfga_authz::{
    AuthorizationDecision, AuthorizationError, CheckRequest, ConditionContext, EvaluationLimits,
    FgaAuthz, ObjectRef, RelationName, RelationshipPage, RelationshipReadSession,
    RelationshipStore, RelationshipTuple, RelationshipWriteStore, StoreCursor, StoreError,
    StoreErrorKind, StoreFuture, Subject, TenantId, TupleSubject, TypeName,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Runs the backend-neutral relationship store and evaluator contracts against
/// one newly constructed store.
pub async fn run_store_contracts<S>(store: S)
where
    S: RelationshipStore + RelationshipWriteStore,
{
    let store = SharedStore(Arc::new(store));
    complete_reads_and_pages(&store).await;
    strict_writes_and_context_identity(&store).await;
    subject_variants_round_trip(&store).await;
    snapshots_are_fixed_before_the_first_read(&store).await;
    evaluation_limits_are_enforced(&store).await;
    evaluator_uses_backend_tuples_and_propagates_errors(store).await;
}

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).expect("test tenant is valid")
}

fn object(type_name: &str, id: &str) -> ObjectRef {
    ObjectRef::new(type_name, id).expect("test object is valid")
}

fn relation(value: &str) -> RelationName {
    RelationName::new(value).expect("test relation is valid")
}

fn subject(type_name: &str, id: &str) -> Subject {
    Subject::new(type_name, id).expect("test subject is valid")
}

fn tuple(
    tenant_name: &str,
    object_type: &str,
    object_id: &str,
    relation_name: &str,
    tuple_subject: impl Into<TupleSubject>,
) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant(tenant_name),
        object(object_type, object_id),
        relation(relation_name),
        tuple_subject,
    )
}

fn conditional_tuple(
    tenant_name: &str,
    object_type: &str,
    object_id: &str,
    relation_name: &str,
    tuple_subject: impl Into<TupleSubject>,
    name: &str,
    values: BTreeMap<String, Value>,
) -> RelationshipTuple {
    tuple(
        tenant_name,
        object_type,
        object_id,
        relation_name,
        tuple_subject,
    )
    .with_condition(ConditionContext::new(name, values).expect("test condition is valid"))
}

fn assert_store_error<T>(result: Result<T, StoreError>, expected: StoreErrorKind) {
    match result {
        Err(error) => assert_eq!(error.kind(), expected),
        Ok(_) => panic!("expected store error {expected:?}"),
    }
}

async fn complete_reads_and_pages<S>(store: &S)
where
    S: RelationshipStore + RelationshipWriteStore,
{
    let tenant_a = tenant("contract-pages");
    let document = object("document", "page-contract");
    let viewer = relation("viewer");
    let expected = ["alice", "bob", "carol"]
        .into_iter()
        .map(|id| {
            RelationshipTuple::new(
                tenant_a.clone(),
                document.clone(),
                viewer.clone(),
                subject("user", id),
            )
        })
        .collect::<Vec<_>>();
    for tuple in &expected {
        store.insert_tuple(&tenant_a, tuple).await.unwrap();
    }

    let session = store.begin_read(&tenant_a).await.unwrap();
    assert!(
        session
            .tuples(&object("document", "empty-contract"), &viewer, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        session
            .tuples(&object("document", "empty-contract"), &viewer, 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert_store_error(
        session.tuples(&document, &viewer, 0).await,
        StoreErrorKind::TupleLimitExceeded,
    );
    assert_eq!(
        session.tuples(&document, &viewer, 3).await.unwrap(),
        expected
    );
    assert_store_error(
        session.tuples(&document, &viewer, 2).await,
        StoreErrorKind::TupleLimitExceeded,
    );
    assert_eq!(
        session
            .tuples(&document, &viewer, usize::MAX)
            .await
            .unwrap(),
        expected
    );

    let exact_page = session
        .tuples_page(&document, &viewer, None, expected.len())
        .await
        .unwrap();
    assert_eq!(exact_page.tuples, expected);
    assert!(exact_page.next_cursor.is_none());

    let first_page = session
        .tuples_page(&document, &viewer, None, 2)
        .await
        .unwrap();
    assert_eq!(first_page.tuples, expected[..2]);
    let cursor = first_page.next_cursor.expect("one tuple remains");
    let final_page = session
        .tuples_page(&document, &viewer, Some(cursor.clone()), 2)
        .await
        .unwrap();
    assert_eq!(final_page.tuples, expected[2..]);
    assert!(final_page.next_cursor.is_none());

    assert_store_error(
        session.tuples_page(&document, &viewer, None, 0).await,
        StoreErrorKind::IncompleteRead,
    );
    assert_store_error(
        session
            .tuples_page(
                &document,
                &viewer,
                Some(StoreCursor::from_bytes(vec![0xff; 16_384])),
                1,
            )
            .await,
        StoreErrorKind::IncompleteRead,
    );

    let other_session = store.begin_read(&tenant_a).await.unwrap();
    assert_store_error(
        other_session
            .tuples_page(&document, &viewer, Some(cursor.clone()), 1)
            .await,
        StoreErrorKind::IncompleteRead,
    );
    let other_tenant_session = store
        .begin_read(&tenant("contract-other-tenant"))
        .await
        .unwrap();
    assert_store_error(
        other_tenant_session
            .tuples_page(&document, &viewer, Some(cursor.clone()), 1)
            .await,
        StoreErrorKind::IncompleteRead,
    );
    assert_store_error(
        session
            .tuples_page(
                &object("folder", "page-contract"),
                &viewer,
                Some(cursor.clone()),
                1,
            )
            .await,
        StoreErrorKind::IncompleteRead,
    );
    assert_store_error(
        session
            .tuples_page(&document, &relation("editor"), Some(cursor), 1)
            .await,
        StoreErrorKind::IncompleteRead,
    );
}

async fn strict_writes_and_context_identity<S>(store: &S)
where
    S: RelationshipStore + RelationshipWriteStore,
{
    let tenant_a = tenant("contract-writes");
    let tenant_b = tenant("contract-writes-other");
    let document = object("document", "write-contract");
    let relation = relation("viewer");
    let tuple_a = conditional_tuple(
        "contract-writes",
        "document",
        "write-contract",
        "viewer",
        subject("user", "alice"),
        "grant",
        BTreeMap::from([("enabled".to_owned(), json!(true))]),
    );
    let tuple_b = conditional_tuple(
        "contract-writes",
        "document",
        "write-contract",
        "viewer",
        subject("user", "alice"),
        "grant",
        BTreeMap::from([("enabled".to_owned(), json!(false))]),
    );
    let tuple_c = conditional_tuple(
        "contract-writes",
        "document",
        "write-contract",
        "viewer",
        subject("user", "alice"),
        "grant",
        BTreeMap::from([("enabled".to_owned(), Value::Null)]),
    );

    assert_store_error(
        store.insert_tuple(&tenant_b, &tuple_a).await,
        StoreErrorKind::CorruptData,
    );
    assert_store_error(
        store.remove_tuple(&tenant_b, &tuple_a).await,
        StoreErrorKind::CorruptData,
    );
    store.insert_tuple(&tenant_a, &tuple_a).await.unwrap();
    assert_store_error(
        store.insert_tuple(&tenant_a, &tuple_a).await,
        StoreErrorKind::CorruptData,
    );
    store.insert_tuple(&tenant_a, &tuple_b).await.unwrap();

    assert!(!store.remove_tuple(&tenant_a, &tuple_c).await.unwrap());
    assert!(store.remove_tuple(&tenant_a, &tuple_a).await.unwrap());
    assert!(!store.remove_tuple(&tenant_a, &tuple_a).await.unwrap());
    let session = store.begin_read(&tenant_a).await.unwrap();
    assert_eq!(
        session.tuples(&document, &relation, 10).await.unwrap(),
        [tuple_b]
    );

    let other_tenant = store.begin_read(&tenant_b).await.unwrap();
    assert!(
        other_tenant
            .tuples(&document, &relation, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

async fn subject_variants_round_trip<S>(store: &S)
where
    S: RelationshipStore + RelationshipWriteStore,
{
    let tenant_a = tenant("contract-subjects");
    let document = object("document", "subject-contract");
    let viewer = relation("viewer");
    let expected = vec![
        RelationshipTuple::new(
            tenant_a.clone(),
            document.clone(),
            viewer.clone(),
            TupleSubject::Direct(subject("user", "alice")),
        ),
        RelationshipTuple::new(
            tenant_a.clone(),
            document.clone(),
            viewer.clone(),
            TupleSubject::Direct(subject("user", "*")),
        ),
        RelationshipTuple::new(
            tenant_a.clone(),
            document.clone(),
            viewer.clone(),
            TupleSubject::Userset {
                object: object("group", "editors"),
                relation: relation("member"),
            },
        ),
        RelationshipTuple::new(
            tenant_a.clone(),
            document.clone(),
            viewer.clone(),
            TupleSubject::TypedWildcard(TypeName::new("user").unwrap()),
        ),
    ];
    for tuple in &expected {
        store.insert_tuple(&tenant_a, tuple).await.unwrap();
    }
    let session = store.begin_read(&tenant_a).await.unwrap();
    assert_eq!(
        session.tuples(&document, &viewer, 10).await.unwrap(),
        expected
    );
}

async fn snapshots_are_fixed_before_the_first_read<S>(store: &S)
where
    S: RelationshipStore + RelationshipWriteStore,
{
    let tenant_a = tenant("contract-snapshot");
    let first_object = object("document", "snapshot-before-first-query");
    let second_object = object("folder", "snapshot-second-query");
    let viewer = relation("viewer");
    let first_old = RelationshipTuple::new(
        tenant_a.clone(),
        first_object.clone(),
        viewer.clone(),
        subject("user", "old-first"),
    );
    let first_new = RelationshipTuple::new(
        tenant_a.clone(),
        first_object.clone(),
        viewer.clone(),
        subject("user", "new-first"),
    );
    let second_old = RelationshipTuple::new(
        tenant_a.clone(),
        second_object.clone(),
        viewer.clone(),
        subject("user", "old-second"),
    );
    let second_new = RelationshipTuple::new(
        tenant_a.clone(),
        second_object.clone(),
        viewer.clone(),
        subject("user", "new-second"),
    );

    store.insert_tuple(&tenant_a, &first_old).await.unwrap();
    store.insert_tuple(&tenant_a, &second_old).await.unwrap();
    let snapshot = store.begin_read(&tenant_a).await.unwrap();

    // These writes happen after begin_read returns but before its first tuple query.
    store.insert_tuple(&tenant_a, &first_new).await.unwrap();
    assert!(store.remove_tuple(&tenant_a, &first_old).await.unwrap());
    assert_eq!(
        snapshot.tuples(&first_object, &viewer, 10).await.unwrap(),
        [first_old.clone()]
    );

    // A second query key must use the same snapshot despite writes between reads.
    store.insert_tuple(&tenant_a, &second_new).await.unwrap();
    assert!(store.remove_tuple(&tenant_a, &second_old).await.unwrap());
    assert_eq!(
        snapshot.tuples(&second_object, &viewer, 10).await.unwrap(),
        [second_old]
    );

    let current = store.begin_read(&tenant_a).await.unwrap();
    assert_eq!(
        current.tuples(&first_object, &viewer, 10).await.unwrap(),
        [first_new]
    );
    assert_eq!(
        current.tuples(&second_object, &viewer, 10).await.unwrap(),
        [second_new]
    );
}

async fn evaluation_limits_are_enforced<S>(store: &SharedStore<S>)
where
    S: RelationshipStore + RelationshipWriteStore,
{
    let tenant_a = tenant("contract-limits");
    let document = object("document", "limits-contract");
    let viewer = relation("viewer");
    for index in 0..130 {
        store
            .insert_tuple(
                &tenant_a,
                &RelationshipTuple::new(
                    tenant_a.clone(),
                    document.clone(),
                    viewer.clone(),
                    subject("user", &format!("limit-user-{index}")),
                ),
            )
            .await
            .unwrap();
    }

    let shared = store.clone();
    let model =
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n";
    let tuple_limited = FgaAuthz::new(model)
        .unwrap()
        .with_store(shared.clone(), EvaluationLimits::new(128).unwrap());
    assert!(matches!(
        tuple_limited
            .check(CheckRequest::new(
                tenant_a.clone(),
                subject("user", "limit-user-129"),
                document.clone(),
                viewer.clone(),
            ))
            .await,
        Err(AuthorizationError::EvaluationLimitExceeded {
            maximum_tuples: 128
        })
    ));

    let call_limited = FgaAuthz::new(model).unwrap().with_store(
        shared.clone(),
        EvaluationLimits::new(1_000)
            .unwrap()
            .with_max_store_calls(1)
            .unwrap(),
    );
    assert!(matches!(
        call_limited
            .check(CheckRequest::new(
                tenant_a.clone(),
                subject("user", "limit-user-129"),
                document,
                viewer,
            ))
            .await,
        Err(AuthorizationError::StoreCallLimitExceeded { maximum_calls: 1 })
    ));

    let deep_document = object("deep_document", "work-limits-contract");
    let deep_group = object("deep_group", "work-limits-group");
    store
        .insert_tuple(
            &tenant_a,
            &RelationshipTuple::new(
                tenant_a.clone(),
                deep_document.clone(),
                relation("viewer"),
                TupleSubject::Userset {
                    object: deep_group.clone(),
                    relation: relation("member"),
                },
            ),
        )
        .await
        .unwrap();
    store
        .insert_tuple(
            &tenant_a,
            &RelationshipTuple::new(
                tenant_a.clone(),
                deep_group,
                relation("member"),
                subject("user", "limit-user-deep"),
            ),
        )
        .await
        .unwrap();
    let work_model = "model\nschema 1.1\ntype user\ntype deep_group\n  relations\n    define member: [user]\ntype deep_document\n  relations\n    define viewer: [deep_group#member]\n";
    let work_limited = FgaAuthz::new(work_model).unwrap().with_store(
        shared,
        EvaluationLimits::default().with_max_work_units(1).unwrap(),
    );
    assert!(matches!(
        work_limited
            .check(CheckRequest::new(
                tenant_a,
                subject("user", "limit-user-deep"),
                deep_document,
                relation("viewer"),
            ))
            .await,
        Err(AuthorizationError::WorkLimitExceeded {
            maximum_work_units: 1
        })
    ));
}

const EVALUATOR_MODEL: &str = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype folder\n  relations\n    define viewer: [user]\ntype document\n  relations\n    define direct: [user]\n    define direct_star: [user]\n    define wildcard: [user:*]\n    define group_viewer: [group#member]\n    define parent: [folder]\n    define parent_viewer: viewer from parent\n    define inherited: direct\n    define owner: [user]\n    define editor: [user]\n    define blocked: [user]\n    define union_viewer: owner or editor\n    define intersection_viewer: owner and editor\n    define unblocked_owner: owner but not blocked\n    define timed: [user with valid_grant]\n    define mixed_viewer: timed or owner\n    define broken: [user]\n    define owner_or_broken: owner or broken\n    define broken_or_owner: broken or owner\n    define other_or_broken: editor or broken\n    define other_and_broken: editor and broken\n    define owner_and_broken: owner and broken\n    define owner_but_not_broken: owner but not broken\ncondition valid_grant(current_time: timestamp, grant_time: timestamp, grant_duration: duration) { current_time < grant_time + grant_duration }\n";

async fn evaluator_uses_backend_tuples_and_propagates_errors<S>(store: S)
where
    S: RelationshipStore + RelationshipWriteStore,
{
    let tenant_a = tenant("contract-evaluator");
    let document_id = "evaluator-contract";
    let document = object("document", document_id);
    let group = object("group", "evaluator-group");
    let folder = object("folder", "evaluator-folder");
    let document_tuple = |relation_name: &str, tuple_subject: TupleSubject| {
        RelationshipTuple::new(
            tenant_a.clone(),
            document.clone(),
            relation(relation_name),
            tuple_subject,
        )
    };
    let tuples = [
        document_tuple("direct", TupleSubject::Direct(subject("user", "alice"))),
        document_tuple("direct_star", TupleSubject::Direct(subject("user", "*"))),
        document_tuple(
            "wildcard",
            TupleSubject::TypedWildcard(TypeName::new("user").unwrap()),
        ),
        document_tuple(
            "group_viewer",
            TupleSubject::Userset {
                object: group.clone(),
                relation: relation("member"),
            },
        ),
        document_tuple(
            "parent",
            TupleSubject::Direct(Subject::new("folder", folder.id().as_str()).unwrap()),
        ),
        document_tuple("owner", TupleSubject::Direct(subject("user", "alice"))),
        document_tuple("editor", TupleSubject::Direct(subject("user", "alice"))),
        document_tuple("editor", TupleSubject::Direct(subject("user", "carol"))),
        document_tuple("blocked", TupleSubject::Direct(subject("user", "carol"))),
        conditional_tuple(
            "contract-evaluator",
            "document",
            document_id,
            "timed",
            TupleSubject::Direct(subject("user", "alice")),
            "valid_grant",
            BTreeMap::from([
                ("grant_time".to_owned(), json!("2025-01-01T00:00:00Z")),
                ("grant_duration".to_owned(), json!("1h")),
            ]),
        ),
    ];
    for tuple in &tuples {
        store.insert_tuple(&tenant_a, tuple).await.unwrap();
    }
    store
        .insert_tuple(
            &tenant_a,
            &RelationshipTuple::new(
                tenant_a.clone(),
                group.clone(),
                relation("member"),
                subject("user", "alice"),
            ),
        )
        .await
        .unwrap();
    store
        .insert_tuple(
            &tenant_a,
            &RelationshipTuple::new(
                tenant_a.clone(),
                folder.clone(),
                relation("viewer"),
                subject("user", "alice"),
            ),
        )
        .await
        .unwrap();

    let authz = FgaAuthz::new(EVALUATOR_MODEL)
        .expect("evaluator model compiles")
        .with_store(
            ErrorOnRelationStore {
                inner: store,
                error_relation: "broken",
            },
            EvaluationLimits::default(),
        );

    for (subject_id, relation_name, expected) in [
        ("alice", "direct", AuthorizationDecision::Allow),
        ("bob", "direct", AuthorizationDecision::Deny),
        ("alice", "inherited", AuthorizationDecision::Allow),
        ("bob", "wildcard", AuthorizationDecision::Allow),
        ("alice", "group_viewer", AuthorizationDecision::Allow),
        ("bob", "group_viewer", AuthorizationDecision::Deny),
        ("alice", "parent_viewer", AuthorizationDecision::Allow),
        ("bob", "parent_viewer", AuthorizationDecision::Deny),
        ("alice", "union_viewer", AuthorizationDecision::Allow),
        ("alice", "intersection_viewer", AuthorizationDecision::Allow),
        ("bob", "intersection_viewer", AuthorizationDecision::Deny),
        ("alice", "unblocked_owner", AuthorizationDecision::Allow),
        ("carol", "unblocked_owner", AuthorizationDecision::Deny),
        ("alice", "direct_star", AuthorizationDecision::Deny),
        ("*", "direct_star", AuthorizationDecision::Allow),
    ] {
        let request = CheckRequest::new(
            tenant_a.clone(),
            subject("user", subject_id),
            document.clone(),
            relation(relation_name),
        );
        assert_eq!(
            authz.check(request).await.unwrap(),
            expected,
            "{relation_name}"
        );
    }

    let timed_request = |current_time: &str, relation_name: &str| {
        CheckRequest::new(
            tenant_a.clone(),
            subject("user", "alice"),
            document.clone(),
            relation(relation_name),
        )
        .with_context(BTreeMap::from([(
            "current_time".to_owned(),
            json!(current_time),
        )]))
    };
    assert_eq!(
        authz
            .check(timed_request("2025-01-01T00:30:00Z", "timed"))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz
            .check(timed_request("2025-01-01T02:00:00Z", "timed"))
            .await
            .unwrap(),
        AuthorizationDecision::Deny
    );

    let context_precedence = CheckRequest::new(
        tenant_a.clone(),
        subject("user", "alice"),
        document.clone(),
        relation("timed"),
    )
    .with_context(BTreeMap::from([(
        "current_time".to_owned(),
        json!("2025-01-01T02:00:00Z"),
    )]))
    .with_condition_context(
        "valid_grant",
        BTreeMap::from([("current_time".to_owned(), json!("2025-01-01T00:30:00Z"))]),
    );
    assert_eq!(
        authz.check(context_precedence).await.unwrap(),
        AuthorizationDecision::Allow
    );

    // Stored condition values take precedence over request values.
    let stored_context_precedence = CheckRequest::new(
        tenant_a.clone(),
        subject("user", "alice"),
        document.clone(),
        relation("timed"),
    )
    .with_context(BTreeMap::from([
        ("current_time".to_owned(), json!("2025-01-01T01:30:00Z")),
        ("grant_time".to_owned(), json!("2025-01-01T02:00:00Z")),
        ("grant_duration".to_owned(), json!("1h")),
    ]));
    assert_eq!(
        authz.check(stored_context_precedence).await.unwrap(),
        AuthorizationDecision::Deny
    );

    // Existing three-valued error rules preserve decisive boolean outcomes.
    assert_eq!(
        authz
            .check(CheckRequest::new(
                tenant_a.clone(),
                subject("user", "alice"),
                document.clone(),
                relation("owner_or_broken"),
            ))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz
            .check(CheckRequest::new(
                tenant_a.clone(),
                subject("user", "alice"),
                document.clone(),
                relation("broken_or_owner"),
            ))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz
            .check(CheckRequest::new(
                tenant_a.clone(),
                subject("user", "bob"),
                document.clone(),
                relation("other_and_broken"),
            ))
            .await
            .unwrap(),
        AuthorizationDecision::Deny
    );
    for (subject_id, relation_name) in [
        ("bob", "other_or_broken"),
        ("alice", "owner_and_broken"),
        ("alice", "owner_but_not_broken"),
    ] {
        assert!(
            matches!(
                authz
                    .check(CheckRequest::new(
                        tenant_a.clone(),
                        subject("user", subject_id),
                        document.clone(),
                        relation(relation_name),
                    ))
                    .await,
                Err(AuthorizationError::Store(error))
                    if error.kind() == StoreErrorKind::Unavailable
            ),
            "{relation_name}"
        );
    }
}

struct ErrorOnRelationStore<S> {
    inner: S,
    error_relation: &'static str,
}

struct SharedStore<S>(Arc<S>);

impl<S> Clone for SharedStore<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<S> RelationshipStore for SharedStore<S>
where
    S: RelationshipStore,
{
    type ReadSession = S::ReadSession;

    fn begin_read<'a>(
        &'a self,
        tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        self.0.as_ref().begin_read(tenant)
    }
}

impl<S> RelationshipWriteStore for SharedStore<S>
where
    S: RelationshipWriteStore,
{
    fn insert_tuple<'a>(
        &'a self,
        tenant: &'a TenantId,
        tuple: &'a RelationshipTuple,
    ) -> StoreFuture<'a, Result<(), StoreError>> {
        self.0.as_ref().insert_tuple(tenant, tuple)
    }

    fn remove_tuple<'a>(
        &'a self,
        tenant: &'a TenantId,
        tuple: &'a RelationshipTuple,
    ) -> StoreFuture<'a, Result<bool, StoreError>> {
        self.0.as_ref().remove_tuple(tenant, tuple)
    }
}

impl<S> RelationshipStore for ErrorOnRelationStore<S>
where
    S: RelationshipStore,
{
    type ReadSession = ErrorOnRelationSession<S::ReadSession>;

    fn begin_read<'a>(
        &'a self,
        tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let read = self.inner.begin_read(tenant);
        Box::pin(async move {
            Ok(ErrorOnRelationSession {
                inner: read.await?,
                error_relation: self.error_relation,
            })
        })
    }
}

struct ErrorOnRelationSession<S> {
    inner: S,
    error_relation: &'static str,
}

impl<S> RelationshipReadSession for ErrorOnRelationSession<S>
where
    S: RelationshipReadSession,
{
    fn tuples<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        if relation.as_str() == self.error_relation {
            return Box::pin(async {
                Err(StoreError::new(
                    StoreErrorKind::Unavailable,
                    "scripted relationship store failure",
                ))
            });
        }
        self.inner.tuples(object, relation, maximum)
    }

    fn tuples_page<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        cursor: Option<StoreCursor>,
        maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
        if relation.as_str() == self.error_relation {
            return Box::pin(async {
                Err(StoreError::new(
                    StoreErrorKind::Unavailable,
                    "scripted relationship store failure",
                ))
            });
        }
        self.inner.tuples_page(object, relation, cursor, maximum)
    }
}
