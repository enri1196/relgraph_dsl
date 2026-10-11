#[allow(dead_code)]
mod common;

use common::{block_on, object, relation, request as check_request, subject, tenant};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, CheckRequest, ConditionContext, EvaluationLimits,
    FgaAuthz, ObjectRef, RelationName, RelationshipPage, RelationshipReadSession,
    RelationshipStore, RelationshipTuple, StoreCursor, StoreError, StoreErrorKind, StoreFuture,
    TenantId, TupleSubject,
};
use std::sync::{Arc, Mutex};

const MODEL: &str =
    "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n";

const USERSET_MODEL: &str = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define member: [user]\n    define viewer: [document#member]\n";

const TUPLESET_MODEL: &str = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define parent: [document]\n    define member: [user]\n    define viewer: member from parent\n";

const CONDITION_MODEL: &str = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with enabled]\ncondition enabled(flag: bool) {\n  flag\n}\n";

#[derive(Clone)]
struct PageScript {
    request_object: ObjectRef,
    request_relation: RelationName,
    request_cursor: Option<StoreCursor>,
    outcome: PageOutcome,
    next_cursor: Option<StoreCursor>,
}

#[derive(Clone)]
enum PageOutcome {
    Tuples(Vec<RelationshipTuple>),
    Error(StoreErrorKind),
}

#[derive(Default)]
struct PageReadLog {
    calls: Vec<(ObjectRef, RelationName, Option<StoreCursor>, usize)>,
}

struct PageStore {
    pages: Vec<PageScript>,
    reads: Arc<Mutex<PageReadLog>>,
}

struct PageSession {
    pages: Vec<PageScript>,
    next_page: Mutex<usize>,
    reads: Arc<Mutex<PageReadLog>>,
}

impl RelationshipStore for PageStore {
    type ReadSession = PageSession;

    fn begin_read<'a>(
        &'a self,
        _tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let pages = self.pages.clone();
        let reads = Arc::clone(&self.reads);
        Box::pin(async move {
            Ok(PageSession {
                pages,
                next_page: Mutex::new(0),
                reads,
            })
        })
    }
}

impl RelationshipReadSession for PageSession {
    fn tuples<'a>(
        &'a self,
        _object: &'a relgraph_authz::ObjectRef,
        _relation: &'a relgraph_authz::RelationName,
        _maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        Box::pin(async {
            Err(StoreError::new(
                StoreErrorKind::IncompleteRead,
                "the test store requires paged reads",
            ))
        })
    }

    fn tuples_page<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        cursor: Option<StoreCursor>,
        maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
        let scripted = {
            let mut next_page = self
                .next_page
                .lock()
                .expect("test page mutex is not poisoned");
            let result = self.pages.get(*next_page).cloned();
            *next_page += 1;
            self.reads
                .lock()
                .expect("test page read log mutex is not poisoned")
                .calls
                .push((object.clone(), relation.clone(), cursor.clone(), maximum));
            result.ok_or_else(|| {
                StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "the test store ran out of scripted pages",
                )
            })
        };

        Box::pin(async move {
            let scripted = scripted?;
            if scripted.request_object != *object || scripted.request_relation != *relation {
                return Err(StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "the evaluator did not preserve the scripted page query",
                ));
            }
            if scripted.request_cursor != cursor {
                return Err(StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "the evaluator did not preserve the opaque cursor",
                ));
            }
            match scripted.outcome {
                PageOutcome::Tuples(tuples) => Ok(RelationshipPage {
                    tuples,
                    next_cursor: scripted.next_cursor,
                }),
                PageOutcome::Error(kind) => {
                    Err(StoreError::new(kind, "scripted page read failure"))
                }
            }
        })
    }
}

fn scripted_page(
    object_id: &str,
    relation_name: &str,
    request_cursor: Option<StoreCursor>,
    tuples: Vec<RelationshipTuple>,
    next_cursor: Option<StoreCursor>,
) -> PageScript {
    PageScript {
        request_object: object("document", object_id),
        request_relation: relation(relation_name),
        request_cursor,
        outcome: PageOutcome::Tuples(tuples),
        next_cursor,
    }
}

fn scripted_error(
    object_id: &str,
    relation_name: &str,
    request_cursor: Option<StoreCursor>,
    kind: StoreErrorKind,
) -> PageScript {
    PageScript {
        request_object: object("document", object_id),
        request_relation: relation(relation_name),
        request_cursor,
        outcome: PageOutcome::Error(kind),
        next_cursor: None,
    }
}

fn tuple() -> RelationshipTuple {
    RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation("viewer"),
        subject("user", "anne"),
    )
}

fn userset_tuple(
    object_id: &str,
    relation_name: &str,
    subject_object_id: &str,
    subject_relation: &str,
) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", object_id),
        relation(relation_name),
        TupleSubject::Userset {
            object: object("document", subject_object_id),
            relation: relation(subject_relation),
        },
    )
}

fn parent_tuple(subject_id: &str) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation("parent"),
        subject("document", subject_id),
    )
}

fn condition_tuple(subject_id: &str, flag: serde_json::Value) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation("viewer"),
        subject("user", subject_id),
    )
    .with_condition(
        ConditionContext::new(
            "enabled",
            std::collections::BTreeMap::from([("flag".to_owned(), flag)]),
        )
        .unwrap(),
    )
}

#[allow(dead_code)]
fn run_check(pages: Vec<PageScript>) -> Result<AuthorizationDecision, AuthorizationError> {
    let expected_pages = pages.clone();
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        pages,
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();
    let expected_object = object("document", "42");
    let expected_relation = relation("viewer");
    for (index, (actual_object, actual_relation, cursor, maximum)) in calls.iter().enumerate() {
        assert_eq!(actual_object, &expected_object);
        assert_eq!(actual_relation, &expected_relation);
        let tuples_already_read = expected_pages
            .iter()
            .take(index)
            .map(|page| match &page.outcome {
                PageOutcome::Tuples(tuples) => tuples.len(),
                PageOutcome::Error(_) => 0,
            })
            .sum::<usize>();
        assert_eq!(*maximum, 10_usize.saturating_sub(tuples_already_read));
        let expected_cursor = if let Some(page) = expected_pages.get(index) {
            page.request_cursor.clone()
        } else {
            expected_pages
                .last()
                .and_then(|page| page.next_cursor.clone())
        };
        assert_eq!(cursor, &expected_cursor);
    }
    result
}

fn run_scripted_check(
    model: &str,
    pages: Vec<PageScript>,
    limits: EvaluationLimits,
    request: CheckRequest,
) -> (
    Result<AuthorizationDecision, AuthorizationError>,
    Arc<Mutex<PageReadLog>>,
) {
    let reads = Arc::new(Mutex::new(PageReadLog::default()));
    let authz = FgaAuthz::new(model).unwrap().with_store(
        PageStore {
            pages,
            reads: Arc::clone(&reads),
        },
        limits,
    );
    (block_on(authz.check(request)), reads)
}

#[test]
fn evaluator_rejects_a_cursor_that_repeats_after_other_tokens() {
    let a = StoreCursor::from_bytes(vec![1]);
    let b = StoreCursor::from_bytes(vec![2]);
    let nonmatching = page_tuple("other-user", "42");
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![
            scripted_page(
                "42",
                "viewer",
                None,
                vec![nonmatching.clone()],
                Some(a.clone()),
            ),
            scripted_page(
                "42",
                "viewer",
                Some(a.clone()),
                vec![nonmatching.clone()],
                Some(b.clone()),
            ),
            scripted_page("42", "viewer", Some(b), vec![nonmatching], Some(a)),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
    assert_eq!(calls.len(), 3);
}

#[test]
fn evaluator_rejects_empty_pages_that_claim_a_continuation() {
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![scripted_page(
            "42",
            "viewer",
            None,
            Vec::new(),
            Some(StoreCursor::from_bytes(vec![9])),
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
    assert_eq!(calls.len(), 1);
}

#[test]
fn evaluator_allows_a_grant_without_reading_later_pages() {
    let cursor = StoreCursor::from_bytes(vec![3]);
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![
            scripted_page("42", "viewer", None, vec![tuple()], Some(cursor.clone())),
            scripted_page(
                "42",
                "viewer",
                Some(cursor),
                vec![page_tuple("other-user", "42")],
                None,
            ),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 1);
}

#[test]
fn evaluator_allows_a_grant_on_a_later_page() {
    let cursor = StoreCursor::from_bytes(vec![4]);
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![
            scripted_page(
                "42",
                "viewer",
                None,
                vec![page_tuple("other-user", "42")],
                Some(cursor.clone()),
            ),
            scripted_page("42", "viewer", Some(cursor), vec![tuple()], None),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 2);
}

#[test]
fn unrequested_store_error_does_not_defeat_an_earlier_grant() {
    let cursor = StoreCursor::from_bytes(vec![5]);
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![
            scripted_page("42", "viewer", None, vec![tuple()], Some(cursor.clone())),
            scripted_error("42", "viewer", Some(cursor), StoreErrorKind::IncompleteRead),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 1);
}

#[test]
fn unrequested_invalid_tuple_does_not_defeat_an_earlier_grant() {
    let cursor = StoreCursor::from_bytes(vec![6]);
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![
            scripted_page("42", "viewer", None, vec![tuple()], Some(cursor.clone())),
            scripted_page(
                "42",
                "viewer",
                Some(cursor),
                vec![page_tuple("anne", "other-object")],
                None,
            ),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 1);
}

#[test]
fn fetched_invalid_tuple_precedes_an_unrequested_store_error() {
    let first_cursor = StoreCursor::from_bytes(vec![7]);
    let second_cursor = StoreCursor::from_bytes(vec![8]);
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![
            scripted_page(
                "42",
                "viewer",
                None,
                vec![page_tuple("other-user", "42")],
                Some(first_cursor.clone()),
            ),
            scripted_page(
                "42",
                "viewer",
                Some(first_cursor),
                vec![page_tuple("anne", "other-object")],
                Some(second_cursor.clone()),
            ),
            scripted_error(
                "42",
                "viewer",
                Some(second_cursor),
                StoreErrorKind::IncompleteRead,
            ),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
    assert_eq!(calls.len(), 2);
}

#[test]
fn fetched_invalid_tuple_defeats_a_same_page_grant() {
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![scripted_page(
            "42",
            "viewer",
            None,
            vec![tuple(), page_tuple("anne", "other-object")],
            None,
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
    assert_eq!(calls.len(), 1);
}

#[test]
fn requested_store_error_is_not_a_deny() {
    let cursor = StoreCursor::from_bytes(vec![10]);
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![
            scripted_page(
                "42",
                "viewer",
                None,
                vec![page_tuple("other-user", "42")],
                Some(cursor.clone()),
            ),
            scripted_error("42", "viewer", Some(cursor), StoreErrorKind::IncompleteRead),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Err(AuthorizationError::Store(_))));
    assert_eq!(calls.len(), 2);
}

#[test]
fn streaming_rejects_pages_larger_than_the_requested_maximum() {
    let limits = EvaluationLimits::new(1_000)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![scripted_page(
            "42",
            "viewer",
            None,
            (0..129).map(|_| page_tuple("other-user", "42")).collect(),
            None,
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(
        result,
        Err(AuthorizationError::EvaluationLimitExceeded {
            maximum_tuples: 1_000
        })
    ));
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].3, 128);
}

#[test]
fn grant_at_the_tuple_limit_skips_continuation() {
    let limits = EvaluationLimits::new(1)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![scripted_page(
            "42",
            "viewer",
            None,
            vec![tuple()],
            Some(StoreCursor::from_bytes(vec![11])),
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].3, 1);
}

#[test]
fn nonmatching_page_at_the_tuple_limit_requires_more_budget() {
    let limits = EvaluationLimits::new(1)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![scripted_page(
            "42",
            "viewer",
            None,
            vec![page_tuple("other-user", "42")],
            Some(StoreCursor::from_bytes(vec![12])),
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(
        result,
        Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples: 1 })
    ));
    assert_eq!(calls.len(), 1);
}

#[test]
fn grant_at_the_store_call_limit_skips_continuation() {
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(1)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![scripted_page(
            "42",
            "viewer",
            None,
            vec![tuple()],
            Some(StoreCursor::from_bytes(vec![13])),
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 1);
}

#[test]
fn streaming_deny_drains_pages_with_decreasing_maximum() {
    let cursor = StoreCursor::from_bytes(vec![14]);
    let limits = EvaluationLimits::new(3)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![
            scripted_page(
                "42",
                "viewer",
                None,
                vec![
                    page_tuple("other-user", "42"),
                    page_tuple("other-user-2", "42"),
                ],
                Some(cursor.clone()),
            ),
            scripted_page(
                "42",
                "viewer",
                Some(cursor),
                vec![page_tuple("other-user-3", "42")],
                None,
            ),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Deny)));
    assert_eq!(
        calls.iter().map(|call| call.3).collect::<Vec<_>>(),
        vec![3, 1]
    );
}

#[test]
fn terminal_empty_page_denies_without_another_read() {
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        MODEL,
        vec![scripted_page("42", "viewer", None, Vec::new(), None)],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Deny)));
    assert_eq!(calls.len(), 1);
}

#[test]
fn userset_grant_skips_the_next_parent_page() {
    let cursor = StoreCursor::from_bytes(vec![15]);
    let direct_grant = page_tuple("anne", "group");
    let member_grant = RelationshipTuple::new(
        direct_grant.tenant().clone(),
        direct_grant.object().clone(),
        relation("member"),
        direct_grant.subject().clone(),
    );
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        USERSET_MODEL,
        vec![
            scripted_page(
                "42",
                "viewer",
                None,
                vec![userset_tuple("42", "viewer", "group", "member")],
                Some(cursor.clone()),
            ),
            scripted_page("group", "member", None, vec![member_grant], None),
            scripted_error("42", "viewer", Some(cursor), StoreErrorKind::IncompleteRead),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (calls[0].0.clone(), calls[0].1.clone()),
        (object("document", "42"), relation("viewer"))
    );
    assert_eq!(
        (calls[1].0.clone(), calls[1].1.clone()),
        (object("document", "group"), relation("member"))
    );
    assert_eq!(calls[0].2, None);
    assert_eq!(calls[1].2, None);
}

#[test]
fn tupleset_grant_skips_the_next_parent_page() {
    let cursor = StoreCursor::from_bytes(vec![16]);
    let direct_grant = page_tuple("anne", "folder");
    let member_grant = RelationshipTuple::new(
        direct_grant.tenant().clone(),
        direct_grant.object().clone(),
        relation("member"),
        direct_grant.subject().clone(),
    );
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        TUPLESET_MODEL,
        vec![
            scripted_page(
                "42",
                "parent",
                None,
                vec![parent_tuple("folder")],
                Some(cursor.clone()),
            ),
            scripted_page("folder", "member", None, vec![member_grant], None),
            scripted_error("42", "parent", Some(cursor), StoreErrorKind::IncompleteRead),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (calls[0].0.clone(), calls[0].1.clone()),
        (object("document", "42"), relation("parent"))
    );
    assert_eq!(
        (calls[1].0.clone(), calls[1].1.clone()),
        (object("document", "folder"), relation("member"))
    );
    assert_eq!(calls[0].2, None);
    assert_eq!(calls[1].2, None);
}

#[test]
fn tupleset_preparation_rejects_a_same_page_invalid_subject() {
    let wildcard_parent = RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation("parent"),
        TupleSubject::TypedWildcard(relgraph_authz::TypeName::new("document").unwrap()),
    );
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        TUPLESET_MODEL,
        vec![scripted_page(
            "42",
            "parent",
            None,
            vec![parent_tuple("folder"), wildcard_parent],
            None,
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, relation("parent"));
}

#[test]
fn nested_reads_share_the_global_tuple_budget() {
    let limits = EvaluationLimits::new(1)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        TUPLESET_MODEL,
        vec![scripted_page(
            "42",
            "parent",
            None,
            vec![parent_tuple("folder")],
            None,
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(
        result,
        Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples: 1 })
    ));
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, relation("parent"));
}

#[test]
fn nested_reads_share_the_global_store_call_budget() {
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(1)
        .unwrap();
    let (result, reads) = run_scripted_check(
        TUPLESET_MODEL,
        vec![scripted_page(
            "42",
            "parent",
            None,
            vec![parent_tuple("folder")],
            None,
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(
        result,
        Err(AuthorizationError::StoreCallLimitExceeded { maximum_calls: 1 })
    ));
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, relation("parent"));
}

#[test]
fn stored_context_is_prepared_before_any_same_page_grant() {
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        CONDITION_MODEL,
        vec![scripted_page(
            "42",
            "viewer",
            None,
            vec![
                condition_tuple("anne", serde_json::Value::Bool(true)),
                condition_tuple(
                    "another-user",
                    serde_json::Value::String("not-a-bool".to_owned()),
                ),
            ],
            None,
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(
        matches!(
            &result,
            Err(AuthorizationError::InvalidConditionContext {
                condition,
                parameter,
                ..
            }) if condition == "enabled" && parameter == "flag"
        ),
        "unexpected same-page preparation result: {result:?}"
    );
    assert_eq!(calls.len(), 1);
}

#[test]
fn condition_false_requires_the_next_page() {
    let cursor = StoreCursor::from_bytes(vec![17]);
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        CONDITION_MODEL,
        vec![
            scripted_page(
                "42",
                "viewer",
                None,
                vec![condition_tuple("anne", serde_json::Value::Bool(false))],
                Some(cursor.clone()),
            ),
            scripted_page(
                "42",
                "viewer",
                Some(cursor),
                vec![condition_tuple("anne", serde_json::Value::Bool(true))],
                None,
            ),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 2);
}

#[test]
fn earlier_condition_evaluation_error_can_be_masked_by_a_later_grant() {
    let cursor = StoreCursor::from_bytes(vec![18]);
    let missing_flag = RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation("viewer"),
        subject("user", "anne"),
    )
    .with_condition(ConditionContext::new("enabled", std::collections::BTreeMap::new()).unwrap());
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        CONDITION_MODEL,
        vec![
            scripted_page(
                "42",
                "viewer",
                None,
                vec![missing_flag],
                Some(cursor.clone()),
            ),
            scripted_page(
                "42",
                "viewer",
                Some(cursor),
                vec![condition_tuple("anne", serde_json::Value::Bool(true))],
                None,
            ),
        ],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
    assert_eq!(calls.len(), 2);
}

#[test]
fn condition_evaluation_error_survives_stream_exhaustion() {
    let missing_flag = RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation("viewer"),
        subject("user", "anne"),
    )
    .with_condition(ConditionContext::new("enabled", std::collections::BTreeMap::new()).unwrap());
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let (result, reads) = run_scripted_check(
        CONDITION_MODEL,
        vec![scripted_page(
            "42",
            "viewer",
            None,
            vec![missing_flag],
            None,
        )],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(
        result,
        Err(AuthorizationError::MissingConditionContext {
            condition,
            parameter,
        }) if condition == "enabled" && parameter == "flag"
    ));
    assert_eq!(calls.len(), 1);
}

#[test]
fn page_preparation_budget_error_defeats_a_same_page_grant() {
    let mut tuples = vec![condition_tuple("anne", serde_json::Value::Bool(true))];
    tuples.extend((0..127).map(|index| {
        condition_tuple(
            &format!("other-user-{index}"),
            serde_json::Value::Bool(true),
        )
    }));
    // Loading the page costs 131 work units and preparing its 128 stored
    // contexts another 256, so preparation fails before any tuple is evaluated.
    let limits = EvaluationLimits::new(128)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap()
        .with_max_work_units(300)
        .unwrap();
    let (result, reads) = run_scripted_check(
        CONDITION_MODEL,
        vec![scripted_page("42", "viewer", None, tuples, None)],
        limits,
        check_request("tenant-a", "user", "anne", "document", "42", "viewer"),
    );
    let calls = reads
        .lock()
        .expect("test page read log mutex is not poisoned")
        .calls
        .clone();

    assert!(matches!(
        result,
        Err(AuthorizationError::WorkLimitExceeded {
            maximum_work_units: 300
        })
    ));
    assert_eq!(calls.len(), 1);
}

fn page_tuple(subject_id: &str, object_id: &str) -> RelationshipTuple {
    RelationshipTuple::new(
        relgraph_authz::TenantId::new("tenant-a").unwrap(),
        relgraph_authz::ObjectRef::new("document", object_id).unwrap(),
        relgraph_authz::RelationName::new("viewer").unwrap(),
        relgraph_authz::TupleSubject::Direct(
            relgraph_authz::Subject::new("user", subject_id).unwrap(),
        ),
    )
}
