#[allow(dead_code)]
mod common;

use common::{block_on, object, relation, request as check_request, subject, tenant};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, CheckRequest, EvaluationLimits, FgaAuthz, ObjectRef,
    RelationName, RelationshipPage, RelationshipReadSession, RelationshipStore, RelationshipTuple,
    StoreCursor, StoreError, StoreErrorKind, StoreFuture, TenantId,
};
use std::sync::{Arc, Mutex};

const MODEL: &str =
    "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n";

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
