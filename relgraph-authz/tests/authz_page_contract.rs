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
    let tuple = tuple();
    let result = run_check(vec![
        scripted_page("42", "viewer", None, vec![tuple.clone()], Some(a.clone())),
        scripted_page(
            "42",
            "viewer",
            Some(a.clone()),
            vec![tuple.clone()],
            Some(b.clone()),
        ),
        scripted_page("42", "viewer", Some(b), vec![tuple], Some(a)),
    ]);

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
}

#[test]
fn evaluator_rejects_empty_pages_that_claim_a_continuation() {
    let result = run_check(vec![scripted_page(
        "42",
        "viewer",
        None,
        Vec::new(),
        Some(StoreCursor::from_bytes(vec![9])),
    )]);

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
}

#[test]
fn evaluator_allows_a_grant_on_the_first_page_after_reading_later_pages() {
    let cursor = StoreCursor::from_bytes(vec![3]);
    let result = run_check(vec![
        scripted_page("42", "viewer", None, vec![tuple()], Some(cursor.clone())),
        scripted_page(
            "42",
            "viewer",
            Some(cursor),
            vec![page_tuple("other-user", "42")],
            None,
        ),
    ]);

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
}

#[test]
fn evaluator_allows_a_grant_on_a_later_page() {
    let cursor = StoreCursor::from_bytes(vec![4]);
    let result = run_check(vec![
        scripted_page(
            "42",
            "viewer",
            None,
            vec![page_tuple("other-user", "42")],
            Some(cursor.clone()),
        ),
        scripted_page("42", "viewer", Some(cursor), vec![tuple()], None),
    ]);

    assert!(matches!(result, Ok(AuthorizationDecision::Allow)));
}

#[test]
fn late_page_store_error_prevents_an_earlier_grant() {
    let cursor = StoreCursor::from_bytes(vec![5]);
    let result = run_check(vec![
        scripted_page("42", "viewer", None, vec![tuple()], Some(cursor.clone())),
        scripted_error("42", "viewer", Some(cursor), StoreErrorKind::IncompleteRead),
    ]);

    assert!(matches!(result, Err(AuthorizationError::Store(_))));
}

#[test]
fn late_invalid_tuple_prevents_an_earlier_grant() {
    let cursor = StoreCursor::from_bytes(vec![6]);
    let result = run_check(vec![
        scripted_page("42", "viewer", None, vec![tuple()], Some(cursor.clone())),
        scripted_page(
            "42",
            "viewer",
            Some(cursor),
            vec![page_tuple("anne", "other-object")],
            None,
        ),
    ]);

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
}

#[test]
fn page_read_error_precedes_validation_of_buffered_tuples() {
    let first_cursor = StoreCursor::from_bytes(vec![7]);
    let missing_page_cursor = StoreCursor::from_bytes(vec![8]);
    let result = run_check(vec![
        scripted_page(
            "42",
            "viewer",
            None,
            vec![tuple()],
            Some(first_cursor.clone()),
        ),
        scripted_page(
            "42",
            "viewer",
            Some(first_cursor),
            vec![page_tuple("anne", "other-object")],
            Some(missing_page_cursor),
        ),
    ]);

    assert!(matches!(result, Err(AuthorizationError::Store(_))));
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
