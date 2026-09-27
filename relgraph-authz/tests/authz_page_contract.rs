#[allow(dead_code)]
mod common;

use common::{block_on, object, relation, request as check_request, subject, tenant};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, EvaluationLimits, FgaAuthz, RelationshipPage,
    RelationshipReadSession, RelationshipStore, RelationshipTuple, StoreCursor, StoreError,
    StoreErrorKind, StoreFuture, TenantId,
};
use std::sync::Mutex;

const MODEL: &str =
    "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n";

#[derive(Clone)]
struct PageScript {
    request_cursor: Option<StoreCursor>,
    tuples: Vec<RelationshipTuple>,
    next_cursor: Option<StoreCursor>,
}

struct PageStore {
    pages: Vec<PageScript>,
}

struct PageSession {
    pages: Vec<PageScript>,
    next_page: Mutex<usize>,
}

impl RelationshipStore for PageStore {
    type ReadSession = PageSession;

    fn begin_read<'a>(
        &'a self,
        _tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let pages = self.pages.clone();
        Box::pin(async move {
            Ok(PageSession {
                pages,
                next_page: Mutex::new(0),
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
        _object: &'a relgraph_authz::ObjectRef,
        _relation: &'a relgraph_authz::RelationName,
        cursor: Option<StoreCursor>,
        _maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
        let scripted = {
            let mut next_page = self
                .next_page
                .lock()
                .expect("test page mutex is not poisoned");
            let result = self.pages.get(*next_page).cloned().ok_or_else(|| {
                StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "the test store ran out of scripted pages",
                )
            });
            *next_page += 1;
            result
        };

        Box::pin(async move {
            let scripted = scripted?;
            if scripted.request_cursor != cursor {
                return Err(StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "the evaluator did not preserve the opaque cursor",
                ));
            }
            Ok(RelationshipPage {
                tuples: scripted.tuples,
                next_cursor: scripted.next_cursor,
            })
        })
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
    let limits = EvaluationLimits::new(10)
        .unwrap()
        .with_max_store_calls(10)
        .unwrap();
    let authz = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(PageStore { pages }, limits);
    block_on(authz.check(check_request(
        "tenant-a", "user", "anne", "document", "42", "viewer",
    )))
}

#[test]
fn evaluator_rejects_a_cursor_that_repeats_after_other_tokens() {
    let a = StoreCursor::from_bytes(vec![1]);
    let b = StoreCursor::from_bytes(vec![2]);
    let tuple = tuple();
    let result = run_check(vec![
        PageScript {
            request_cursor: None,
            tuples: vec![tuple.clone()],
            next_cursor: Some(a.clone()),
        },
        PageScript {
            request_cursor: Some(a.clone()),
            tuples: vec![tuple.clone()],
            next_cursor: Some(b.clone()),
        },
        PageScript {
            request_cursor: Some(b),
            tuples: vec![tuple],
            next_cursor: Some(a),
        },
    ]);

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
}

#[test]
fn evaluator_rejects_empty_pages_that_claim_a_continuation() {
    let result = run_check(vec![PageScript {
        request_cursor: None,
        tuples: Vec::new(),
        next_cursor: Some(StoreCursor::from_bytes(vec![9])),
    }]);

    assert!(matches!(result, Err(AuthorizationError::InvalidTuple(_))));
}
