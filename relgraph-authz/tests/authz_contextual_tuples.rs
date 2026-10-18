//! Contextual tuples through the public check and batch APIs.

#[allow(dead_code)]
mod common;

use std::collections::BTreeMap;

use common::{object, relation, subject, tenant};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, Bound, CheckRequest,
    ConditionContext, ContextualTupleError, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore,
    MAX_CONTEXTUAL_TUPLES, ObjectRef, RelationshipReadSession, RelationshipStore,
    RelationshipTuple, StoreError, StoreErrorKind, StoreFuture, TenantId, TupleSubject,
};
use serde_json::{Value, json};

const MODEL: &str = "\
model
  schema 1.1
type user
type group
  relations
    define member: [user]
type folder
  relations
    define viewer: [user, group#member]
type document
  relations
    define parent: [folder]
    define viewer: [user, user with in_hours, group#member] or viewer from parent
    define blocked: [user]
    define reader: viewer but not blocked
condition in_hours(hour: int, limit: int) {
  hour < limit
}
";

fn tuple(
    object_type: &str,
    object_id: &str,
    name: &str,
    subject: impl Into<TupleSubject>,
) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant("acme"),
        object(object_type, object_id),
        relation(name),
        subject,
    )
}

fn user(id: &str) -> TupleSubject {
    subject("user", id).into()
}

fn group_members(id: &str) -> TupleSubject {
    TupleSubject::Userset {
        object: object("group", id),
        relation: relation("member"),
    }
}

fn values(entries: impl IntoIterator<Item = (&'static str, Value)>) -> BTreeMap<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn in_hours(limit: Value) -> ConditionContext {
    ConditionContext::new("in_hours", values([("limit", limit)])).unwrap()
}

fn authz(
    stored: impl IntoIterator<Item = RelationshipTuple>,
    limits: EvaluationLimits,
) -> FgaAuthz<Bound<InMemoryRelationshipStore>> {
    let store = InMemoryRelationshipStore::new();
    for tuple in stored {
        store.insert(tuple).unwrap();
    }
    FgaAuthz::new(MODEL).unwrap().with_store(store, limits)
}

fn check(object_type: &str, object_id: &str, name: &str) -> CheckRequest {
    CheckRequest::new(
        tenant("acme"),
        subject("user", "anne"),
        object(object_type, object_id),
        relation(name),
    )
}

fn invalid_index(error: &AuthorizationError) -> Option<(usize, &ContextualTupleError)> {
    match error {
        AuthorizationError::InvalidContextualTuple { index, reason } => Some((*index, reason)),
        _ => None,
    }
}

#[tokio::test]
async fn contextual_tuples_grant_only_the_check_that_carries_them() {
    let authz = authz([], EvaluationLimits::default());
    let grant = tuple("document", "1", "viewer", user("anne"));

    let with = check("document", "1", "viewer").with_contextual_tuples([grant.clone()]);
    assert_eq!(with.contextual_tuples(), std::slice::from_ref(&grant));
    assert_eq!(
        authz.check(with).await.unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz.check(check("document", "1", "viewer")).await.unwrap(),
        AuthorizationDecision::Deny
    );
}

#[tokio::test]
async fn contextual_and_stored_tuples_combine_through_usersets_and_tuplesets() {
    // Stored: document:spec's parent is folder:shared, whose viewers are
    // group:eng members. Contextual: anne is a member of group:eng.
    let authz = authz(
        [
            tuple("document", "spec", "parent", subject("folder", "shared")),
            tuple("folder", "shared", "viewer", group_members("eng")),
        ],
        EvaluationLimits::default(),
    );
    let membership = tuple("group", "eng", "member", user("anne"));

    assert_eq!(
        authz
            .check(check("document", "spec", "viewer").with_contextual_tuples([membership]))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz
            .check(check("document", "spec", "viewer"))
            .await
            .unwrap(),
        AuthorizationDecision::Deny
    );

    // A contextual tupleset tuple reaches stored folder viewers.
    let authz = authz_with_folder_viewer();
    let parent = tuple("document", "draft", "parent", subject("folder", "shared"));
    assert_eq!(
        authz
            .check(check("document", "draft", "viewer").with_contextual_tuples([parent]))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
}

fn authz_with_folder_viewer() -> FgaAuthz<Bound<InMemoryRelationshipStore>> {
    authz(
        [tuple("folder", "shared", "viewer", user("anne"))],
        EvaluationLimits::default(),
    )
}

#[tokio::test]
async fn a_contextual_subtraction_tuple_denies() {
    let authz = authz(
        [tuple("document", "1", "viewer", user("anne"))],
        EvaluationLimits::default(),
    );
    assert_eq!(
        authz.check(check("document", "1", "reader")).await.unwrap(),
        AuthorizationDecision::Allow
    );
    let blocked = tuple("document", "1", "blocked", user("anne"));
    assert_eq!(
        authz
            .check(check("document", "1", "reader").with_contextual_tuples([blocked]))
            .await
            .unwrap(),
        AuthorizationDecision::Deny
    );
}

#[tokio::test]
async fn a_tuple_of_another_tenant_is_rejected_before_the_store_is_read() {
    let authz = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(UnavailableStore, EvaluationLimits::default());
    let other_tenant = RelationshipTuple::new(
        TenantId::new("globex").unwrap(),
        object("document", "1"),
        relation("viewer"),
        user("anne"),
    );
    let request = check("document", "1", "viewer")
        .with_contextual_tuples([tuple("document", "1", "viewer", user("bob")), other_tenant]);

    let error = authz.check(request).await.unwrap_err();
    assert!(
        matches!(
            invalid_index(&error),
            Some((1, ContextualTupleError::TenantMismatch))
        ),
        "{error:?}"
    );

    // Valid contextual tuples do reach the store.
    let request = check("document", "1", "viewer").with_contextual_tuples([tuple(
        "document",
        "1",
        "viewer",
        user("anne"),
    )]);
    assert!(matches!(
        authz.check(request).await,
        Err(AuthorizationError::Store(_))
    ));
}

#[tokio::test]
async fn tuples_that_do_not_fit_the_model_are_rejected_with_the_write_error() {
    let authz = authz([], EvaluationLimits::default());
    let cases = [
        (
            tuple("spreadsheet", "1", "viewer", user("anne")),
            "UnknownObjectType",
        ),
        (
            tuple("document", "1", "owner", user("anne")),
            "UnknownRelation",
        ),
        // `blocked` accepts only direct users.
        (
            tuple("document", "1", "blocked", group_members("eng")),
            "InvalidTuple",
        ),
        // `reader` has no direct assignment.
        (
            tuple("document", "1", "reader", user("anne")),
            "InvalidTuple",
        ),
        // The condition's declared parameter type is int.
        (
            tuple("document", "1", "viewer", user("anne")).with_condition(in_hours(json!("x"))),
            "InvalidConditionContext",
        ),
    ];
    for (invalid, variant) in cases {
        let expected = authz.validate_tuple(&invalid).unwrap_err();
        assert!(format!("{expected:?}").starts_with(variant), "{expected:?}");
        let request = check("document", "1", "viewer").with_contextual_tuples([invalid.clone()]);

        let error = authz.check(request).await.unwrap_err();
        let Some((0, ContextualTupleError::Model(inner))) = invalid_index(&error) else {
            panic!("{invalid:?} gave {error:?}");
        };
        assert_eq!(format!("{inner:?}"), format!("{expected:?}"));
        assert!(std::error::Error::source(&error).is_some());
    }
}

#[tokio::test]
async fn exact_repeats_within_the_set_are_rejected() {
    let authz = authz([], EvaluationLimits::default());
    let grant = tuple("document", "1", "viewer", user("anne"));
    let request = check("document", "1", "viewer").with_contextual_tuples([
        grant.clone(),
        tuple("document", "2", "viewer", user("anne")),
        grant.clone(),
    ]);

    let error = authz.check(request).await.unwrap_err();
    assert!(
        matches!(
            invalid_index(&error),
            Some((2, ContextualTupleError::Duplicate { first_index: 0 }))
        ),
        "{error:?}"
    );

    // A different condition context makes a different tuple.
    let request = check("document", "1", "viewer")
        .with_context(values([("hour", json!(9))]))
        .with_contextual_tuples([
            grant.clone().with_condition(in_hours(json!(8))),
            grant.with_condition(in_hours(json!(17))),
        ]);
    assert_eq!(
        authz.check(request).await.unwrap(),
        AuthorizationDecision::Allow
    );
}

#[tokio::test]
async fn a_contextual_tuple_equal_to_a_stored_one_is_accepted() {
    let conditional =
        tuple("document", "1", "viewer", user("anne")).with_condition(in_hours(json!(17)));
    let authz = authz([conditional.clone()], EvaluationLimits::default());

    for (hour, expected) in [
        (9, AuthorizationDecision::Allow),
        (18, AuthorizationDecision::Deny),
    ] {
        let request = check("document", "1", "viewer")
            .with_context(values([("hour", json!(hour))]))
            .with_contextual_tuples([conditional.clone()]);
        assert_eq!(authz.check(request).await.unwrap(), expected, "hour {hour}");
    }
}

#[tokio::test]
async fn contextual_condition_context_keeps_tuple_precedence() {
    let authz = authz([], EvaluationLimits::default());
    let grant = tuple("document", "1", "viewer", user("anne")).with_condition(in_hours(json!(17)));
    let request = |hour: i64| {
        check("document", "1", "viewer")
            // If the request's `limit` replaced the tuple's, 18 would allow.
            .with_context(values([("hour", json!(hour)), ("limit", json!(99))]))
            .with_contextual_tuples([grant.clone()])
    };

    assert_eq!(
        authz.check(request(9)).await.unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz.check(request(18)).await.unwrap(),
        AuthorizationDecision::Deny
    );
    // Without `hour`, the condition cannot be evaluated: an error, not a deny.
    let missing = check("document", "1", "viewer").with_contextual_tuples([grant.clone()]);
    assert!(matches!(
        authz.check(missing).await,
        Err(AuthorizationError::MissingConditionContext { .. })
    ));
}

#[tokio::test]
async fn the_limit_matches_openfga() {
    assert_eq!(MAX_CONTEXTUAL_TUPLES, 100);
    let authz = authz([], EvaluationLimits::default());
    let tuples = |count: usize| {
        (0..count)
            .map(|index| tuple("document", &format!("d{index}"), "viewer", user("anne")))
            .collect::<Vec<_>>()
    };

    let at_limit = check("document", "d0", "viewer").with_contextual_tuples(tuples(100));
    assert_eq!(
        authz.check(at_limit).await.unwrap(),
        AuthorizationDecision::Allow
    );
    let over = check("document", "d0", "viewer").with_contextual_tuples(tuples(101));
    assert!(matches!(
        authz.check(over).await,
        Err(AuthorizationError::ContextualTupleLimitExceeded {
            maximum_tuples: 100
        })
    ));
    let over_batch = BatchCheckRequest::new(
        tenant("acme"),
        subject("user", "anne"),
        [(object("document", "d0"), relation("viewer"))],
    )
    .with_contextual_tuples(tuples(101));
    assert!(matches!(
        authz.batch_check(&over_batch).await,
        Err(AuthorizationError::ContextualTupleLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn contextual_tuples_count_toward_the_tuple_scan_budget() {
    let grants = [
        tuple("document", "1", "viewer", user("bob")),
        tuple("document", "1", "viewer", user("anne")),
    ];
    let tight = authz([], EvaluationLimits::new(1).unwrap());
    assert!(matches!(
        tight
            .check(check("document", "1", "viewer").with_contextual_tuples(grants.clone()))
            .await,
        Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples: 1 })
    ));
    let enough = authz([], EvaluationLimits::new(2).unwrap());
    assert_eq!(
        enough
            .check(check("document", "1", "viewer").with_contextual_tuples(grants))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
}

#[tokio::test]
async fn a_batch_shares_its_contextual_tuples_across_items() {
    let authz = authz(
        [tuple(
            "document",
            "spec",
            "parent",
            subject("folder", "shared"),
        )],
        EvaluationLimits::default(),
    );
    let contextual = [
        tuple("folder", "shared", "viewer", group_members("eng")),
        tuple("group", "eng", "member", user("anne")),
    ];
    let pairs = [
        ("document", "spec", "viewer"),
        ("folder", "shared", "viewer"),
        ("group", "eng", "member"),
        ("document", "other", "viewer"),
        ("document", "spec", "owner"),
    ];
    let request = BatchCheckRequest::new(
        tenant("acme"),
        subject("user", "anne"),
        pairs
            .iter()
            .map(|(object_type, id, name)| (object(object_type, id), relation(name))),
    )
    .with_contextual_tuples(contextual.clone());
    assert_eq!(request.contextual_tuples(), contextual.as_slice());

    let results = authz.batch_check(&request).await.unwrap();
    assert_eq!(results.len(), pairs.len());
    for ((object, relation), batched) in request.items().iter().zip(results) {
        let individual = authz
            .check(
                CheckRequest::new(
                    tenant("acme"),
                    subject("user", "anne"),
                    object.clone(),
                    relation.clone(),
                )
                .with_contextual_tuples(contextual.clone()),
            )
            .await;
        assert_eq!(
            format!("{batched:?}"),
            format!("{individual:?}"),
            "{object:?} {relation:?}"
        );
    }
    let decisions: Vec<_> = authz
        .batch_check(&request)
        .await
        .unwrap()
        .into_iter()
        .take(4)
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        decisions,
        [
            AuthorizationDecision::Allow,
            AuthorizationDecision::Allow,
            AuthorizationDecision::Allow,
            AuthorizationDecision::Deny,
        ]
    );

    // An invalid set fails the whole batch.
    let invalid = BatchCheckRequest::new(
        tenant("acme"),
        subject("user", "anne"),
        [(object("document", "spec"), relation("viewer"))],
    )
    .with_contextual_tuples([tuple("spreadsheet", "1", "viewer", user("anne"))]);
    assert!(matches!(
        authz.batch_check(&invalid).await,
        Err(AuthorizationError::InvalidContextualTuple { index: 0, .. })
    ));
}

#[tokio::test]
async fn decisions_do_not_leak_between_different_contextual_sets() {
    let authz = authz([], EvaluationLimits::default());
    let items = || {
        [
            (object("document", "1"), relation("viewer")),
            (object("document", "2"), relation("viewer")),
        ]
    };
    let batch = |contextual: Vec<RelationshipTuple>| {
        BatchCheckRequest::new(tenant("acme"), subject("user", "anne"), items())
            .with_contextual_tuples(contextual)
    };
    let decisions = |results: Vec<Result<AuthorizationDecision, AuthorizationError>>| {
        results.into_iter().map(Result::unwrap).collect::<Vec<_>>()
    };
    use AuthorizationDecision::{Allow, Deny};

    let first = batch(vec![tuple("document", "1", "viewer", user("anne"))]);
    let second = batch(vec![tuple("document", "2", "viewer", user("anne"))]);
    assert_eq!(
        decisions(authz.batch_check(&first).await.unwrap()),
        [Allow, Deny]
    );
    assert_eq!(
        decisions(authz.batch_check(&second).await.unwrap()),
        [Deny, Allow]
    );
    assert_eq!(
        decisions(authz.batch_check(&batch(Vec::new())).await.unwrap()),
        [Deny, Deny]
    );

    // A cloned authorizer evaluates each request in its own scope as well.
    let clone = authz.clone();
    let shared = tuple("document", "1", "viewer", user("anne"));
    assert_eq!(
        clone
            .check(check("document", "1", "viewer").with_contextual_tuples([shared]))
            .await
            .unwrap(),
        Allow
    );
    assert_eq!(
        authz.check(check("document", "1", "viewer")).await.unwrap(),
        Deny
    );
}

/// A store that cannot open a read session.
struct UnavailableStore;

struct UnusedSession;

impl RelationshipStore for UnavailableStore {
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
