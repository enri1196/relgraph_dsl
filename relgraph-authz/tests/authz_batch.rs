#[allow(dead_code)]
mod common;

use std::collections::BTreeMap;

use common::{object, relation, subject, tenant};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, CheckRequest, ConditionContext,
    EvaluationLimits, EvaluationLimitsError, FgaAuthz, InMemoryRelationshipStore, ObjectRef,
    RelationName, RelationshipTuple, TupleSubject,
};
use serde_json::json;

const MODEL: &str = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user, group#member]\ntype folder\n  relations\n    define viewer: [user, group#member]\ntype document\n  relations\n    define parent: [folder]\n    define viewer: [user, group#member, user with enabled] or viewer from parent\n    define editor: [user]\ncondition enabled(flag: bool) {\n  flag\n}\n";

fn store() -> InMemoryRelationshipStore {
    let store = InMemoryRelationshipStore::new();
    let tuples = [
        RelationshipTuple::new(
            tenant("acme"),
            object("group", "eng"),
            relation("member"),
            subject("user", "anne"),
        ),
        RelationshipTuple::new(
            tenant("acme"),
            object("folder", "shared"),
            relation("viewer"),
            TupleSubject::Userset {
                object: object("group", "eng"),
                relation: relation("member"),
            },
        ),
        RelationshipTuple::new(
            tenant("acme"),
            object("document", "spec"),
            relation("parent"),
            subject("folder", "shared"),
        ),
        RelationshipTuple::new(
            tenant("acme"),
            object("document", "notes"),
            relation("viewer"),
            subject("user", "anne"),
        ),
        RelationshipTuple::new(
            tenant("acme"),
            object("document", "flagged"),
            relation("viewer"),
            subject("user", "anne"),
        )
        .with_condition(ConditionContext::new("enabled", BTreeMap::new()).unwrap()),
    ];
    for tuple in tuples {
        store.insert(tuple).unwrap();
    }
    store
}

fn authz(limits: EvaluationLimits) -> FgaAuthz<relgraph_authz::Bound<InMemoryRelationshipStore>> {
    FgaAuthz::new(MODEL).unwrap().with_store(store(), limits)
}

fn items(pairs: &[(&str, &str, &str)]) -> Vec<(ObjectRef, RelationName)> {
    pairs
        .iter()
        .map(|(object_type, id, name)| (object(object_type, id), relation(name)))
        .collect()
}

#[tokio::test]
async fn batch_results_follow_item_order_and_match_individual_checks() {
    let authz = authz(EvaluationLimits::default());
    let pairs = [
        ("document", "spec", "viewer"),
        ("document", "notes", "viewer"),
        ("document", "secret", "viewer"),
        ("folder", "shared", "viewer"),
        ("document", "spec", "editor"),
        ("group", "eng", "member"),
        ("document", "spec", "viewer"),
    ];
    let request = BatchCheckRequest::new(tenant("acme"), subject("user", "anne"), items(&pairs));

    let results = authz.batch_check(&request).await.unwrap();

    assert_eq!(results.len(), pairs.len());
    for ((object, relation), result) in request.items().iter().zip(results) {
        let individual = authz
            .check(CheckRequest::new(
                tenant("acme"),
                subject("user", "anne"),
                object.clone(),
                relation.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(result.unwrap(), individual, "{object:?} {relation:?}");
    }
}

#[tokio::test]
async fn item_errors_stay_in_their_own_slot() {
    let authz = authz(EvaluationLimits::default());
    let request = BatchCheckRequest::new(
        tenant("acme"),
        subject("user", "anne"),
        items(&[
            ("document", "notes", "viewer"),
            ("document", "notes", "owner"),
            ("spreadsheet", "q3", "viewer"),
            // The stored condition lacks `flag` and this batch supplies none.
            ("document", "flagged", "viewer"),
            ("document", "secret", "viewer"),
        ]),
    );

    let results = authz.batch_check(&request).await.unwrap();

    assert!(matches!(
        results.as_slice(),
        [
            Ok(AuthorizationDecision::Allow),
            Err(AuthorizationError::UnknownRelation { .. }),
            Err(AuthorizationError::UnknownObjectType(_)),
            Err(AuthorizationError::MissingConditionContext { .. }),
            Ok(AuthorizationDecision::Deny),
        ]
    ));
}

#[tokio::test]
async fn batch_context_applies_to_every_item() {
    let authz = authz(EvaluationLimits::default());
    let request = BatchCheckRequest::new(
        tenant("acme"),
        subject("user", "anne"),
        items(&[
            ("document", "flagged", "viewer"),
            ("document", "notes", "viewer"),
        ]),
    )
    .with_condition_context(
        "enabled",
        BTreeMap::from([("flag".to_owned(), json!(true))]),
    );

    let results = authz.batch_check(&request).await.unwrap();

    assert!(matches!(
        results.as_slice(),
        [
            Ok(AuthorizationDecision::Allow),
            Ok(AuthorizationDecision::Allow)
        ]
    ));

    let denied = BatchCheckRequest::new(
        tenant("acme"),
        subject("user", "anne"),
        items(&[("document", "flagged", "viewer")]),
    )
    .with_context(BTreeMap::from([("flag".to_owned(), json!(false))]));
    assert!(matches!(
        authz.batch_check(&denied).await.unwrap().as_slice(),
        [Ok(AuthorizationDecision::Deny)]
    ));
}

/// Returns the smallest work budget with which one item checks without error.
async fn minimal_work_units(object: ObjectRef, relation: RelationName) -> usize {
    for maximum in 1..=1_000 {
        let limits = EvaluationLimits::default()
            .with_max_work_units(maximum)
            .unwrap();
        let request = CheckRequest::new(
            tenant("acme"),
            subject("user", "anne"),
            object.clone(),
            relation.clone(),
        );
        if authz(limits).check(request).await.is_ok() {
            return maximum;
        }
    }
    panic!("item needs more than 1,000 work units");
}

#[tokio::test]
async fn item_budgets_restart_for_each_item() {
    // These items share no relation keys, so the memo cannot shrink their cost.
    let pairs = items(&[
        ("document", "notes", "viewer"),
        ("group", "eng", "member"),
        ("document", "secret", "viewer"),
    ]);
    let mut costs = Vec::new();
    for (object, relation) in &pairs {
        costs.push(minimal_work_units(object.clone(), relation.clone()).await);
    }
    let maximum = *costs.iter().max().unwrap();
    assert!(costs.iter().sum::<usize>() > maximum);

    let limits = EvaluationLimits::default()
        .with_max_work_units(maximum)
        .unwrap();
    let request = BatchCheckRequest::new(tenant("acme"), subject("user", "anne"), pairs);
    let results = authz(limits).batch_check(&request).await.unwrap();

    assert!(
        matches!(
            results.as_slice(),
            [
                Ok(AuthorizationDecision::Allow),
                Ok(AuthorizationDecision::Allow),
                Ok(AuthorizationDecision::Deny),
            ]
        ),
        "{results:?}"
    );
}

#[tokio::test]
async fn batch_level_failures_use_the_outer_error() {
    let limits = EvaluationLimits::default().with_max_batch_items(2).unwrap();
    let authz = authz(limits);

    let oversized = BatchCheckRequest::new(
        tenant("acme"),
        subject("user", "anne"),
        items(&[
            ("document", "notes", "viewer"),
            ("document", "spec", "viewer"),
            ("document", "secret", "viewer"),
        ]),
    );
    assert!(matches!(
        authz.batch_check(&oversized).await,
        Err(AuthorizationError::BatchLimitExceeded { maximum_items: 2 })
    ));

    let unknown_subject = BatchCheckRequest::new(
        tenant("acme"),
        subject("robot", "r2"),
        items(&[("document", "notes", "viewer")]),
    );
    assert!(matches!(
        authz.batch_check(&unknown_subject).await,
        Err(AuthorizationError::UnknownSubjectType(name)) if name == "robot"
    ));

    let empty = BatchCheckRequest::new(tenant("acme"), subject("user", "anne"), Vec::new());
    assert!(authz.batch_check(&empty).await.unwrap().is_empty());
}

#[test]
fn batch_item_limit_is_validated() {
    assert_eq!(
        EvaluationLimits::default().max_batch_items(),
        EvaluationLimits::DEFAULT_MAX_BATCH_ITEMS
    );
    assert_eq!(EvaluationLimits::DEFAULT_MAX_BATCH_ITEMS, 100);
    assert_eq!(
        EvaluationLimits::default().with_max_batch_items(0),
        Err(EvaluationLimitsError::ZeroBatchItemLimit)
    );
    assert_eq!(
        EvaluationLimits::default().with_max_batch_items(EvaluationLimits::MAX_BATCH_ITEMS + 1),
        Err(EvaluationLimitsError::BatchItemLimitTooLarge { maximum: 1_000 })
    );
    assert_eq!(
        EvaluationLimits::default()
            .with_max_batch_items(EvaluationLimits::MAX_BATCH_ITEMS)
            .unwrap()
            .max_batch_items(),
        1_000
    );
}

#[tokio::test]
async fn filter_objects_splits_allowed_candidates_and_errors() {
    let authz = authz(EvaluationLimits::default());
    let filtered = authz
        .filter_objects(
            tenant("acme"),
            subject("user", "anne"),
            relation("viewer"),
            vec![
                object("document", "secret"),
                object("document", "spec"),
                object("folder", "shared"),
                object("group", "eng"),
                object("document", "flagged"),
                object("document", "notes"),
            ],
        )
        .await
        .unwrap();

    assert_eq!(
        filtered.allowed,
        [
            object("document", "spec"),
            object("folder", "shared"),
            object("document", "notes"),
        ]
    );
    assert!(matches!(
        filtered.errors.as_slice(),
        [
            (group, AuthorizationError::UnknownRelation { .. }),
            (flagged, AuthorizationError::MissingConditionContext { .. }),
        ] if *group == object("group", "eng") && *flagged == object("document", "flagged")
    ));
}
