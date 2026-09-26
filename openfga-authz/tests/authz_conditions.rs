use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use openfga_authz::{
    AuthorizationDecision, AuthorizationError, CheckRequest, ConditionContext, ConstructionError,
    EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ObjectRef, RelationName,
    RelationshipTuple, Subject, TenantId,
};
use serde_json::{Value, json};

const TIME_MODEL: &str = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with valid_grant]\ncondition valid_grant(current_time: timestamp, grant_time: timestamp, grant_duration: duration) {\n  current_time < grant_time + grant_duration\n}\n";

fn subject(kind: &str, id: &str) -> Subject {
    Subject::new(kind, id).unwrap()
}

fn object(kind: &str, id: &str) -> ObjectRef {
    ObjectRef::new(kind, id).unwrap()
}

fn tuple(
    relation: &str,
    subject: Subject,
    condition: Option<ConditionContext>,
) -> RelationshipTuple {
    let tuple = RelationshipTuple::new(
        TenantId::new("tenant-a").unwrap(),
        object("document", "42"),
        RelationName::new(relation).unwrap(),
        subject,
    );
    match condition {
        Some(condition) => tuple.with_condition(condition),
        None => tuple,
    }
}

fn values(entries: impl IntoIterator<Item = (&'static str, Value)>) -> BTreeMap<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn request(context: BTreeMap<String, Value>) -> CheckRequest {
    CheckRequest::new(
        TenantId::new("tenant-a").unwrap(),
        subject("user", "anne"),
        object("document", "42"),
        RelationName::new("viewer").unwrap(),
    )
    .with_context(context)
}

fn authz_with_tuple(
    definition: &str,
    condition: Option<ConditionContext>,
    limits: EvaluationLimits,
) -> FgaAuthz<openfga_authz::Bound<InMemoryRelationshipStore>> {
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple("viewer", subject("user", "anne"), condition))
        .unwrap();
    FgaAuthz::new(definition).unwrap().with_store(store, limits)
}

#[test]
fn compiles_and_evaluates_scalar_container_and_time_parameters() {
    let definition = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with typed]\ncondition typed(enabled: bool, count: int, maximum: uint, ratio: double, role: string, roles: list<string>, metrics: map<int>) {\n  enabled && count < int(maximum) && ratio > 1.5 && role.startsWith(\"adm\") && \"writer\" in roles && metrics[\"score\"] > 3\n}\n";
    let condition_values = values([
        ("enabled", json!(true)),
        ("count", json!(4)),
        ("maximum", json!(9)),
        ("ratio", json!(2.5)),
        ("role", json!("admin")),
        ("roles", json!(["reader", "writer"])),
        ("metrics", json!({"score": 4})),
    ]);
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple(
            "viewer",
            subject("user", "anne"),
            Some(ConditionContext::new("typed", condition_values).unwrap()),
        ))
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    let result = block_on(authz.check(request(BTreeMap::new()))).unwrap();
    assert_eq!(result, AuthorizationDecision::Allow);

    let result = block_on(authz.check(request(values([(
        "current_time",
        json!("2025-01-01T00:30:00Z"),
    )]))));
    assert_eq!(result.unwrap(), AuthorizationDecision::Allow);
}

#[test]
fn timestamps_and_durations_are_compiled_and_expired_grants_deny() {
    let tuple_context = ConditionContext::new(
        "valid_grant",
        values([
            ("grant_time", json!("2025-01-01T00:00:00Z")),
            ("grant_duration", json!("1h")),
        ]),
    )
    .unwrap();
    let authz = authz_with_tuple(TIME_MODEL, Some(tuple_context), EvaluationLimits::default());

    let before_expiry = request(values([("current_time", json!("2025-01-01T00:30:00Z"))]));
    assert_eq!(
        block_on(authz.check(before_expiry)).unwrap(),
        AuthorizationDecision::Allow
    );

    let after_expiry = request(values([("current_time", json!("2025-01-01T02:00:00Z"))]));
    assert_eq!(
        block_on(authz.check(after_expiry)).unwrap(),
        AuthorizationDecision::Deny
    );
}

#[test]
fn tuple_context_wins_and_request_context_fills_missing_values() {
    let tuple_context = ConditionContext::new(
        "valid_grant",
        values([
            ("grant_time", json!("2025-01-01T00:00:00Z")),
            ("grant_duration", json!("1h")),
        ]),
    )
    .unwrap();
    let authz = authz_with_tuple(TIME_MODEL, Some(tuple_context), EvaluationLimits::default());
    let check = request(values([
        ("current_time", json!("2025-01-01T01:30:00Z")),
        // If these replaced the stored values, the grant would be valid.
        ("grant_time", json!("2025-01-01T02:00:00Z")),
        ("grant_duration", json!("1h")),
    ]));

    assert_eq!(
        block_on(authz.check(check)).unwrap(),
        AuthorizationDecision::Deny
    );
}

#[test]
fn missing_and_wrong_context_values_are_typed_errors() {
    let tuple_context = ConditionContext::new(
        "valid_grant",
        values([("grant_time", json!("2025-01-01T00:00:00Z"))]),
    )
    .unwrap();
    let authz = authz_with_tuple(
        TIME_MODEL,
        Some(tuple_context.clone()),
        EvaluationLimits::default(),
    );
    let missing = block_on(authz.check(request(BTreeMap::new())));
    assert!(matches!(
        missing,
        Err(AuthorizationError::MissingConditionContext {
            condition,
            parameter
        }) if condition == "valid_grant" && parameter == "current_time"
    ));

    let authz = authz_with_tuple(TIME_MODEL, Some(tuple_context), EvaluationLimits::default());
    let wrong = block_on(authz.check(request(values([(
        "current_time",
        json!("not-a-timestamp"),
    )]))));
    assert!(matches!(
        wrong,
        Err(AuthorizationError::InvalidConditionContext {
            condition,
            parameter,
            source: openfga_authz::ConditionContextSource::Request,
            ..
        }) if condition == "valid_grant" && parameter == "current_time"
    ));
}

#[test]
fn unconditional_union_allow_survives_an_unrelated_missing_condition_value() {
    let base = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define owner: [user]\n    define timed: [user with valid_grant]\n    define viewer: timed or owner\ncondition valid_grant(current_time: timestamp) { current_time < timestamp(\"2030-01-01T00:00:00Z\") }\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple("owner", subject("user", "anne"), None))
        .unwrap();
    store
        .insert(tuple(
            "timed",
            subject("user", "anne"),
            Some(ConditionContext::new("valid_grant", BTreeMap::new()).unwrap()),
        ))
        .unwrap();
    let authz = FgaAuthz::new(base)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    assert_eq!(
        block_on(authz.check(request(BTreeMap::new()))).unwrap(),
        AuthorizationDecision::Allow
    );
}

#[test]
fn condition_cost_budget_is_enforced() {
    let tuple_context = ConditionContext::new(
        "valid_grant",
        values([
            ("grant_time", json!("2025-01-01T00:00:00Z")),
            ("grant_duration", json!("1h")),
        ]),
    )
    .unwrap();
    let limits = EvaluationLimits::default()
        .with_max_condition_cost(1)
        .unwrap();
    let authz = authz_with_tuple(TIME_MODEL, Some(tuple_context), limits);
    let result = block_on(authz.check(request(values([(
        "current_time",
        json!("2025-01-01T00:30:00Z"),
    )]))));
    assert!(matches!(
        result,
        Err(AuthorizationError::ConditionCostLimitExceeded { .. })
    ));
}

#[test]
fn invalid_cel_undeclared_variables_and_unsupported_syntax_fail_construction() {
    let invalid = TIME_MODEL.replace(
        "current_time < grant_time + grant_duration",
        "current_time <",
    );
    assert!(matches!(
        FgaAuthz::new(&invalid),
        Err(ConstructionError::ConditionCompilation { .. })
    ));

    let undeclared = TIME_MODEL.replace(
        "current_time < grant_time + grant_duration",
        "current_time < grant_time + grant_duration + not_declared",
    );
    assert!(matches!(
        FgaAuthz::new(&undeclared),
        Err(ConstructionError::ConditionCompilation { .. })
    ));

    let unsupported = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with allowed]\ncondition allowed(roles: list<string>) { roles.exists(role, role == \"admin\") }\n";
    assert!(matches!(
        FgaAuthz::new(unsupported),
        Err(ConstructionError::ConditionCompilation { .. })
    ));
}

#[test]
fn unsupported_condition_parameter_types_fail_construction() {
    let unsupported = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with allowed]\ncondition allowed(address: ipaddress) { address == \"192.0.2.1\" }\n";
    assert!(matches!(
        FgaAuthz::new(unsupported),
        Err(ConstructionError::ConditionCompilation { .. })
    ));
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
    }
}
