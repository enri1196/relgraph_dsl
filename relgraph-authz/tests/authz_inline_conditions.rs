//! Inline condition expressions (`[user with $expression]`, decision S3):
//! each tuple stores its CEL source and parameter types.

use std::collections::BTreeMap;

use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, CheckRequest, ConditionContext,
    ConditionContextSource, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ObjectRef,
    RelationName, RelationshipReadSession, RelationshipStore, RelationshipTuple, StoreError,
    StoreErrorKind, StoreFuture, Subject, TenantId, WriteError,
};
use serde_json::{Value, json};

const INLINE_MODEL: &str = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with $expression]\n";

type Authz = FgaAuthz<relgraph_authz::Bound<InMemoryRelationshipStore>>;

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn document(id: &str) -> ObjectRef {
    ObjectRef::new("document", id).unwrap()
}

fn inline(expression: &str, parameters: &[(&str, &str)]) -> ConditionContext {
    let mut values = BTreeMap::from([("expression".to_owned(), json!(expression))]);
    if !parameters.is_empty() {
        let declared: serde_json::Map<String, Value> = parameters
            .iter()
            .map(|(name, type_name)| ((*name).to_owned(), json!(type_name)))
            .collect();
        values.insert("parameters".to_owned(), Value::Object(declared));
    }
    ConditionContext::new("$expression", values).unwrap()
}

fn viewer_tuple(object: &str, condition: ConditionContext) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant(),
        document(object),
        RelationName::new("viewer").unwrap(),
        Subject::new("user", "anne").unwrap(),
    )
    .with_condition(condition)
}

fn request(object: &str, context: Value) -> CheckRequest {
    let Value::Object(context) = context else {
        panic!("request context must be an object");
    };
    CheckRequest::new(
        tenant(),
        Subject::new("user", "anne").unwrap(),
        document(object),
        RelationName::new("viewer").unwrap(),
    )
    .with_context(context.into_iter().collect())
}

fn authz() -> Authz {
    FgaAuthz::new(INLINE_MODEL).unwrap().with_store(
        InMemoryRelationshipStore::new(),
        EvaluationLimits::default(),
    )
}

/// Binds the model to a store holding `tuple` without validating it, as a
/// tuple written before a model change or by another writer would be.
fn authz_with_unvalidated(tuple: RelationshipTuple) -> Authz {
    let store = InMemoryRelationshipStore::new();
    store.insert(tuple).unwrap();
    FgaAuthz::new(INLINE_MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default())
}

/// A store that serves one tuple without the in-memory store's write checks.
struct UncheckedTupleStore(RelationshipTuple);

struct UncheckedTupleReadSession(RelationshipTuple);

impl RelationshipStore for UncheckedTupleStore {
    type ReadSession = UncheckedTupleReadSession;

    fn begin_read<'a>(
        &'a self,
        _tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let tuple = self.0.clone();
        Box::pin(async move { Ok(UncheckedTupleReadSession(tuple)) })
    }
}

impl RelationshipReadSession for UncheckedTupleReadSession {
    fn tuples<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        _maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        let matches = self.0.object() == object && self.0.relation() == relation;
        let tuples = if matches {
            vec![self.0.clone()]
        } else {
            Vec::new()
        };
        Box::pin(async move { Ok(tuples) })
    }
}

async fn write(authz: &Authz, tuple: &RelationshipTuple) -> Result<(), WriteError> {
    authz.write_tuple(&tenant(), tuple).await
}

fn invalid_tuple(result: Result<(), WriteError>) -> &'static str {
    match result {
        Err(WriteError::Validation(AuthorizationError::InvalidTuple(reason))) => reason,
        other => panic!("expected an InvalidTuple write rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn a_valid_inline_condition_allows_and_denies_from_request_values() {
    let authz = authz();
    write(
        &authz,
        &viewer_tuple("1", inline("count > 5", &[("count", "int")])),
    )
    .await
    .unwrap();

    assert_eq!(
        authz
            .check(request("1", json!({"count": 10})))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz
            .check(request("1", json!({"count": 3})))
            .await
            .unwrap(),
        AuthorizationDecision::Deny
    );
    assert!(matches!(
        authz.check(request("1", json!({}))).await,
        Err(AuthorizationError::MissingConditionContext { condition, parameter })
            if condition == "$expression" && parameter == "count"
    ));
    // Condition-scoped values under `$expression` take precedence over global ones.
    assert_eq!(
        authz
            .check(request("1", json!({"count": 3})).with_condition_context(
                "$expression",
                BTreeMap::from([("count".to_owned(), json!(10))]),
            ),)
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
}

#[tokio::test]
async fn an_undeclared_parameter_is_inferred_as_a_string() {
    let authz = authz();
    write(&authz, &viewer_tuple("1", inline("env == 'prod'", &[])))
        .await
        .unwrap();

    assert_eq!(
        authz
            .check(request("1", json!({"env": "prod"})))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz
            .check(request("1", json!({"env": "dev"})))
            .await
            .unwrap(),
        AuthorizationDecision::Deny
    );
    assert!(matches!(
        authz.check(request("1", json!({"env": 5}))).await,
        Err(AuthorizationError::InvalidConditionContext {
            parameter,
            source: ConditionContextSource::Request,
            ..
        }) if parameter == "env"
    ));

    // The inferred type is string, so a numeric comparison does not compile.
    invalid_tuple(write(&authz, &viewer_tuple("2", inline("count > 5", &[]))).await);
}

#[tokio::test]
async fn parameter_types_are_enforced_and_kept_in_the_profile() {
    let authz = authz();
    write(
        &authz,
        &viewer_tuple("1", inline("count > 5", &[("count", "int")])),
    )
    .await
    .unwrap();
    assert!(matches!(
        authz.check(request("1", json!({"count": "ten"}))).await,
        Err(AuthorizationError::InvalidConditionContext {
            parameter,
            source: ConditionContextSource::Request,
            ..
        }) if parameter == "count"
    ));

    // A declared type that disagrees with the expression does not compile.
    invalid_tuple(
        write(
            &authz,
            &viewer_tuple("2", inline("count > 5", &[("count", "string")])),
        )
        .await,
    );
    // Types outside the runtime profile are rejected, as for model conditions.
    for type_name in [
        "any",
        "bytes",
        "list",
        "list<list<int>>",
        "map<int",
        "integer",
    ] {
        let reason = invalid_tuple(
            write(
                &authz,
                &viewer_tuple("3", inline("true", &[("x", type_name)])),
            )
            .await,
        );
        assert!(reason.contains("parameter type"), "{type_name}: {reason}");
    }
    // One-level containers and the ipaddress extension are in the profile.
    write(
        &authz,
        &viewer_tuple(
            "4",
            inline(
                "ip.in_cidr('10.0.0.0/8') && 'eng' in teams",
                &[("ip", "ipaddress"), ("teams", "list<string>")],
            ),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        authz
            .check(request("4", json!({"ip": "10.1.2.3", "teams": ["eng"]})))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
}

#[tokio::test]
async fn a_non_bool_expression_is_rejected_on_write_and_on_read() {
    let tuple = viewer_tuple("1", inline("count + 1", &[("count", "int")]));
    invalid_tuple(write(&authz(), &tuple).await);

    // A stored tuple that bypassed validation is a strict read error, not a deny.
    let authz = authz_with_unvalidated(tuple);
    assert!(matches!(
        authz.check(request("1", json!({"count": 1}))).await,
        Err(AuthorizationError::InvalidTuple(_))
    ));
}

#[tokio::test]
async fn invalid_expressions_and_contexts_are_rejected_at_write_time() {
    let authz = authz();
    for expression in ["count >", "count.exists(c, c > 1)", ".count == 1"] {
        invalid_tuple(
            write(
                &authz,
                &viewer_tuple("1", inline(expression, &[("count", "int")])),
            )
            .await,
        );
    }
    let malformed = [
        BTreeMap::new(),
        BTreeMap::from([("expression".to_owned(), json!(""))]),
        BTreeMap::from([("expression".to_owned(), json!(true))]),
        BTreeMap::from([
            ("expression".to_owned(), json!("true")),
            ("parameters".to_owned(), json!(["x"])),
        ]),
        BTreeMap::from([
            ("expression".to_owned(), json!("true")),
            ("parameters".to_owned(), json!({"x": 1})),
        ]),
        // A stored value would be a grant the request cannot override; the
        // inline form stores none, so any other key is rejected.
        BTreeMap::from([
            ("expression".to_owned(), json!("count > 5")),
            ("count".to_owned(), json!(10)),
        ]),
    ];
    for values in malformed {
        let condition = ConditionContext::new("$expression", values.clone()).unwrap();
        invalid_tuple(write(&authz, &viewer_tuple("1", condition)).await);
    }

    // A named restriction does not accept an inline tuple, nor the reverse.
    let named = FgaAuthz::new(
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with big]\ncondition big(count: int) {\n  count > 5\n}\n",
    )
    .unwrap()
    .with_store(InMemoryRelationshipStore::new(), EvaluationLimits::default());
    invalid_tuple(write(&named, &viewer_tuple("1", inline("true", &[]))).await);
    let named_tuple = viewer_tuple("1", ConditionContext::new("big", BTreeMap::new()).unwrap());
    assert!(matches!(
        write(&authz, &named_tuple).await,
        Err(WriteError::Validation(_))
    ));
}

#[tokio::test]
async fn tuples_differing_only_in_expression_are_distinct() {
    let authz = authz();
    let low = viewer_tuple("1", inline("count > 5", &[("count", "int")]));
    let high = viewer_tuple("1", inline("count > 50", &[("count", "int")]));
    write(&authz, &low).await.unwrap();
    write(&authz, &high).await.unwrap();
    assert!(matches!(
        write(&authz, &low).await,
        Err(WriteError::Store(error)) if error.kind() == StoreErrorKind::Conflict
    ));
    // Declaring an otherwise inferred parameter also makes a distinct tuple.
    let inferred = viewer_tuple("2", inline("size(name) > 0", &[]));
    let declared = viewer_tuple("2", inline("size(name) > 0", &[("name", "string")]));
    write(&authz, &inferred).await.unwrap();
    write(&authz, &declared).await.unwrap();
    authz.delete_tuple(&tenant(), &inferred).await.unwrap();
    assert_eq!(
        authz
            .check(request("2", json!({"name": "x"})))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );

    // Either tuple can grant; each compiles to its own condition.
    assert_eq!(
        authz
            .check(request("1", json!({"count": 10})))
            .await
            .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        authz
            .check(request("1", json!({"count": 1})))
            .await
            .unwrap(),
        AuthorizationDecision::Deny
    );

    // Removing one leaves the other; the batch reuses compiled conditions.
    authz.delete_tuple(&tenant(), &low).await.unwrap();
    let batch = BatchCheckRequest::new(
        tenant(),
        Subject::new("user", "anne").unwrap(),
        [
            (document("1"), RelationName::new("viewer").unwrap()),
            (document("1"), RelationName::new("viewer").unwrap()),
        ],
    )
    .with_context(BTreeMap::from([("count".to_owned(), json!(10))]));
    let results = authz.batch_check(&batch).await.unwrap();
    assert!(
        results
            .iter()
            .all(|result| matches!(result, Ok(AuthorizationDecision::Deny))),
        "{results:?}"
    );
}

#[tokio::test]
async fn stored_inline_contexts_keep_the_element_limit_on_read() {
    let parameters: serde_json::Map<String, Value> = (0..10_001)
        .map(|index| (format!("p{index}"), json!("int")))
        .collect();
    let condition = ConditionContext::new(
        "$expression",
        BTreeMap::from([
            ("expression".to_owned(), json!("true")),
            ("parameters".to_owned(), Value::Object(parameters)),
        ]),
    )
    .unwrap();
    // The in-memory store rejects this context, so serve it from a custom one.
    let authz = FgaAuthz::new(INLINE_MODEL).unwrap().with_store(
        UncheckedTupleStore(viewer_tuple("1", condition)),
        EvaluationLimits::default(),
    );
    assert!(matches!(
        authz.check(request("1", json!({}))).await,
        Err(AuthorizationError::InvalidConditionContext {
            condition,
            source: ConditionContextSource::StoredTuple,
            ..
        }) if condition == "$expression"
    ));
}
