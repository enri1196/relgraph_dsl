use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use relgraph_authz::{
    AuthorizationDecision, BatchCheckRequest, CheckRequest, ConditionContext, ConstructionError,
    EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ObjectRef, RelationName,
    RelationshipTuple, Subject, TenantId, TupleSubject, TypeName,
};
use serde_json::{Value, json};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/authz");
const MODEL: &str = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define direct: [user]\n    define conditional: [user with request_flag]\ncondition request_flag(flag: bool) { flag }\n";
const DIRECT_MODEL: &str =
    "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n";

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURE_DIR).join(name)
}

fn read_json(name: &str) -> Value {
    let path = fixture_path(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read fixture {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("invalid fixture JSON {}: {error}", path.display()))
}

fn values(object: Option<&Value>) -> BTreeMap<String, Value> {
    object
        .and_then(Value::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_object(value: &str) -> ObjectRef {
    let (kind, id) = value
        .split_once(':')
        .unwrap_or_else(|| panic!("fixture object is not type:id: {value}"));
    ObjectRef::new(kind, id).expect("checked-in fixture object should be valid")
}

fn parse_tuple_subject(value: &str) -> TupleSubject {
    let (kind, tail) = value
        .split_once(':')
        .unwrap_or_else(|| panic!("fixture tuple subject is not type:id: {value}"));
    if tail == "*" {
        return TupleSubject::TypedWildcard(
            TypeName::new(kind).expect("checked-in wildcard type should be valid"),
        );
    }
    if let Some((id, relation)) = tail.split_once('#') {
        return TupleSubject::Userset {
            object: ObjectRef::new(kind, id).expect("checked-in userset object should be valid"),
            relation: RelationName::new(relation)
                .expect("checked-in userset relation should be valid"),
        };
    }
    TupleSubject::Direct(
        Subject::new(kind, tail).expect("checked-in direct subject should be valid"),
    )
}

fn build_store(fixture: &Value) -> InMemoryRelationshipStore {
    let store = InMemoryRelationshipStore::new();
    let tenant = TenantId::new(
        fixture["tenant"]
            .as_str()
            .expect("fixture has a tenant namespace"),
    )
    .expect("checked-in fixture tenant should be valid");

    for raw in fixture["tuples"]
        .as_array()
        .expect("fixture tuples are an array")
    {
        let mut tuple = RelationshipTuple::new(
            tenant.clone(),
            parse_object(raw["object"].as_str().expect("tuple object")),
            RelationName::new(raw["relation"].as_str().expect("tuple relation"))
                .expect("checked-in tuple relation should be valid"),
            parse_tuple_subject(raw["user"].as_str().expect("tuple user")),
        );
        if let Some(condition) = raw.get("condition") {
            let context = ConditionContext::new(
                condition["name"].as_str().expect("condition name"),
                values(condition.get("context")),
            )
            .expect("checked-in condition should be valid");
            tuple = tuple.with_condition(context);
        }
        store
            .insert(tuple)
            .expect("checked-in relationship tuple should be insertable");
    }
    store
}

fn check_request(fixture: &Value, raw: &Value) -> CheckRequest {
    let tenant = TenantId::new(
        raw.get("tenant")
            .and_then(Value::as_str)
            .or_else(|| fixture["tenant"].as_str())
            .expect("fixture check has a tenant namespace"),
    )
    .expect("checked-in check tenant should be valid");
    let user = raw["user"].as_str().expect("check user");
    let subject = parse_tuple_subject(user);
    let TupleSubject::Direct(subject) = subject else {
        panic!("check principals must be concrete users: {user}");
    };
    let mut request = CheckRequest::new(
        tenant,
        subject,
        parse_object(raw["object"].as_str().expect("check object")),
        RelationName::new(raw["relation"].as_str().expect("check relation"))
            .expect("checked-in check relation should be valid"),
    );
    if let Some(context) = raw.get("context") {
        request = request.with_context(values(Some(context)));
    }
    request
}

fn model_definition(fixture: &Value, fixture_file: &str) -> String {
    let model_file = fixture["model_file"]
        .as_str()
        .expect("fixture model filename");
    let path = fixture_path(model_file);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read model for {fixture_file}: {error}"))
}

#[tokio::test]
async fn checked_in_openfga_cases_match_the_offline_runtime() {
    for fixture_file in [
        "relationships.json",
        "conditions.json",
        "branch_errors.json",
        "recursion.json",
        "ipaddress.json",
    ] {
        let fixture = read_json(fixture_file);
        assert_eq!(fixture["server"]["version"], "v1.21.0");
        assert_eq!(fixture["server"]["image"], "openfga/openfga:v1.21.0");
        let definition = model_definition(&fixture, fixture_file);
        let local_max_condition_cost = fixture
            .get("local_max_condition_cost")
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or_else(|| EvaluationLimits::default().max_condition_cost());
        let limits = EvaluationLimits::default()
            .with_max_condition_cost(local_max_condition_cost)
            .expect("fixture condition-cost budget should be valid");
        let authz = FgaAuthz::new(&definition)
            .unwrap_or_else(|error| {
                panic!("fixture model {fixture_file} failed construction: {error}")
            })
            .with_store(build_store(&fixture), limits);

        for case in fixture["cases"]
            .as_array()
            .expect("fixture cases are an array")
        {
            let case_id = case["id"].as_str().expect("case id");
            let result = authz.check(check_request(&fixture, &case["request"])).await;
            let expected = &case["expected"];
            if let Some(expected_error) = expected.get("local_error").and_then(Value::as_str) {
                let error = result.unwrap_err();
                assert!(
                    format!("{error:?}").starts_with(expected_error),
                    "{fixture_file}/{case_id}: expected {expected_error}, got {error:?}"
                );
            } else {
                let actual = match result {
                    Ok(AuthorizationDecision::Allow) => "allow",
                    Ok(AuthorizationDecision::Deny) => "deny",
                    Err(error) => {
                        panic!("{fixture_file}/{case_id}: unexpected local error: {error:?}")
                    }
                };
                assert_eq!(
                    actual,
                    expected["local"]
                        .as_str()
                        .expect("local decision expectation"),
                    "{fixture_file}/{case_id}"
                );
            }
        }
    }
}

/// Batches of the checked-in cases, grouped by tenant, subject, and context,
/// must reproduce every individual check result, including its error.
#[tokio::test]
async fn checked_in_cases_match_individual_checks_when_batched() {
    for fixture_file in [
        "relationships.json",
        "conditions.json",
        "branch_errors.json",
        "recursion.json",
        "ipaddress.json",
    ] {
        let fixture = read_json(fixture_file);
        let definition = model_definition(&fixture, fixture_file);
        let local_max_condition_cost = fixture
            .get("local_max_condition_cost")
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or_else(|| EvaluationLimits::default().max_condition_cost());
        let limits = EvaluationLimits::default()
            .with_max_condition_cost(local_max_condition_cost)
            .expect("fixture condition-cost budget should be valid");
        let authz = FgaAuthz::new(&definition)
            .expect("fixture model should construct")
            .with_store(build_store(&fixture), limits);

        let mut groups: BTreeMap<(String, String, String), Vec<CheckRequest>> = BTreeMap::new();
        for case in fixture["cases"]
            .as_array()
            .expect("fixture cases are an array")
        {
            let request = check_request(&fixture, &case["request"]);
            let key = (
                request.tenant().as_str().to_owned(),
                format!("{:?}", request.subject()),
                serde_json::to_string(request.context()).expect("context serializes"),
            );
            groups.entry(key).or_default().push(request);
        }

        for requests in groups.values() {
            for chunk in requests.chunks(EvaluationLimits::DEFAULT_MAX_BATCH_ITEMS) {
                let first = &chunk[0];
                let batch = BatchCheckRequest::new(
                    first.tenant().clone(),
                    first.subject().clone(),
                    chunk
                        .iter()
                        .map(|request| (request.object().clone(), request.relation().clone())),
                )
                .with_context(first.context().clone());
                let results = authz
                    .batch_check(&batch)
                    .await
                    .unwrap_or_else(|error| panic!("{fixture_file}: batch failed: {error:?}"));
                for (request, batched) in chunk.iter().zip(results) {
                    let individual = authz.check(request.clone()).await;
                    assert_eq!(
                        format!("{batched:?}"),
                        format!("{individual:?}"),
                        "{fixture_file}: {:?}#{}",
                        request.object(),
                        request.relation().as_str()
                    );
                }
            }
        }
    }
}

/// Recorded OpenFGA model acceptance for cycle shapes the local runtime rejects.
///
/// Server decisions on accepted models are checked only by the differential
/// runner; locally every listed model must fail construction with exactly the
/// recorded capability diagnostics.
#[test]
fn checked_in_cyclic_models_are_rejected_with_their_recorded_capabilities() {
    let fixture = read_json("recursion_models.json");
    assert_eq!(fixture["server"]["version"], "v1.21.0");
    for entry in fixture["models"].as_array().expect("fixture models") {
        let id = entry["id"].as_str().expect("model id");
        let definition = entry["definition"].as_str().expect("model definition");
        let Err(ConstructionError::UnsupportedCapabilities(diagnostics)) =
            FgaAuthz::new(definition)
        else {
            panic!("{id}: expected unsupported-capability diagnostics");
        };
        let actual = diagnostics
            .iter()
            .map(|diagnostic| format!("{:?}", diagnostic.capability))
            .collect::<Vec<_>>();
        let expected = entry["local_capabilities"]
            .as_array()
            .expect("local capabilities")
            .iter()
            .map(|capability| capability.as_str().expect("capability name").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{id}");
    }
}

fn request(tenant: &str, subject: &str, relation: &str, object: &str) -> CheckRequest {
    CheckRequest::new(
        TenantId::new(tenant).unwrap(),
        Subject::new("user", subject).unwrap(),
        ObjectRef::new("document", object).unwrap(),
        RelationName::new(relation).unwrap(),
    )
}

fn boolean_context(name: &str, value: bool) -> BTreeMap<String, Value> {
    [(name.to_owned(), json!(value))].into_iter().collect()
}

#[tokio::test]
async fn concurrent_checks_isolate_principals_tenants_and_condition_context() {
    let store = InMemoryRelationshipStore::new();
    let tenant_a = TenantId::new("tenant-a").unwrap();
    let direct = RelationshipTuple::new(
        tenant_a.clone(),
        ObjectRef::new("document", "shared").unwrap(),
        RelationName::new("direct").unwrap(),
        Subject::new("user", "alice").unwrap(),
    );
    let conditional = RelationshipTuple::new(
        tenant_a,
        ObjectRef::new("document", "context-shared").unwrap(),
        RelationName::new("conditional").unwrap(),
        Subject::new("user", "alice").unwrap(),
    )
    .with_condition(ConditionContext::new("request_flag", BTreeMap::new()).unwrap());
    store.insert(direct).unwrap();
    store.insert(conditional).unwrap();
    let authz = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    let alice = authz.check(request("tenant-a", "alice", "direct", "shared"));
    let bob = authz.check(request("tenant-a", "bob", "direct", "shared"));
    let other_tenant = authz.check(request("tenant-b", "alice", "direct", "shared"));
    let context_allow = authz.check(
        request("tenant-a", "alice", "conditional", "context-shared")
            .with_context(boolean_context("flag", true)),
    );
    let context_deny = authz.check(
        request("tenant-a", "alice", "conditional", "context-shared")
            .with_context(boolean_context("flag", false)),
    );
    let (alice, bob, other_tenant, context_allow, context_deny) =
        tokio::join!(alice, bob, other_tenant, context_allow, context_deny);

    assert!(matches!(alice, Ok(AuthorizationDecision::Allow)));
    assert!(matches!(bob, Ok(AuthorizationDecision::Deny)));
    assert!(matches!(other_tenant, Ok(AuthorizationDecision::Deny)));
    assert!(matches!(context_allow, Ok(AuthorizationDecision::Allow)));
    assert!(matches!(context_deny, Ok(AuthorizationDecision::Deny)));
}

#[tokio::test]
async fn revocation_is_observed_by_the_next_independent_read_session() {
    let store = InMemoryRelationshipStore::new();
    let tuple = RelationshipTuple::new(
        TenantId::new("tenant-a").unwrap(),
        ObjectRef::new("document", "42").unwrap(),
        RelationName::new("viewer").unwrap(),
        Subject::new("user", "anne").unwrap(),
    );
    store.insert(tuple.clone()).unwrap();
    let authz = FgaAuthz::new(DIRECT_MODEL)
        .unwrap()
        .with_store(store.clone(), EvaluationLimits::default());
    let request = request("tenant-a", "anne", "viewer", "42");

    assert!(matches!(
        authz.check(request.clone()).await,
        Ok(AuthorizationDecision::Allow)
    ));
    assert!(store.remove(&tuple).unwrap());
    assert!(matches!(
        authz.check(request).await,
        Ok(AuthorizationDecision::Deny)
    ));
}
