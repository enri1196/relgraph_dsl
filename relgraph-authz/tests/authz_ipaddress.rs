//! OpenFGA's `ipaddress` CEL extension through the public API.
//!
//! Decisions shared with the pinned server are in the `ipaddress.json`
//! differential fixture; these tests cover construction, tuple validation,
//! batches and the documented local differences.

use std::collections::BTreeMap;

use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, CheckRequest, ConditionContext,
    ConditionContextSource, ConstructionError, EvaluationLimits, FgaAuthz,
    InMemoryRelationshipStore, ObjectRef, RelationName, RelationshipTuple, Subject, TenantId,
    WriteError,
};
use serde_json::{Value, json};

const MODEL: &str = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with in_network]\n    define pinned: [user with pinned_address]\ncondition in_network(user_ip: ipaddress, cidr: string) {\n  user_ip.in_cidr(cidr)\n}\ncondition pinned_address(user_ip: ipaddress, granted: list<ipaddress>) {\n  user_ip in granted\n}\n";

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn condition_model(condition: &str) -> String {
    format!(
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with probe]\n{condition}\n"
    )
}

fn values(entries: impl IntoIterator<Item = (&'static str, Value)>) -> BTreeMap<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn tuple(relation: &str, condition: &str, context: BTreeMap<String, Value>) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant(),
        ObjectRef::new("document", "1").unwrap(),
        RelationName::new(relation).unwrap(),
        Subject::new("user", "anne").unwrap(),
    )
    .with_condition(ConditionContext::new(condition, context).unwrap())
}

fn request(relation: &str, context: BTreeMap<String, Value>) -> CheckRequest {
    CheckRequest::new(
        tenant(),
        Subject::new("user", "anne").unwrap(),
        ObjectRef::new("document", "1").unwrap(),
        RelationName::new(relation).unwrap(),
    )
    .with_context(context)
}

#[test]
fn ipaddress_parameters_and_extension_functions_compile() {
    for condition in [
        "condition probe(user_ip: ipaddress) { user_ip.in_cidr(\"10.0.0.0/8\") }",
        "condition probe(user_ip: ipaddress) { user_ip == ipaddress(\"10.0.0.1\") }",
        "condition probe(user_ip: ipaddress) { user_ip != ipaddress(\"10.0.0.1\") }",
        "condition probe(text: string) { ipaddress(text).in_cidr(\"10.0.0.0/8\") }",
        "condition probe(user_ip: ipaddress, allowed: list<ipaddress>) { user_ip in allowed }",
        "condition probe(sites: map<ipaddress>) { sites[\"office\"].in_cidr(\"10.0.0.0/8\") }",
    ] {
        if let Err(error) = FgaAuthz::new(&condition_model(condition)) {
            panic!("{condition}: {error}");
        }
    }
}

#[test]
fn ipaddress_misuse_fails_construction() {
    for condition in [
        // Wrong argument type for the OpenFGA overload.
        "condition probe(user_ip: ipaddress) { user_ip.in_cidr(8) }",
        // `in_cidr` is a member function only.
        "condition probe(user_ip: ipaddress) { in_cidr(user_ip, \"10.0.0.0/8\") }",
        // No string conversion, ordering, size or fields on the opaque type.
        "condition probe(user_ip: ipaddress) { string(user_ip) == \"10.0.0.1\" }",
        "condition probe(user_ip: ipaddress) { user_ip < ipaddress(\"10.0.0.2\") }",
        "condition probe(user_ip: ipaddress) { size(user_ip) > 0 }",
        "condition probe(user_ip: ipaddress) { user_ip.octets == 4 }",
        // The condition must still compile to bool.
        "condition probe(text: string) { ipaddress(text) }",
    ] {
        assert!(
            matches!(
                FgaAuthz::new(&condition_model(condition)),
                Err(ConstructionError::ConditionCompilation { .. })
            ),
            "{condition}"
        );
    }
}

#[tokio::test]
async fn stored_ipaddress_context_is_validated_on_write_and_keeps_precedence() {
    let authz = FgaAuthz::new(MODEL).unwrap().with_store(
        InMemoryRelationshipStore::new(),
        EvaluationLimits::default(),
    );

    // A malformed stored address is rejected before it reaches the store.
    let malformed = tuple(
        "pinned",
        "pinned_address",
        values([("granted", json!(["203.0.113.7", "203.0.113.300"]))]),
    );
    assert!(matches!(
        authz.validate_tuple(&malformed),
        Err(AuthorizationError::InvalidConditionContext {
            source: ConditionContextSource::StoredTuple,
            ..
        })
    ));
    assert!(matches!(
        authz.write_tuple(&tenant(), &malformed).await,
        Err(WriteError::Validation(
            AuthorizationError::InvalidConditionContext { .. }
        ))
    ));

    authz
        .write_tuple(
            &tenant(),
            &tuple(
                "pinned",
                "pinned_address",
                values([("granted", json!(["::ffff:203.0.113.7"]))]),
            ),
        )
        .await
        .unwrap();
    // The stored list wins over a request list naming the request address.
    assert_eq!(
        authz
            .check(request(
                "pinned",
                values([
                    ("user_ip", json!("203.0.113.8")),
                    ("granted", json!(["203.0.113.8"])),
                ]),
            ))
            .await
            .ok(),
        Some(AuthorizationDecision::Deny)
    );
    // The stored IPv4-mapped address equals its unmapped form.
    assert_eq!(
        authz
            .check(request(
                "pinned",
                values([("user_ip", json!("203.0.113.7"))])
            ))
            .await
            .ok(),
        Some(AuthorizationDecision::Allow)
    );
}

#[tokio::test]
async fn request_ipaddress_errors_are_errors_not_denials() {
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple("viewer", "in_network", BTreeMap::new()))
        .unwrap();
    let authz = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    for (user_ip, cidr) in [
        (json!("192.0.2.300"), json!("192.0.2.0/24")),
        (json!(3_221_225_985_u64), json!("192.0.2.0/24")),
        // OpenFGA parses zoned IPv6 addresses; Relgraph rejects them.
        (json!("fe80::1%eth0"), json!("fe80::/10")),
    ] {
        assert!(
            matches!(
                authz
                    .check(request(
                        "viewer",
                        values([("user_ip", user_ip.clone()), ("cidr", cidr)]),
                    ))
                    .await,
                Err(AuthorizationError::InvalidConditionContext {
                    source: ConditionContextSource::Request,
                    ..
                })
            ),
            "{user_ip}"
        );
    }

    for cidr in ["192.0.2.0/33", "192.0.2.0/+8", "192.0.2.0/08", "192.0.2.0"] {
        assert!(
            matches!(
                authz
                    .check(request(
                        "viewer",
                        values([("user_ip", json!("192.0.2.1")), ("cidr", json!(cidr))]),
                    ))
                    .await,
                Err(AuthorizationError::ConditionEvaluationFailed { .. })
            ),
            "{cidr}"
        );
    }

    assert!(matches!(
        authz
            .check(request("viewer", values([("cidr", json!("192.0.2.0/24"))])))
            .await,
        Err(AuthorizationError::MissingConditionContext { .. })
    ));
}

#[tokio::test]
async fn batched_ipaddress_checks_match_individual_checks() {
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple(
            "viewer",
            "in_network",
            values([("cidr", json!("2001:db8::/32"))]),
        ))
        .unwrap();
    store
        .insert(tuple(
            "pinned",
            "pinned_address",
            values([("granted", json!(["192.0.2.1", "2001:db8::7"]))]),
        ))
        .unwrap();
    let authz = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    for user_ip in [
        "2001:db8::7",
        "2001:db9::7",
        "192.0.2.1",
        "::ffff:192.0.2.1",
    ] {
        let context = values([("user_ip", json!(user_ip))]);
        let batch = BatchCheckRequest::new(
            tenant(),
            Subject::new("user", "anne").unwrap(),
            ["viewer", "pinned"].map(|relation| {
                (
                    ObjectRef::new("document", "1").unwrap(),
                    RelationName::new(relation).unwrap(),
                )
            }),
        )
        .with_context(context.clone());
        let batched = authz.batch_check(&batch).await.unwrap();
        for (relation, batched) in ["viewer", "pinned"].into_iter().zip(batched) {
            let individual = authz.check(request(relation, context.clone())).await;
            assert_eq!(
                format!("{batched:?}"),
                format!("{individual:?}"),
                "{user_ip} {relation}"
            );
        }
    }
    assert_eq!(
        authz
            .check(request(
                "viewer",
                values([("user_ip", json!("2001:db8::7"))])
            ))
            .await
            .ok(),
        Some(AuthorizationDecision::Allow)
    );
    assert_eq!(
        authz
            .check(request(
                "pinned",
                values([("user_ip", json!("::ffff:192.0.2.1"))])
            ))
            .await
            .ok(),
        Some(AuthorizationDecision::Allow)
    );
}

/// The pinned `cel-core` checker accepts equality between different types,
/// which OpenFGA v1.21.0 rejects when the model is written (`found no matching
/// overload for '_==_' applied to '(IPAddress, string)'`). Locally an address
/// never equals a string. This pins the documented difference.
#[tokio::test]
async fn mixed_type_address_equality_compiles_and_is_false() {
    let definition =
        condition_model("condition probe(user_ip: ipaddress) { user_ip == \"192.0.2.1\" }");
    let store = InMemoryRelationshipStore::new();
    store
        .insert(tuple("viewer", "probe", BTreeMap::new()))
        .unwrap();
    let authz = FgaAuthz::new(&definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());
    assert_eq!(
        authz
            .check(request("viewer", values([("user_ip", json!("192.0.2.1"))])))
            .await
            .ok(),
        Some(AuthorizationDecision::Deny)
    );
}
