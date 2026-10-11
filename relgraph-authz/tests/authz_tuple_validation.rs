use std::collections::BTreeMap;

use relgraph_authz::{
    AuthorizationError, ConditionContext, ConditionContextSource, FgaAuthz, ObjectRef,
    RelationName, RelationshipTuple, Subject, TenantId, TupleSubject, TypeName,
};
use serde_json::json;

const MODEL: &str = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype document\n  relations\n    define owner: [user]\n    define editor: [user, group#member, user:*]\n    define viewer: [user with recent] or editor\n    define can_view: viewer\ncondition recent(age: int) { age < 30 }\n";

fn tuple(relation: &str, subject: impl Into<TupleSubject>) -> RelationshipTuple {
    RelationshipTuple::new(
        TenantId::new("tenant-a").unwrap(),
        ObjectRef::new("document", "42").unwrap(),
        RelationName::new(relation).unwrap(),
        subject,
    )
}

fn user(id: &str) -> Subject {
    Subject::new("user", id).unwrap()
}

fn recent(values: BTreeMap<String, serde_json::Value>) -> ConditionContext {
    ConditionContext::new("recent", values).unwrap()
}

#[test]
fn tuples_matching_declared_targets_are_valid() {
    let model = FgaAuthz::new(MODEL).unwrap();
    let group_members = TupleSubject::Userset {
        object: ObjectRef::new("group", "eng").unwrap(),
        relation: RelationName::new("member").unwrap(),
    };
    let everyone = TupleSubject::TypedWildcard(TypeName::new("user").unwrap());
    let conditioned = tuple("viewer", user("anne"))
        .with_condition(recent(BTreeMap::from([("age".to_owned(), json!(3))])));

    for valid in [
        tuple("owner", user("anne")),
        tuple("editor", group_members),
        tuple("editor", everyone),
        // The request may supply parameters omitted from the stored context.
        tuple("viewer", user("anne")).with_condition(recent(BTreeMap::new())),
        conditioned,
    ] {
        assert!(model.validate_tuple(&valid).is_ok(), "{valid:?}");
    }
}

#[test]
fn tuples_outside_the_model_are_rejected() {
    let model = FgaAuthz::new(MODEL).unwrap();
    let unknown_type = RelationshipTuple::new(
        TenantId::new("tenant-a").unwrap(),
        ObjectRef::new("folder", "1").unwrap(),
        RelationName::new("owner").unwrap(),
        user("anne"),
    );
    assert!(matches!(
        model.validate_tuple(&unknown_type),
        Err(AuthorizationError::UnknownObjectType(object_type)) if object_type == "folder"
    ));
    assert!(matches!(
        model.validate_tuple(&tuple("reader", user("anne"))),
        Err(AuthorizationError::UnknownRelation { relation, .. }) if relation == "reader"
    ));

    for invalid in [
        // Computed relations have no tuples of their own.
        tuple("can_view", user("anne")),
        // Subject type, userset relation, and wildcard must be declared targets.
        tuple("owner", Subject::new("group", "eng").unwrap()),
        tuple(
            "owner",
            TupleSubject::Userset {
                object: ObjectRef::new("group", "eng").unwrap(),
                relation: RelationName::new("member").unwrap(),
            },
        ),
        tuple(
            "owner",
            TupleSubject::TypedWildcard(TypeName::new("user").unwrap()),
        ),
        // The condition must match the declared target exactly.
        tuple("viewer", user("anne")),
        tuple("owner", user("anne")).with_condition(recent(BTreeMap::new())),
    ] {
        assert!(
            matches!(
                model.validate_tuple(&invalid),
                Err(AuthorizationError::InvalidTuple(_))
            ),
            "{invalid:?}"
        );
    }
}

#[test]
fn stored_condition_context_must_match_parameter_types() {
    let model = FgaAuthz::new(MODEL).unwrap();
    let wrong_type = tuple("viewer", user("anne"))
        .with_condition(recent(BTreeMap::from([("age".to_owned(), json!("old"))])));
    assert!(matches!(
        model.validate_tuple(&wrong_type),
        Err(AuthorizationError::InvalidConditionContext {
            parameter,
            source: ConditionContextSource::StoredTuple,
            ..
        }) if parameter == "age"
    ));

    let undeclared = tuple("viewer", user("anne"))
        .with_condition(recent(BTreeMap::from([("region".to_owned(), json!("eu"))])));
    assert!(matches!(
        model.validate_tuple(&undeclared),
        Err(AuthorizationError::UndeclaredConditionContext { parameter, .. }) if parameter == "region"
    ));
}
