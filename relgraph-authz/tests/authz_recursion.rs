//! Least-fixed-point evaluation of recursive models.

#[allow(dead_code)]
mod common;

use common::{block_on, request};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, ConditionContext, ConstructionError,
    EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ObjectRef, RelationName,
    RelationshipTuple, RuntimeCapability, Subject, TenantId, TupleSubject,
};
use serde_json::json;
use std::collections::BTreeMap;

const GROUPS: &str = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user, group#member]\n";

fn insert(
    store: &InMemoryRelationshipStore,
    object_type: &str,
    object_id: &str,
    relation: &str,
    subject: impl Into<TupleSubject>,
) {
    store
        .insert(RelationshipTuple::new(
            TenantId::new("tenant-a").unwrap(),
            ObjectRef::new(object_type, object_id).unwrap(),
            RelationName::new(relation).unwrap(),
            subject,
        ))
        .unwrap();
}

fn user(id: &str) -> Subject {
    Subject::new("user", id).unwrap()
}

fn userset(object_type: &str, object_id: &str, relation: &str) -> TupleSubject {
    TupleSubject::Userset {
        object: ObjectRef::new(object_type, object_id).unwrap(),
        relation: RelationName::new(relation).unwrap(),
    }
}

fn decide(
    authz: &FgaAuthz<relgraph_authz::Bound<InMemoryRelationshipStore>>,
    subject: &str,
    object_type: &str,
    object_id: &str,
    relation: &str,
) -> Result<AuthorizationDecision, AuthorizationError> {
    block_on(authz.check(request(
        "tenant-a",
        "user",
        subject,
        object_type,
        object_id,
        relation,
    )))
}

#[test]
fn nested_groups_and_data_cycles_resolve_without_errors() {
    let store = InMemoryRelationshipStore::new();
    insert(&store, "group", "eng", "member", user("anne"));
    insert(
        &store,
        "group",
        "all",
        "member",
        userset("group", "eng", "member"),
    );
    insert(
        &store,
        "group",
        "cyc-a",
        "member",
        userset("group", "cyc-b", "member"),
    );
    insert(
        &store,
        "group",
        "cyc-b",
        "member",
        userset("group", "cyc-a", "member"),
    );
    insert(&store, "group", "cyc-b", "member", user("bob"));
    insert(
        &store,
        "group",
        "self",
        "member",
        userset("group", "self", "member"),
    );
    let authz = FgaAuthz::new(GROUPS)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    use AuthorizationDecision::{Allow, Deny};
    assert_eq!(
        decide(&authz, "anne", "group", "all", "member").unwrap(),
        Allow
    );
    assert_eq!(
        decide(&authz, "zoe", "group", "all", "member").unwrap(),
        Deny
    );
    assert_eq!(
        decide(&authz, "bob", "group", "cyc-a", "member").unwrap(),
        Allow
    );
    assert_eq!(
        decide(&authz, "zoe", "group", "cyc-a", "member").unwrap(),
        Deny
    );
    assert_eq!(
        decide(&authz, "zoe", "group", "self", "member").unwrap(),
        Deny
    );
}

#[test]
fn same_type_hierarchies_and_intersections_recurse() {
    let definition = "model\nschema 1.1\ntype user\ntype folder\n  relations\n    define parent: [folder]\n    define active: [user]\n    define viewer: [user] or viewer from parent\n    define active_viewer: ([user] or active_viewer from parent) and active\n";
    let store = InMemoryRelationshipStore::new();
    insert(&store, "folder", "root", "viewer", user("anne"));
    insert(&store, "folder", "root", "active_viewer", user("anne"));
    insert(&store, "folder", "root", "active", user("anne"));
    insert(&store, "folder", "root", "active_viewer", user("dave"));
    let parent = |child: &str, parent: &str| {
        insert(
            &store,
            "folder",
            child,
            "parent",
            Subject::new("folder", parent).unwrap(),
        );
    };
    parent("mid", "root");
    parent("leaf", "mid");
    parent("loop-a", "loop-b");
    parent("loop-b", "loop-a");
    insert(&store, "folder", "leaf", "active", user("anne"));
    insert(&store, "folder", "mid", "active", user("anne"));
    insert(&store, "folder", "leaf", "active", user("dave"));
    insert(&store, "folder", "mid", "active", user("dave"));
    insert(&store, "folder", "loop-b", "viewer", user("carol"));
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    use AuthorizationDecision::{Allow, Deny};
    assert_eq!(
        decide(&authz, "anne", "folder", "leaf", "viewer").unwrap(),
        Allow
    );
    assert_eq!(
        decide(&authz, "zoe", "folder", "leaf", "viewer").unwrap(),
        Deny
    );
    assert_eq!(
        decide(&authz, "carol", "folder", "loop-a", "viewer").unwrap(),
        Allow
    );
    assert_eq!(
        decide(&authz, "zoe", "folder", "loop-a", "viewer").unwrap(),
        Deny
    );
    assert_eq!(
        decide(&authz, "anne", "folder", "leaf", "active_viewer").unwrap(),
        Allow
    );
    // Dave is active below the root but not on it, so the root grant is cut.
    assert_eq!(
        decide(&authz, "dave", "folder", "leaf", "active_viewer").unwrap(),
        Deny
    );
}

#[test]
fn provisional_denials_inside_an_open_cycle_are_not_memoized() {
    // `a` and `b` on one node depend on each other through userset tuples.
    // Evaluating `both` visits `b` while `a` is in flight, so `b` first sees a
    // provisional `false` for `a`. `a` then allows through `x`; `b` must be
    // evaluated again rather than reuse its provisional denial.
    let definition = "model\nschema 1.1\ntype user\ntype node\n  relations\n    define x: [user]\n    define a: [node#b] or x\n    define b: [node#a]\n    define both: a and b\n";
    let store = InMemoryRelationshipStore::new();
    insert(&store, "node", "n", "a", userset("node", "n", "b"));
    insert(&store, "node", "n", "b", userset("node", "n", "a"));
    insert(&store, "node", "n", "x", user("anne"));
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    use AuthorizationDecision::{Allow, Deny};
    for relation in ["a", "b", "both"] {
        assert_eq!(
            decide(&authz, "anne", "node", "n", relation).unwrap(),
            Allow,
            "{relation}"
        );
        assert_eq!(
            decide(&authz, "zoe", "node", "n", relation).unwrap(),
            Deny,
            "{relation}"
        );
    }
}

#[test]
fn recursion_through_conditioned_tuples_evaluates_each_condition() {
    let definition = "model\nschema 1.1\ntype user\ntype circle\n  relations\n    define member: [user with active, circle#member]\ncondition active(enabled: bool) {\n  enabled\n}\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(
            RelationshipTuple::new(
                TenantId::new("tenant-a").unwrap(),
                ObjectRef::new("circle", "inner").unwrap(),
                RelationName::new("member").unwrap(),
                user("anne"),
            )
            .with_condition(ConditionContext::new("active", BTreeMap::new()).unwrap()),
        )
        .unwrap();
    insert(
        &store,
        "circle",
        "outer",
        "member",
        userset("circle", "inner", "member"),
    );
    insert(
        &store,
        "circle",
        "inner",
        "member",
        userset("circle", "outer", "member"),
    );
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());
    let check = |subject: &str, enabled: Option<bool>| {
        let mut request = request("tenant-a", "user", subject, "circle", "outer", "member");
        if let Some(enabled) = enabled {
            request = request.with_context([("enabled".to_owned(), json!(enabled))].into());
        }
        block_on(authz.check(request))
    };

    use AuthorizationDecision::{Allow, Deny};
    assert_eq!(check("anne", Some(true)).unwrap(), Allow);
    assert_eq!(check("anne", Some(false)).unwrap(), Deny);
    assert!(matches!(
        check("anne", None),
        Err(AuthorizationError::MissingConditionContext { .. })
    ));
    assert_eq!(check("zoe", Some(true)).unwrap(), Deny);
}

#[test]
fn dense_group_cycles_resolve_once_per_check() {
    // Every group contains every other group's members (24 groups, 552
    // userset tuples), and the document grants all of them. The first group
    // visited roots the cycle; resolving it memoizes every member's denial, so
    // the remaining document tuples need no further store reads.
    let definition = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user, group#member]\ntype document\n  relations\n    define viewer: [group#member]\n";
    let store = InMemoryRelationshipStore::new();
    let groups = (0..24).map(|index| format!("g{index}")).collect::<Vec<_>>();
    for group in &groups {
        insert(
            &store,
            "document",
            "d",
            "viewer",
            userset("group", group, "member"),
        );
        for other in groups.iter().filter(|other| *other != group) {
            insert(
                &store,
                "group",
                group,
                "member",
                userset("group", other, "member"),
            );
        }
    }
    insert(&store, "group", "g23", "member", user("anne"));
    let limits = EvaluationLimits::default()
        .with_max_store_calls(groups.len() + 1)
        .unwrap();
    let authz = FgaAuthz::new(definition).unwrap().with_store(store, limits);

    assert_eq!(
        decide(&authz, "zoe", "document", "d", "viewer").unwrap(),
        AuthorizationDecision::Deny
    );
    assert_eq!(
        decide(&authz, "anne", "document", "d", "viewer").unwrap(),
        AuthorizationDecision::Allow
    );
}

#[test]
fn wide_nested_groups_stay_within_default_limits() {
    // A root with 500 child groups that each include the root back.
    let store = InMemoryRelationshipStore::new();
    for index in 0..500 {
        let child = format!("child-{index}");
        insert(
            &store,
            "group",
            "root",
            "member",
            userset("group", &child, "member"),
        );
        insert(
            &store,
            "group",
            &child,
            "member",
            userset("group", "root", "member"),
        );
        insert(
            &store,
            "group",
            &child,
            "member",
            user(&format!("user-{index}")),
        );
    }
    let authz = FgaAuthz::new(GROUPS)
        .unwrap()
        .with_store(store, EvaluationLimits::default());

    assert_eq!(
        decide(&authz, "user-499", "group", "root", "member").unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        decide(&authz, "user-0", "group", "child-499", "member").unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        decide(&authz, "zoe", "group", "child-0", "member").unwrap(),
        AuthorizationDecision::Deny
    );
}

/// The least-fixed-point rules above are sound only because construction
/// rejects cycles through a `but not` subtracted operand (decision S2). These
/// are the models of the skipped upstream stages
/// `{false,true}_butnot_cycle_return_false::0` and
/// `list_objects_expands_wildcard_tuple::2`.
#[test]
fn upstream_negation_cycle_models_are_rejected_at_construction() {
    let butnot_cycle = concat!(
        "model\nschema 1.1\ntype user\ntype document\n  relations\n",
        "    define restricted: [user, document#viewer]\n",
        "    define viewer: [user] but not restricted\n",
    );
    // The cycle `group#member -> group#blocked -> group#member` shares its
    // component with positive tuple-to-userset cycles and has an intersection
    // as its base operand.
    let wildcard_complex = concat!(
        "model\nschema 1.1\ntype user\ntype folder\n  relations\n",
        "    define parent: [folder]\n",
        "    define owner: [group]\n",
        "    define folder_reader: [user, group#member] or folder_reader from owner or folder_reader from parent\n",
        "    define blocked: [user, user:*, group#member] or nblocked from parent\n",
        "    define unblocked: [user, group#member]\n",
        "    define nblocked: blocked but not unblocked\n",
        "    define allowed: [user, user:*, group#member] or allowed from parent\n",
        "    define super_allowed: [user, group#member] or super_allowed from parent\n",
        "    define reader: folder_reader and allowed and super_allowed\n",
        "    define can_read: reader but not nblocked\n",
        "type group\n  relations\n",
        "    define parent: [group]\n",
        "    define allowed: [user, group#member] or allowed from parent\n",
        "    define super_allowed: [user, group#super_allowed]\n",
        "    define blocked: [user, group#member] or blocked from parent\n",
        "    define og_member: [user] or member from parent\n",
        "    define allowed_member: og_member and allowed and super_allowed\n",
        "    define member: allowed_member but not blocked\n",
        "    define folder_reader: [group#member] or folder_reader from parent\n",
    );

    for (definition, object_type, relation) in [
        (butnot_cycle, "document", "viewer"),
        (wildcard_complex, "group", "member"),
    ] {
        let Err(ConstructionError::UnsupportedCapabilities(diagnostics)) =
            FgaAuthz::new(definition)
        else {
            panic!("expected runtime capability diagnostics for {definition}");
        };
        let rejected = diagnostics
            .iter()
            .map(|diagnostic| {
                let location = diagnostic.relation.as_ref().expect("diagnostic relation");
                (
                    diagnostic.capability.clone(),
                    location.object_type.as_str(),
                    location.relation.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rejected,
            [(
                RuntimeCapability::RecursiveDifference,
                object_type,
                relation
            )],
            "{definition}"
        );
    }
}
