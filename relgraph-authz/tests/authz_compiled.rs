use relgraph_authz::{FgaAuthz, RelationKey, RequirementExpression};
const COMPILED_MODEL: &str = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype folder\n  relations\n    define reader: [user]\ntype document\n  relations\n    define owner: [user]\n    define editor: [user]\n    define blocked: [user]\n    define parent: [folder]\n    define inherited_owner: owner\n    define parent_viewer: reader from parent\n    define union_viewer: owner or editor\n    define intersection_viewer: owner and editor\n    define difference_viewer: owner but not blocked\n    define group_viewer: [group#member]\n    define wildcard_viewer: [user:*]\n    define nested_direct: [user] or editor\n";
#[test]
fn public_requirements_follow_compiled_nodes_and_resolved_edges() {
    let model = FgaAuthz::new(COMPILED_MODEL).unwrap();
    let cases = [
        ("owner", 0),
        ("inherited_owner", 1),
        ("parent_viewer", 2),
        ("union_viewer", 3),
        ("intersection_viewer", 4),
        ("difference_viewer", 5),
        ("nested_direct", 3),
    ];
    for (relation, expected_shape) in cases {
        let requirements = model.requirements("document", relation).unwrap();
        let expression = requirements
            .relations()
            .get(&RelationKey::new("document", relation))
            .unwrap()
            .expression();
        let matches = match expected_shape {
            0 => matches!(expression, RequirementExpression::DirectAssignment(_)),
            1 => matches!(expression, RequirementExpression::ComputedUserset(_)),
            2 => matches!(expression, RequirementExpression::TupleToUserset { .. }),
            3 => matches!(expression, RequirementExpression::Union(_, _)),
            4 => matches!(expression, RequirementExpression::Intersection(_, _)),
            5 => matches!(expression, RequirementExpression::Difference(_, _)),
            _ => unreachable!(),
        };
        assert!(matches, "wrong compiled requirement shape for {relation}");
    }
    let parent = model.requirements("document", "parent_viewer").unwrap();
    let parent_viewer = parent
        .relations()
        .get(&RelationKey::new("document", "parent_viewer"))
        .unwrap();
    let RequirementExpression::TupleToUserset {
        tupleset,
        computed_usersets,
    } = parent_viewer.expression()
    else {
        panic!("parent_viewer is tuple-to-userset");
    };
    assert_eq!(tupleset, &RelationKey::new("document", "parent"));
    assert_eq!(computed_usersets, &[RelationKey::new("folder", "reader")]);
    assert!(
        parent
            .relations()
            .contains_key(&RelationKey::new("folder", "reader"))
    );
    let group = model.requirements("document", "group_viewer").unwrap();
    let RequirementExpression::DirectAssignment(assignments) = group
        .relations()
        .get(&RelationKey::new("document", "group_viewer"))
        .unwrap()
        .expression()
    else {
        panic!("group_viewer is a direct assignment");
    };
    assert_eq!(assignments[0].subject_type(), "group");
    assert_eq!(assignments[0].subject_relation(), Some("member"));
    assert!(
        group
            .relations()
            .contains_key(&RelationKey::new("group", "member"))
    );
    let wildcard = model.requirements("document", "wildcard_viewer").unwrap();
    let RequirementExpression::DirectAssignment(assignments) = wildcard
        .relations()
        .get(&RelationKey::new("document", "wildcard_viewer"))
        .unwrap()
        .expression()
    else {
        panic!("wildcard_viewer is a direct assignment");
    };
    assert!(assignments[0].is_wildcard());
}

#[test]
fn requirements_report_tuple_targets_without_the_computed_relation() {
    let definition = "model\nschema 1.1\ntype user\ntype folder\n  relations\n    define reader: [user]\ntype team\ntype document\n  relations\n    define parent: [folder, team]\n    define reader: reader from parent\n";
    let model = FgaAuthz::new(definition).unwrap();
    let error = model.requirements("document", "reader").unwrap_err();
    assert!(matches!(
        error,
        relgraph_authz::PolicyError::UnknownRelation { object_type, relation }
            if object_type == "team" && relation == "reader"
    ));
}
