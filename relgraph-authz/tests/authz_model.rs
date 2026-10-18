use relgraph_authz::{ConstructionError, FgaAuthz, RuntimeCapability};
use relgraph_dsl::{ParseErrorCode, ValidationIssue};

const DIRECT_MODEL: &str =
    "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n";

#[test]
fn constructs_a_valid_unconditional_direct_assignment_model() {
    let model = FgaAuthz::new(DIRECT_MODEL).unwrap();

    assert_eq!(model.schema().type_definitions.len(), 2);
    assert_eq!(
        model.schema().type_definitions[1].relations[0].name,
        "viewer"
    );
}

#[test]
fn preserves_parser_diagnostics_for_malformed_syntax() {
    let error = FgaAuthz::new("model\nschema 1.1\ntype").unwrap_err();

    let ConstructionError::Parse(error) = error else {
        panic!("expected parser diagnostic");
    };
    assert_eq!(error.code, ParseErrorCode::UnexpectedEof);
    assert_eq!(error.span.start, error.span.end);
}

#[test]
fn preserves_semantic_diagnostics_for_unresolved_references() {
    let definition =
        "model\nschema 1.1\ntype document\n  relations\n    define viewer: [missing]\n";
    let error = FgaAuthz::new(definition).unwrap_err();

    let ConstructionError::Validation(errors) = error else {
        panic!("expected semantic validation diagnostics");
    };
    assert!(
        errors
            .iter()
            .any(|error| error.issue == ValidationIssue::UnknownType)
    );
}

#[test]
fn accepts_every_supported_relation_expression() {
    let cases = [
        "owner",
        "editor from parent",
        "owner or editor",
        "owner and editor",
        "owner but not editor",
    ];

    for expression in cases {
        let definition = format!(
            "model\nschema 1.1\ntype user\ntype folder\n  relations\n    define editor: [user]\ntype document\n  relations\n    define owner: [user]\n    define editor: [user]\n    define parent: [folder]\n    define viewer: {expression}\n"
        );
        let _model = FgaAuthz::new(&definition).unwrap_or_else(|error| {
            panic!("supported expression {expression} was rejected: {error}")
        });
    }
}

#[test]
fn accepts_recursive_dependencies_through_monotone_operators() {
    let cases = [
        // Nested groups through a self-referencing userset restriction.
        "type group\n  relations\n    define member: [user, group#member]\n",
        // A same-type hierarchy through tuple-to-userset.
        "type folder\n  relations\n    define parent: [folder]\n    define viewer: [user] or viewer from parent\n",
        // Mutual recursion across two types.
        "type org\n  relations\n    define member: [user, team#member]\ntype team\n  relations\n    define member: [user, org#member]\n",
        // Recursion under intersection.
        "type project\n  relations\n    define parent: [project]\n    define active: [user]\n    define viewer: ([user] or viewer from parent) and active\n",
        // Recursion through the base operand of a difference.
        "type folder\n  relations\n    define parent: [folder]\n    define blocked: [user]\n    define viewer: ([user] or viewer from parent) but not blocked\n",
        // A same-object computed userset inside a cycle that hops objects.
        "type node\n  relations\n    define x: [user]\n    define a: [node#b] or x\n    define b: [node#a]\n    define both: a and b\n",
    ];
    for types in cases {
        let definition = format!("model\nschema 1.1\ntype user\n{types}");
        let _model = FgaAuthz::new(&definition)
            .unwrap_or_else(|error| panic!("recursive model was rejected: {error}\n{definition}"));
    }

    let conditional = "model\nschema 1.1\ntype user\ntype circle\n  relations\n    define member: [user with active, circle#member]\ncondition active(enabled: bool) {\n  enabled\n}\n";
    let _model = FgaAuthz::new(conditional).unwrap();
}

/// Asserts one diagnostic of `capability` on `relation`, spanning its definition.
fn assert_cycle_rejected(
    definition: &str,
    capability: RuntimeCapability,
    object_type: &str,
    relation: &str,
    path: &str,
) {
    let error = FgaAuthz::new(definition).unwrap_err();
    let ConstructionError::UnsupportedCapabilities(diagnostics) = error else {
        panic!("expected runtime capability diagnostics for {definition}");
    };
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    let diagnostic = &diagnostics[0];
    assert_eq!(diagnostic.capability, capability);
    let location = diagnostic.relation.as_ref().expect("diagnostic relation");
    assert_eq!(
        (location.object_type.as_str(), location.relation.as_str()),
        (object_type, relation)
    );
    let span = diagnostic.span.as_ref().expect("diagnostic span");
    assert!(
        definition[span.start..span.end].starts_with(&format!("define {relation}:")),
        "span {span:?} does not cover {relation} in {definition}"
    );
    assert!(
        diagnostic.message.ends_with(path),
        "unexpected message: {}",
        diagnostic.message
    );
}

#[test]
fn rejects_relation_cycles_that_stay_on_one_object() {
    // A cycle without any entry point never reaches runtime construction:
    // DSL validation rejects it, as OpenFGA does.
    let error = FgaAuthz::new(
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define first: second\n    define second: first\n",
    )
    .unwrap_err();
    let ConstructionError::Validation(errors) = error else {
        panic!("expected validation errors, got {error:?}");
    };
    assert!(
        errors
            .iter()
            .all(|error| error.issue == ValidationIssue::NoEntryPoint),
        "{errors:?}"
    );
    assert_eq!(errors.len(), 2);

    assert_cycle_rejected(
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define first: [user] or second\n    define second: first\n",
        RuntimeCapability::SameObjectRelationCycle,
        "document",
        "first",
        "document#first -> document#second -> document#first",
    );
    assert_cycle_rejected(
        "model\nschema 1.1\ntype user\ntype pair\n  relations\n    define x: [user]\n    define y: [user]\n    define a: b or x\n    define b: a or y\n",
        RuntimeCapability::SameObjectRelationCycle,
        "pair",
        "a",
        "pair#a -> pair#b -> pair#a",
    );
    assert_cycle_rejected(
        "model\nschema 1.1\ntype user\ntype doc\n  relations\n    define a: [user] and b\n    define b: [user] or a\n",
        RuntimeCapability::SameObjectRelationCycle,
        "doc",
        "a",
        "doc#a -> doc#b -> doc#a",
    );
    assert_cycle_rejected(
        "model\nschema 1.1\ntype user\ntype doc\n  relations\n    define viewer: [user] or viewer\n",
        RuntimeCapability::SameObjectRelationCycle,
        "doc",
        "viewer",
        "doc#viewer -> doc#viewer",
    );
}

#[test]
fn rejects_relation_cycles_through_a_subtracted_operand() {
    assert_cycle_rejected(
        "model\nschema 1.1\ntype user\ntype folder\n  relations\n    define parent: [folder]\n    define blocked: [user] or viewer from parent\n    define viewer: [user] but not blocked\n",
        RuntimeCapability::RecursiveDifference,
        "folder",
        "viewer",
        "folder#viewer -> folder#blocked -> folder#viewer",
    );
    assert_cycle_rejected(
        "model\nschema 1.1\ntype user\ntype group\n  relations\n    define banned: [user, group#member]\n    define member: [user] but not banned\n",
        RuntimeCapability::RecursiveDifference,
        "group",
        "member",
        "group#member -> group#banned -> group#member",
    );

    // A cycle through the subtracted operand that also stays on one object
    // reports both shapes.
    let definition = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define a: [user] but not b\n    define b: [user] or a\n";
    let ConstructionError::UnsupportedCapabilities(diagnostics) =
        FgaAuthz::new(definition).unwrap_err()
    else {
        panic!("expected runtime capability diagnostics");
    };
    let capabilities = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.capability.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        capabilities,
        [
            RuntimeCapability::RecursiveDifference,
            RuntimeCapability::SameObjectRelationCycle
        ]
    );
}

#[test]
fn accepts_typed_wildcards_and_compiled_conditions() {
    let wildcard =
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user:*]\n";
    let _model = FgaAuthz::new(wildcard).unwrap();

    let conditional = "model\nschema 1.2\ntype user\ntype document\n  relations\n    define viewer: [user with active]\ncondition active(now: timestamp) { now < timestamp(\"2030-01-01T00:00:00Z\") }\n";
    let _model = FgaAuthz::new(conditional).unwrap();
}

#[test]
fn accepts_userset_restrictions_for_graph_traversal() {
    let definition = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype document\n  relations\n    define viewer: [group#member]\n";
    let _model = FgaAuthz::new(definition).unwrap();
}
