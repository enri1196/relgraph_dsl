use openfga_authz::{ConstructionError, FgaAuthz, RuntimeCapability};
use openfga_dsl::{ParseErrorCode, ValidationIssue};

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
fn rejects_relation_dependency_cycles_even_when_the_parser_accepts_them() {
    let definition = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define first: second\n    define second: first\n";
    let error = FgaAuthz::new(definition).unwrap_err();

    let ConstructionError::UnsupportedCapabilities(diagnostics) = error else {
        panic!("expected runtime capability diagnostic");
    };
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.capability == RuntimeCapability::RecursiveRelationDependency
    }));
}

#[test]
fn accepts_typed_wildcards_but_rejects_conditions_until_task_four() {
    let wildcard =
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user:*]\n";
    let _model = FgaAuthz::new(wildcard).unwrap();

    let conditional = "model\nschema 1.2\ntype user\ntype document\n  relations\n    define viewer: [user with active]\ncondition active(now: timestamp) { now < timestamp(\"2030-01-01T00:00:00Z\") }\n";
    let error = FgaAuthz::new(conditional).unwrap_err();
    assert!(matches!(
        error,
        ConstructionError::UnsupportedCapabilities(diagnostics)
            if diagnostics.iter().any(|diagnostic| diagnostic.capability == RuntimeCapability::ConditionalRelationship)
                && diagnostics.iter().any(|diagnostic| diagnostic.capability == RuntimeCapability::ConditionDefinitions)
    ));
}

#[test]
fn accepts_userset_restrictions_for_graph_traversal() {
    let definition = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype document\n  relations\n    define viewer: [group#member]\n";
    let _model = FgaAuthz::new(definition).unwrap();
}
