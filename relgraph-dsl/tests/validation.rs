use relgraph_dsl::ast::{
    ConditionDefinition, ConditionParameter, ParameterType, Relation, RelationDefinitionBody,
    RelationExpression, Schema, SchemaHeader, TypeDefinition,
};
use relgraph_dsl::diagnostics::{SourceLocation, SourceSpan, ValidationError};
use relgraph_dsl::{ValidationIssue, parse_fga_schema, validate_schema};

fn parse(source: &str) -> Schema {
    parse_fga_schema(source).expect("fixture should parse")
}

fn validate_source(source: &str) -> Result<(), Vec<ValidationError>> {
    validate_schema(&parse(source))
}

fn issue(errors: &[ValidationError], expected: ValidationIssue) -> &ValidationError {
    errors
        .iter()
        .find(|error| error.issue == expected)
        .unwrap_or_else(|| panic!("missing {} in {errors:#?}", expected.code()))
}

fn codes(errors: &[ValidationError]) -> Vec<&'static str> {
    errors.iter().map(|error| error.issue.code()).collect()
}

fn assert_standalone_location(error: &ValidationError, span: Option<SourceSpan>) {
    assert_eq!(
        error.location,
        SourceLocation {
            file: None,
            module: None,
            span,
        }
    );
}

#[test]
fn accepts_forward_references_and_a_locally_resolved_cycle() {
    for source in [
        include_str!("fixtures/validation/valid/forward-references.fga"),
        include_str!("fixtures/validation/valid/cyclic.fga"),
    ] {
        validate_schema(&parse(source)).expect("bounded validation should accept the model");
    }
}

#[test]
fn rejects_relations_without_an_entry_point() {
    let source = include_str!("fixtures/validation/invalid/no-entry-point-cycle.fga");
    let schema = parse(source);
    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(codes(&errors), ["NoEntryPoint", "NoEntryPoint"]);
    for (error, relation) in errors.iter().zip(&schema.type_definitions[0].relations) {
        assert_standalone_location(error, relation.span.clone());
        assert!(error.message.contains(&format!("'{}'", relation.name)));
    }

    // Each shape lists the relations OpenFGA reports as impossible.
    for (types, impossible) in [
        // A userset restriction on the relation itself.
        (
            "type group\n  relations\n    define viewer: [group#viewer]\n",
            vec!["viewer"],
        ),
        // A tuple-to-userset loop between two types.
        (
            "type folder\n  relations\n    define parent: [document]\n    define viewer: viewer from parent\ntype document\n  relations\n    define parent: [folder]\n    define viewer: viewer from parent\n",
            vec!["viewer", "viewer"],
        ),
        // An intersection needs every operand.
        (
            "type doc\n  relations\n    define editor: [user]\n    define viewer: [doc#viewer] and editor\n",
            vec!["viewer"],
        ),
        // As in OpenFGA, a difference needs an entry point in both operands.
        (
            "type doc\n  relations\n    define admin: [user]\n    define a: admin but not b\n    define b: admin but not a\n",
            vec!["a", "b"],
        ),
    ] {
        let source = format!("model\nschema 1.1\ntype user\n{types}");
        let errors = validate_source(&source).unwrap_err();
        assert!(
            errors
                .iter()
                .all(|error| error.issue == ValidationIssue::NoEntryPoint),
            "{errors:#?}"
        );
        assert_eq!(errors.len(), impossible.len(), "{source}");
        for (error, relation) in errors.iter().zip(impossible) {
            assert!(error.message.contains(&format!("'{relation}'")));
        }
    }

    // Entry points through usersets, tuple-to-usersets, wildcards and
    // conditional restrictions, including recursive definitions.
    let reachable = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user:*, group#member]\ntype folder\n  relations\n    define parent: [folder]\n    define viewer: [user with active] or viewer from parent\n    define member: member from parent or viewer\ntype doc\n  relations\n    define parent: [folder]\n    define viewer: [group#member] and viewer from parent\ncondition active(on: bool) { on }\n";
    validate_source(reachable).expect("every relation has an entry point");
}

#[test]
fn checks_entry_points_only_when_every_other_rule_passes() {
    let source = "model\nschema 1.1\ntype user\ntype doc\n  relations\n    define a: b\n    define b: a\n    define c: missing\n";
    let errors = validate_source(source).unwrap_err();
    assert_eq!(codes(&errors), ["UnknownRelation"]);
}

#[test]
fn preserves_unsupported_versions_and_handles_header_and_module_rules() {
    let source = "model\nschema 2.0\n";
    let schema = parse(source);
    let SchemaHeader::ModelSchema { version } = &schema.header else {
        panic!("expected a standalone schema header");
    };
    assert_eq!(version, "2.0");
    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(codes(&errors), ["EmptyModel", "UnsupportedSchemaVersion"]);
    let header_span = schema.header_span.clone();
    assert_standalone_location(
        issue(&errors, ValidationIssue::UnsupportedSchemaVersion),
        header_span.clone(),
    );
    assert_standalone_location(issue(&errors, ValidationIssue::EmptyModel), header_span);

    let module_source = "module team-access\ntype user\n";
    let module = parse(module_source);
    let errors = validate_schema(&module).unwrap_err();
    assert_eq!(codes(&errors), ["ModuleRequiresComposition"]);
    assert_standalone_location(
        issue(&errors, ValidationIssue::ModuleRequiresComposition),
        module.header_span.clone(),
    );
}

#[test]
fn reports_standalone_extensions_without_resolving_their_references() {
    let source =
        "model\nschema 1.2\nextend type user\n  relations\n    define reader: [ghost]\ntype user\n";
    let schema = parse(source);
    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(codes(&errors), ["ExtensionOutsideModule"]);
    let extension = &schema.type_definitions[0];
    assert_standalone_location(
        issue(&errors, ValidationIssue::ExtensionOutsideModule),
        extension.span.clone(),
    );
}

#[test]
fn locates_duplicate_declarations_and_links_them_to_the_first_declaration() {
    let source = "model\nschema 1.2\ntype doc\n  relations\n    define viewer: [user]\n    define viewer: [user]\ntype doc\ntype user\ncondition check(x: string, x: int) { true }\ncondition check(y: int) { true }\n";
    let schema = parse(source);
    let errors = validate_schema(&schema).unwrap_err();

    let duplicate_type = issue(&errors, ValidationIssue::DuplicateType);
    assert_eq!(duplicate_type.issue.code(), "DuplicateType");
    assert_standalone_location(duplicate_type, schema.type_definitions[1].span.clone());
    assert_eq!(
        duplicate_type.related[0]
            .span
            .as_ref()
            .map(|span| span.start),
        schema.type_definitions[0]
            .span
            .as_ref()
            .map(|span| span.start)
    );

    let duplicate_relation = issue(&errors, ValidationIssue::DuplicateRelation);
    assert_eq!(duplicate_relation.issue.code(), "DuplicateRelation");
    assert_standalone_location(duplicate_relation, duplicate_relation.location.span.clone());
    assert_eq!(
        duplicate_relation
            .location
            .span
            .as_ref()
            .map(|span| span.start),
        Some(source.rfind("define viewer").unwrap())
    );
    assert_eq!(
        duplicate_relation.related[0]
            .span
            .as_ref()
            .map(|span| span.start),
        Some(source.find("define viewer").unwrap())
    );

    let duplicate_condition = issue(&errors, ValidationIssue::DuplicateCondition);
    assert_eq!(duplicate_condition.issue.code(), "DuplicateCondition");
    assert_standalone_location(
        duplicate_condition,
        duplicate_condition.location.span.clone(),
    );
    assert_eq!(
        duplicate_condition
            .location
            .span
            .as_ref()
            .map(|span| span.start),
        Some(source.rfind("condition check").unwrap())
    );
    assert_eq!(
        duplicate_condition.related[0]
            .span
            .as_ref()
            .map(|span| span.start),
        Some(source.find("condition check").unwrap())
    );

    let duplicate_parameter = issue(&errors, ValidationIssue::DuplicateParameter);
    assert_eq!(duplicate_parameter.issue.code(), "DuplicateParameter");
    assert_standalone_location(
        duplicate_parameter,
        duplicate_parameter.location.span.clone(),
    );
    assert_eq!(
        duplicate_parameter
            .location
            .span
            .as_ref()
            .map(|span| span.start),
        Some(source.match_indices("x: ").nth(1).unwrap().0)
    );
    assert_eq!(
        duplicate_parameter.related[0]
            .span
            .as_ref()
            .map(|span| span.start),
        Some(source.find("x: ").unwrap())
    );
}

#[test]
fn sorts_multiple_errors_and_suppresses_dependent_cascades() {
    let source = include_str!("fixtures/validation/invalid/reference-cascade.fga");
    let schema = parse(source);
    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(
        codes(&errors),
        [
            "UnsupportedSchemaVersion",
            "UnknownCondition",
            "UnknownType",
            "UnknownRelation",
            "UnknownTuplesetRelation",
            "UnknownType",
        ]
    );
    assert!(errors.windows(2).all(|pair| {
        pair[0].location.span.as_ref().unwrap().start
            <= pair[1].location.span.as_ref().unwrap().start
    }));

    let lookup_start = source.find("define lookup").unwrap();
    assert_standalone_location(
        issue(&errors, ValidationIssue::UnknownType),
        schema.type_definitions[0].relations[0].span.clone(),
    );
    for error in errors.iter().filter(|error| {
        matches!(
            error.issue,
            ValidationIssue::UnknownCondition | ValidationIssue::UnknownType
        )
    }) {
        if error.location.span.as_ref().unwrap().start == lookup_start {
            assert!(
                error.message.contains("absent_condition") || error.message.contains("missing")
            );
        }
    }
    assert!(errors.iter().any(|error| {
        error.issue == ValidationIssue::UnknownRelation
            && error.message.contains("missing_relation")
    }));
    assert!(errors.iter().any(|error| {
        error.issue == ValidationIssue::UnknownTuplesetRelation
            && error.message.contains("missing_tupleset")
    }));
    assert!(!errors.iter().any(|error| {
        error.issue == ValidationIssue::UnknownComputedRelation
            || (error.issue == ValidationIssue::UnknownRelation && error.message.contains("absent"))
    }));
}

#[test]
fn checks_userset_relations_and_named_conditions_on_known_types() {
    let source = "model\nschema 1.2\ntype document\n  relations\n    define viewer: [user#missing with absent]\ntype user\n  relations\n    define allowed: [user]\n";
    let errors = validate_source(source).unwrap_err();
    assert_eq!(codes(&errors), ["UnknownCondition", "UnknownRelation"]);
    assert!(
        issue(&errors, ValidationIssue::UnknownRelation)
            .message
            .contains("missing")
    );
    assert!(
        issue(&errors, ValidationIssue::UnknownCondition)
            .message
            .contains("absent")
    );
    let relation_start = source.find("define viewer").unwrap();
    for error in &errors {
        assert_eq!(
            error.location.span.as_ref().map(|span| span.start),
            Some(relation_start)
        );
    }
}

fn tuple_source(tupleset: &str, target_types: &str) -> String {
    format!(
        "model\nschema 1.2\ntype document\n  relations\n    define parent: {tupleset}\n    define derived: view from parent\ntype folder{target_types}\n"
    )
}

#[test]
fn validates_tuple_to_userset_prerequisites_and_target_coverage() {
    let absent =
        "model\nschema 1.2\ntype document\n  relations\n    define derived: view from missing\n";
    let errors = validate_source(absent).unwrap_err();
    assert_eq!(codes(&errors), ["UnknownTuplesetRelation"]);
    assert!(
        issue(&errors, ValidationIssue::UnknownTuplesetRelation)
            .message
            .contains("missing")
    );
    assert_standalone_location(
        issue(&errors, ValidationIssue::UnknownTuplesetRelation),
        parse(absent).type_definitions[0].relations[0].span.clone(),
    );

    let rewrite = "model\nschema 1.2\ntype document\n  relations\n    define parent: [folder] or file\n    define file: [file]\n    define derived: view from parent\ntype folder\ntype file\n";
    let errors = validate_source(rewrite).unwrap_err();
    assert_eq!(codes(&errors), ["InvalidTuplesetRelation"]);
    assert_eq!(
        issue(&errors, ValidationIssue::InvalidTuplesetRelation)
            .issue
            .code(),
        "InvalidTuplesetRelation"
    );
    assert_standalone_location(
        issue(&errors, ValidationIssue::InvalidTuplesetRelation),
        parse(rewrite).type_definitions[0].relations[2].span.clone(),
    );

    let restricted_targets = "model\nschema 1.2\ntype document\n  relations\n    define parent: [folder:*, folder#member]\n    define derived: view from parent\ntype folder\n  relations\n    define member: [user]\ntype user\n";
    let errors = validate_source(restricted_targets).unwrap_err();
    assert_eq!(codes(&errors), ["InvalidTuplesetRelation"]);

    let conditioned_plain_target = "model\nschema 1.2\ntype document\n  relations\n    define parent: [folder with allowed]\n    define derived: view from parent\ntype folder\n  relations\n    define view: [user]\ntype user\ncondition allowed(id: string) { true }\n";
    validate_source(conditioned_plain_target).expect("conditions on plain targets are allowed");

    let none = tuple_source("[folder, file]", "\ntype file\n");
    let errors = validate_source(&none).unwrap_err();
    assert_eq!(codes(&errors), ["UnknownComputedRelation"]);
    assert!(
        issue(&errors, ValidationIssue::UnknownComputedRelation)
            .message
            .contains("view")
    );
    let tuple_use_start = none.find("define derived").unwrap();
    assert_eq!(
        issue(&errors, ValidationIssue::UnknownComputedRelation)
            .location
            .span
            .as_ref()
            .map(|span| span.start),
        Some(tuple_use_start)
    );

    let some = "model\nschema 1.2\ntype document\n  relations\n    define parent: [folder, file]\n    define derived: view from parent\ntype folder\n  relations\n    define view: [user]\ntype file\ntype user\n";
    validate_source(some).expect("one target type defining the relation is sufficient");

    let all = "model\nschema 1.2\ntype document\n  relations\n    define parent: [folder, file]\n    define derived: view from parent\ntype folder\n  relations\n    define view: [user]\ntype file\n  relations\n    define view: [user]\ntype user\n";
    validate_source(all).expect("all target types may define the relation");

    let unresolved = "model\nschema 1.2\ntype document\n  relations\n    define parent: [missing, folder]\n    define derived: view from parent\ntype folder\n";
    let errors = validate_source(unresolved).unwrap_err();
    assert_eq!(codes(&errors), ["UnknownType"]);
    assert!(
        !errors
            .iter()
            .any(|error| error.issue == ValidationIssue::UnknownComputedRelation)
    );
}

fn manual_relation(name: &str, expression: RelationExpression) -> Relation {
    Relation {
        name: name.to_string(),
        definition: RelationDefinitionBody { expression },
        comments_before: Vec::new(),
        span: None,
    }
}

#[test]
fn checks_manually_constructed_ast_invariants_and_missing_spans() {
    let schema = Schema {
        header: SchemaHeader::ModelSchema {
            version: "1.2".to_string(),
        },
        header_span: None,
        type_definitions: vec![TypeDefinition {
            is_extended: false,
            name: "document".to_string(),
            relations: vec![manual_relation(
                "empty",
                RelationExpression::DirectAssignment(Vec::new()),
            )],
            comments_before: Vec::new(),
            span: None,
        }],
        condition_definitions: vec![ConditionDefinition {
            name: "condition".to_string(),
            parameters: vec![ConditionParameter {
                name: "value".to_string(),
                param_type: ParameterType::Simple("bytes".to_string()),
                span: None,
            }],
            expression: String::new(),
            comments_before: Vec::new(),
            span: None,
        }],
    };

    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(
        codes(&errors),
        [
            "EmptyDirectAssignment",
            "InvalidParameterType",
            "UnusedCondition"
        ]
    );
    assert_eq!(
        issue(&errors, ValidationIssue::EmptyDirectAssignment)
            .issue
            .code(),
        "EmptyDirectAssignment"
    );
    assert_eq!(
        issue(&errors, ValidationIssue::InvalidParameterType)
            .issue
            .code(),
        "InvalidParameterType"
    );
    assert_standalone_location(issue(&errors, ValidationIssue::EmptyDirectAssignment), None);
    assert_standalone_location(issue(&errors, ValidationIssue::InvalidParameterType), None);
    assert_standalone_location(issue(&errors, ValidationIssue::UnusedCondition), None);
}

#[test]
fn rejects_reserved_type_and_relation_names_at_their_declarations() {
    let source = "model\nschema 1.1\ntype user\ntype self\n  relations\n    define this: [user]\n";
    let schema = parse(source);
    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(codes(&errors), ["ReservedTypeName", "ReservedRelationName"]);
    assert_standalone_location(
        issue(&errors, ValidationIssue::ReservedTypeName),
        schema.type_definitions[1].span.clone(),
    );
    assert_standalone_location(
        issue(&errors, ValidationIssue::ReservedRelationName),
        schema.type_definitions[1].relations[0].span.clone(),
    );
}

#[test]
fn applies_openfga_name_length_and_character_rules() {
    let long_relation = "r".repeat(51);
    let source = format!(
        "model\nschema 1.1\ntype user\ntype {}\n  relations\n    define {long_relation}: [user]\n    define {}: [user]\n",
        "t".repeat(255),
        "r".repeat(50),
    );
    let errors = validate_source(&source).unwrap_err();
    assert_eq!(codes(&errors), ["InvalidName", "InvalidName"]);
    assert!(errors[0].message.contains("1 to 254 characters"));
    assert!(errors[1].message.contains(&long_relation));

    let accepted = format!(
        "model\nschema 1.1\ntype user\ntype {}\n  relations\n    define {}: [user]\n",
        "t".repeat(254),
        "r".repeat(50),
    );
    validate_source(&accepted).expect("names at the length limits are valid");

    let schema = Schema {
        header: SchemaHeader::ModelSchema {
            version: "1.1".to_string(),
        },
        header_span: None,
        type_definitions: vec![TypeDefinition {
            is_extended: false,
            name: "bad:type".to_string(),
            relations: vec![
                manual_relation("", RelationExpression::ComputedUserset("ok".to_string())),
                manual_relation(
                    "has space",
                    RelationExpression::ComputedUserset("ok".to_string()),
                ),
                manual_relation("ok", RelationExpression::ComputedUserset("ok".to_string())),
            ],
            comments_before: Vec::new(),
            span: None,
        }],
        condition_definitions: Vec::new(),
    };
    let errors = validate_schema(&schema).unwrap_err();
    let invalid: Vec<&str> = errors
        .iter()
        .filter(|error| error.issue == ValidationIssue::InvalidName)
        .map(|error| error.message.as_str())
        .collect();
    assert_eq!(invalid.len(), 3, "{errors:#?}");
    assert!(invalid.iter().any(|message| message.contains("'bad:type'")));
    assert!(invalid.iter().any(|message| message.contains("''")));
    assert!(
        invalid
            .iter()
            .any(|message| message.contains("'has space'"))
    );
}

#[test]
fn rejects_repeated_type_restrictions_but_not_differing_conditions() {
    let source = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user, user:*, group#member, user, user:*, group#member, user with allowed]\ncondition allowed(flag: bool) { flag }\n";
    let schema = parse(source);
    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(
        codes(&errors),
        [
            "DuplicateTypeRestriction",
            "DuplicateTypeRestriction",
            "DuplicateTypeRestriction"
        ]
    );
    for (error, restriction) in errors.iter().zip(["'group#member'", "'user'", "'user:*'"]) {
        assert!(error.message.contains(restriction), "{}", error.message);
        assert_standalone_location(error, schema.type_definitions[1].relations[0].span.clone());
    }
}

#[test]
fn rejects_repeated_top_level_operands() {
    for (expression, operand) in [
        ("viewer or editor or viewer", "'viewer'"),
        ("viewer and viewer", "'viewer'"),
        ("viewer but not viewer", "'viewer'"),
        (
            "viewer from parent or viewer from parent",
            "'viewer from parent'",
        ),
    ] {
        let source = format!(
            "model\nschema 1.1\ntype user\ntype doc\n  relations\n    define parent: [doc]\n    define editor: [user]\n    define viewer: [user]\n    define other: {expression}\n"
        );
        let schema = parse(&source);
        let errors = validate_schema(&schema).unwrap_err();
        assert_eq!(codes(&errors), ["DuplicateOperand"], "{expression}");
        assert!(errors[0].message.contains(operand), "{}", errors[0].message);
        assert_standalone_location(
            &errors[0],
            schema.type_definitions[1].relations[3].span.clone(),
        );
    }

    // As in OpenFGA, only the operands of the top-level operator are compared;
    // a parenthesized group on the right is one operand without a name.
    for expression in [
        "viewer or (viewer and editor)",
        "(viewer or editor) and (viewer or editor)",
        "viewer but not (viewer and editor)",
    ] {
        let source = format!(
            "model\nschema 1.1\ntype user\ntype doc\n  relations\n    define editor: [user]\n    define viewer: [user]\n    define other: {expression}\n"
        );
        validate_source(&source)
            .unwrap_or_else(|errors| panic!("{expression} should validate: {errors:#?}"));
    }
}

#[test]
fn reports_each_unused_condition_once_at_its_declaration() {
    let source = "model\nschema 1.1\ntype user\ntype doc\n  relations\n    define viewer: [user with less_than]\ncondition less_than(x: int) { x < 100 }\ncondition less(x: int) { x < 10 }\n";
    let schema = parse(source);
    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(codes(&errors), ["UnusedCondition"]);
    assert!(errors[0].message.contains("'less'"));
    assert_standalone_location(&errors[0], schema.condition_definitions[1].span.clone());

    let duplicated = "model\nschema 1.1\ntype user\ncondition unused(x: int) { x < 1 }\ncondition unused(x: int) { x < 2 }\n";
    let schema = parse(duplicated);
    let errors = validate_schema(&schema).unwrap_err();
    assert_eq!(codes(&errors), ["UnusedCondition", "DuplicateCondition"]);
    assert_standalone_location(
        issue(&errors, ValidationIssue::UnusedCondition),
        schema.condition_definitions[0].span.clone(),
    );
}
