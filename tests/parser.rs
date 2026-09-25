use openfga_dsl::{
    ConditionDefinition, ParameterType, RelationExpression, SchemaHeader, parse_fga_schema,
};

#[test]
fn parses_model_header_and_type_definitions() {
    let schema = parse_fga_schema(
        "model schema 1.1\ntype user\ntype document\n  relations\n    define owner: [user]\n",
    )
    .expect("valid model schema should parse");

    assert_eq!(
        schema.header,
        SchemaHeader::ModelSchema {
            version: "1.1".into()
        }
    );
    assert_eq!(schema.type_definitions.len(), 2);
    assert_eq!(schema.type_definitions[0].name, "user");
    assert!(schema.type_definitions[0].relations.is_empty());

    let document = &schema.type_definitions[1];
    assert_eq!(document.name, "document");
    assert_eq!(document.relations.len(), 1);
    assert_eq!(document.relations[0].name, "owner");
    assert_eq!(
        document.relations[0].definition.expression,
        RelationExpression::DirectAssignment(vec![openfga_dsl::RelationTarget {
            target_type: "user".into(),
            relation_or_wildcard: None,
            condition: None,
        }])
    );
}

#[test]
fn parses_module_header() {
    let schema = parse_fga_schema("module team/access\ntype user\n")
        .expect("valid module schema should parse");

    assert_eq!(
        schema.header,
        SchemaHeader::Module {
            name: "team/access".into()
        }
    );
}

#[test]
fn parses_relation_target_restrictions_and_conditions() {
    let schema = parse_fga_schema(
        "model schema 1.1\ntype document\n  relations\n    define viewer: [user, group#member, document:* with can_view]\n",
    )
    .expect("valid relation target list should parse");

    let RelationExpression::DirectAssignment(targets) = &schema.type_definitions[0].relations[0]
        .definition
        .expression
    else {
        panic!("expected a direct assignment");
    };
    assert_eq!(targets.len(), 3);
    assert_eq!(targets[0].target_type, "user");
    assert_eq!(targets[1].relation_or_wildcard.as_deref(), Some("member"));
    assert_eq!(targets[2].relation_or_wildcard.as_deref(), Some("*"));
    assert_eq!(targets[2].condition.as_deref(), Some("can_view"));
}

#[test]
fn parses_union_intersection_and_difference_expressions() {
    let schema = parse_fga_schema(
        "model schema 1.1\ntype document\n  relations\n    define union: writer or editor\n    define intersection: writer and editor\n    define difference: writer but not suspended\n",
    )
    .expect("valid relation expressions should parse");

    let relations = &schema.type_definitions[0].relations;
    assert!(matches!(
        relations[0].definition.expression,
        RelationExpression::Union(_, _)
    ));
    assert!(matches!(
        relations[1].definition.expression,
        RelationExpression::Intersection(_, _)
    ));
    assert!(matches!(
        relations[2].definition.expression,
        RelationExpression::Difference(_, _)
    ));
}

#[test]
fn parses_parenthesized_mixed_expressions() {
    let schema = parse_fga_schema(
        "model schema 1.1\ntype document\n  relations\n    define viewer: (writer and editor) or owner\n",
    )
    .expect("parentheses should allow mixed operators");

    assert!(matches!(
        schema.type_definitions[0].relations[0]
            .definition
            .expression,
        RelationExpression::Union(_, _)
    ));
}

#[test]
fn parses_condition_parameter_types_and_expression() {
    let schema = parse_fga_schema(
        "model schema 1.1\ncondition valid(ids: list<string>, values: map<int>) { ids.size() > 0 }\n",
    )
    .expect("valid condition should parse");

    let condition: &ConditionDefinition = &schema.condition_definitions[0];
    assert_eq!(condition.name, "valid");
    assert_eq!(condition.expression, "ids.size() > 0");
    assert_eq!(
        condition.parameters[0].param_type,
        ParameterType::Generic {
            container: "list".into(),
            inner: "string".into(),
        }
    );
    assert_eq!(
        condition.parameters[1].param_type,
        ParameterType::Generic {
            container: "map".into(),
            inner: "int".into(),
        }
    );
}

#[test]
fn rejects_invalid_operator_mixing_and_trailing_text() {
    let invalid_mixing = "model schema 1.1\ntype document\n  relations\n    define viewer: writer and editor or owner\n";
    let trailing_text = "model schema 1.1\ntype user\nthis is not part of the schema";

    assert!(parse_fga_schema(invalid_mixing).is_err());
    assert!(parse_fga_schema(trailing_text).is_err());
}
