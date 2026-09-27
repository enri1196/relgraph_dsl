use openfga_dsl::{
    ConditionDefinition, ParameterType, ParseErrorCode, RelationCondition, RelationExpression,
    SchemaHeader, SourceSpan, parse_fga_schema,
};

#[test]
fn parses_model_header_and_type_definitions() {
    let schema = parse_fga_schema(
        "model\nschema 1.1\ntype user\ntype document\n  relations\n    define owner: [user]\n",
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
    let schema = parse_fga_schema("module team-access\ntype user\n")
        .expect("valid module schema should parse");

    assert_eq!(
        schema.header,
        SchemaHeader::Module {
            name: "team-access".into()
        }
    );
}

#[test]
fn parses_relation_target_restrictions_and_conditions() {
    let schema = parse_fga_schema(
        "model\nschema 1.1\ntype document\n  relations\n    define viewer: [user, group#member, document:* with can_view]\n",
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
    assert_eq!(
        targets[2].condition,
        Some(RelationCondition::Named("can_view".to_string()))
    );
}

#[test]
fn parses_named_and_inline_relation_conditions() {
    let schema = parse_fga_schema(
        "model\nschema 1.2\ntype document\n  relations\n    define viewer: [user with can_view, group#member with $expression, document:* with can_view]\n",
    )
    .expect("named and inline restriction conditions should parse");

    let RelationExpression::DirectAssignment(targets) = &schema.type_definitions[0].relations[0]
        .definition
        .expression
    else {
        panic!("expected a direct assignment");
    };
    assert_eq!(
        targets[0].condition,
        Some(RelationCondition::Named("can_view".to_string()))
    );
    assert_eq!(
        targets[1].condition,
        Some(RelationCondition::InlineExpression)
    );
    assert_eq!(
        targets[2].condition,
        Some(RelationCondition::Named("can_view".to_string()))
    );

    let unconditioned = parse_fga_schema(
        "model\nschema 1.2\ntype document\n  relations\n    define viewer: [user, group#member with $expression, document:*]\n",
    )
    .expect("conditioned and unconditioned targets should mix");
    let RelationExpression::DirectAssignment(targets) = &unconditioned.type_definitions[0]
        .relations[0]
        .definition
        .expression
    else {
        panic!("expected a direct assignment");
    };
    assert_eq!(targets[0].condition, None);
    assert_eq!(
        targets[1].condition,
        Some(RelationCondition::InlineExpression)
    );
    assert_eq!(targets[2].condition, None);
}

#[test]
fn rejects_missing_and_invalid_inline_relation_conditions() {
    for source in [
        "model\nschema 1.2\ntype document\n  relations\n    define viewer: [user with]\n",
        "model\nschema 1.2\ntype document\n  relations\n    define viewer: [user with $foo]\n",
        "model\nschema 1.2\ntype document\n  relations\n    define viewer: [user with $expression_suffix]\n",
    ] {
        assert!(
            parse_fga_schema(source).is_err(),
            "invalid restriction condition should fail: {source:?}"
        );
    }
}

#[test]
fn parses_union_intersection_and_difference_expressions() {
    let schema = parse_fga_schema(
        "model\nschema 1.1\ntype document\n  relations\n    define union: writer or editor\n    define intersection: writer and editor\n    define difference: writer but not suspended\n",
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
        "model\nschema 1.1\ntype document\n  relations\n    define viewer: (writer and editor) or owner\n",
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
        "model\nschema 1.1\ncondition valid(ids: list<string>, values: map<int>) { ids.size() > 0 }\n",
    )
    .expect("valid condition should parse");

    let condition: &ConditionDefinition = &schema.condition_definitions[0];
    assert_eq!(condition.name, "valid");
    assert_eq!(condition.expression, " ids.size() > 0 ");
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
    assert_eq!(
        condition.parameters[0].span,
        Some(SourceSpan {
            start: "model\nschema 1.1\ncondition valid(".len(),
            end: "model\nschema 1.1\ncondition valid(ids: list<string>".len(),
        })
    );
}

#[test]
fn parses_all_supported_condition_parameter_types() {
    let simple_types = [
        "bool",
        "string",
        "int",
        "uint",
        "double",
        "duration",
        "timestamp",
        "ipaddress",
    ];
    let container_types = ["list", "map"];

    for value_type in simple_types {
        let input = format!("model\nschema 1.1\ncondition check(value: {value_type}) {{ }}");
        let schema = parse_fga_schema(&input).expect("supported simple parameter type");
        assert_eq!(schema.condition_definitions[0].parameters.len(), 1);
        assert_eq!(
            schema.condition_definitions[0].parameters[0].param_type,
            ParameterType::Simple(value_type.into())
        );
    }

    for container in container_types {
        for value_type in simple_types {
            let input = format!(
                "model\nschema 1.1\ncondition check(value: {container}<{value_type}>) {{ }}"
            );
            let schema = parse_fga_schema(&input).expect("supported container parameter type");
            assert_eq!(
                schema.condition_definitions[0].parameters[0].param_type,
                ParameterType::Generic {
                    container: container.into(),
                    inner: value_type.into(),
                }
            );
        }
    }
}

#[test]
fn rejects_unsupported_condition_parameter_forms() {
    for parameters in [
        "",
        "value: int,",
        "value: integer",
        "value: any",
        "value: float",
        "value: bytes",
        "value: list",
        "value: map<string, int>",
        "value: list<list<int>>",
        "value: list< string >",
    ] {
        let input = format!("model\nschema 1.1\ncondition check({parameters}) {{ true }}");
        assert!(
            parse_fga_schema(&input).is_err(),
            "parameter form should be rejected: {parameters:?}"
        );
    }
}

#[test]
fn preserves_cel_body_bytes_and_stops_at_first_visible_brace() {
    let input = r##"model
schema 1.1
condition check(value: string) {  value == "}" && r'}' && b"}" && R'''x}y''' && B"""z}""" // } comment
 }
"##;
    let schema = parse_fga_schema(input).expect("braces in CEL tokens do not close the body");
    assert_eq!(
        schema.condition_definitions[0].expression,
        r##"  value == "}" && r'}' && b"}" && R'''x}y''' && B"""z}""" // } comment
 "##
    );

    let empty = parse_fga_schema("model\nschema 1.1\ncondition empty(value: int) {  \n\t}\n")
        .expect("empty CEL body is valid syntax");
    assert_eq!(empty.condition_definitions[0].expression, "  \n\t");

    let nested_map =
        "model\nschema 1.1\ncondition nested(value: int) { {\"outer\": {\"inner\": 1}} }";
    assert!(parse_fga_schema(nested_map).is_err());

    let escapes = r##"model
schema 1.1
condition escaped(value: string) { value == "quote: \" brace: } newline: \n unicode: \u0041" }
condition raw(value: string) { r"raw } text" }
condition unvalidated(value: int) { definitely not valid CEL ??? }
"##;
    let escaped = parse_fga_schema(escapes).expect("valid token forms and arbitrary CEL semantics");
    assert_eq!(escaped.condition_definitions.len(), 3);
    assert_eq!(
        escaped.condition_definitions[0].expression,
        r##" value == "quote: \" brace: } newline: \n unicode: \u0041" "##
    );
    assert_eq!(
        escaped.condition_definitions[1].expression,
        " r\"raw } text\" "
    );

    let missing_close = "model\nschema 1.1\ncondition missing(value: int) { true";
    assert_eq!(
        parse_fga_schema(missing_close).unwrap_err().code,
        openfga_dsl::diagnostics::ParseErrorCode::UnexpectedEof
    );
    let unterminated_string =
        "model\nschema 1.1\ncondition invalid(value: string) { \"unterminated }";
    assert_eq!(
        parse_fga_schema(unterminated_string).unwrap_err().code,
        openfga_dsl::diagnostics::ParseErrorCode::InvalidToken
    );
}

#[test]
fn rejects_invalid_operator_mixing_and_trailing_text() {
    let invalid_mixing = "model\nschema 1.1\ntype document\n  relations\n    define viewer: writer and editor or owner\n";
    let trailing_text = "model\nschema 1.1\ntype user\nthis is not part of the schema";

    assert!(parse_fga_schema(invalid_mixing).is_err());
    assert!(parse_fga_schema(trailing_text).is_err());
}

#[test]
fn preserves_original_byte_spans_for_parsed_nodes() {
    let input = "// café\n  model\r\nschema 1.2\ntype user\ntype document\n  relations\n    define owner: [user]\n";
    let schema = parse_fga_schema(input).expect("canonical multiline header should parse");

    let model_start = input.find("model").unwrap();
    let version_end = input.find("1.2").unwrap() + "1.2".len();
    assert_eq!(
        schema.header_span,
        Some(SourceSpan {
            start: model_start,
            end: version_end,
        })
    );

    let document_start = input.find("type document").unwrap();
    let relation_end = input.find("[user]").unwrap() + "[user]".len();
    let document = &schema.type_definitions[1];
    assert_eq!(
        document.span,
        Some(SourceSpan {
            start: document_start,
            end: relation_end,
        })
    );
    assert_eq!(
        document.relations[0].span,
        Some(SourceSpan {
            start: input.find("define owner").unwrap(),
            end: relation_end,
        })
    );
}

#[test]
fn reports_lexical_errors_first_with_utf8_scalar_spans() {
    let invalid_character = "model\nschema 1.2\ntype café\n";
    let error = parse_fga_schema(invalid_character).unwrap_err();
    let invalid_start = invalid_character.find('é').unwrap();
    assert_eq!(error.code, ParseErrorCode::InvalidToken);
    assert_eq!(
        error.span,
        SourceSpan {
            start: invalid_start,
            end: invalid_start + 'é'.len_utf8(),
        }
    );

    let earlier_syntax_later_lexical = "not a schema @";
    let error = parse_fga_schema(earlier_syntax_later_lexical).unwrap_err();
    assert_eq!(error.code, ParseErrorCode::InvalidToken);
    assert_eq!(
        error.span.start,
        earlier_syntax_later_lexical.find('@').unwrap()
    );

    let unterminated_string = "model\nschema 1.2\ncondition c(value: string) { \"not closed }";
    let error = parse_fga_schema(unterminated_string).unwrap_err();
    let quote_start = unterminated_string.find('"').unwrap();
    assert_eq!(error.code, ParseErrorCode::InvalidToken);
    assert_eq!(
        error.span,
        SourceSpan {
            start: quote_start,
            end: quote_start + 1,
        }
    );
}

#[test]
fn parses_header_versions_names_extensions_and_declaration_comments() {
    for input in [
        "model\nschema 1.2",
        "model\nschema 2.0",
        "model\nschema 01.02",
        "module team-access",
        "module model",
        "model\nschema 1.1\ntype team/access\n  relations\n    define team/access: team/access\n",
        "model\nschema 1.1\ntype document\n  relations\n    define viewer: [user, group#member, user:*]\n",
        "model\nschema 1.1\ntype document\n  relations\n    define viewer: [user] or viewer\n",
        "model\nschema 1.1\ntype document\n  relations\n    define viewer: (writer and editor) or owner\n",
        "model\nschema 1.1\ntype document\n  relations\n    define union: a or b or c\n    define intersection: a and b and c\n    define difference: a but not b\n",
        "# discarded header note\nmodel\nschema 1.1\n# type note\ntype document\n  relations\n    # relation note\n    define viewer: [user]\n",
    ] {
        let parsed = openfga_dsl::parse_fga_schema(input);
        assert!(
            parsed.is_ok(),
            "expected valid grammar input to parse: {input:?}; got {parsed:?}"
        );
    }

    let schema = openfga_dsl::parse_fga_schema(
        "model\nschema 1.1\ntype document\n  relations\n    define union: a or b or c\n    define intersection: a and b and c\n    define difference: a but not b\n",
    )
    .expect("homogeneous rewrite chains should parse");
    let union = &schema.type_definitions[0].relations[0]
        .definition
        .expression;
    assert!(matches!(
        union,
        openfga_dsl::ast::RelationExpression::Union(left, right)
            if matches!(left.as_ref(), openfga_dsl::ast::RelationExpression::Union(_, _))
                && matches!(right.as_ref(), openfga_dsl::ast::RelationExpression::ComputedUserset(name) if name == "c")
    ));
    assert!(matches!(
        &schema.type_definitions[0].relations[1]
            .definition
            .expression,
        openfga_dsl::ast::RelationExpression::Intersection(left, right)
            if matches!(left.as_ref(), openfga_dsl::ast::RelationExpression::Intersection(_, _))
                && matches!(right.as_ref(), openfga_dsl::ast::RelationExpression::ComputedUserset(name) if name == "c")
    ));
    assert!(matches!(
        schema.type_definitions[0].relations[2]
            .definition
            .expression,
        openfga_dsl::ast::RelationExpression::Difference(_, _)
    ));

    let schema = openfga_dsl::parse_fga_schema(
        "# ignored header comments\nmodel\nschema 1.1\n# type documentation\ntype document\n",
    )
    .expect("header-only types and attached comments should parse");
    assert_eq!(
        schema.type_definitions[0].comments_before,
        vec!["type documentation"]
    );

    let schema = openfga_dsl::parse_fga_schema(
        "# header note\nmodel\nschema 1.1\n# type note\ntype document\n  relations\n    # relation note\n    define viewer: [user]\n",
    )
    .expect("grammar-attached comments should parse");
    assert_eq!(schema.type_definitions[0].comments_before, ["type note"]);
    assert_eq!(
        schema.type_definitions[0].relations[0].comments_before,
        ["relation note"]
    );
}

#[test]
fn rejects_non_grammar_headers_declarations_and_rewrites() {
    for input in [
        "model schema 1.1",
        "model\nschema 1",
        "model\nschema 1.",
        "model\nschema .1",
        "model\nschema 1.1.0",
        "model\nschema v1.1",
        "model\nschema 1.1suffix",
        "module team/access",
        "module team.access",
        "model\nschema 1.1 type document",
        "model\nschema 1.1\ntype document relations\n    define viewer: [user]\n",
        "model\nschema 1.1\ntype document\n  relations\n",
        "model\nschema 1.1\ncondition c(value: bool) { true }\ntype document\n",
        "model\nschema 1.1\ntype document\n  relations\n    define empty: []\n",
        "model\nschema 1.1\ntype document\n  relations\n    define trailing: [user,]\n",
        "model\nschema 1.1\ntype document\n  relations\n    define malformed: [user#*]\n",
        "model\nschema 1.1\ntype document\n  relations\n    define malformed: [user:member]\n",
        "model\nschema 1.1\ntype document\n  relations\n    define malformed: [group#member:*]\n",
        "model\nschema 1.1\ntype document\n  relations\n    define mixed: a and b or c\n",
        "model\nschema 1.1\ntype document\n  relations\n    define repeated: a but not b but not c\n",
        "model\nschema 1.1\ntype document\n  relations\n    define missing: a or\n",
        "model\nschema 1.1\ntype document\n  relations\n    define invalid: a or [user]\n",
        "model\nschema 1.1\ntype document\n  relations\n    define invalid: a or ([user])\n",
        "model\nschema 1.1\ntype document\n  relations\n    define invalid: a or (([user]))\n",
        "model\nschema 1.1\ntype document\n  relations\n    define invalid: a or\n      b\n",
        "model\nschema 1.1\ntype document\n  relations\n    define invalid: a # not a grammar comment\n",
        "model\nschema 1.1\ntype document\n# trailing prose\n",
        "model\nschema 1.1\nmodel\nschema 1.2\n",
    ] {
        assert!(
            openfga_dsl::parse_fga_schema(input).is_err(),
            "expected invalid grammar input to fail: {input:?}"
        );
    }
}

#[test]
fn honors_identifier_priority_module_names_and_line_endings() {
    for newline in ["\n", "\r\n", "\r", " \u{000c}\n "] {
        let source = format!("model{newline}schema 1.1{newline}type modelx--{newline}");
        let schema = parse_fga_schema(&source).expect("supported newline form should parse");
        assert_eq!(schema.type_definitions[0].name, "modelx--");
    }

    let keyword_name = parse_fga_schema("module model\ntype type\n")
        .expect("listed keywords are identifier alternatives in the grammar");
    assert_eq!(keyword_name.type_definitions[0].name, "type");

    let slash_name = parse_fga_schema("module team/access\n").unwrap_err();
    assert_eq!(slash_name.code, ParseErrorCode::UnexpectedToken);
    assert_eq!(slash_name.span.start, "module ".len());
}

#[test]
fn condition_mode_rejects_newlines_and_hidden_comments_keep_source_offsets() {
    let invalid = "model\nschema 1.2\ncondition c(value: string,\n other: int) { true }";
    let error = parse_fga_schema(invalid).unwrap_err();
    assert_eq!(error.code, ParseErrorCode::InvalidToken);
    assert_eq!(error.span.start, invalid.find(",\n").unwrap() + 1);

    let source = "model\nschema 1.2\ncondition c(value: string) { true // unicode café\n }";
    let schema = parse_fga_schema(source).expect("hidden CEL comment should not end the body");
    let condition = &schema.condition_definitions[0];
    let start = source.find("condition").unwrap();
    let end = source.find('}').unwrap() + 1;
    assert_eq!(condition.span, Some(SourceSpan { start, end }));
}

#[test]
fn attaches_hash_comments_without_confusing_userset_hashes() {
    let source = "model\nschema 1.2\n# type note\ntype document\n  relations\n    # relation note\n    define viewer: [user, group#member]\n";
    let schema = parse_fga_schema(source).expect("hash comments and userset markers coexist");
    let document = &schema.type_definitions[0];
    assert_eq!(document.comments_before, ["type note"]);
    assert_eq!(document.relations[0].comments_before, ["relation note"]);
    let RelationExpression::DirectAssignment(targets) =
        &document.relations[0].definition.expression
    else {
        panic!("expected direct assignment");
    };
    assert_eq!(targets[1].relation_or_wildcard.as_deref(), Some("member"));
}

#[test]
fn syntax_errors_distinguish_unexpected_tokens_and_eof() {
    let error = parse_fga_schema("model\nschema 1.2\ntype").unwrap_err();
    assert_eq!(error.code, ParseErrorCode::UnexpectedEof);
    assert_eq!(error.span.start, "model\nschema 1.2\ntype".len());
    assert_eq!(error.span.end, error.span.start);

    let error = parse_fga_schema("not a schema").unwrap_err();
    assert_eq!(error.code, ParseErrorCode::UnexpectedToken);
    assert_eq!(error.span, SourceSpan { start: 0, end: 3 });

    let hidden_comment_at_eof = "// comment with unicode café";
    let error = parse_fga_schema(hidden_comment_at_eof).unwrap_err();
    assert_eq!(error.code, ParseErrorCode::UnexpectedEof);
    assert_eq!(error.span.start, hidden_comment_at_eof.len());
}

#[test]
fn manually_constructed_ast_nodes_can_omit_spans() {
    let parameter = openfga_dsl::ConditionParameter {
        name: "id".into(),
        param_type: ParameterType::Simple("string".into()),
        span: None,
    };
    assert_eq!(parameter.span, None);
}
