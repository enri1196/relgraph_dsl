use relgraph_dsl::{
    ModelManifest, ModularModel, ModuleSource, ValidationError, ValidationIssue,
    assemble_modular_model, parse_fga_schema, parse_model_manifest, validate_modular_model,
    validate_schema,
};
use std::path::PathBuf;

fn module(path: &str, source: &str) -> ModuleSource {
    ModuleSource {
        path: PathBuf::from(path),
        schema: parse_fga_schema(source).unwrap_or_else(|error| panic!("{path}: {error}")),
    }
}

fn assemble(manifest_source: &str, modules: Vec<ModuleSource>) -> ModularModel {
    let manifest = parse_model_manifest(manifest_source).expect("manifest should parse");
    assemble_modular_model(manifest, modules).expect("modules should compose")
}

fn cross_file_model() -> ModularModel {
    assemble(
        include_str!("fixtures/openfga/modular/validation/cross/manifest.yaml"),
        vec![
            module(
                "document.fga",
                include_str!("fixtures/openfga/modular/validation/cross/document.fga"),
            ),
            module(
                "user.fga",
                include_str!("fixtures/openfga/modular/validation/cross/user.fga"),
            ),
            module(
                "team.fga",
                include_str!("fixtures/openfga/modular/validation/cross/team.fga"),
            ),
        ],
    )
}

fn codes(errors: &[ValidationError]) -> Vec<&'static str> {
    errors.iter().map(|error| error.issue.code()).collect()
}

#[test]
fn resolves_cross_file_types_relations_conditions_and_repeated_module_names() {
    let model = cross_file_model();

    assert!(model.modules.iter().all(|module| matches!(
        &module.schema.header,
        relgraph_dsl::SchemaHeader::Module { name } if name == "shared"
    )));
    validate_modular_model(&model).expect("cross-file references should resolve");
}

#[test]
fn resolves_tuple_to_userset_relation_added_by_an_extension() {
    let model = assemble(
        include_str!("fixtures/openfga/modular/validation/tuple/manifest.yaml"),
        vec![
            module(
                "extensions/folder.fga",
                include_str!("fixtures/openfga/modular/validation/tuple/extensions/folder.fga"),
            ),
            module(
                "model/document.fga",
                include_str!("fixtures/openfga/modular/validation/tuple/model/document.fga"),
            ),
            module(
                "model/folder.fga",
                include_str!("fixtures/openfga/modular/validation/tuple/model/folder.fga"),
            ),
            module(
                "model/user.fga",
                include_str!("fixtures/openfga/modular/validation/tuple/model/user.fga"),
            ),
        ],
    );

    validate_modular_model(&model).expect("the extension supplies folder#viewer");
}

#[test]
fn locates_duplicate_conditions_and_parameters_in_their_source_files() {
    let model = assemble(
        include_str!("fixtures/openfga/modular/validation/duplicates/manifest.yaml"),
        vec![
            module(
                "parameters.fga",
                include_str!("fixtures/openfga/modular/validation/duplicates/parameters.fga"),
            ),
            module(
                "condition.fga",
                include_str!("fixtures/openfga/modular/validation/duplicates/condition.fga"),
            ),
        ],
    );

    let errors = validate_modular_model(&model).expect_err("duplicates should be diagnosed");
    assert_eq!(codes(&errors), ["DuplicateParameter", "DuplicateCondition"]);
    assert_eq!(
        errors[0].location.file,
        Some(PathBuf::from("parameters.fga"))
    );
    assert_eq!(errors[0].location.module.as_deref(), Some("shared"));
    assert_eq!(
        errors[1].location.file,
        Some(PathBuf::from("condition.fga"))
    );
    assert_eq!(errors[1].location.module.as_deref(), Some("shared"));
    assert_eq!(
        errors[1].related[0].file,
        Some(PathBuf::from("parameters.fga"))
    );
}

#[test]
fn validates_references_in_extensions_at_the_extension_origin() {
    let model = assemble(
        include_str!("fixtures/openfga/modular/validation/extension-errors/manifest.yaml"),
        vec![
            module(
                "base/document.fga",
                include_str!(
                    "fixtures/openfga/modular/validation/extension-errors/base/document.fga"
                ),
            ),
            module(
                "extensions/document.fga",
                include_str!(
                    "fixtures/openfga/modular/validation/extension-errors/extensions/document.fga"
                ),
            ),
        ],
    );

    let errors = validate_modular_model(&model).expect_err("extension references are invalid");
    assert_eq!(
        codes(&errors),
        [
            "UnknownCondition",
            "UnknownType",
            "UnknownRelation",
            "UnknownRelation"
        ]
    );
    for error in &errors {
        assert_eq!(
            error.location.file,
            Some(PathBuf::from("extensions/document.fga"))
        );
        assert_eq!(error.location.module.as_deref(), Some("shared"));
        assert!(error.location.span.is_some());
    }
}

#[test]
fn standalone_accepts_1_1_while_modular_validation_requires_exact_1_2() {
    let standalone =
        parse_fga_schema("model\nschema 1.1\ntype user\n").expect("standalone schema should parse");
    validate_schema(&standalone).expect("standalone 1.1 remains supported");

    let old_version = assemble(
        include_str!("fixtures/openfga/modular/validation/schema-1.1.yaml"),
        vec![module(
            "old.fga",
            include_str!("fixtures/openfga/modular/validation/old.fga"),
        )],
    );
    let errors = validate_modular_model(&old_version).expect_err("modular 1.1 is unsupported");
    assert_eq!(codes(&errors), ["UnsupportedSchemaVersion"]);
    assert_eq!(
        errors[0].location,
        relgraph_dsl::SourceLocation {
            file: None,
            module: None,
            span: None,
        }
    );

    let noncanonical = assemble_modular_manifest("01.02");
    let errors = validate_modular_model(&noncanonical).expect_err("modular version is exact");
    assert_eq!(codes(&errors), ["UnsupportedSchemaVersion"]);
}

fn assemble_modular_manifest(schema: &str) -> ModularModel {
    assemble_modular_model(
        ModelManifest {
            schema: schema.to_string(),
            contents: vec![PathBuf::from("old.fga")],
        },
        vec![module(
            "old.fga",
            include_str!("fixtures/openfga/modular/validation/old.fga"),
        )],
    )
    .expect("module should compose regardless of supported validation version")
}

#[test]
fn rejects_mutated_public_schema_and_each_origin_vector() {
    let mut altered_schema = cross_file_model();
    altered_schema.schema.type_definitions[0].name = "tampered".to_string();
    let errors = validate_modular_model(&altered_schema).expect_err("schema must match modules");
    assert_eq!(codes(&errors), ["InvalidComposition"]);
    assert_eq!(errors[0].location.file, None);
    assert_eq!(errors[0].location.module, None);
    assert_eq!(errors[0].location.span, None);
    assert!(errors[0].message.contains("assembled schema"));

    for mutation in 0..3 {
        let mut model = cross_file_model();
        match mutation {
            0 => model.type_origins[0].file = Some(PathBuf::from("tampered.fga")),
            1 => model.relation_origins[0][0].module = Some("tampered".to_string()),
            2 => model.condition_origins[0].span = None,
            _ => unreachable!(),
        }
        let errors = validate_modular_model(&model).expect_err("origins must match modules");
        assert_eq!(codes(&errors), ["InvalidComposition"]);
        assert!(errors[0].message.contains("origins"));
    }
}

#[test]
fn synthetic_invalid_composition_precedes_recomposition_conflicts() {
    let mut model = cross_file_model();
    let duplicate = model.modules[0].schema.type_definitions[0].clone();
    model.modules[0].schema.type_definitions.push(duplicate);

    let errors = validate_modular_model(&model).expect_err("mutated inputs conflict");
    assert_eq!(errors[0].issue, ValidationIssue::InvalidComposition);
    assert!(
        errors
            .iter()
            .any(|error| error.issue == ValidationIssue::DuplicateType)
    );
    assert_eq!(errors[0].location.file, None);
    assert_eq!(errors[0].location.module, None);
    assert_eq!(errors[0].location.span, None);
}

#[test]
fn modular_diagnostics_follow_manifest_then_span_then_issue_order() {
    let model = assemble(
        include_str!("fixtures/openfga/modular/validation/error-order/manifest.yaml"),
        vec![
            module(
                "z-first.fga",
                include_str!("fixtures/openfga/modular/validation/error-order/z-first.fga"),
            ),
            module(
                "a-second.fga",
                include_str!("fixtures/openfga/modular/validation/error-order/a-second.fga"),
            ),
        ],
    );

    let errors = validate_modular_model(&model).expect_err("references are unresolved");
    assert_eq!(
        codes(&errors),
        [
            "UnknownCondition",
            "UnknownType",
            "UnknownType",
            "UnknownType"
        ]
    );
    assert_eq!(errors[0].location.file, Some(PathBuf::from("z-first.fga")));
    assert_eq!(errors[1].location.file, Some(PathBuf::from("z-first.fga")));
    assert_eq!(errors[2].location.file, Some(PathBuf::from("z-first.fga")));
    assert_eq!(errors[3].location.file, Some(PathBuf::from("a-second.fga")));
    assert!(errors[0].message.contains("no_condition"));
    assert!(errors[1].message.contains("missing_z"));
    assert!(errors[2].message.contains("missing_y"));
    assert!(errors[3].message.contains("missing_x"));
}
