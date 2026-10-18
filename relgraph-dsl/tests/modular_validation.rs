use relgraph_dsl::{
    ManifestErrorCode, ModelManifest, ModularModel, ModularModelError, ModuleSource,
    ValidationError, assemble_modular_model, parse_fga_schema, parse_model_manifest,
    validate_modular_model, validate_schema,
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

    assert!(model.modules().iter().all(|module| matches!(
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
fn standalone_accepts_1_1_while_modular_manifests_require_exact_1_2() {
    let standalone =
        parse_fga_schema("model\nschema 1.1\ntype user\n").expect("standalone schema should parse");
    validate_schema(&standalone).expect("standalone 1.1 remains supported");

    let error = parse_model_manifest(include_str!(
        "fixtures/openfga/modular/validation/schema-1.1.yaml"
    ))
    .expect_err("a 1.1 manifest is rejected before composition");
    assert_eq!(error.code, ManifestErrorCode::InvalidSchemaVersion);

    for schema in ["1.1", "01.02"] {
        let error = assemble_modular_model(
            ModelManifest {
                schema: schema.to_string(),
                contents: vec![PathBuf::from("old.fga")],
            },
            vec![module(
                "old.fga",
                include_str!("fixtures/openfga/modular/validation/old.fga"),
            )],
        )
        .expect_err("a constructed manifest must also be 1.2");
        assert!(matches!(
            error,
            ModularModelError::InvalidManifest { source }
                if source.code == ManifestErrorCode::InvalidSchemaVersion
        ));
    }
}

#[test]
fn exposes_composed_schema_and_aligned_origins() {
    let model = cross_file_model();
    validate_modular_model(&model).expect("assembled model is valid");

    assert_eq!(model.manifest().contents.len(), model.modules().len());
    assert_eq!(
        model.schema().type_definitions.len(),
        model.type_origins().len()
    );
    assert_eq!(
        model.schema().type_definitions.len(),
        model.relation_origins().len()
    );
    assert_eq!(
        model.schema().condition_definitions.len(),
        model.condition_origins().len()
    );
    for (definition, origins) in model
        .schema()
        .type_definitions
        .iter()
        .zip(model.relation_origins())
    {
        assert_eq!(definition.relations.len(), origins.len());
    }
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
