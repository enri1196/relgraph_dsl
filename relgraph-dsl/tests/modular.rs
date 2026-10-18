use std::fs;
use std::path::{Path, PathBuf};

use relgraph_dsl::{
    ManifestErrorCode, ModelManifest, ModularModelError, ModuleSource, SchemaHeader,
    ValidationIssue, assemble_modular_model, load_modular_model, parse_fga_schema,
    parse_model_manifest, validate_modular_model,
};
use tempfile::tempdir;

fn manifest(paths: &[&str], schema: &str) -> ModelManifest {
    ModelManifest {
        schema: schema.to_string(),
        contents: paths.iter().map(PathBuf::from).collect(),
    }
}

fn module(path: &str, source: &str) -> ModuleSource {
    ModuleSource {
        path: PathBuf::from(path),
        schema: parse_fga_schema(source).unwrap_or_else(|error| panic!("{path}: {error}")),
    }
}

fn structural_errors(
    manifest: ModelManifest,
    modules: Vec<ModuleSource>,
) -> Vec<relgraph_dsl::ValidationError> {
    match assemble_modular_model(manifest, modules).unwrap_err() {
        ModularModelError::Composition { errors } => errors,
        other => panic!("expected composition error, got {other}"),
    }
}

fn assert_location_file(location: &relgraph_dsl::SourceLocation, path: &str) {
    assert_eq!(location.file.as_deref(), Some(Path::new(path)));
    assert_eq!(location.module.as_deref(), Some("shared"));
    assert!(location.span.is_some());
}

#[test]
fn assembles_extension_before_base_and_tracks_ordered_origins() {
    let manifest =
        parse_model_manifest(include_str!("fixtures/openfga/modular/manifest.yaml")).unwrap();
    let modules = vec![
        module(
            "extensions/document.fga",
            include_str!("fixtures/openfga/modular/extensions/document.fga"),
        ),
        module(
            "base/document.fga",
            include_str!("fixtures/openfga/modular/base/document.fga"),
        ),
        module(
            "base/user.fga",
            include_str!("fixtures/openfga/modular/base/user.fga"),
        ),
    ];

    let model = assemble_modular_model(manifest, modules).unwrap();
    assert_eq!(model.modules().len(), 3);
    assert_eq!(
        model.schema().header,
        SchemaHeader::ModelSchema {
            version: "1.2".to_string()
        }
    );
    assert_eq!(model.schema().header_span, None);
    assert_eq!(
        model
            .schema()
            .type_definitions
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>(),
        ["document", "user"]
    );
    assert!(!model.schema().type_definitions[0].is_extended);
    assert_eq!(
        model.schema().type_definitions[0]
            .relations
            .iter()
            .map(|relation| relation.name.as_str())
            .collect::<Vec<_>>(),
        ["viewer", "editor"]
    );
    assert_eq!(
        model
            .schema()
            .condition_definitions
            .iter()
            .map(|condition| condition.name.as_str())
            .collect::<Vec<_>>(),
        ["can_view", "can_edit"]
    );

    assert_eq!(model.type_origins().len(), 2);
    assert_location_file(&model.type_origins()[0], "base/document.fga");
    assert_location_file(&model.type_origins()[1], "base/user.fga");
    assert_eq!(model.relation_origins().len(), 2);
    assert_eq!(model.relation_origins()[0].len(), 2);
    assert_location_file(&model.relation_origins()[0][0], "base/document.fga");
    assert_location_file(&model.relation_origins()[0][1], "extensions/document.fga");
    assert_eq!(model.condition_origins().len(), 2);
    assert_location_file(&model.condition_origins()[0], "base/document.fga");
    assert_location_file(&model.condition_origins()[1], "base/user.fga");
    assert_eq!(
        model.type_origins()[0].span,
        model.modules()[1].schema.type_definitions[0].span
    );
    assert_eq!(
        model.relation_origins()[0][1].span,
        model.modules()[0].schema.type_definitions[0].relations[0].span
    );
    validate_modular_model(&model).expect("the composed model is semantically valid");
}

#[test]
fn allows_empty_extensions_repeated_module_names_and_skips_semantic_validation() {
    let modules = vec![
        module("extension.fga", "module shared\n\nextend type document\n"),
        module(
            "base.fga",
            "module shared\n\ntype document\n  relations\n    define viewer: [missing]\n",
        ),
    ];
    let model = assemble_modular_model(manifest(&["extension.fga", "base.fga"], "9.7"), modules)
        .expect("composition does not apply version or reference validation");
    assert_eq!(
        model.schema().header,
        SchemaHeader::ModelSchema {
            version: "9.7".to_string()
        }
    );
    assert_eq!(model.schema().type_definitions[0].relations.len(), 1);
    assert_eq!(
        model.modules()[0].schema.header,
        SchemaHeader::Module {
            name: "shared".to_string()
        }
    );
    assert_eq!(
        model.modules()[1].schema.header,
        SchemaHeader::Module {
            name: "shared".to_string()
        }
    );
}

#[test]
fn reports_duplicate_base_types_with_both_document_origins() {
    let errors = structural_errors(
        manifest(&["first.fga", "second.fga"], "1.2"),
        vec![
            module("first.fga", "module shared\n\ntype document\n"),
            module("second.fga", "module shared\n\ntype document\n"),
        ],
    );

    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].issue, ValidationIssue::DuplicateType);
    assert_eq!(errors[0].issue.code(), "DuplicateType");
    assert_location_file(&errors[0].location, "second.fga");
    assert_location_file(&errors[0].related[0], "first.fga");
}

#[test]
fn reports_duplicate_relations_with_both_document_origins() {
    let errors = structural_errors(
        manifest(&["base.fga", "extension.fga"], "1.2"),
        vec![
            module(
                "base.fga",
                "module shared\n\ntype document\n  relations\n    define viewer: [user]\n",
            ),
            module(
                "extension.fga",
                "module shared\n\nextend type document\n  relations\n    define viewer: [user]\n",
            ),
        ],
    );

    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].issue, ValidationIssue::DuplicateRelation);
    assert_eq!(errors[0].issue.code(), "DuplicateRelation");
    assert_location_file(&errors[0].location, "extension.fga");
    assert_location_file(&errors[0].related[0], "base.fga");
}

#[test]
fn reports_extension_without_any_base_type() {
    let errors = structural_errors(
        manifest(&["extension.fga"], "1.2"),
        vec![module(
            "extension.fga",
            "module shared\n\nextend type missing\n  relations\n    define viewer: [user]\n",
        )],
    );

    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].issue, ValidationIssue::UnknownExtensionType);
    assert_eq!(errors[0].issue.code(), "UnknownExtensionType");
    assert_location_file(&errors[0].location, "extension.fga");
    assert!(errors[0].related.is_empty());
}

#[test]
fn reports_same_file_duplicate_extensions_but_allows_them_across_files() {
    let errors = structural_errors(
        manifest(&["base.fga", "extension.fga"], "1.2"),
        vec![
            module("base.fga", "module shared\n\ntype document\n"),
            module(
                "extension.fga",
                "module shared\n\nextend type document\n\nextend type document\n",
            ),
        ],
    );

    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].issue, ValidationIssue::DuplicateExtension);
    assert_eq!(errors[0].issue.code(), "DuplicateExtension");
    assert_location_file(&errors[0].location, "extension.fga");
    assert_location_file(&errors[0].related[0], "extension.fga");

    let model = assemble_modular_model(
        manifest(&["base.fga", "first.fga", "second.fga"], "1.2"),
        vec![
            module("base.fga", "module shared\n\ntype document\n"),
            module("first.fga", "module shared\n\nextend type document\n"),
            module("second.fga", "module shared\n\nextend type document\n"),
        ],
    )
    .unwrap();
    assert_eq!(model.schema().type_definitions.len(), 1);
}

#[test]
fn detects_duplicate_relations_inside_base_and_extension_declarations() {
    let base_errors = structural_errors(
        manifest(&["base.fga"], "1.2"),
        vec![module(
            "base.fga",
            "module shared\n\ntype document\n  relations\n    define viewer: [user]\n    define viewer: [user]\n",
        )],
    );
    assert_eq!(base_errors.len(), 1);
    assert_eq!(base_errors[0].issue, ValidationIssue::DuplicateRelation);
    assert_location_file(&base_errors[0].location, "base.fga");
    assert_location_file(&base_errors[0].related[0], "base.fga");

    let extension_errors = structural_errors(
        manifest(&["base.fga", "extension.fga"], "1.2"),
        vec![
            module("base.fga", "module shared\n\ntype document\n"),
            module(
                "extension.fga",
                "module shared\n\nextend type document\n  relations\n    define editor: [user]\n    define editor: [user]\n",
            ),
        ],
    );
    assert_eq!(extension_errors.len(), 1);
    assert_eq!(
        extension_errors[0].issue,
        ValidationIssue::DuplicateRelation
    );
    assert_location_file(&extension_errors[0].location, "extension.fga");
    assert_location_file(&extension_errors[0].related[0], "extension.fga");
}

#[test]
fn suppresses_extension_merge_conflicts_when_the_base_is_missing_or_ambiguous() {
    let missing = structural_errors(
        manifest(&["first.fga", "second.fga"], "1.2"),
        vec![
            module(
                "first.fga",
                "module shared\n\nextend type ghost\n  relations\n    define viewer: [user]\n",
            ),
            module(
                "second.fga",
                "module shared\n\nextend type ghost\n  relations\n    define viewer: [user]\n",
            ),
        ],
    );
    assert_eq!(missing.len(), 2);
    assert!(
        missing
            .iter()
            .all(|error| error.issue == ValidationIssue::UnknownExtensionType)
    );

    let ambiguous = structural_errors(
        manifest(&["first.fga", "second.fga", "extension.fga"], "1.2"),
        vec![
            module(
                "first.fga",
                "module shared\n\ntype document\n  relations\n    define viewer: [user]\n",
            ),
            module(
                "second.fga",
                "module shared\n\ntype document\n  relations\n    define editor: [user]\n",
            ),
            module(
                "extension.fga",
                "module shared\n\nextend type document\n  relations\n    define editor: [user]\n",
            ),
        ],
    );
    assert_eq!(ambiguous.len(), 1);
    assert_eq!(ambiguous[0].issue, ValidationIssue::DuplicateType);
}

#[test]
fn validates_manual_manifest_values_before_matching_modules() {
    let error = assemble_modular_model(
        manifest(&["./a.fga"], "1.2"),
        vec![module("a.fga", "module shared\n")],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ModularModelError::InvalidManifest { source }
            if source.code == ManifestErrorCode::InvalidPath
                && source.field.as_deref() == Some("contents[0]")
    ));

    let error = assemble_modular_model(
        manifest(&["a.fga"], "not-a-version"),
        vec![module("wrong.fga", "module shared\n")],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ModularModelError::InvalidManifest { source }
            if source.code == ManifestErrorCode::InvalidSchemaVersion
    ));

    for (contents, expected_code) in [
        (Vec::new(), ManifestErrorCode::EmptyContents),
        (
            vec![PathBuf::from("../a.fga")],
            ManifestErrorCode::InvalidPath,
        ),
        (
            vec![PathBuf::from("a.fga"), PathBuf::from("a.fga")],
            ManifestErrorCode::DuplicatePath,
        ),
    ] {
        let error = assemble_modular_model(
            ModelManifest {
                schema: "1.2".to_string(),
                contents,
            },
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ModularModelError::InvalidManifest { source } if source.code == expected_code
        ));
    }
}

#[test]
fn rejects_first_module_count_order_or_path_mismatch() {
    let too_few = assemble_modular_model(
        manifest(&["a.fga", "b.fga"], "1.2"),
        vec![module("a.fga", "module shared\n")],
    )
    .unwrap_err();
    assert!(matches!(
        too_few,
        ModularModelError::InputMismatch { entry: 1, .. }
    ));

    let too_many = assemble_modular_model(
        manifest(&["a.fga"], "1.2"),
        vec![
            module("a.fga", "module shared\n"),
            module("extra.fga", "module shared\n"),
        ],
    )
    .unwrap_err();
    assert!(matches!(
        too_many,
        ModularModelError::InputMismatch { entry: 1, .. }
    ));

    let wrong_order = assemble_modular_model(
        manifest(&["a.fga", "b.fga"], "1.2"),
        vec![
            module("b.fga", "module shared\n"),
            module("a.fga", "module shared\n"),
        ],
    )
    .unwrap_err();
    assert!(matches!(
        wrong_order,
        ModularModelError::InputMismatch { entry: 0, .. }
    ));

    let non_normalized = assemble_modular_model(
        manifest(&["a.fga"], "1.2"),
        vec![module("./a.fga", "module shared\n")],
    )
    .unwrap_err();
    assert!(matches!(
        non_normalized,
        ModularModelError::InputMismatch { entry: 0, .. }
    ));
}

#[test]
fn rejects_non_module_documents_during_assembly() {
    let error = assemble_modular_model(
        manifest(&["model.fga"], "1.2"),
        vec![module("model.fga", "model\n  schema 1.2\n")],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ModularModelError::NonModuleDocument { entry: 0, path }
            if path.as_path() == std::path::Path::new("model.fga")
    ));
}

fn write_manifest(directory: &Path, contents: &str) -> PathBuf {
    let path = directory.join("model.yaml");
    fs::write(&path, format!("schema: '1.2'\ncontents: [{contents}]\n")).unwrap();
    path
}

#[test]
fn loads_modules_and_reports_io_utf8_parse_and_header_errors_with_context() {
    let directory = tempdir().unwrap();
    let manifest_path = write_manifest(directory.path(), "module.fga");

    let missing = load_modular_model(&manifest_path).unwrap_err();
    assert!(matches!(
        missing,
        ModularModelError::Io {
            entry: Some(0),
            path,
            ..
        } if path == directory.path().join("module.fga")
    ));

    fs::write(directory.path().join("module.fga"), [0xff, 0xfe]).unwrap();
    let invalid_utf8 = load_modular_model(&manifest_path).unwrap_err();
    assert!(matches!(
        invalid_utf8,
        ModularModelError::Io {
            entry: Some(0),
            source,
            ..
        } if source.kind() == std::io::ErrorKind::InvalidData
    ));

    fs::write(directory.path().join("module.fga"), "???\n").unwrap();
    let parse_error = load_modular_model(&manifest_path).unwrap_err();
    assert!(matches!(
        parse_error,
        ModularModelError::Parse { entry: 0, path, .. }
            if path.as_path() == std::path::Path::new("module.fga")
    ));

    fs::write(directory.path().join("module.fga"), "model\n  schema 1.2\n").unwrap();
    let header_error = load_modular_model(&manifest_path).unwrap_err();
    assert!(matches!(
        header_error,
        ModularModelError::NonModuleDocument { entry: 0, path }
            if path.as_path() == std::path::Path::new("module.fga")
    ));

    fs::write(
        directory.path().join("module.fga"),
        "module shared\n\ntype user\n",
    )
    .unwrap();
    let model = load_modular_model(&manifest_path).unwrap();
    assert_eq!(model.modules().len(), 1);
    assert_eq!(model.modules()[0].path, PathBuf::from("module.fga"));
}
