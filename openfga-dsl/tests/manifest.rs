use std::path::PathBuf;

use openfga_dsl::{ManifestError, ManifestErrorCode, ModelManifest, parse_model_manifest};

fn assert_error(input: &str, code: ManifestErrorCode, field: Option<&str>) -> ManifestError {
    let error = parse_model_manifest(input).expect_err(input);
    assert_eq!(error.code, code, "input: {input}");
    assert_eq!(error.code.code(), format!("{code:?}"));
    assert_eq!(error.field.as_deref(), field, "input: {input}");
    assert!(!error.message.is_empty(), "input: {input}");
    error
}

#[test]
fn parses_ordered_paths_without_io_or_suffix_requirements() {
    let parsed =
        parse_model_manifest(include_str!("fixtures/openfga/manifest/ordered.yaml")).unwrap();

    assert_eq!(
        parsed,
        ModelManifest {
            schema: "1.2".to_string(),
            contents: vec![
                PathBuf::from("models/base.fga"),
                PathBuf::from("docs/model source.txt"),
            ],
        }
    );
}

#[test]
fn accepts_unsupported_versions_and_resolved_yaml_aliases() {
    let parsed =
        parse_model_manifest(include_str!("fixtures/openfga/manifest/aliases.yaml")).unwrap();

    assert_eq!(parsed.schema, "2.0");
    assert_eq!(
        parsed.contents,
        vec![PathBuf::from("2.0"), PathBuf::from("models/base.fga")]
    );

    let leading_zeroes =
        parse_model_manifest("schema: '01.02'\ncontents: [models/base.fga]\n").unwrap();
    assert_eq!(leading_zeroes.schema, "01.02");
}

#[test]
fn normalizes_paths_lexically_and_preserves_entry_order() {
    let parsed = parse_model_manifest(include_str!(
        "fixtures/openfga/manifest/normalized_paths.yaml"
    ))
    .unwrap();

    assert_eq!(
        parsed.contents,
        vec![
            PathBuf::from("models/base.fga"),
            PathBuf::from("docs/model.txt")
        ]
    );
}

#[test]
fn enforces_document_yaml_tag_and_root_precedence() {
    assert_error("schema: [\n", ManifestErrorCode::InvalidYaml, None);
    assert_error(
        "schema: '1.2'\ncontents: [a.fga]\n---\nschema: '1.2'\ncontents: [b.fga]\n",
        ManifestErrorCode::InvalidYaml,
        None,
    );
    assert_error(
        "!root [schema, contents]\n---\nschema: '1.2'\ncontents: [a.fga]\n",
        ManifestErrorCode::InvalidYaml,
        None,
    );
    assert_error("!root [invalid\n", ManifestErrorCode::InvalidYaml, None);
    assert_error(
        "schema: !version '1.2'\ncontents: [a.fga]\n",
        ManifestErrorCode::UnsupportedYamlFeature,
        None,
    );
    assert_error(
        "schema: '1.2'\ncontents: [!path a.fga]\n",
        ManifestErrorCode::UnsupportedYamlFeature,
        None,
    );
    assert_error(
        "- schema\n- contents\n",
        ManifestErrorCode::InvalidRoot,
        None,
    );
    assert_error(
        "!root [schema, contents]\n",
        ManifestErrorCode::UnsupportedYamlFeature,
        None,
    );
}

#[test]
fn accepts_yaml_comments_and_resolved_aliases() {
    let parsed = parse_model_manifest(
        "# model version\nschema: &version '1.2' # YAML comment\ncontents: [*version, model.yaml]\n",
    )
    .unwrap();

    assert_eq!(parsed.schema, "1.2");
    assert_eq!(
        parsed.contents,
        vec![PathBuf::from("1.2"), PathBuf::from("model.yaml")]
    );
}

#[test]
fn rejects_recursive_aliases_and_merge_keys() {
    assert_error(
        "schema: '1.2'\ncontents: &loop [*loop]\n",
        ManifestErrorCode::InvalidYaml,
        None,
    );
    assert_error(
        "schema: '1.2'\ncontents: [a.fga]\n<<: {extra: true}\n",
        ManifestErrorCode::UnknownField,
        Some("<<"),
    );
}

#[test]
fn checks_mapping_keys_and_required_fields_in_source_order() {
    assert_error(
        "contents: [a.fga]\n",
        ManifestErrorCode::MissingField,
        Some("schema"),
    );
    assert_error(
        "contents: []\n",
        ManifestErrorCode::MissingField,
        Some("schema"),
    );
    assert_error(
        "schema: '1.2'\n",
        ManifestErrorCode::MissingField,
        Some("contents"),
    );
    assert_error(
        "other: yes\nschema: '1.2'\ncontents: [a.fga]\n",
        ManifestErrorCode::UnknownField,
        Some("other"),
    );
    assert_error(
        "schema: '1.2'\nschema: '1.2'\ncontents: [a.fga]\n",
        ManifestErrorCode::DuplicateField,
        Some("schema"),
    );
    assert_error(
        "? [not, scalar]\n: value\nschema: '1.2'\ncontents: [a.fga]\n",
        ManifestErrorCode::WrongType,
        None,
    );
    assert_error(
        "unknown: x\nschema: '1.2'\nschema: '1.3'\n",
        ManifestErrorCode::UnknownField,
        Some("unknown"),
    );
    assert_error(
        "schema: '1.2'\nschema: '1.3'\nunknown: x\ncontents: [a.fga]\n",
        ManifestErrorCode::DuplicateField,
        Some("schema"),
    );
    assert_error(
        "schema: invalid\n",
        ManifestErrorCode::MissingField,
        Some("contents"),
    );
}

#[test]
fn requires_quoted_numeric_schema_versions_and_string_contents() {
    assert_error(
        "schema: 1.2\ncontents: [a.fga]\n",
        ManifestErrorCode::WrongType,
        Some("schema"),
    );
    assert_error(
        "schema: null\ncontents: []\n",
        ManifestErrorCode::WrongType,
        Some("schema"),
    );
    for version in ["1", "1.", ".1", "1.2.0", "v1.1", "１.2"] {
        assert_error(
            &format!("schema: '{version}'\ncontents: []\n"),
            ManifestErrorCode::InvalidSchemaVersion,
            Some("schema"),
        );
    }
    assert_error(
        "schema: '1.2'\ncontents: a.fga\n",
        ManifestErrorCode::WrongType,
        Some("contents"),
    );
    assert_error(
        "schema: '1.2'\ncontents: null\n",
        ManifestErrorCode::WrongType,
        Some("contents"),
    );
    assert_error(
        "schema: '1.2'\ncontents: []\n",
        ManifestErrorCode::EmptyContents,
        Some("contents"),
    );
    assert_error(
        "schema: '1.2'\ncontents: [a.fga, 4]\n",
        ManifestErrorCode::WrongType,
        Some("contents[1]"),
    );
}

#[test]
fn rejects_invalid_and_duplicate_normalized_paths_in_entry_order() {
    for path in [
        "",
        ".",
        "a/..",
        "../a",
        "a/../../b",
        "/a",
        "C:models/a",
        "C:/a",
        "a\\b",
        "a\0b",
    ] {
        let input = format!("schema: '1.2'\ncontents:\n  - {path:?}\n");
        assert_error(&input, ManifestErrorCode::InvalidPath, Some("contents[0]"));
    }
    assert_error(
        "schema: '1.2'\ncontents: [a/./b.fga, a/b.fga]\n",
        ManifestErrorCode::DuplicatePath,
        Some("contents[1]"),
    );
    assert_error(
        "schema: '1.2'\ncontents: [../bad, 7]\n",
        ManifestErrorCode::InvalidPath,
        Some("contents[0]"),
    );
}

#[test]
fn checks_schema_before_contents_values() {
    assert_error(
        "schema: 'bad'\ncontents: [../bad]\n",
        ManifestErrorCode::InvalidSchemaVersion,
        Some("schema"),
    );
}
