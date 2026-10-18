use std::path::PathBuf;

use relgraph_dsl::{ManifestError, ManifestErrorCode, ModelManifest, parse_model_manifest};

fn assert_error(input: &str, code: ManifestErrorCode, field: Option<&str>) -> ManifestError {
    let error = parse_model_manifest(input).expect_err(input);
    assert_eq!(error.code, code, "input: {input}");
    assert_eq!(error.code.code(), format!("{code:?}"));
    assert_eq!(error.field.as_deref(), field, "input: {input}");
    assert!(!error.message.is_empty(), "input: {input}");
    error
}

#[test]
fn parses_ordered_paths_without_io() {
    let parsed =
        parse_model_manifest(include_str!("fixtures/openfga/manifest/ordered.yaml")).unwrap();

    assert_eq!(
        parsed,
        ModelManifest {
            schema: "1.2".to_string(),
            contents: vec![
                PathBuf::from("models/base.fga"),
                PathBuf::from("docs/model source.fga"),
            ],
        }
    );
}

#[test]
fn accepts_yaml_anchors_and_checks_resolved_aliases_as_values() {
    let parsed =
        parse_model_manifest(include_str!("fixtures/openfga/manifest/aliases.yaml")).unwrap();

    assert_eq!(parsed.schema, "1.2");
    assert_eq!(
        parsed.contents,
        vec![
            PathBuf::from("models/base.fga"),
            PathBuf::from("models/extra.fga")
        ]
    );

    // The alias resolves to the string `1.2`, which is not a `.fga` path.
    assert_error(
        "schema: &version '1.2'\ncontents: [*version]\n",
        ManifestErrorCode::InvalidPath,
        Some("contents[0]"),
    );
    assert_error(
        "schema: '1.2'\ncontents: [&base base.fga, *base]\n",
        ManifestErrorCode::DuplicatePath,
        Some("contents[1]"),
    );
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
            PathBuf::from("docs/model.fga")
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
fn accepts_yaml_comments() {
    let parsed = parse_model_manifest(
        "# model version\nschema: '1.2' # YAML comment\ncontents: [model.fga, extra.fga] # files\n",
    )
    .unwrap();

    assert_eq!(parsed.schema, "1.2");
    assert_eq!(
        parsed.contents,
        vec![PathBuf::from("model.fga"), PathBuf::from("extra.fga")]
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
fn requires_the_quoted_schema_version_1_2_and_string_contents() {
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
    for version in [
        "1", "1.", ".1", "1.2.0", "v1.1", "１.2", "1.1", "2.0", "01.02", "1.20", " 1.2",
    ] {
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
        "../a.fga",
        "a/../b.fga",
        "a/../../b.fga",
        "/a.fga",
        "C:models/a.fga",
        "C:/a.fga",
        "a\\b.fga",
        "a\0b.fga",
        "a",
        "a.txt",
        "a.fga.txt",
        "a.fga/b",
        "a%2fb.fga",
        "a%20b.fga",
        "100%.fga",
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

/// Replays each entry of the pinned `fga-mod-transformer-cases.yaml` case
/// "contents path contains dot-dot-slash sequence and other invalid paths" on
/// its own: upstream reports every entry except the first and last, while the
/// corpus runner only gates on the whole manifest being rejected.
#[test]
fn rejects_each_upstream_invalid_contents_item() {
    for path in ["core.fga", "wiki.fga"] {
        parse_model_manifest(&format!("schema: '1.2'\ncontents:\n  - {path}\n")).unwrap();
    }
    for path in [
        "../team1/project.fga",
        "team2/../team3/board.fga",
        "team2\\\\..\\\\team3\\\\board.fga",
        "/absolute/path.fga",
        "\"%2e%2e%2fteam4%2fproject.fga\"",
        "\"%2e%2e%5cteam4%5cproject.fga\"",
    ] {
        assert_error(
            &format!("schema: '1.2'\ncontents:\n  - {path}\n"),
            ManifestErrorCode::InvalidPath,
            Some("contents[0]"),
        );
    }
    assert_error(
        "schema: '1.2'\ncontents:\n  - core.txt\n",
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
