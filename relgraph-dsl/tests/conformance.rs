use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use relgraph_dsl::parse_fga_schema;
use serde::Deserialize;

const FIXTURE_ROOT: &str = "tests/fixtures/openfga";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureMetadata {
    id: String,
    owner_task: String,
    source_url: String,
    production: String,
    /// Relgraph's parse outcome, checked by `parse_fga_schema`.
    expected_parse: String,
    /// The raw pinned grammar's outcome, recorded only where it differs from
    /// `expected_parse` (Relgraph strips `#` comments as the OpenFGA tooling
    /// does; the ANTLR runner checks the grammar alone).
    grammar_parse: Option<String>,
    evidence: String,
    notes: String,
    error_code: Option<String>,
    span_start: Option<usize>,
    span_end: Option<usize>,
}

fn collect_files(path: &Path, extension: &str, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(path).unwrap_or_else(|error| {
        panic!(
            "could not read fixture directory {}: {error}",
            path.display()
        )
    });

    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("could not read entry in {}: {error}", path.display()));
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_files(&entry_path, extension, files);
        } else if entry_path
            .extension()
            .is_some_and(|found| found == extension)
        {
            files.push(entry_path);
        }
    }
}

fn fixtures() -> Vec<(PathBuf, FixtureMetadata)> {
    let root = Path::new(FIXTURE_ROOT);
    let mut source_paths = Vec::new();
    let mut metadata_paths = Vec::new();
    collect_files(&root.join("valid"), "fga", &mut source_paths);
    collect_files(&root.join("invalid"), "fga", &mut source_paths);
    collect_files(&root.join("valid"), "json", &mut metadata_paths);
    collect_files(&root.join("invalid"), "json", &mut metadata_paths);
    source_paths.sort();
    metadata_paths.sort();

    let paired_metadata: BTreeSet<_> = source_paths
        .iter()
        .map(|source| source.with_extension("json"))
        .collect();
    assert_eq!(
        paired_metadata,
        metadata_paths.iter().cloned().collect(),
        "fixture .fga/.json pairing mismatch; sources: {source_paths:#?}; metadata: {metadata_paths:#?}"
    );

    let mut ids = BTreeSet::new();
    source_paths
        .into_iter()
        .map(|source_path| {
            let metadata_path = source_path.with_extension("json");
            let source_text = fs::read_to_string(&source_path).unwrap_or_else(|error| {
                panic!("could not read fixture {}: {error}", source_path.display())
            });
            let metadata_text = fs::read_to_string(&metadata_path).unwrap_or_else(|error| {
                panic!(
                    "could not read metadata {}: {error}",
                    metadata_path.display()
                )
            });
            let metadata: FixtureMetadata =
                serde_json::from_str(&metadata_text).unwrap_or_else(|error| {
                    panic!("invalid metadata {}: {error}", metadata_path.display())
                });

            assert_eq!(
                metadata.id,
                source_path.file_stem().unwrap().to_string_lossy(),
                "fixture ID must match file stem for {}",
                source_path.display()
            );
            assert!(
                ids.insert(metadata.id.clone()),
                "duplicate fixture ID {} at {}",
                metadata.id,
                source_path.display()
            );
            assert!(
                !metadata.owner_task.is_empty(),
                "missing owner_task in {}",
                metadata_path.display()
            );
            assert!(
                !metadata.source_url.is_empty(),
                "missing source_url in {}",
                metadata_path.display()
            );
            assert!(
                !metadata.production.is_empty(),
                "missing production in {}",
                metadata_path.display()
            );
            assert!(
                !metadata.notes.is_empty(),
                "missing notes in {}",
                metadata_path.display()
            );
            assert!(
                matches!(
                    metadata.evidence.as_str(),
                    "grammar-derived" | "upstream-executed"
                ),
                "unknown evidence value {:?} in {}",
                metadata.evidence,
                metadata_path.display()
            );

            if let Some(grammar_parse) = &metadata.grammar_parse {
                assert!(
                    matches!(grammar_parse.as_str(), "accept" | "reject")
                        && grammar_parse != &metadata.expected_parse,
                    "grammar_parse must be accept/reject and differ from expected_parse: {}",
                    metadata_path.display()
                );
            }

            match metadata.expected_parse.as_str() {
                "accept" => assert!(
                    metadata.error_code.is_none()
                        && metadata.span_start.is_none()
                        && metadata.span_end.is_none(),
                    "accepted fixture must not declare rejection diagnostics: {}",
                    metadata_path.display()
                ),
                "reject" => {
                    let (Some(error_code), Some(span_start), Some(span_end)) = (
                        metadata.error_code.as_ref(),
                        metadata.span_start,
                        metadata.span_end,
                    ) else {
                        panic!(
                            "rejected fixture needs error_code and span_start/span_end: {}",
                            metadata_path.display()
                        );
                    };
                    assert!(
                        !error_code.is_empty(),
                        "empty error_code in {}",
                        metadata_path.display()
                    );
                    assert!(
                        span_start <= span_end && span_end <= source_text.len(),
                        "invalid diagnostic span in {}",
                        metadata_path.display()
                    );
                }
                other => panic!(
                    "unknown expected_parse value {other:?} in {}",
                    metadata_path.display()
                ),
            }

            (source_path, metadata)
        })
        .collect()
}

#[test]
fn syntax_fixtures_match_parser_acceptance_and_diagnostics() {
    for (path, metadata) in fixtures() {
        let input = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read fixture {}: {error}", path.display()));
        let parsed = parse_fga_schema(&input);
        match metadata.expected_parse.as_str() {
            "accept" => assert!(
                parsed.is_ok(),
                "fixture {} ({}) should parse, got {parsed:?}",
                path.display(),
                metadata.id
            ),
            "reject" => {
                let error = parsed.unwrap_err();
                assert_eq!(
                    error.code.code(),
                    metadata.error_code.as_deref().unwrap(),
                    "fixture {} ({}) diagnostic code",
                    path.display(),
                    metadata.id
                );
                assert_eq!(
                    (error.span.start, error.span.end),
                    (metadata.span_start.unwrap(), metadata.span_end.unwrap()),
                    "fixture {} ({}) diagnostic span",
                    path.display(),
                    metadata.id
                );
            }
            _ => unreachable!("fixture metadata validated during discovery"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrammarResult {
    fixture_id: String,
    accepted: bool,
    diagnostic_count: usize,
}

/// The recorded ANTLR runner output (`tools/conformance`) must cover every
/// fixture and agree with its raw-grammar outcome: `grammar_parse` where
/// Relgraph deliberately differs, otherwise `expected_parse`.
#[test]
fn recorded_grammar_results_match_fixture_metadata() {
    let results = fs::read_to_string(Path::new(FIXTURE_ROOT).join("upstream-results.jsonl"))
        .expect("recorded ANTLR results should be readable");
    let mut recorded = std::collections::BTreeMap::new();
    for line in results.lines() {
        let result: GrammarResult = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("invalid ANTLR result line {line:?}: {error}"));
        assert_eq!(
            result.accepted,
            result.diagnostic_count == 0,
            "inconsistent ANTLR result {line:?}"
        );
        assert!(
            recorded
                .insert(result.fixture_id.clone(), result.accepted)
                .is_none(),
            "duplicate ANTLR result for {}",
            result.fixture_id
        );
    }

    let fixtures = fixtures();
    assert_eq!(
        recorded.keys().collect::<BTreeSet<_>>(),
        fixtures
            .iter()
            .map(|(_, metadata)| &metadata.id)
            .collect::<BTreeSet<_>>(),
        "ANTLR results and fixtures must name the same IDs"
    );
    for (_, metadata) in &fixtures {
        let grammar = metadata
            .grammar_parse
            .as_deref()
            .unwrap_or(&metadata.expected_parse);
        assert_eq!(
            recorded[&metadata.id],
            grammar == "accept",
            "fixture {} raw-grammar outcome disagrees with the recorded ANTLR result",
            metadata.id
        );
    }
}
