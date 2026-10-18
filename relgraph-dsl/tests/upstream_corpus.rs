//! Replays the pinned `openfga/language` test corpora against Relgraph.
//!
//! The corpora live in `tests/fixtures/openfga/upstream/` (see its README for
//! the pin). Reviewed exceptions are in
//! `tests/fixtures/openfga/upstream-skip.yaml`; the shared skip-list rules are in
//! `tests/support/skip_list.rs`.
//!
//! Both corpora are driven upstream by `validateDSL`
//! (`pkg/js/validator/validate-dsl.ts`, exercised by
//! `pkg/js/tests/validator.test.ts` at the pin). It runs in two stages:
//! `parseDSL` first strips comment lines and ` #` comment tails, parses, and
//! lets its listener report file-local structural errors (an `extend` outside a
//! module, a type extended twice in one file); any of those throws a
//! `DSLSyntaxError` and stops. Otherwise the model is validated, and a module
//! document, which has no schema version, yields only `schema-version-required`.
//! The harness mirrors those stages without copying the comment stripping
//! (Relgraph parses the raw text):
//!
//! - Each DSL case is parsed with `parse_fga_schema`. A `model` document is then
//!   checked with `validate_schema`.
//! - A `module` document is first composed alone, as the single file of a
//!   schema `1.2` manifest, with `assemble_modular_model`. Composition
//!   diagnostics that depend on other files ([`CROSS_FILE_ISSUES`]) are
//!   dropped; any remaining (file-local) ones are the result. Otherwise the
//!   module goes through `validate_schema`, which reports
//!   `ModuleRequiresComposition`, upstream's `schema-version-required`.
//! - When Relgraph reports an issue that upstream raises in its listener
//!   stage ([`LISTENER_STAGE_ISSUES`]), only those issues are compared, because
//!   upstream never reaches validation for such a document.
//!
//! The gate is accept versus reject. For rejected cases the harness compares
//! diagnostic *kinds*, never message text:
//!
//! - An expected ANTLR syntax error (classified by its message prefix, because
//!   the syntax corpus has no `errorType`) requires a Relgraph `ParseError`.
//!   Relgraph stops at the first syntax error and ANTLR recovers, so only the
//!   stage is compared for syntax errors, not their number.
//! - Every other expected error has an upstream `errorType` (or, in the syntax
//!   corpus, a harness-local type derived from the message by
//!   [`SYNTAX_FILE_MESSAGE_TYPES`]). The multiset of those types must equal the
//!   multiset of Relgraph `ValidationIssue`s mapped through [`ERROR_TYPE_TABLE`];
//!   one issue may map to several upstream types, so the comparison is a
//!   perfect bipartite matching.
//! - `ValidationError` has no symbol field, so upstream `metadata.symbol` is
//!   not gated. It is reported as a metric: whether the symbol text occurs
//!   inside a Relgraph diagnostic span.
//! - Line and column positions are reported as a metric only: the share of
//!   expected errors that start where a Relgraph diagnostic span starts.
//!   Relgraph validation spans cover the owning declaration, and ANTLR's error
//!   recovery positions differ, so this is not gated.
//! - An expectation the harness cannot classify, or a Relgraph diagnostic with
//!   no table entry, makes the case a harness gap rather than a pass or fail.
//!
//! `fga-mod-transformer-cases.yaml` runs `modFile` through
//! `parse_model_manifest` and gates on accept versus reject only. Its expected
//! `json` output is a separate never-run case (`…::json`) covered by the
//! `fga-mod-json-output` rule. Manifest errors carry no spans, so no position
//! metric is computed for that file.
//!
//! Upstream cases marked `skip: true` are not run or gated. Run with
//! `-- --nocapture` to see per-file totals and metrics.

mod support;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use relgraph_dsl::{
    ModelManifest, ModularModelError, ModuleSource, ParseError, SchemaHeader, SourceSpan,
    ValidationError, ValidationIssue, assemble_modular_model, parse_fga_schema,
    parse_model_manifest, validate_schema,
};
use serde::Deserialize;
use support::skip_list::{self, CaseResult, NotPassingKind, Outcome, SkipReason};

const UPSTREAM_DIR: &str = "tests/fixtures/openfga/upstream";
const SKIP_LIST: &str = "tests/fixtures/openfga/upstream-skip.yaml";
const SKIP_LIST_HEADER: &str = "\
# Reviewed exceptions for the pinned openfga/language corpora.
# Checked by `cargo test -p relgraph_dsl --test upstream_corpus`; see the
# module docs of tests/upstream_corpus.rs and CONFORMANCE_PLAN.md.
# Keep sorted and canonical; the test prints the expected form on mismatch.
";

const SYNTAX_FILE: &str = "dsl-syntax-validation-cases.yaml";
const SEMANTIC_FILE: &str = "dsl-semantic-validation-cases.yaml";
const FGA_MOD_FILE: &str = "fga-mod-transformer-cases.yaml";

const FGA_MOD_JSON_RULE: &str = "fga-mod-json-output";
const KNOWN_RULES: &[&str] = &[FGA_MOD_JSON_RULE];

/// Path given to a lone module document when it is composed for validation.
const MODULE_PATH: &str = "module.fga";

/// Harness-local type for "extend can only be used in a modular model".
const EXTEND_OUTSIDE_MODEL: &str = "syntax-file:extend-outside-model";
/// Harness-local type for "'x' is already extended in file.".
const DUPLICATE_EXTENSION: &str = "syntax-file:duplicate-extension";

/// Upstream `errorType` (or harness-local type) to Relgraph issue.
///
/// An upstream type may have several Relgraph counterparts and one Relgraph
/// issue may stand for several upstream types; the comparison accepts any
/// pairing listed here.
const ERROR_TYPE_TABLE: &[(&str, ValidationIssue)] = &[
    ("condition-not-defined", ValidationIssue::UnknownCondition),
    ("condition-not-used", ValidationIssue::UnusedCondition),
    ("duplicated-error", ValidationIssue::DuplicateCondition),
    ("duplicated-error", ValidationIssue::DuplicateParameter),
    ("duplicated-error", ValidationIssue::DuplicateOperand),
    ("duplicated-error", ValidationIssue::DuplicateRelation),
    ("duplicated-error", ValidationIssue::DuplicateType),
    (
        "duplicated-error",
        ValidationIssue::DuplicateTypeRestriction,
    ),
    // `x from parent` where no type of `parent` defines `x`.
    (
        "invalid-relation-on-tupleset",
        ValidationIssue::UnknownComputedRelation,
    ),
    // `[group#missing]` restrictions.
    ("invalid-relation-type", ValidationIssue::UnknownRelation),
    // `x from missing` where the tupleset relation does not exist.
    (
        "invalid-relation-type",
        ValidationIssue::UnknownTuplesetRelation,
    ),
    ("invalid-name", ValidationIssue::InvalidName),
    ("invalid-schema", ValidationIssue::UnsupportedSchemaVersion),
    ("invalid-type", ValidationIssue::UnknownType),
    // A computed userset naming a relation the type lacks.
    ("missing-definition", ValidationIssue::UnknownRelation),
    ("relation-no-entry-point", ValidationIssue::NoEntryPoint),
    (
        "reserved-relation-keywords",
        ValidationIssue::ReservedRelationName,
    ),
    ("reserved-type-keywords", ValidationIssue::ReservedTypeName),
    // Upstream reports a lone module validated standalone this way.
    (
        "schema-version-required",
        ValidationIssue::ModuleRequiresComposition,
    ),
    (
        "tupleuserset-not-direct",
        ValidationIssue::InvalidTuplesetRelation,
    ),
    (
        EXTEND_OUTSIDE_MODEL,
        ValidationIssue::ExtensionOutsideModule,
    ),
    (DUPLICATE_EXTENSION, ValidationIssue::DuplicateExtension),
];

/// Issues that upstream's parse listener raises as a `DSLSyntaxError` before
/// semantic validation runs. When Relgraph reports any of them, later-stage
/// issues (for example `EmptyModel` for a model that only extends a type) are
/// not compared.
const LISTENER_STAGE_ISSUES: &[ValidationIssue] = &[
    ValidationIssue::ExtensionOutsideModule,
    ValidationIssue::DuplicateExtension,
];

/// Composition issues that depend on other module files. Upstream checks one
/// module file at a time, so a lone module is not judged on them.
const CROSS_FILE_ISSUES: &[ValidationIssue] = &[ValidationIssue::UnknownExtensionType];

/// Upstream error types that Relgraph validation does not diagnose at all
/// (none at the current pin). A failing case expecting one is suggested as
/// `unsupported-feature`.
const UPSTREAM_TYPES_WITHOUT_COUNTERPART: &[&str] = &[];

/// Message prefixes of ANTLR parser diagnostics in the syntax corpus.
const ANTLR_MESSAGE_PREFIXES: &[&str] = &[
    "extraneous input ",
    "mismatched input ",
    "missing ",
    "no viable alternative at input ",
    "token recognition error",
];

/// Syntax-corpus messages (which have no `errorType`) to an error type.
const SYNTAX_FILE_MESSAGE_TYPES: &[(&str, &str)] = &[
    ("is already defined", "duplicated-error"),
    (
        "extend can only be used in a modular model",
        EXTEND_OUTSIDE_MODEL,
    ),
    ("is already extended in file", DUPLICATE_EXTENSION),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DslCase {
    name: String,
    dsl: String,
    #[serde(default)]
    expected_errors: Option<Vec<ExpectedError>>,
    #[serde(default)]
    skip: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedError {
    msg: String,
    line: Range,
    column: Range,
    #[serde(default)]
    metadata: Option<ErrorMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    start: usize,
    #[allow(dead_code)]
    end: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorMetadata {
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default, rename = "errorType")]
    error_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FgaModCase {
    name: String,
    #[serde(rename = "modFile")]
    mod_file: String,
    #[serde(default)]
    json: Option<String>,
    #[serde(default)]
    expected_errors: Option<Vec<FgaModError>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FgaModError {
    #[allow(dead_code)]
    msg: String,
    #[allow(dead_code)]
    line: Range,
    #[allow(dead_code)]
    column: Range,
}

/// Classified upstream expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expected {
    Syntax,
    Typed(String),
    Unclassified(String),
}

/// What Relgraph did with a DSL document.
enum Actual {
    Accepted,
    Parse(ParseError),
    Validation(Vec<ValidationError>),
    Other(String),
}

impl Actual {
    fn spans(&self) -> Vec<SourceSpan> {
        match self {
            Self::Parse(error) => vec![error.span.clone()],
            Self::Validation(errors) => errors
                .iter()
                .filter_map(|error| error.location.span.clone())
                .collect(),
            Self::Accepted | Self::Other(_) => Vec::new(),
        }
    }

    fn describe(&self, source: &str) -> String {
        match self {
            Self::Accepted => String::from("Relgraph accepts"),
            Self::Parse(error) => {
                let (line, column) = line_column(source, error.span.start);
                format!(
                    "Relgraph parse error {} at {line}:{column}",
                    error.code.code()
                )
            }
            Self::Validation(errors) => format!(
                "Relgraph validation [{}]",
                errors
                    .iter()
                    .map(|error| error.issue.code())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Other(message) => format!("Relgraph composition error: {message}"),
        }
    }
}

#[derive(Default)]
struct FileStats {
    total: usize,
    pass: usize,
    fail: usize,
    gap: usize,
    not_run: usize,
    upstream_skip: usize,
    positions_matched: usize,
    positions_total: usize,
    symbols_matched: usize,
    symbols_total: usize,
}

fn read_corpus<T: for<'de> Deserialize<'de>>(file: &str) -> Vec<T> {
    let path = Path::new(UPSTREAM_DIR).join(file);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_yaml::from_str(&text)
        .unwrap_or_else(|error| panic!("could not deserialize {}: {error}", path.display()))
}

/// Builds `file::name` IDs, appending `#n` from a name's second occurrence.
fn case_ids<'a>(file: &str, names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut occurrences = HashMap::<&str, usize>::new();
    names
        .map(|name| {
            let count = occurrences.entry(name).or_default();
            *count += 1;
            if *count == 1 {
                format!("{file}::{name}")
            } else {
                format!("{file}::{name}#{count}")
            }
        })
        .collect()
}

fn run_dsl(dsl: &str) -> Actual {
    let schema = match parse_fga_schema(dsl) {
        Ok(schema) => schema,
        Err(error) => return Actual::Parse(error),
    };
    if let SchemaHeader::Module { .. } = schema.header {
        let manifest = ModelManifest {
            schema: String::from("1.2"),
            contents: vec![PathBuf::from(MODULE_PATH)],
        };
        let module = ModuleSource {
            path: PathBuf::from(MODULE_PATH),
            schema: schema.clone(),
        };
        match assemble_modular_model(manifest, vec![module]) {
            Ok(_) => {}
            Err(ModularModelError::Composition { errors }) => {
                let local: Vec<ValidationError> = errors
                    .into_iter()
                    .filter(|error| !CROSS_FILE_ISSUES.contains(&error.issue))
                    .collect();
                if !local.is_empty() {
                    return Actual::Validation(listener_stage(local));
                }
            }
            Err(other) => return Actual::Other(other.to_string()),
        }
    }
    match validate_schema(&schema) {
        Ok(()) => Actual::Accepted,
        Err(errors) => Actual::Validation(listener_stage(errors)),
    }
}

/// Keeps only the listener-stage issues when there are any (see the module
/// docs).
fn listener_stage(errors: Vec<ValidationError>) -> Vec<ValidationError> {
    if errors
        .iter()
        .any(|error| LISTENER_STAGE_ISSUES.contains(&error.issue))
    {
        errors
            .into_iter()
            .filter(|error| LISTENER_STAGE_ISSUES.contains(&error.issue))
            .collect()
    } else {
        errors
    }
}

fn classify(file: &str, error: &ExpectedError) -> Expected {
    if let Some(error_type) = error
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.error_type.as_ref())
    {
        let known = ERROR_TYPE_TABLE.iter().any(|(name, _)| name == error_type)
            || UPSTREAM_TYPES_WITHOUT_COUNTERPART.contains(&error_type.as_str());
        return if known {
            Expected::Typed(error_type.clone())
        } else {
            Expected::Unclassified(format!("unknown errorType {error_type:?}"))
        };
    }
    if file == SYNTAX_FILE {
        if ANTLR_MESSAGE_PREFIXES
            .iter()
            .any(|prefix| error.msg.starts_with(prefix))
        {
            return Expected::Syntax;
        }
        if let Some((_, error_type)) = SYNTAX_FILE_MESSAGE_TYPES
            .iter()
            .find(|(pattern, _)| error.msg.contains(pattern))
        {
            return Expected::Typed((*error_type).to_owned());
        }
    }
    Expected::Unclassified(format!("no errorType for message {:?}", error.msg))
}

fn upstream_types_for(issue: ValidationIssue) -> Vec<&'static str> {
    ERROR_TYPE_TABLE
        .iter()
        .filter(|(_, mapped)| *mapped == issue)
        .map(|(name, _)| *name)
        .collect()
}

/// Kuhn's augmenting-path matching: true when every expected type pairs with a
/// distinct Relgraph diagnostic and no diagnostic is left over.
fn perfect_matching(expected: &[String], candidates: &[Vec<&'static str>]) -> bool {
    fn augment(
        left: usize,
        expected: &[String],
        candidates: &[Vec<&'static str>],
        visited: &mut [bool],
        owner: &mut [Option<usize>],
    ) -> bool {
        for right in 0..candidates.len() {
            if visited[right] || !candidates[right].contains(&expected[left].as_str()) {
                continue;
            }
            visited[right] = true;
            if owner[right].is_none_or(|other| augment(other, expected, candidates, visited, owner))
            {
                owner[right] = Some(left);
                return true;
            }
        }
        false
    }

    if expected.len() != candidates.len() {
        return false;
    }
    let mut owner = vec![None; candidates.len()];
    (0..expected.len()).all(|left| {
        let mut visited = vec![false; candidates.len()];
        augment(left, expected, candidates, &mut visited, &mut owner)
    })
}

fn summarize(expected: &[Expected]) -> String {
    let mut counts = BTreeMap::<String, usize>::new();
    for item in expected {
        let label = match item {
            Expected::Syntax => String::from("syntax"),
            Expected::Typed(name) => name.clone(),
            Expected::Unclassified(_) => String::from("unclassified"),
        };
        *counts.entry(label).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(label, count)| {
            if count == 1 {
                label
            } else {
                format!("{label} x{count}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn not_passing(
    kind: NotPassingKind,
    detail: String,
    suggested_reason: SkipReason,
    suggested_task: &'static str,
) -> Outcome {
    Outcome::NotPassing {
        kind,
        detail,
        suggested_reason,
        suggested_task,
    }
}

fn compare_dsl(expected: &[Expected], actual: &Actual, source: &str) -> Outcome {
    let summary = format!(
        "upstream expects [{}]; {}",
        summarize(expected),
        actual.describe(source)
    );
    if expected.is_empty() {
        return match actual {
            Actual::Accepted => Outcome::Pass,
            _ => not_passing(
                NotPassingKind::Fail,
                format!("upstream accepts; {}", actual.describe(source)),
                SkipReason::SemanticDivergence,
                "4",
            ),
        };
    }
    if let Some(Expected::Unclassified(why)) = expected
        .iter()
        .find(|item| matches!(item, Expected::Unclassified(_)))
    {
        return not_passing(
            NotPassingKind::HarnessGap,
            format!("{summary}; unclassified expectation: {why}"),
            SkipReason::HarnessGap,
            "4",
        );
    }
    let lacks_counterpart = expected.iter().any(|item| {
        matches!(item, Expected::Typed(name)
            if UPSTREAM_TYPES_WITHOUT_COUNTERPART.contains(&name.as_str()))
    });
    let (reason, task) = if lacks_counterpart {
        (SkipReason::UnsupportedFeature, "5")
    } else {
        (SkipReason::SemanticDivergence, "4")
    };
    let fail = |summary: String| not_passing(NotPassingKind::Fail, summary, reason, task);
    let expects_syntax = expected.contains(&Expected::Syntax);
    match actual {
        Actual::Accepted | Actual::Other(_) => fail(summary),
        Actual::Parse(_) => {
            if expected.iter().all(|item| *item == Expected::Syntax) {
                Outcome::Pass
            } else {
                // Upstream parses this document, so the parser is the first
                // divergence regardless of which validation rule follows.
                not_passing(
                    NotPassingKind::Fail,
                    summary,
                    SkipReason::SemanticDivergence,
                    "4",
                )
            }
        }
        Actual::Validation(errors) => {
            if expects_syntax {
                return fail(summary);
            }
            let candidates: Vec<Vec<&'static str>> = errors
                .iter()
                .map(|error| upstream_types_for(error.issue))
                .collect();
            if let Some(unmapped) = errors
                .iter()
                .zip(&candidates)
                .find(|(_, candidates)| candidates.is_empty())
            {
                return not_passing(
                    NotPassingKind::HarnessGap,
                    format!("{summary}; no table entry for {}", unmapped.0.issue.code()),
                    SkipReason::HarnessGap,
                    "4",
                );
            }
            let expected_types: Vec<String> = expected
                .iter()
                .map(|item| match item {
                    Expected::Typed(name) => name.clone(),
                    Expected::Syntax | Expected::Unclassified(_) => unreachable!(),
                })
                .collect();
            if perfect_matching(&expected_types, &candidates) {
                Outcome::Pass
            } else {
                fail(summary)
            }
        }
    }
}

/// Zero-based (line, column) of a byte offset, counting columns in characters.
fn line_column(source: &str, offset: usize) -> (usize, usize) {
    let before = &source[..offset.min(source.len())];
    let line = before.matches('\n').count();
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    (line, before[line_start..].chars().count())
}

fn record_metrics(stats: &mut FileStats, dsl: &str, errors: &[ExpectedError], actual: &Actual) {
    if matches!(actual, Actual::Accepted | Actual::Other(_)) {
        return;
    }
    let spans = actual.spans();
    let starts: Vec<(usize, usize)> = spans
        .iter()
        .map(|span| line_column(dsl, span.start))
        .collect();
    for error in errors {
        stats.positions_total += 1;
        if starts.contains(&(error.line.start, error.column.start)) {
            stats.positions_matched += 1;
        }
        let symbol = error
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.symbol.as_deref())
            .filter(|symbol| !symbol.trim().is_empty() && *symbol != "<EOF>");
        if let Some(symbol) = symbol {
            stats.symbols_total += 1;
            if spans.iter().any(|span| {
                dsl.get(span.start..span.end)
                    .is_some_and(|text| text.contains(symbol))
            }) {
                stats.symbols_matched += 1;
            }
        }
    }
}

fn run_dsl_file(file: &'static str, stats: &mut FileStats, results: &mut Vec<CaseResult>) {
    let cases: Vec<DslCase> = read_corpus(file);
    assert!(!cases.is_empty(), "{file} has no cases");
    let ids = case_ids(file, cases.iter().map(|case| case.name.as_str()));
    for (case, id) in cases.iter().zip(ids) {
        stats.total += 1;
        let outcome = if case.skip {
            Outcome::UpstreamSkip
        } else {
            let errors = case.expected_errors.as_deref().unwrap_or_default();
            let expected: Vec<Expected> =
                errors.iter().map(|error| classify(file, error)).collect();
            let actual = run_dsl(&case.dsl);
            record_metrics(stats, &case.dsl, errors, &actual);
            compare_dsl(&expected, &actual, &case.dsl)
        };
        results.push(CaseResult { file, id, outcome });
    }
}

fn run_fga_mod_file(stats: &mut FileStats, results: &mut Vec<CaseResult>) {
    let cases: Vec<FgaModCase> = read_corpus(FGA_MOD_FILE);
    assert!(!cases.is_empty(), "{FGA_MOD_FILE} has no cases");
    let ids = case_ids(FGA_MOD_FILE, cases.iter().map(|case| case.name.as_str()));
    for (case, id) in cases.iter().zip(ids) {
        stats.total += 1;
        let expect_reject = case
            .expected_errors
            .as_ref()
            .is_some_and(|errors| !errors.is_empty());
        let actual = parse_model_manifest(&case.mod_file);
        let outcome = match (&actual, expect_reject) {
            (Ok(_), false) | (Err(_), true) => Outcome::Pass,
            (Ok(_), true) => not_passing(
                NotPassingKind::Fail,
                String::from("upstream rejects; Relgraph accepts the manifest"),
                SkipReason::SemanticDivergence,
                "6",
            ),
            (Err(error), false) => not_passing(
                NotPassingKind::Fail,
                format!(
                    "upstream accepts; Relgraph rejects with {}",
                    error.code.code()
                ),
                SkipReason::SemanticDivergence,
                "6",
            ),
        };
        if case.json.is_some() {
            stats.total += 1;
            results.push(CaseResult {
                file: FGA_MOD_FILE,
                id: format!("{id}::json"),
                outcome: not_passing(
                    NotPassingKind::NotRun,
                    String::from("JSON transformer output is not compared"),
                    SkipReason::UnsupportedFeature,
                    "permanent",
                ),
            });
        }
        results.push(CaseResult {
            file: FGA_MOD_FILE,
            id,
            outcome,
        });
    }
}

fn rule_covers(rule: &str, id: &str) -> bool {
    match rule {
        FGA_MOD_JSON_RULE => id.starts_with(&format!("{FGA_MOD_FILE}::")) && id.ends_with("::json"),
        _ => false,
    }
}

fn format_counts(counts: Option<&BTreeMap<String, usize>>) -> String {
    match counts {
        Some(counts) if !counts.is_empty() => counts
            .iter()
            .map(|(label, count)| format!("{label} {count}"))
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::from("none"),
    }
}

fn percent(matched: usize, total: usize) -> String {
    if total == 0 {
        String::from("n/a")
    } else {
        format!(
            "{matched}/{total} ({:.0}%)",
            matched as f64 * 100.0 / total as f64
        )
    }
}

#[test]
fn upstream_language_corpora_match_or_are_skip_listed() {
    let mut results = Vec::new();
    let mut stats = BTreeMap::<&'static str, FileStats>::new();
    for file in [SYNTAX_FILE, SEMANTIC_FILE] {
        run_dsl_file(file, stats.entry(file).or_default(), &mut results);
    }
    run_fga_mod_file(stats.entry(FGA_MOD_FILE).or_default(), &mut results);

    for result in &results {
        let file_stats = stats.get_mut(result.file).expect("stats exist per file");
        match &result.outcome {
            Outcome::Pass => file_stats.pass += 1,
            Outcome::UpstreamSkip => file_stats.upstream_skip += 1,
            Outcome::NotPassing { kind, .. } => match kind {
                NotPassingKind::Fail => file_stats.fail += 1,
                NotPassingKind::HarnessGap => file_stats.gap += 1,
                NotPassingKind::NotRun => file_stats.not_run += 1,
            },
        }
    }

    let list = skip_list::load(Path::new(SKIP_LIST), SKIP_LIST_HEADER)
        .unwrap_or_else(|problems| panic!("{problems}"));
    let by_reason = skip_list::covered_counts(&list, &results, &rule_covers);

    let mut report = String::new();
    for (file, file_stats) in &stats {
        let _ = writeln!(
            report,
            "{file}: {} cases; {} pass; skip-listed {} (fail {}, harness-gap {}, not-run {}); \
             upstream skip {}; positions {}; symbols {}",
            file_stats.total,
            file_stats.pass,
            file_stats.fail + file_stats.gap + file_stats.not_run,
            file_stats.fail,
            file_stats.gap,
            file_stats.not_run,
            file_stats.upstream_skip,
            if *file == FGA_MOD_FILE {
                String::from("n/a (manifest errors carry no spans)")
            } else {
                percent(file_stats.positions_matched, file_stats.positions_total)
            },
            if *file == FGA_MOD_FILE {
                String::from("n/a")
            } else {
                percent(file_stats.symbols_matched, file_stats.symbols_total)
            },
        );
        let _ = writeln!(
            report,
            "  skipped by reason/tag: {}",
            format_counts(by_reason.get(file))
        );
    }
    println!("{report}");

    let problems = skip_list::check(&list, &results, KNOWN_RULES, &rule_covers);
    assert!(
        problems.is_empty(),
        "upstream corpus mismatches:\n{}\n\n{report}",
        problems.join("\n")
    );
}

#[test]
fn case_ids_disambiguate_repeated_names() {
    assert_eq!(
        case_ids("f.yaml", ["a", "b", "a", "a"].into_iter()),
        ["f.yaml::a", "f.yaml::b", "f.yaml::a#2", "f.yaml::a#3"]
    );
}

#[test]
fn matching_accepts_any_listed_pairing() {
    let expected = vec![
        String::from("missing-definition"),
        String::from("invalid-relation-type"),
    ];
    let both = vec!["invalid-relation-type", "missing-definition"];
    assert!(perfect_matching(
        &expected,
        &[vec!["invalid-relation-type"], both.clone()]
    ));
    assert!(!perfect_matching(&expected, std::slice::from_ref(&both)));
    assert!(!perfect_matching(
        &expected,
        &[vec!["invalid-relation-type"], vec!["invalid-relation-type"]]
    ));
}

#[test]
fn skip_list_rejects_stale_uncovered_and_unknown_entries() {
    use support::skip_list::{SkipEntry, SkipList};

    let entry = |case: Option<&str>, rule: Option<&str>| SkipEntry {
        case: case.map(str::to_owned),
        rule: rule.map(str::to_owned),
        reason: SkipReason::SemanticDivergence,
        tag: String::from("bug"),
        task: String::from("5"),
        justification: String::from("test"),
    };
    let failing = |id: &str| CaseResult {
        file: SYNTAX_FILE,
        id: id.to_owned(),
        outcome: not_passing(
            NotPassingKind::Fail,
            String::from("differs"),
            SkipReason::SemanticDivergence,
            "4",
        ),
    };
    let passing = |id: &str| CaseResult {
        file: SYNTAX_FILE,
        id: id.to_owned(),
        outcome: Outcome::Pass,
    };
    let results = [failing("f::a::0"), passing("f::b"), failing("f::c")];
    let never = |_: &str, _: &str| false;

    let covered = SkipList {
        entries: vec![entry(Some("f::a"), None), entry(Some("f::c"), None)],
    };
    assert!(skip_list::check(&covered, &results, &[], &never).is_empty());

    let problems = skip_list::check(
        &SkipList {
            entries: vec![
                entry(Some("f::a"), None),
                entry(Some("f::b"), None),
                entry(Some("f::"), None),
                entry(None, Some("unknown")),
            ],
        },
        &results,
        &[],
        &never,
    );
    let text = problems.join("\n");
    assert!(text.contains("case f::b is stale"), "{text}");
    assert!(text.contains("case f:: covers no corpus case"), "{text}");
    assert!(text.contains("unknown skip rule"), "{text}");
    assert!(text.contains("f::c is not covered"), "{text}");
}
