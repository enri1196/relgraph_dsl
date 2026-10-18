//! Replays the pinned `openfga/openfga` Check corpora against Relgraph.
//!
//! The corpora live in `tests/fixtures/authz/upstream/` (see the fixtures
//! README for the `v1.21.0` pin). Reviewed exceptions are in
//! `tests/fixtures/authz/upstream-skip.yaml`; the shared skip-list rules are in
//! `tests/support/skip_list.rs`.
//!
//! # Upstream driver
//!
//! Upstream loads these files in `tests/check/check.go` (`runTests` /
//! `runTest`) at `v1.21.0`. It creates **one store per test** and runs the
//! stages in order against it: each stage writes its model as a new
//! authorization model, writes the stage's tuples (shuffled, in chunks of 40)
//! with `require.NoError`, and runs its `checkAssertions` against that stage's
//! model. Tuples therefore **accumulate across stages**; a stage never starts
//! from an empty store. An assertion without `errorCode` requires `allowed ==
//! expectation` (a missing `expectation` is Go's `false`); one with `errorCode`
//! requires an error whose gRPC status code equals it. Upstream skips a stage
//! whose model fails its internal `modelgraph.New`, and also replays every
//! single-stage test a second time with the stage tuples sent as contextual
//! tuples (`…_ctxTuples`). Neither of those two behaviors is replayed here: the
//! first needs OpenFGA internals, the second needs contextual tuples (Task 7).
//! List assertions are driven by other upstream files and are only parsed here.
//!
//! # Harness
//!
//! This runner mirrors that driver. Per test it creates one
//! `InMemoryRelationshipStore`; per stage it constructs `FgaAuthz::new(model)`,
//! binds it to a clone of that store with default `EvaluationLimits`, and
//! writes the stage tuples through the validating `write_tuple` under one fixed
//! tenant (`condition{name, context}` becomes the stored `ConditionContext`).
//! Case IDs are `file::test-name::stage-index::kind::index` (a repeated test
//! name gets `#n` from its second occurrence):
//!
//! - `model::0` passes when construction succeeds (upstream requires every
//!   corpus model to be written). When it fails, the stage's checks are not
//!   run, and, because their tuples cannot be written through the validating
//!   API, neither are the checks of later stages that would read them.
//! - A rejected tuple write likewise leaves the stage's and later stages'
//!   checks not run, because upstream requires every write to succeed.
//! - `check::i` runs the assertion: `tuple.user` must be a concrete `type:id`
//!   subject (a userset or wildcard check subject is not expressible by
//!   `CheckRequest` and is not run), and `context` becomes the global request
//!   context. Allow/deny is compared with `expectation`; an error with
//!   `errorCode` through [`ERROR_CODE_TABLE`]. An `errorCode` without a table
//!   entry is a harness gap.
//! - Assertions with `contextualTuples` are not run (rule `contextual-tuples`,
//!   Task 7). `listObjectsAssertions` / `listUsersAssertions` entries are
//!   `listObjects::i` / `listUsers::i` and are never run (rules
//!   `list-objects-assertions` / `list-users-assertions`).
//!
//! Every stage's run checks are also replayed through `batch_check`, grouped
//! by subject and context, as `authz_compatibility.rs` does for the hand-written
//! fixtures. A batched result that differs from the individual check is a hard
//! failure, not a skip-list candidate. Run with `-- --nocapture` to see
//! per-file totals.

#[allow(dead_code)] // Shared with relgraph-dsl; this runner does not use every item.
#[path = "support/skip_list.rs"]
mod skip_list;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, CheckRequest, ConditionContext,
    ConstructionError, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ObjectRef,
    RelationName, RelationshipTuple, Subject, TenantId, TupleSubject, TypeName,
};
use serde::Deserialize;
use serde_json::Value;
use skip_list::{CaseResult, NotPassingKind, Outcome, SkipReason};

const UPSTREAM_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/authz/upstream");
const SKIP_LIST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/authz/upstream-skip.yaml"
);
const SKIP_LIST_HEADER: &str = "\
# Reviewed exceptions for the pinned openfga/openfga Check corpora.
# Checked by `cargo test -p relgraph-authz --test upstream_check`; see the
# module docs of tests/upstream_check.rs and CONFORMANCE_PLAN.md.
# Keep sorted and canonical; the test prints the expected form on mismatch.
";

const CONSOLIDATED_FILE: &str = "consolidated_1_1_tests.yaml";
const ABAC_FILE: &str = "abac_tests.yaml";

const CONTEXTUAL_TUPLES_RULE: &str = "contextual-tuples";
const LIST_OBJECTS_RULE: &str = "list-objects-assertions";
const LIST_USERS_RULE: &str = "list-users-assertions";
const KNOWN_RULES: &[&str] = &[CONTEXTUAL_TUPLES_RULE, LIST_OBJECTS_RULE, LIST_USERS_RULE];

/// The single tenant every corpus tuple and check uses.
const TENANT: &str = "upstream-corpus";

/// Harness-local name for a request the typed constructors reject.
const IDENTIFIER_ERROR: &str = "IdentifierError";

/// Upstream Check `errorCode` → Relgraph error variants that count as the same
/// outcome. Codes are `openfga.v1.ErrorCode` values from `openfga/api` at the
/// revision `v1.21.0` pins. Check reports every request-validation failure,
/// including an unknown user type or relation, as `validation_error` (2000);
/// the more specific type/relation codes occur only in list assertions.
const ERROR_CODE_TABLE: &[(i64, &str, &[&str])] = &[
    (
        2000,
        "validation_error",
        &[
            "UnknownObjectType",
            "UnknownSubjectType",
            "UnknownRelation",
            "MissingConditionContext",
            "InvalidConditionContext",
            "ConditionEvaluationFailed",
            IDENTIFIER_ERROR,
        ],
    ),
    (
        2002,
        "authorization_model_resolution_too_complex",
        &["RelationDepthExceeded"],
    ),
    (2027, "invalid_tuple", &["InvalidTuple"]),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusFile {
    tests: Vec<CorpusTest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusTest {
    name: String,
    stages: Vec<Stage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Stage {
    #[serde(default)]
    #[allow(dead_code)] // Upstream's optional stage label; IDs use the index.
    name: Option<String>,
    model: String,
    #[serde(default)]
    tuples: Option<Vec<TupleKey>>,
    #[serde(default)]
    check_assertions: Option<Vec<CheckAssertion>>,
    #[serde(default)]
    list_objects_assertions: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    list_users_assertions: Option<Vec<serde_yaml::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TupleKey {
    user: String,
    relation: String,
    object: String,
    #[serde(default)]
    condition: Option<TupleCondition>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TupleCondition {
    name: String,
    #[serde(default)]
    context: Option<serde_yaml::Value>,
}

/// Mirrors upstream `internal/test/check.Assertion`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckAssertion {
    #[serde(default)]
    #[allow(dead_code)] // Optional upstream label; IDs use the index.
    name: Option<String>,
    tuple: TupleKey,
    #[serde(default)]
    context: Option<serde_yaml::Value>,
    #[serde(default)]
    contextual_tuples: Option<Vec<TupleKey>>,
    #[serde(default)]
    expectation: Option<bool>,
    #[serde(default)]
    error_code: Option<i64>,
}

#[derive(Debug, Default)]
struct FileStats {
    tests: usize,
    stages: usize,
    total: usize,
    pass: usize,
    fail: usize,
    gap: usize,
    not_run: usize,
    by_kind: BTreeMap<&'static str, (usize, usize)>,
    /// Run assertions expecting an error: code → (run, pass).
    error_codes: BTreeMap<i64, (usize, usize)>,
    batches: usize,
    batch_items: usize,
}

/// What one check assertion is expected to produce.
#[derive(Debug, Clone, Copy)]
enum Expected {
    Decision(bool),
    Error(i64),
}

/// A check the harness ran individually, kept for the batch replay.
struct RunCheck {
    id: String,
    request: CheckRequest,
    individual: String,
}

fn read_corpus(file: &str) -> CorpusFile {
    let path = Path::new(UPSTREAM_DIR).join(file);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_yaml::from_str(&text)
        .unwrap_or_else(|error| panic!("could not parse {}: {error}", path.display()))
}

/// Builds `file::name` IDs, appending `#n` to the second and later occurrences.
fn test_ids<'a>(file: &str, names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = HashMap::<&str, usize>::new();
    names
        .map(|name| {
            let count = seen.entry(name).or_default();
            *count += 1;
            if *count == 1 {
                format!("{file}::{name}")
            } else {
                format!("{file}::{name}#{count}")
            }
        })
        .collect()
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

fn json_map(value: Option<&serde_yaml::Value>) -> Result<BTreeMap<String, Value>, String> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    match serde_json::to_value(value).map_err(|error| error.to_string())? {
        Value::Null => Ok(BTreeMap::new()),
        Value::Object(map) => Ok(map.into_iter().collect()),
        other => Err(format!("context is not a mapping: {other}")),
    }
}

fn parse_object(value: &str) -> Result<ObjectRef, String> {
    let (kind, id) = value
        .split_once(':')
        .ok_or_else(|| format!("object is not type:id: {value}"))?;
    ObjectRef::new(kind, id).map_err(|error| format!("object {value}: {error}"))
}

fn parse_tuple_subject(value: &str) -> Result<TupleSubject, String> {
    let (kind, tail) = value
        .split_once(':')
        .ok_or_else(|| format!("user is not type:id: {value}"))?;
    if tail == "*" {
        return TypeName::new(kind)
            .map(TupleSubject::TypedWildcard)
            .map_err(|error| format!("user {value}: {error}"));
    }
    if let Some((id, relation)) = tail.split_once('#') {
        return Ok(TupleSubject::Userset {
            object: ObjectRef::new(kind, id).map_err(|error| format!("user {value}: {error}"))?,
            relation: RelationName::new(relation)
                .map_err(|error| format!("user {value}: {error}"))?,
        });
    }
    Subject::new(kind, tail)
        .map(TupleSubject::Direct)
        .map_err(|error| format!("user {value}: {error}"))
}

fn build_tuple(tenant: &TenantId, raw: &TupleKey) -> Result<RelationshipTuple, String> {
    let mut tuple = RelationshipTuple::new(
        tenant.clone(),
        parse_object(&raw.object)?,
        RelationName::new(raw.relation.as_str())
            .map_err(|error| format!("relation {}: {error}", raw.relation))?,
        parse_tuple_subject(&raw.user)?,
    );
    if let Some(condition) = &raw.condition {
        let context = ConditionContext::new(
            condition.name.as_str(),
            json_map(condition.context.as_ref())?,
        )
        .map_err(|error| format!("condition {}: {error:?}", condition.name))?;
        tuple = tuple.with_condition(context);
    }
    Ok(tuple)
}

/// The check request for an assertion, or why the harness cannot express it.
enum Request {
    Run(CheckRequest),
    /// The typed constructors reject the request (a validation error).
    Invalid(String),
    /// `CheckRequest` has no form for this subject.
    Unsupported(String),
}

fn check_request(tenant: &TenantId, assertion: &CheckAssertion) -> Request {
    let user = assertion.tuple.user.as_str();
    let subject = match parse_tuple_subject(user) {
        Ok(TupleSubject::Direct(subject)) => subject,
        Ok(TupleSubject::Userset { .. }) => {
            return Request::Unsupported(format!(
                "userset check subject {user} is not expressible by CheckRequest"
            ));
        }
        Ok(TupleSubject::TypedWildcard(_)) => {
            return Request::Unsupported(format!(
                "wildcard check subject {user} is not expressible by CheckRequest"
            ));
        }
        Err(error) => return Request::Invalid(error),
    };
    let object = match parse_object(&assertion.tuple.object) {
        Ok(object) => object,
        Err(error) => return Request::Invalid(error),
    };
    let relation = match RelationName::new(assertion.tuple.relation.as_str()) {
        Ok(relation) => relation,
        Err(error) => return Request::Invalid(format!("relation: {error}")),
    };
    let context = match json_map(assertion.context.as_ref()) {
        Ok(context) => context,
        Err(error) => return Request::Invalid(error),
    };
    Request::Run(CheckRequest::new(tenant.clone(), subject, object, relation).with_context(context))
}

fn expected(assertion: &CheckAssertion) -> Expected {
    match assertion.error_code {
        Some(code) if code != 0 => Expected::Error(code),
        _ => Expected::Decision(assertion.expectation.unwrap_or(false)),
    }
}

/// The enum variant name at the start of a `Debug` rendering.
fn variant_name(error: &AuthorizationError) -> String {
    format!("{error:?}")
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect()
}

fn describe_expected(expected: Expected) -> String {
    match expected {
        Expected::Decision(true) => String::from("allow"),
        Expected::Decision(false) => String::from("deny"),
        Expected::Error(code) => match ERROR_CODE_TABLE.iter().find(|(c, ..)| *c == code) {
            Some((_, name, _)) => format!("error {code} ({name})"),
            None => format!("error {code}"),
        },
    }
}

/// Compares one Relgraph outcome (a decision or an error variant name with
/// its rendering) with the upstream expectation.
fn compare(expected: Expected, actual: Result<bool, (String, String)>) -> Outcome {
    let fail = |detail: String| {
        not_passing(
            NotPassingKind::Fail,
            detail,
            SkipReason::SemanticDivergence,
            "4",
        )
    };
    match (expected, actual) {
        (Expected::Decision(want), Ok(got)) if want == got => Outcome::Pass,
        (Expected::Decision(want), Ok(got)) => fail(format!(
            "upstream expects {}; Relgraph {}",
            describe_expected(Expected::Decision(want)),
            if got { "allows" } else { "denies" }
        )),
        (Expected::Decision(want), Err((_, rendered))) => fail(format!(
            "upstream expects {}; Relgraph errors {rendered}",
            describe_expected(Expected::Decision(want))
        )),
        (Expected::Error(code), actual) => {
            let Some((_, _, variants)) = ERROR_CODE_TABLE.iter().find(|(c, ..)| *c == code) else {
                return not_passing(
                    NotPassingKind::HarnessGap,
                    format!("upstream expects error {code}, which has no table entry"),
                    SkipReason::HarnessGap,
                    "4",
                );
            };
            match actual {
                Err((variant, _)) if variants.contains(&variant.as_str()) => Outcome::Pass,
                Err((_, rendered)) => fail(format!(
                    "upstream expects {}; Relgraph errors {rendered}",
                    describe_expected(Expected::Error(code))
                )),
                Ok(got) => fail(format!(
                    "upstream expects {}; Relgraph {}",
                    describe_expected(Expected::Error(code)),
                    if got { "allows" } else { "denies" }
                )),
            }
        }
    }
}

fn construction_outcome(error: &ConstructionError) -> Outcome {
    let (reason, summary) = match error {
        ConstructionError::Parse(_) => {
            (SkipReason::SemanticDivergence, String::from("parse error"))
        }
        ConstructionError::Validation(errors) => (
            SkipReason::SemanticDivergence,
            format!(
                "validation {:?}",
                errors.iter().map(|error| error.issue).collect::<Vec<_>>()
            ),
        ),
        ConstructionError::UnsupportedCapabilities(diagnostics) => (
            SkipReason::UnsupportedFeature,
            format!(
                "unsupported capabilities {:?}",
                diagnostics
                    .iter()
                    .map(|diagnostic| &diagnostic.capability)
                    .collect::<Vec<_>>()
            ),
        ),
        ConstructionError::ConditionCompilation { condition, .. } => (
            SkipReason::UnsupportedFeature,
            format!("condition {condition} does not compile"),
        ),
    };
    not_passing(
        NotPassingKind::Fail,
        format!("upstream accepts the model; Relgraph construction fails: {summary}"),
        reason,
        "4",
    )
}

fn not_run(detail: String, reason: SkipReason, task: &'static str) -> Outcome {
    not_passing(NotPassingKind::NotRun, detail, reason, task)
}

fn render(result: &Result<AuthorizationDecision, AuthorizationError>) -> String {
    format!("{result:?}")
}

/// Replays a stage's run checks as batches and returns every mismatch.
async fn replay_as_batches(
    authz: &FgaAuthz<relgraph_authz::Bound<InMemoryRelationshipStore>>,
    checks: &[RunCheck],
    stats: &mut FileStats,
) -> Vec<String> {
    let mut groups: BTreeMap<(String, String), Vec<&RunCheck>> = BTreeMap::new();
    for check in checks {
        let key = (
            format!("{:?}", check.request.subject()),
            serde_json::to_string(check.request.context()).expect("context serializes"),
        );
        groups.entry(key).or_default().push(check);
    }
    let mut problems = Vec::new();
    for group in groups.values() {
        for chunk in group.chunks(EvaluationLimits::DEFAULT_MAX_BATCH_ITEMS) {
            let first = &chunk[0].request;
            let batch = BatchCheckRequest::new(
                first.tenant().clone(),
                first.subject().clone(),
                chunk.iter().map(|check| {
                    (
                        check.request.object().clone(),
                        check.request.relation().clone(),
                    )
                }),
            )
            .with_context(first.context().clone());
            stats.batches += 1;
            stats.batch_items += chunk.len();
            let batched: Vec<String> = match authz.batch_check(&batch).await {
                Ok(results) => results.iter().map(render).collect(),
                Err(error) => vec![format!("Err({error:?})"); chunk.len()],
            };
            for (check, batched) in chunk.iter().zip(batched) {
                if batched != check.individual {
                    problems.push(format!(
                        "{}: batch_check gave {batched}, check gave {}",
                        check.id, check.individual
                    ));
                }
            }
        }
    }
    problems
}

async fn run_file(
    file: &'static str,
    stats: &mut FileStats,
    results: &mut Vec<CaseResult>,
    contextual: &mut BTreeSet<String>,
    batch_problems: &mut Vec<String>,
) {
    let corpus = read_corpus(file);
    assert!(!corpus.tests.is_empty(), "{file} has no tests");
    let tenant = TenantId::new(TENANT).expect("harness tenant is valid");
    let ids = test_ids(file, corpus.tests.iter().map(|test| test.name.as_str()));
    for (test, test_id) in corpus.tests.iter().zip(ids) {
        stats.tests += 1;
        let store = InMemoryRelationshipStore::new();
        // Why later stages cannot be replayed faithfully, once that happens.
        let mut store_incomplete: Option<String> = None;
        for (stage_index, stage) in test.stages.iter().enumerate() {
            stats.stages += 1;
            let stage_id = format!("{test_id}::{stage_index}");
            let constructed = FgaAuthz::new(&stage.model);
            let tuples = stage.tuples.as_deref().unwrap_or_default();

            let mut stage_block: Option<(String, SkipReason)> = None;
            let authz = match constructed {
                Ok(authz) => {
                    results.push(CaseResult {
                        file,
                        id: format!("{stage_id}::model::0"),
                        outcome: Outcome::Pass,
                    });
                    let authz = authz.with_store(store.clone(), EvaluationLimits::default());
                    if store_incomplete.is_none() {
                        for raw in tuples {
                            let written = match build_tuple(&tenant, raw) {
                                Ok(tuple) => authz
                                    .write_tuple(&tenant, &tuple)
                                    .await
                                    .map_err(|error| format!("{error:?}")),
                                Err(error) => Err(error),
                            };
                            if let Err(error) = written {
                                store_incomplete = Some(format!(
                                    "stage {stage_index} tuple {}#{}@{} was rejected: {error}",
                                    raw.object, raw.relation, raw.user
                                ));
                                break;
                            }
                        }
                    }
                    if let Some(why) = &store_incomplete {
                        stage_block = Some((why.clone(), SkipReason::SemanticDivergence));
                    }
                    Some(authz)
                }
                Err(error) => {
                    let outcome = construction_outcome(&error);
                    let reason = match &outcome {
                        Outcome::NotPassing {
                            suggested_reason, ..
                        } => *suggested_reason,
                        _ => unreachable!("construction failures do not pass"),
                    };
                    results.push(CaseResult {
                        file,
                        id: format!("{stage_id}::model::0"),
                        outcome,
                    });
                    stage_block = Some((
                        format!("stage {stage_index} model construction failed: {error}"),
                        reason,
                    ));
                    if !tuples.is_empty() && store_incomplete.is_none() {
                        store_incomplete = Some(format!(
                            "stage {stage_index} tuples could not be written (model construction failed)"
                        ));
                    }
                    None
                }
            };

            let mut run_checks = Vec::new();
            for (index, assertion) in stage
                .check_assertions
                .as_deref()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                let id = format!("{stage_id}::check::{index}");
                let outcome = if assertion
                    .contextual_tuples
                    .as_ref()
                    .is_some_and(|tuples| !tuples.is_empty())
                {
                    contextual.insert(id.clone());
                    not_run(
                        String::from("assertion uses contextualTuples"),
                        SkipReason::UnsupportedFeature,
                        "7",
                    )
                } else if let Some((why, reason)) = &stage_block {
                    not_run(why.clone(), *reason, "4")
                } else {
                    let authz = authz.as_ref().expect("stage has an authorizer");
                    match check_request(&tenant, assertion) {
                        Request::Unsupported(detail) => {
                            not_run(detail, SkipReason::UnsupportedFeature, "4")
                        }
                        Request::Invalid(detail) => compare(
                            expected(assertion),
                            Err((IDENTIFIER_ERROR.to_owned(), detail)),
                        ),
                        Request::Run(request) => {
                            let result = authz.check(request.clone()).await;
                            let actual = match &result {
                                Ok(decision) => Ok(*decision == AuthorizationDecision::Allow),
                                Err(error) => Err((variant_name(error), format!("{error:?}"))),
                            };
                            run_checks.push(RunCheck {
                                id: id.clone(),
                                request,
                                individual: render(&result),
                            });
                            compare(expected(assertion), actual)
                        }
                    }
                };
                if let Expected::Error(code) = expected(assertion)
                    && !matches!(
                        outcome,
                        Outcome::NotPassing {
                            kind: NotPassingKind::NotRun,
                            ..
                        }
                    )
                {
                    let tally = stats.error_codes.entry(code).or_default();
                    tally.0 += 1;
                    tally.1 += usize::from(outcome == Outcome::Pass);
                }
                results.push(CaseResult { file, id, outcome });
            }
            if let Some(authz) = &authz {
                batch_problems.extend(replay_as_batches(authz, &run_checks, stats).await);
            }

            for (kind, rule, count) in [
                (
                    "listObjects",
                    LIST_OBJECTS_RULE,
                    stage.list_objects_assertions.as_ref().map_or(0, Vec::len),
                ),
                (
                    "listUsers",
                    LIST_USERS_RULE,
                    stage.list_users_assertions.as_ref().map_or(0, Vec::len),
                ),
            ] {
                for index in 0..count {
                    results.push(CaseResult {
                        file,
                        id: format!("{stage_id}::{kind}::{index}"),
                        outcome: not_run(
                            format!("{kind} assertions are not run (rule {rule})"),
                            SkipReason::UnsupportedFeature,
                            "deferred list-API plan",
                        ),
                    });
                }
            }
        }
    }
}

/// The assertion kind segment of a case ID.
fn case_kind(id: &str) -> &'static str {
    ["model", "check", "listObjects", "listUsers"]
        .into_iter()
        .find(|kind| id.contains(&format!("::{kind}::")))
        .expect("every case ID has a kind")
}

#[tokio::test]
async fn upstream_check_corpora_match_or_are_skip_listed() {
    let mut results = Vec::new();
    let mut stats = BTreeMap::<&'static str, FileStats>::new();
    let mut contextual = BTreeSet::new();
    let mut batch_problems = Vec::new();
    for file in [CONSOLIDATED_FILE, ABAC_FILE] {
        run_file(
            file,
            stats.entry(file).or_default(),
            &mut results,
            &mut contextual,
            &mut batch_problems,
        )
        .await;
    }

    for result in &results {
        let file_stats = stats.get_mut(result.file).expect("stats exist per file");
        file_stats.total += 1;
        let by_kind = file_stats.by_kind.entry(case_kind(&result.id)).or_default();
        by_kind.0 += 1;
        match &result.outcome {
            Outcome::Pass => {
                file_stats.pass += 1;
                by_kind.1 += 1;
            }
            Outcome::UpstreamSkip => unreachable!("the Check corpora have no skip flag"),
            Outcome::NotPassing { kind, .. } => match kind {
                NotPassingKind::Fail => file_stats.fail += 1,
                NotPassingKind::HarnessGap => file_stats.gap += 1,
                NotPassingKind::NotRun => file_stats.not_run += 1,
            },
        }
    }

    let mut report = String::new();
    for (file, file_stats) in &stats {
        let kinds = file_stats
            .by_kind
            .iter()
            .map(|(kind, (total, pass))| format!("{kind} {pass}/{total}"))
            .collect::<Vec<_>>()
            .join(", ");
        let error_codes = file_stats
            .error_codes
            .iter()
            .map(|(code, (run, pass))| format!("{code} {pass}/{run}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            report,
            "{file}: {} tests, {} stages, {} cases; {} pass; skip-listed {} (fail {}, \
             harness-gap {}, not-run {}); pass by kind: {kinds}; run error-code checks passing: [{error_codes}]; \
             batch replay {} items in {} batches",
            file_stats.tests,
            file_stats.stages,
            file_stats.total,
            file_stats.pass,
            file_stats.fail + file_stats.gap + file_stats.not_run,
            file_stats.fail,
            file_stats.gap,
            file_stats.not_run,
            file_stats.batch_items,
            file_stats.batches,
        );
    }
    println!("{report}");

    assert!(
        batch_problems.is_empty(),
        "batch_check disagrees with individual checks:\n{}",
        batch_problems.join("\n")
    );

    let rule_covers = |rule: &str, id: &str| match rule {
        CONTEXTUAL_TUPLES_RULE => contextual.contains(id),
        LIST_OBJECTS_RULE => id.contains("::listObjects::"),
        LIST_USERS_RULE => id.contains("::listUsers::"),
        _ => false,
    };
    let list = skip_list::load(Path::new(SKIP_LIST), SKIP_LIST_HEADER)
        .unwrap_or_else(|problems| panic!("{problems}"));
    let problems = skip_list::check(&list, &results, KNOWN_RULES, &rule_covers);
    assert!(
        problems.is_empty(),
        "upstream corpus mismatches:\n{}\n\n{report}",
        problems.join("\n")
    );
}

#[test]
fn test_ids_disambiguate_repeated_names() {
    assert_eq!(
        test_ids("f.yaml", ["a", "b", "a", "a"].into_iter()),
        ["f.yaml::a", "f.yaml::b", "f.yaml::a#2", "f.yaml::a#3"]
    );
}

#[test]
fn error_codes_compare_through_the_table() {
    let error = |variant: &str| Err((variant.to_owned(), variant.to_owned()));
    assert_eq!(
        compare(Expected::Error(2000), error("MissingConditionContext")),
        Outcome::Pass
    );
    assert_eq!(
        compare(Expected::Error(2002), error("RelationDepthExceeded")),
        Outcome::Pass
    );
    assert!(matches!(
        compare(Expected::Error(2002), error("WorkLimitExceeded")),
        Outcome::NotPassing {
            kind: NotPassingKind::Fail,
            ..
        }
    ));
    assert!(matches!(
        compare(Expected::Error(2000), Ok(false)),
        Outcome::NotPassing {
            kind: NotPassingKind::Fail,
            ..
        }
    ));
    assert!(matches!(
        compare(Expected::Error(4000), error("Store")),
        Outcome::NotPassing {
            kind: NotPassingKind::HarnessGap,
            ..
        }
    ));
    assert!(matches!(
        compare(Expected::Decision(false), error("UnknownRelation")),
        Outcome::NotPassing {
            kind: NotPassingKind::Fail,
            ..
        }
    ));
    assert_eq!(compare(Expected::Decision(true), Ok(true)), Outcome::Pass);
}
