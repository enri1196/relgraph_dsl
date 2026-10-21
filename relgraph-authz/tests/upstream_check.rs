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
//! requires an error whose gRPC status code equals it. An assertion's
//! `contextualTuples` go into the Check request; the server validates them like
//! written tuples (`invalid_tuple`, 2027) after the checked tuple key. Upstream
//! skips a stage whose model fails its internal `modelgraph.New` (not replayed
//! here: it needs OpenFGA internals). It also runs every **single-stage** test a
//! second time (`…_ctxTuples`) against an empty store, sending the assertion's
//! contextual tuples followed by the stage tuples as contextual tuples, and
//! skips that stage when it has more than 100 tuples (the API limit). The
//! same files' `listObjectsAssertions` / `listUsersAssertions` are run by
//! upstream's ListObjects and ListUsers test drivers; this runner replays
//! them against the same per-test store as the checks. An assertion without
//! `errorCode` is compared with `expectation` as a set (null or missing is
//! empty).
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
//!   `check` cases not run, because upstream requires every write to succeed.
//! - `check::i` runs the assertion: `tuple.user` becomes the check subject (a
//!   concrete `type:id`, a userset `type:id#relation` or a typed wildcard
//!   `type:*`, as `CheckRequest` accepts all three), `context` becomes the global request
//!   context, and `contextualTuples` become the request's contextual tuples
//!   (same tenant). Allow/deny is compared with `expectation`; an error with
//!   `errorCode` through [`CHECK_ERROR_CODES`]. An `errorCode` without a table
//!   entry is a harness gap.
//! - `ctxCheck::i` is upstream's `_ctxTuples` replay of `check::i`, for
//!   single-stage tests with at most `MAX_CONTEXTUAL_TUPLES` stage tuples: the
//!   same model bound to a new empty store, with the stage tuples appended to
//!   the assertion's contextual tuples. Only a failed model construction
//!   blocks it.
//! - `listObjects::i` runs a `listObjectsAssertions` entry through
//!   `FgaAuthz::list_objects` (`request.user` as the subject, in the same
//!   three forms) and `listUsers::i` a `listUsersAssertions` entry through
//!   `FgaAuthz::list_users` (its one `filters` entry parsed as a
//!   `UserFilter`; more than one is a harness gap), both against the stage's
//!   store with the assertion's `context` and `contextualTuples`. Results are
//!   rendered as `type:id`, `type:id#relation` or `type:*` and compared with
//!   `expectation` after sorting; an `errorCode` goes through the kind's own
//!   table ([`LIST_OBJECTS_ERROR_CODES`], [`LIST_USERS_ERROR_CODES`]), because
//!   the list APIs report unknown types and relations as 2021 / 2022. They are
//!   blocked exactly when the stage's checks are. This runner has no
//!   `_ctxTuples`-style replay for lists.
//!
//! Every stage's run checks (each replay separately) are also replayed through
//! `batch_check`, grouped by subject, context and contextual tuples, as
//! `authz_compatibility.rs` does for the hand-written fixtures. A batched
//! result that differs from the individual check is a hard failure, not a
//! skip-list candidate. Run with `-- --nocapture` to see per-file totals.

#[allow(dead_code)] // Shared with relgraph-dsl; this runner does not use every item.
#[path = "support/skip_list.rs"]
mod skip_list;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, CheckRequest, ConditionContext,
    ConstructionError, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ListObjectsRequest,
    ListUsersRequest, ObjectRef, RelationName, RelationshipTuple, Subject, TenantId, TupleSubject,
    TypeName, UserFilter,
};
use serde::Deserialize;
use serde_json::Value;
use skip_list::{CaseResult, NotPassingKind, Outcome, SkipEntry, SkipList, SkipReason};

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
/// The guide that records the decisions `deliberate` entries cite.
const DECISION_RECORD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../AGENTS.md");
const DECISIONS_HEADING: &str = "## Maintainer decisions";

const CONSOLIDATED_FILE: &str = "consolidated_1_1_tests.yaml";
const ABAC_FILE: &str = "abac_tests.yaml";

/// Rule entries this runner understands. The list-assertion rules went away
/// when the list corpora started running (skip-list plan Task 8).
const KNOWN_RULES: &[&str] = &[];

/// The single tenant every corpus tuple and check uses.
const TENANT: &str = "upstream-corpus";

/// Harness-local name for a request the typed constructors reject.
const IDENTIFIER_ERROR: &str = "IdentifierError";

/// Harness-local name for a contextual tuple the typed constructors reject.
const CONTEXTUAL_IDENTIFIER_ERROR: &str = "ContextualIdentifierError";

/// Upstream's driver skips the `_ctxTuples` replay of a stage with more stage
/// tuples than one request may carry (`MAX_CONTEXTUAL_TUPLES`).
const CONTEXTUAL_REPLAY_MAXIMUM: usize = relgraph_authz::MAX_CONTEXTUAL_TUPLES;

/// Harness-local name for a ListUsers filter that `UserFilter` rejects.
const FILTER_ERROR: &str = "UserFilterError";

/// Upstream `errorCode` → Relgraph error variants that count as the same
/// outcome, for one assertion kind. Codes are `openfga.v1.ErrorCode` values
/// from `openfga/api` at the revision `v1.21.0` pins.
type ErrorCodeTable = &'static [(i64, &'static str, &'static [&'static str])];

/// Check reports every request-validation failure, including an unknown user
/// type or relation, as `validation_error` (2000); the more specific
/// type/relation codes occur only in list assertions.
const CHECK_ERROR_CODES: ErrorCodeTable = &[
    (
        2000,
        "validation_error",
        &[
            "UnknownObjectType",
            "UnknownSubjectType",
            "UnknownSubjectRelation",
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
    (
        2027,
        "invalid_tuple",
        &[
            "InvalidTuple",
            "InvalidContextualTuple",
            CONTEXTUAL_IDENTIFIER_ERROR,
        ],
    ),
];

/// ListObjects reports an unknown object type as `type_not_found` (2021) and
/// an unknown relation on it as `relation_not_found` (2022); an unknown user
/// type or userset relation is a `validation_error` (2000), as in Check.
const LIST_OBJECTS_ERROR_CODES: ErrorCodeTable = &[
    (
        2000,
        "validation_error",
        &[
            "UnknownSubjectType",
            "UnknownSubjectRelation",
            "MissingConditionContext",
            "InvalidConditionContext",
            "ConditionEvaluationFailed",
            IDENTIFIER_ERROR,
        ],
    ),
    (2021, "type_not_found", &["UnknownObjectType"]),
    (2022, "relation_not_found", &["UnknownRelation"]),
    (
        2027,
        "invalid_tuple",
        &[
            "InvalidTuple",
            "InvalidContextualTuple",
            CONTEXTUAL_IDENTIFIER_ERROR,
        ],
    ),
];

/// ListUsers reports an unknown type, of the object or of the filter, as
/// `type_not_found` (2021) and an unknown relation, on the object or in a
/// userset filter, as `relation_not_found` (2022).
const LIST_USERS_ERROR_CODES: ErrorCodeTable = &[
    (
        2000,
        "validation_error",
        &[
            "MissingConditionContext",
            "InvalidConditionContext",
            "ConditionEvaluationFailed",
            IDENTIFIER_ERROR,
            FILTER_ERROR,
        ],
    ),
    (
        2002,
        "authorization_model_resolution_too_complex",
        &["RelationDepthExceeded"],
    ),
    (
        2021,
        "type_not_found",
        &["UnknownObjectType", "UnknownSubjectType"],
    ),
    (
        2022,
        "relation_not_found",
        &["UnknownRelation", "UnknownSubjectRelation"],
    ),
    (
        2027,
        "invalid_tuple",
        &[
            "InvalidTuple",
            "InvalidContextualTuple",
            CONTEXTUAL_IDENTIFIER_ERROR,
        ],
    ),
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
    list_objects_assertions: Option<Vec<ListAssertion<ListObjectsQuery>>>,
    #[serde(default)]
    list_users_assertions: Option<Vec<ListAssertion<ListUsersQuery>>>,
}

/// A `listObjectsAssertions` or `listUsersAssertions` entry: the request,
/// with `context` and `contextualTuples` beside it as in upstream's
/// `listobjects` / `listusers` test assertions. A missing or null
/// `expectation` is the empty list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ListAssertion<Q> {
    request: Q,
    #[serde(default)]
    context: Option<serde_yaml::Value>,
    #[serde(default)]
    contextual_tuples: Option<Vec<TupleKey>>,
    #[serde(default)]
    expectation: Option<Vec<String>>,
    #[serde(default)]
    error_code: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListObjectsQuery {
    user: String,
    #[serde(rename = "type")]
    object_type: String,
    relation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListUsersQuery {
    filters: Vec<String>,
    object: String,
    relation: String,
    /// One upstream assertion (`simple_computeduserset_indirect_ref`) puts a
    /// null `expectation` inside `request`, where upstream's driver ignores
    /// it. Only null is accepted here, so nothing is silently dropped.
    #[serde(default)]
    #[allow(dead_code)]
    expectation: Option<()>,
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
    /// Run assertions expecting an error: (kind, code) → (run, pass), where
    /// the kind is `check` (both check replays), `listObjects` or `listUsers`.
    error_codes: BTreeMap<(&'static str, i64), (usize, usize)>,
    batches: usize,
    batch_items: usize,
    /// Single-stage tests whose `ctxCheck` replay upstream skips (too many tuples).
    ctx_replay_skipped: usize,
}

/// What one assertion is expected to produce: a decision or a sorted list.
#[derive(Debug, Clone)]
enum Expected<T> {
    Value(T),
    Error(i64),
}

/// A successful result an assertion compares.
trait Answer: PartialEq {
    /// The expectation as the failure detail names it (`allow`, `[a, b]`).
    fn expected(&self) -> String;
    /// What Relgraph did when it produced this value (`allows`, `returns []`).
    fn produced(&self) -> String;
}

impl Answer for bool {
    fn expected(&self) -> String {
        String::from(if *self { "allow" } else { "deny" })
    }

    fn produced(&self) -> String {
        String::from(if *self { "allows" } else { "denies" })
    }
}

impl Answer for Vec<String> {
    fn expected(&self) -> String {
        format!("[{}]", self.join(", "))
    }

    fn produced(&self) -> String {
        format!("returns {}", self.expected())
    }
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
    Run(Box<CheckRequest>),
    /// The typed constructors reject the request (a validation error).
    Invalid(String),
    /// The typed constructors reject a contextual tuple (an invalid tuple).
    InvalidContextual(String),
}

/// Builds the check for an assertion. Its contextual tuples are the
/// assertion's own followed by `extra_contextual` (the stage tuples in the
/// `ctxCheck` replay), as upstream appends them.
fn check_request(
    tenant: &TenantId,
    assertion: &CheckAssertion,
    extra_contextual: &[TupleKey],
) -> Request {
    let user = assertion.tuple.user.as_str();
    let subject = match parse_tuple_subject(user) {
        Ok(subject) => subject,
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
    let contextual: Result<Vec<_>, _> = assertion
        .contextual_tuples
        .iter()
        .flatten()
        .chain(extra_contextual)
        .map(|raw| build_tuple(tenant, raw))
        .collect();
    let contextual = match contextual {
        Ok(contextual) => contextual,
        Err(error) => return Request::InvalidContextual(error),
    };
    Request::Run(Box::new(
        CheckRequest::new(tenant.clone(), subject, object, relation)
            .with_context(context)
            .with_contextual_tuples(contextual),
    ))
}

fn expected(assertion: &CheckAssertion) -> Expected<bool> {
    match assertion.error_code {
        Some(code) if code != 0 => Expected::Error(code),
        _ => Expected::Value(assertion.expectation.unwrap_or(false)),
    }
}

/// The enum variant name at the start of a `Debug` rendering.
fn variant_name(error: &AuthorizationError) -> String {
    format!("{error:?}")
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect()
}

fn describe_error(table: ErrorCodeTable, code: i64) -> String {
    match table.iter().find(|(c, ..)| *c == code) {
        Some((_, name, _)) => format!("error {code} ({name})"),
        None => format!("error {code}"),
    }
}

/// Compares one Relgraph outcome (a value, or an error variant name with its
/// rendering) with the upstream expectation, mapping error codes through
/// `table`.
fn compare<T: Answer>(
    table: ErrorCodeTable,
    expected: Expected<T>,
    actual: Result<T, (String, String)>,
) -> Outcome {
    let fail = |detail: String| {
        not_passing(
            NotPassingKind::Fail,
            detail,
            SkipReason::SemanticDivergence,
            "4",
        )
    };
    match (expected, actual) {
        (Expected::Value(want), Ok(got)) if want == got => Outcome::Pass,
        (Expected::Value(want), Ok(got)) => fail(format!(
            "upstream expects {}; Relgraph {}",
            want.expected(),
            got.produced()
        )),
        (Expected::Value(want), Err((_, rendered))) => fail(format!(
            "upstream expects {}; Relgraph errors {rendered}",
            want.expected()
        )),
        (Expected::Error(code), actual) => {
            let Some((_, _, variants)) = table.iter().find(|(c, ..)| *c == code) else {
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
                    describe_error(table, code)
                )),
                Ok(got) => fail(format!(
                    "upstream expects {}; Relgraph {}",
                    describe_error(table, code),
                    got.produced()
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
    let mut groups: BTreeMap<(String, String, String), Vec<&RunCheck>> = BTreeMap::new();
    for check in checks {
        let key = (
            format!("{:?}", check.request.subject()),
            serde_json::to_string(check.request.context()).expect("context serializes"),
            format!("{:?}", check.request.contextual_tuples()),
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
            .with_context(first.context().clone())
            .with_contextual_tuples(first.contextual_tuples().to_vec());
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

type BoundAuthz = FgaAuthz<relgraph_authz::Bound<InMemoryRelationshipStore>>;

/// Runs a stage's check assertions and records their outcomes.
struct AssertionReplay<'a> {
    file: &'static str,
    tenant: &'a TenantId,
    stats: &'a mut FileStats,
    results: &'a mut Vec<CaseResult>,
    batch_problems: &'a mut Vec<String>,
}

impl AssertionReplay<'_> {
    /// Records `{prefix}::i` for each assertion, then replays the run checks
    /// as batches. `block` explains why none can run.
    async fn run(
        &mut self,
        prefix: &str,
        authz: Option<&BoundAuthz>,
        block: Option<&(String, SkipReason)>,
        assertions: &[CheckAssertion],
        extra_contextual: &[TupleKey],
    ) {
        let mut run_checks = Vec::new();
        for (index, assertion) in assertions.iter().enumerate() {
            let id = format!("{prefix}::{index}");
            let outcome = if let Some((why, reason)) = block {
                not_run(why.clone(), *reason, "4")
            } else {
                let authz = authz.expect("an unblocked stage has an authorizer");
                match check_request(self.tenant, assertion, extra_contextual) {
                    Request::Invalid(detail) => compare(
                        CHECK_ERROR_CODES,
                        expected(assertion),
                        Err((IDENTIFIER_ERROR.to_owned(), detail)),
                    ),
                    Request::InvalidContextual(detail) => compare(
                        CHECK_ERROR_CODES,
                        expected(assertion),
                        Err((CONTEXTUAL_IDENTIFIER_ERROR.to_owned(), detail)),
                    ),
                    Request::Run(request) => {
                        let request = *request;
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
                        compare(CHECK_ERROR_CODES, expected(assertion), actual)
                    }
                }
            };
            let code = match expected(assertion) {
                Expected::Error(code) => Some(code),
                Expected::Value(_) => None,
            };
            self.record("check", id, code, outcome);
        }
        if let Some(authz) = authz {
            self.batch_problems
                .extend(replay_as_batches(authz, &run_checks, self.stats).await);
        }
    }

    /// Records `{prefix}::i` for each ListObjects assertion. `block` explains
    /// why none can run.
    async fn run_list_objects(
        &mut self,
        prefix: &str,
        authz: Option<&BoundAuthz>,
        block: Option<&(String, SkipReason)>,
        assertions: &[ListAssertion<ListObjectsQuery>],
    ) {
        for (index, assertion) in assertions.iter().enumerate() {
            let expected = list_expected(assertion);
            let outcome = if let Some((why, reason)) = block {
                not_run(why.clone(), *reason, "4")
            } else {
                let authz = authz.expect("an unblocked stage has an authorizer");
                let actual = match list_objects_request(self.tenant, assertion) {
                    Ok(request) => match authz.list_objects(&request).await {
                        Ok(objects) => Ok(objects
                            .iter()
                            .map(|object| {
                                format!("{}:{}", object.type_name().as_str(), object.id().as_str())
                            })
                            .collect()),
                        Err(error) => Err((variant_name(&error), format!("{error:?}"))),
                    },
                    Err(error) => Err(error),
                };
                compare(
                    LIST_OBJECTS_ERROR_CODES,
                    expected.clone(),
                    actual.map(sorted),
                )
            };
            self.record_list("listObjects", prefix, index, &expected, outcome);
        }
    }

    /// Records `{prefix}::i` for each ListUsers assertion. `block` explains
    /// why none can run.
    async fn run_list_users(
        &mut self,
        prefix: &str,
        authz: Option<&BoundAuthz>,
        block: Option<&(String, SkipReason)>,
        assertions: &[ListAssertion<ListUsersQuery>],
    ) {
        for (index, assertion) in assertions.iter().enumerate() {
            let expected = list_expected(assertion);
            let outcome = if let Some((why, reason)) = block {
                not_run(why.clone(), *reason, "4")
            } else if assertion.request.filters.len() != 1 {
                not_passing(
                    NotPassingKind::HarnessGap,
                    format!(
                        "ListUsers takes one filter; the assertion has {}",
                        assertion.request.filters.len()
                    ),
                    SkipReason::HarnessGap,
                    "4",
                )
            } else {
                let authz = authz.expect("an unblocked stage has an authorizer");
                let actual = match list_users_request(self.tenant, assertion) {
                    Ok(request) => match authz.list_users(&request).await {
                        Ok(users) => Ok(users.iter().map(render_subject).collect()),
                        Err(error) => Err((variant_name(&error), format!("{error:?}"))),
                    },
                    Err(error) => Err(error),
                };
                compare(LIST_USERS_ERROR_CODES, expected.clone(), actual.map(sorted))
            };
            self.record_list("listUsers", prefix, index, &expected, outcome);
        }
    }

    fn record_list(
        &mut self,
        kind: &'static str,
        prefix: &str,
        index: usize,
        expected: &Expected<Vec<String>>,
        outcome: Outcome,
    ) {
        let code = match expected {
            Expected::Error(code) => Some(*code),
            Expected::Value(_) => None,
        };
        self.record(kind, format!("{prefix}::{index}"), code, outcome);
    }

    /// Stores one case outcome and, for a run case expecting an error,
    /// tallies its code under `kind`.
    fn record(&mut self, kind: &'static str, id: String, code: Option<i64>, outcome: Outcome) {
        if let Some(code) = code
            && !matches!(
                outcome,
                Outcome::NotPassing {
                    kind: NotPassingKind::NotRun,
                    ..
                }
            )
        {
            let tally = self.stats.error_codes.entry((kind, code)).or_default();
            tally.0 += 1;
            tally.1 += usize::from(outcome == Outcome::Pass);
        }
        self.results.push(CaseResult {
            file: self.file,
            id,
            outcome,
        });
    }
}

fn list_expected<Q>(assertion: &ListAssertion<Q>) -> Expected<Vec<String>> {
    match assertion.error_code {
        Some(code) if code != 0 => Expected::Error(code),
        _ => Expected::Value(sorted(assertion.expectation.clone().unwrap_or_default())),
    }
}

fn sorted(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items
}

/// Renders a listed subject in upstream's `type:id`, `type:id#relation` or
/// `type:*` form.
fn render_subject(subject: &TupleSubject) -> String {
    match subject {
        TupleSubject::Direct(subject) => {
            format!("{}:{}", subject.type_name().as_str(), subject.id().as_str())
        }
        TupleSubject::Userset { object, relation } => format!(
            "{}:{}#{}",
            object.type_name().as_str(),
            object.id().as_str(),
            relation.as_str()
        ),
        TupleSubject::TypedWildcard(type_name) => format!("{}:*", type_name.as_str()),
    }
}

/// The request context and contextual tuples of a list assertion.
type ListInputs = (BTreeMap<String, Value>, Vec<RelationshipTuple>);

/// The inputs of a list assertion, or the harness-local error (variant name
/// and detail) a typed constructor reports.
fn list_inputs<Q>(
    tenant: &TenantId,
    assertion: &ListAssertion<Q>,
) -> Result<ListInputs, (String, String)> {
    let context = json_map(assertion.context.as_ref())
        .map_err(|detail| (IDENTIFIER_ERROR.to_owned(), detail))?;
    let contextual = assertion
        .contextual_tuples
        .iter()
        .flatten()
        .map(|raw| build_tuple(tenant, raw))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|detail| (CONTEXTUAL_IDENTIFIER_ERROR.to_owned(), detail))?;
    Ok((context, contextual))
}

fn list_objects_request(
    tenant: &TenantId,
    assertion: &ListAssertion<ListObjectsQuery>,
) -> Result<ListObjectsRequest, (String, String)> {
    let invalid = |detail: String| (IDENTIFIER_ERROR.to_owned(), detail);
    let query = &assertion.request;
    let subject = parse_tuple_subject(&query.user).map_err(invalid)?;
    let object_type = TypeName::new(query.object_type.as_str())
        .map_err(|error| invalid(format!("type {}: {error}", query.object_type)))?;
    let relation = RelationName::new(query.relation.as_str())
        .map_err(|error| invalid(format!("relation {}: {error}", query.relation)))?;
    let (context, contextual) = list_inputs(tenant, assertion)?;
    Ok(
        ListObjectsRequest::new(tenant.clone(), subject, object_type, relation)
            .with_context(context)
            .with_contextual_tuples(contextual),
    )
}

fn list_users_request(
    tenant: &TenantId,
    assertion: &ListAssertion<ListUsersQuery>,
) -> Result<ListUsersRequest, (String, String)> {
    let invalid = |detail: String| (IDENTIFIER_ERROR.to_owned(), detail);
    let query = &assertion.request;
    let filter = query.filters[0]
        .parse::<UserFilter>()
        .map_err(|error| (FILTER_ERROR.to_owned(), format!("{error:?}")))?;
    let object = parse_object(&query.object).map_err(invalid)?;
    let relation = RelationName::new(query.relation.as_str())
        .map_err(|error| invalid(format!("relation {}: {error}", query.relation)))?;
    let (context, contextual) = list_inputs(tenant, assertion)?;
    Ok(
        ListUsersRequest::new(tenant.clone(), object, relation, filter)
            .with_context(context)
            .with_contextual_tuples(contextual),
    )
}

async fn run_file(
    file: &'static str,
    stats: &mut FileStats,
    results: &mut Vec<CaseResult>,
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

            let assertions = stage.check_assertions.as_deref().unwrap_or_default();
            let mut replay = AssertionReplay {
                file,
                tenant: &tenant,
                stats: &mut *stats,
                results: &mut *results,
                batch_problems: &mut *batch_problems,
            };
            replay
                .run(
                    &format!("{stage_id}::check"),
                    authz.as_ref(),
                    stage_block.as_ref(),
                    assertions,
                    &[],
                )
                .await;

            // Upstream's `_ctxTuples` replay: a single-stage test runs again
            // against an empty store with the stage tuples sent as
            // contextual tuples, unless there are more than one request may
            // carry.
            if test.stages.len() == 1 && tuples.len() > CONTEXTUAL_REPLAY_MAXIMUM {
                replay.stats.ctx_replay_skipped += 1;
            } else if test.stages.len() == 1 {
                let empty = authz.as_ref().map(|_| {
                    FgaAuthz::new(&stage.model)
                        .expect("the model constructed above")
                        .with_store(
                            InMemoryRelationshipStore::new(),
                            EvaluationLimits::default(),
                        )
                });
                // Only a construction failure blocks this replay; stored
                // tuples play no part in it.
                let block = authz.is_none().then(|| stage_block.clone()).flatten();
                replay
                    .run(
                        &format!("{stage_id}::ctxCheck"),
                        empty.as_ref(),
                        block.as_ref(),
                        assertions,
                        tuples,
                    )
                    .await;
            }

            // List assertions run against the stage's store, as upstream's
            // `listobjects` / `listusers` drivers do; they are blocked exactly
            // when the stage's checks are.
            replay
                .run_list_objects(
                    &format!("{stage_id}::listObjects"),
                    authz.as_ref(),
                    stage_block.as_ref(),
                    stage.list_objects_assertions.as_deref().unwrap_or_default(),
                )
                .await;
            replay
                .run_list_users(
                    &format!("{stage_id}::listUsers"),
                    authz.as_ref(),
                    stage_block.as_ref(),
                    stage.list_users_assertions.as_deref().unwrap_or_default(),
                )
                .await;
        }
    }
}

/// The assertion kind segment of a case ID.
fn case_kind(id: &str) -> &'static str {
    ["model", "check", "ctxCheck", "listObjects", "listUsers"]
        .into_iter()
        .find(|kind| id.contains(&format!("::{kind}::")))
        .expect("every case ID has a kind")
}

#[tokio::test]
async fn upstream_check_corpora_match_or_are_skip_listed() {
    let mut results = Vec::new();
    let mut stats = BTreeMap::<&'static str, FileStats>::new();
    let mut batch_problems = Vec::new();
    for file in [CONSOLIDATED_FILE, ABAC_FILE] {
        run_file(
            file,
            stats.entry(file).or_default(),
            &mut results,
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

    // No rule entries remain: every non-passing case has its own entry.
    let rule_covers = |_: &str, _: &str| false;
    let list = skip_list::load(Path::new(SKIP_LIST), SKIP_LIST_HEADER)
        .unwrap_or_else(|problems| panic!("{problems}"));
    let by_reason = skip_list::covered_counts(&list, &results, &rule_covers);

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
            .map(|((kind, code), (run, pass))| format!("{kind} {code} {pass}/{run}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            report,
            "{file}: {} tests, {} stages, {} cases; {} pass; skip-listed {} (fail {}, \
             harness-gap {}, not-run {}); pass by kind: {kinds}; run error-code checks passing: [{error_codes}]; \
             batch replay {} items in {} batches; ctxCheck replay skipped for {} test(s) with more \
             than {CONTEXTUAL_REPLAY_MAXIMUM} tuples (as upstream)",
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
            file_stats.ctx_replay_skipped,
        );
        let reasons = by_reason.get(file).map_or_else(
            || String::from("none"),
            |counts| {
                counts
                    .iter()
                    .map(|(label, count)| format!("{label} {count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        );
        let _ = writeln!(report, "  skipped by reason/tag: {reasons}");
    }
    println!("{report}");

    assert!(
        batch_problems.is_empty(),
        "batch_check disagrees with individual checks:\n{}",
        batch_problems.join("\n")
    );

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
    let check = |expected, actual| compare::<bool>(CHECK_ERROR_CODES, expected, actual);
    assert_eq!(
        check(Expected::Error(2000), error("MissingConditionContext")),
        Outcome::Pass
    );
    assert_eq!(
        check(Expected::Error(2002), error("RelationDepthExceeded")),
        Outcome::Pass
    );
    assert!(matches!(
        check(Expected::Error(2002), error("WorkLimitExceeded")),
        Outcome::NotPassing {
            kind: NotPassingKind::Fail,
            ..
        }
    ));
    assert!(matches!(
        check(Expected::Error(2000), Ok(false)),
        Outcome::NotPassing {
            kind: NotPassingKind::Fail,
            ..
        }
    ));
    assert!(matches!(
        check(Expected::Error(4000), error("Store")),
        Outcome::NotPassing {
            kind: NotPassingKind::HarnessGap,
            ..
        }
    ));
    assert!(matches!(
        check(Expected::Value(false), error("UnknownRelation")),
        Outcome::NotPassing {
            kind: NotPassingKind::Fail,
            ..
        }
    ));
    assert_eq!(check(Expected::Value(true), Ok(true)), Outcome::Pass);
}

#[test]
fn list_error_codes_compare_through_their_own_tables() {
    let error = |variant: &str| Err((variant.to_owned(), variant.to_owned()));
    let objects =
        |expected, actual| compare::<Vec<String>>(LIST_OBJECTS_ERROR_CODES, expected, actual);
    let users = |expected, actual| compare::<Vec<String>>(LIST_USERS_ERROR_CODES, expected, actual);
    let fails = |outcome: Outcome| {
        matches!(
            outcome,
            Outcome::NotPassing {
                kind: NotPassingKind::Fail,
                ..
            }
        )
    };
    // An unknown object type or relation has its own code in both lists.
    assert_eq!(
        objects(Expected::Error(2021), error("UnknownObjectType")),
        Outcome::Pass
    );
    assert_eq!(
        objects(Expected::Error(2022), error("UnknownRelation")),
        Outcome::Pass
    );
    assert_eq!(
        users(Expected::Error(2021), error("UnknownObjectType")),
        Outcome::Pass
    );
    assert_eq!(
        users(Expected::Error(2022), error("UnknownRelation")),
        Outcome::Pass
    );
    // An unknown user is a validation error for ListObjects, but an unknown
    // filter type or relation is type/relation-not-found for ListUsers.
    assert_eq!(
        objects(Expected::Error(2000), error("UnknownSubjectType")),
        Outcome::Pass
    );
    assert!(fails(objects(
        Expected::Error(2021),
        error("UnknownSubjectType")
    )));
    assert_eq!(
        users(Expected::Error(2021), error("UnknownSubjectType")),
        Outcome::Pass
    );
    assert_eq!(
        users(Expected::Error(2022), error("UnknownSubjectRelation")),
        Outcome::Pass
    );
    assert!(fails(users(
        Expected::Error(2000),
        error("UnknownSubjectType")
    )));
    assert_eq!(
        users(Expected::Error(2000), error(FILTER_ERROR)),
        Outcome::Pass
    );
    assert!(fails(users(Expected::Error(2027), Ok(Vec::new()))));
    // A code neither list table maps is a harness gap, not a pass.
    assert!(matches!(
        objects(Expected::Error(2002), error("RelationDepthExceeded")),
        Outcome::NotPassing {
            kind: NotPassingKind::HarnessGap,
            ..
        }
    ));
    let listed = vec![String::from("document:1")];
    assert_eq!(
        objects(Expected::Value(listed.clone()), Ok(listed.clone())),
        Outcome::Pass
    );
    assert!(fails(objects(Expected::Value(listed), Ok(Vec::new()))));
}

/// The IDs listed under `## Maintainer decisions` in the guide, from items of
/// the form `- **S1 (title).** …`.
fn recorded_decisions(guide: &str) -> BTreeSet<&str> {
    guide
        .lines()
        .skip_while(|line| *line != DECISIONS_HEADING)
        .skip(1)
        .take_while(|line| !line.starts_with("## "))
        .filter_map(|line| line.strip_prefix("- **")?.split(' ').next())
        .collect()
}

/// Problems with `deliberate` entries whose justification does not start with
/// `<ID>: ` for a recorded decision ID.
fn uncited_deliberate_entries(list: &SkipList, recorded: &BTreeSet<&str>) -> Vec<String> {
    list.entries
        .iter()
        .filter(|entry| entry.tag == "deliberate")
        .filter(|entry| {
            entry
                .justification
                .split_once(": ")
                .is_none_or(|(id, _)| !recorded.contains(id))
        })
        .map(|entry| {
            format!(
                "{} is deliberate but its justification cites no decision recorded in AGENTS.md: {:?}",
                entry.case.as_deref().or(entry.rule.as_deref()).unwrap_or("<invalid entry>"),
                entry.justification
            )
        })
        .collect()
}

#[test]
fn deliberate_entries_cite_a_recorded_decision() {
    let guide = fs::read_to_string(DECISION_RECORD)
        .unwrap_or_else(|error| panic!("could not read {DECISION_RECORD}: {error}"));
    let recorded = recorded_decisions(&guide);
    assert!(
        recorded.contains("S1") && recorded.contains("S2"),
        "{DECISION_RECORD} must list S1 and S2 under {DECISIONS_HEADING:?}, found {recorded:?}"
    );
    let list = skip_list::load(Path::new(SKIP_LIST), SKIP_LIST_HEADER)
        .unwrap_or_else(|problems| panic!("{problems}"));
    let problems = uncited_deliberate_entries(&list, &recorded);
    assert!(problems.is_empty(), "{}", problems.join("\n"));

    let entry = |tag: &str, justification: &str| SkipEntry {
        case: Some(String::from("f.yaml::t::0")),
        rule: None,
        reason: SkipReason::SemanticDivergence,
        tag: tag.to_owned(),
        task: String::from("permanent"),
        justification: justification.to_owned(),
    };
    let probe = SkipList {
        entries: vec![
            entry("deliberate", "S1: upstream expects deny"),
            entry("deliberate", "S99: an unknown decision"),
            entry("deliberate", "no decision cited"),
            entry("bug", "no decision needed"),
        ],
    };
    let problems = uncited_deliberate_entries(&probe, &recorded);
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(problems[0].contains("S99"), "{problems:?}");
}
