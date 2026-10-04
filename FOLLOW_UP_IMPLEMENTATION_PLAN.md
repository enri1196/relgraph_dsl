# Tuple-page streaming and construction-cost plan

This is an implementation plan, not an implementation report. All tasks below
are unstarted. Source was inspected through CodeGraph MCP on 2026-10-04.

## Execution and ownership

Execute tasks 1–7 in order, with one task-scoped subagent at a time. The owning
subagent changes its heading from `[TODO]` to `[PROGRESS]` before editing and
to `[DONE]` only after its acceptance criteria pass. The coordinator waits for
that subagent before assigning the next task. Each task depends on the preceding
task and is an independently reviewable commit; use the specified commit subject.
The status update belongs in that commit. Record commands, results, and any
environment blockers under the task's **Execution record**. A blocked task stays
`[PROGRESS]`; do not silently reduce its acceptance criteria.

Use CodeGraph MCP before changing Rust. Preserve unrelated changes and generated
`.codegraph` files. At planning time `git status --short` showed only the unrelated
untracked `.codegraph/daemon.pid`. No tests or measurements were run to write this
plan. The supplied AGENTS.md describes an older snapshot; use current code and
current command results, not its historical failure claims, as evidence.

The file and symbol names below are binding. Reuse existing functions unless a
new name is listed. Local variables, imports, formatting, and assertion messages
are ordinary implementation details. Do not invent additional files, types,
functions, public APIs, dependencies, feature flags, compatibility wrappers, or
optimization work. If the specified design cannot satisfy a criterion, explain
the concrete conflict in the execution record and return it to the coordinator
for a plan amendment. Document every new or materially changed Rust symbol.

## Inspected implementation

| Location | Current behavior relevant to this plan |
| --- | --- |
| `relgraph-authz/src/authz/evaluator.rs::load_tuples` | Returns `Vec<Vec<RelationshipTuple>>`; drains all pages before either caller validates a tuple. Enforces global tuple, store-call, and work budgets, empty-continuation rejection, and repeated-cursor rejection. |
| `evaluate_direct_assignment` | Validates every loaded tuple and assignment restriction. Accumulates membership/condition errors; an allow defeats those errors, but tuple validation uses immediate propagation. |
| `evaluate_tuple_to_userset` | Also drains first. Validates ownership/context, direct subject shape, compatible edge, and target object before recursive membership. |
| `validate_tuple` / `evaluate_tuple_condition` | Stored context is prepared and charged once before membership, then consumed during applicable condition evaluation. |
| `relgraph-authz/tests/authz_page_contract.rs` | Contains `PageScript`, `PageStore`, `PageSession`, `run_check`, cursor tests, and explicit regressions requiring late errors/malformed tuples to defeat an early grant. |
| `relgraph-authz/tests/authz_relations.rs` | `paged_reads_complete_within_the_tuple_budget_and_respect_store_call_limits` puts the matching tuple after 129 nonmatching tuples. |
| `relgraph-authz/src/authz/model.rs` | `compile` validates; `compile_validated` checks capabilities/dependencies and conditions; `compile_indexes` builds indexes and invokes recursive `compile_expression`. |
| `relgraph-dsl/src/parser/relation.rs` | Flat `or`/`and` chains are folded into left-deep binary trees. The budget counts expression nodes **and restriction targets**. Parentheses do not consume node units. |
| `relgraph-dsl/src/parser/schema.rs` | Limits are 128 nested parentheses, 512 expression/target units per relation, and 4,096 declarations per document. |
| `relgraph-authz/tests/construction_depth.rs` | A 200-term case only parses/validates; subprocess cases reject excessive syntax and compile a 3,000-relation dependency chain. Near-limit expression compilation is not measured. |

## Binding streaming behavior

The first follow-up intentionally changes the existing drain-before-evaluation
contract. Use **whole-page validation followed by incremental evaluation**:

1. Fetch one page, bounded by `min(128, remaining global tuple budget)`.
2. Validate its envelope and account for the entire fetched tuple vector.
3. Validate and prepare **every tuple in that page**, in returned order, including
   stored condition context and assignment/tupleset restrictions.
4. Evaluate that page's tuples in returned order. A successful membership plus
   applicable true condition returns allow immediately. A membership alone is
   insufficient. Release the current page and its prepared metadata before
   fetching the next page.
5. Continue only while the result remains unresolved. End-of-stream without an
   allow returns the first membership/condition evaluation error, or deny if none.

This keeps malformed tuples in an already fetched page fatal, even when an
earlier tuple in that page could grant access. It does not validate or read an
unrequested later page. Thus an early valid grant can skip a later malformed
tuple, store failure, cursor failure, or exhaustion that would occur only on a
subsequent fetch. Decisions in a corrupt custom store can depend on page
boundaries; document this explicitly. The evaluator is not a store-integrity
scanner. Strict write validation and tenant-scoped snapshots remain required.

| Situation | Required result |
| --- | --- |
| Grant plus malformed tuple anywhere in the fetched page | Validation error; no allow and no next-page read. |
| Grant in page 1; malformed tuple or store error only in page 2 | Allow; page 2 is never requested. |
| No grant yet; next requested page fails | Propagate the mapped store error immediately. |
| Malformed tuple now; a hypothetical next page would fail | Current validation error; do not request the next page. This changes old read-error precedence. |
| Earlier membership/condition evaluation error; later valid grant | Allow, using existing union-style accumulation. |
| Earlier membership/condition evaluation error; no grant before normal end | First evaluation error. |
| Empty continuing page, repeated cursor, or oversized fetched page | Envelope/budget error before tuple preparation or evaluation. |
| Fetched page consumes the final tuple allowance and contains a grant | Allow, including when its cursor advertises more tuples. |
| Same budget boundary, no grant, continuation required | Tuple-limit error before the next store call. |
| Store-call allowance ends after a granting page | Allow; only an attempted additional fetch checks that allowance. |
| Work or condition preparation budget expires in the fetched page | Error before evaluating the page, even if it includes a grant. |

Global tuple/store/work/CEL counters remain shared by all nested traversals.
Charge all tuples fetched, including those not evaluated after an early grant.
Keep `evaluate_expression`, `combine_union`, `combine_intersection`, and
`combine_difference` unchanged. Their existing three-valued behavior still
applies to the result returned by a streaming branch. In particular, an unresolved
subtraction branch cannot produce allow. Do not globally turn errors into deny.

Memory claim: at most one tuple page and one page of prepared metadata **per
active traversal**, plus bounded cursor history. Parent pages may remain live
while nested membership checks run. This is not a constant-memory claim for the
entire recursion tree, and backend snapshot memory is outside this claim.

## Task 1 — Instrument the scripted page store without changing semantics [DONE]

**Dependency:** none. **Commit:** `test(authz): instrument scripted page reads`.

**Owned files:** existing `relgraph-authz/tests/authz_page_contract.rs` only.

Extend the existing test harness, keeping all seven current tests and their
current expected outcomes passing in this task:

- Add `#[derive(Clone)] enum PageOutcome { Tuples(Vec<RelationshipTuple>), Error(StoreErrorKind) }`.
- Change `PageScript` to fields `request_object: ObjectRef`,
  `request_relation: RelationName`, `request_cursor: Option<StoreCursor>`,
  `outcome: PageOutcome`, and `next_cursor: Option<StoreCursor>`.
- Add `#[derive(Default)] struct PageReadLog { calls: Vec<(ObjectRef, RelationName, Option<StoreCursor>, usize)> }`.
- Add `reads: Arc<Mutex<PageReadLog>>` to both `PageStore` and `PageSession`.
  Preserve `PageSession.pages` and `next_page`. `begin_read` shares the log.
- Change `PageSession::tuples_page` to log every invocation, verify the expected
  object/relation/cursor, and return the scripted outcome. An `Error(kind)` uses
  `StoreError::new(kind, "scripted page read failure")`. Running out of scripts
  retains the existing `IncompleteRead` error. Do not enforce the requested
  maximum in this harness: tests must be able to script an oversized response.
- Add `scripted_page(object_id: &str, relation_name: &str, request_cursor: Option<StoreCursor>, tuples: Vec<RelationshipTuple>, next_cursor: Option<StoreCursor>) -> PageScript`.
  Its object type is `document`. Add `scripted_error(object_id: &str,
  relation_name: &str, request_cursor: Option<StoreCursor>, kind: StoreErrorKind)
  -> PageScript`, with `next_cursor: None`.
- Add `run_scripted_check(model: &str, pages: Vec<PageScript>, limits: EvaluationLimits,
  request: CheckRequest) -> (Result<AuthorizationDecision, AuthorizationError>, Arc<Mutex<PageReadLog>>)`.
  Keep `run_check(pages)` as its adapter using existing `MODEL`, limits, and request.
  Adapt all current script literals to `scripted_page`; do not change their tuples.

Use the existing `common` constructors and executor. Assert page calls through
the returned log; no separate executor, mock framework, or counter API.

**Acceptance:** all current page-contract tests retain their results; logged
entries contain the actual query, cursor, and maximum. Explicit scripted errors
are supported for task 2.

**Verification:** `cargo test -p relgraph-authz --test authz_page_contract`;
`cargo fmt --all -- --check`; `git diff --check`.

**Execution record:** 2026-10-04
- `cargo test -p relgraph-authz --test authz_page_contract` — passed (7 passed, 0 failed).
- `cargo fmt --all -- --check` — passed.
- `git diff --check` — passed.

## Task 2 — Stream and validate bounded pages in both tuple traversals [DONE]

**Dependency:** task 1. **Commit:** `feat(authz): evaluate tuple pages incrementally`.

**Owned files:** `relgraph-authz/src/authz/evaluator.rs`,
`relgraph-authz/tests/authz_page_contract.rs`, and `relgraph-authz/README.md`.

Add these private evaluator symbols, with exactly these responsibilities:

```rust
const EVALUATION_PAGE_SIZE: usize = 128;

#[derive(Default)]
struct TuplePageState {
    cursor: Option<StoreCursor>,
    seen_cursors: HashSet<StoreCursor>,
    exhausted: bool,
}

struct PreparedTuplesetTuple {
    condition_context: Option<super::conditions::PreparedConditionContext>,
    target_object: ObjectRef,
    computed_relation_id: Option<usize>,
}
```

Replace `load_tuples` with `async fn load_tuple_page(&mut self, object: &ObjectRef,
relation_id: usize, state: &mut TuplePageState)
-> Result<Option<RelationshipPage>, AuthorizationError>`. Import the existing
store page type; do not add a stream crate or change public store contracts.

When `state.exhausted`, return `Ok(None)` without charging work or a store call.
Otherwise check store-call budget, remaining global tuple budget, increment the
call counter, and charge one work unit exactly as the current loader does.
Request `remaining.min(EVALUATION_PAGE_SIZE)` tuples using the current opaque
cursor. Preserve `map_store_error`. Reject a response exceeding the **requested
maximum**, using the existing `EvaluationLimitExceeded` variant. Charge its
entire length and increment `tuples_scanned`. Reject empty continuation and
any cursor seen previously in this traversal, preserving current error strings.
Set the next cursor or `exhausted` and return this page. Remove the old immediate
tuple-budget error on a nonterminal page reaching the allowance: that check
belongs to an attempted next fetch so the current page can decide the result.

Add two methods:

```rust
fn prepare_assignment_page(
    &mut self,
    tuples: &[RelationshipTuple],
    object: &ObjectRef,
    relation_id: usize,
    targets: &CompiledTargetRange,
) -> Result<Vec<Option<super::conditions::PreparedConditionContext>>, AuthorizationError>;

fn prepare_tupleset_page(
    &mut self,
    tuples: &[RelationshipTuple],
    object: &ObjectRef,
    tupleset_relation_id: usize,
    edge_range: CompiledTargetRange,
) -> Result<Vec<PreparedTuplesetTuple>, AuthorizationError>;
```

`prepare_assignment_page` calls `validate_tuple` and
`validate_assignment_subject` once per tuple, then saves the prepared context.
`prepare_tupleset_page` moves the current tupleset validation/compatible-edge/
target-object construction into its preparation pass, once per tuple. Save the
resolved optional computed relation ID and context. Missing computed relations
remain membership evaluation errors, not tuple preparation errors. Keep the
existing tupleset-direct-assignment check before preparation of the first page.
Use the current diagnostic strings for all validation failures.

Rewrite both existing evaluation methods as page loops with local
`TuplePageState` and `first_error`. Prepare a page fully, then zip its borrowed
tuples with the owned prepared vector. Preserve membership and applicable
condition handling. Return `Ok(true)` on the first successful result. Preserve
the first membership/condition error across pages. At normal exhaustion return
that error or `Ok(false)`. Scope each page and prepared vector so both are
released before the next fetch. Never clone a page's tuple vector or retain
pages in evaluator state. Nested traversal retains the same read session.

Replace these old regressions and expectations explicitly:

| Existing test | Replacement name and behavior |
| --- | --- |
| `evaluator_allows_a_grant_on_the_first_page_after_reading_later_pages` | `evaluator_allows_a_grant_without_reading_later_pages`: allow, exactly one logged call. |
| `late_page_store_error_prevents_an_earlier_grant` | `unrequested_store_error_does_not_defeat_an_earlier_grant`: script an explicit second-page error, allow, exactly one call. |
| `late_invalid_tuple_prevents_an_earlier_grant` | `unrequested_invalid_tuple_does_not_defeat_an_earlier_grant`: retain malformed second page, allow, exactly one call. |
| `page_read_error_precedes_validation_of_buffered_tuples` | `fetched_invalid_tuple_precedes_an_unrequested_store_error`: first page nonmatching, second malformed, third explicit error; `InvalidTuple`, exactly two calls. |

Retain `evaluator_allows_a_grant_on_a_later_page` and assert two calls. Retain
both cursor/empty-page tests; change their ordinary tuples to nonmatching
`page_tuple("other-user", "42")` so short circuit does not bypass the intended
protocol violation. Repeated A→B→A cursors must still fail on call 3.

Add these tests with the exact names and fixtures:

- `fetched_invalid_tuple_defeats_a_same_page_grant`: one page `[grant,
  page_tuple("anne", "other-object")]`; `InvalidTuple`, one call.
- `requested_store_error_is_not_a_deny`: nonmatching page then scripted
  `IncompleteRead`; `AuthorizationError::Store`, two calls.
- `streaming_rejects_pages_larger_than_the_requested_maximum`: return 129
  nonmatching tuples with limits 1,000; error and logged maximum 128.
- `grant_at_the_tuple_limit_skips_continuation`: limit 1, page contains grant
  and cursor; allow and one call with maximum 1.
- `nonmatching_page_at_the_tuple_limit_requires_more_budget`: same fixture
  with nonmatching tuple; tuple-limit error and one call.
- `grant_at_the_store_call_limit_skips_continuation`: tuple limit 10,
  store-call limit 1, granting page with cursor; allow and one call.
- `streaming_deny_drains_pages_with_decreasing_maximum`: limit 3, first page
  has two nonmatching tuples plus cursor, terminal page has one nonmatching
  tuple; deny, maxima `[3, 1]`.
- `terminal_empty_page_denies_without_another_read`: terminal empty page;
  deny and one call.

Update the README's **Errors and execution limits** section in the same commit:
replace its unconditional assertion that every malformed tuple/read error
prevents allow with the binding page contract above. State page size, same-page
validation, skipped later-page errors, page-boundary dependence for corrupt
stores, global accounting, and memory bounds per active traversal. No claim of
upstream equivalence for malformed custom-store results.

**Acceptance:** all named tests pass; both callers use the new loader; there is
no all-pages collection; unchanged operator combiners preserve their behavior.

**Verification:** `cargo test -p relgraph-authz --test authz_page_contract`;
`cargo test -p relgraph-authz --test authz_relations`;
`cargo test -p relgraph-authz --test authz_conditions`;
`cargo fmt --all -- --check`; `git diff --check`.

**Execution record:** 2026-10-04
- Implemented bounded 128-tuple page loading, full fetched-page preparation, and
  incremental evaluation in both tuple traversals. Grants skip later pages;
  malformed data in the fetched page remains fatal. Updated the README page
  contract and scripted page regressions.
- `cargo test -p relgraph-authz --test authz_page_contract` — passed (15 passed,
  0 failed).
- `cargo test -p relgraph-authz --test authz_relations` — passed (10 passed,
  0 failed).
- `cargo test -p relgraph-authz --test authz_conditions` — passed (11 passed,
  0 failed).
- `cargo fmt --all -- --check` — passed.
- `git diff --check` — passed.

## Task 3 — Cover nested traversal, condition preparation, and short circuit [DONE]

**Dependency:** task 2. **Commit:** `test(authz): cover streaming traversal boundaries`.

**Owned files:** existing `relgraph-authz/tests/authz_page_contract.rs` only.

Reuse task 1's query-aware scripts and read log. Add constants
`USERSET_MODEL`, `TUPLESET_MODEL`, and `CONDITION_MODEL` with these exact models:

```text
# USERSET_MODEL (omit this comment from the constant)
model
schema 1.1
type user
type document
  relations
    define member: [user]
    define viewer: [document#member]

# TUPLESET_MODEL
model
schema 1.1
type user
type document
  relations
    define parent: [document]
    define member: [user]
    define viewer: member from parent

# CONDITION_MODEL
model
schema 1.1
type user
type document
  relations
    define viewer: [user with enabled]
condition enabled(flag: bool) {
  flag
}
```

Add `userset_tuple(object_id: &str, relation_name: &str, subject_object_id: &str,
subject_relation: &str) -> RelationshipTuple`,
`parent_tuple(subject_id: &str) -> RelationshipTuple`, and
`condition_tuple(subject_id: &str, flag: serde_json::Value) -> RelationshipTuple`.
All use tenant-a and document:42 unless the object parameter specifies otherwise.
The userset subject is document#relation; parent tuples are direct document
subjects on `parent`; condition tuples are direct user subjects on `viewer`,
using existing `ConditionContext`/tuple construction APIs with `enabled` and
stored `flag`. Reuse `page_tuple` for unconditional member grants by changing
its tuple relation with the existing constructor in the test body; no new helper.

Add these tests; inspect existing public constructors through CodeGraph before
writing them:

| Test name | Fixture and assertions |
| --- | --- |
| `userset_grant_skips_the_next_parent_page` | viewer page has userset document:group#member and continuation; group/member terminal grant; later viewer page scripted error. Allow, query sequence viewer→member only, same session. |
| `tupleset_grant_skips_the_next_parent_page` | parent page points to document:folder and continues; folder/member grants; next parent page errors. Allow; parent→member only. |
| `tupleset_preparation_rejects_a_same_page_invalid_subject` | parent page has valid folder tuple then typed wildcard document subject. `InvalidTuple`; no member query because the entire page must prepare first. |
| `nested_reads_share_the_global_tuple_budget` | parent page consumes one of limit 1; nested member fetch would be required. Tuple-limit error; parent read only. |
| `nested_reads_share_the_global_store_call_budget` | parent page read with store-call limit 1; nested member fetch required. Store-call error; parent read only. |
| `stored_context_is_prepared_before_any_same_page_grant` | CONDITION_MODEL, page has Anne/true then another user's `flag` as string. Stored-context error; one call; malformed stored context cannot be hidden by Anne's grant. |
| `condition_false_requires_the_next_page` | Anne/false first page, Anne/true second page. Allow; two calls. |
| `earlier_condition_evaluation_error_can_be_masked_by_a_later_grant` | First conditional tuple has empty stored context and missing request flag, second has stored true, in separate pages. Allow; two calls. Build the empty-context tuple inline with existing constructors. |
| `condition_evaluation_error_survives_stream_exhaustion` | Only empty stored context and missing request flag. Applicable condition error, never deny. |
| `page_preparation_budget_error_defeats_a_same_page_grant` | Start with one Anne/true tuple; append 127 nonmatching tuples each with stored bool context. Condition-cost limit 1. Condition-cost error, one call. |

Run the existing relation operator and condition suites unchanged; they cover
union/intersection/difference error rules and stored-context precedence. Do not
weaken assertions to accommodate the streaming change. Also retain the existing
late-match tuple/store-budget regression in `authz_relations.rs` unchanged.

**Acceptance:** direct usersets and tuple-to-userset early grants skip parent
continuations; preparation precedes nested reads; counters are global; false or
unresolved conditions never short circuit to allow. Memory claims remain limited
to the inspected ownership design; scripted fixtures themselves retain tuples.

**Verification:** `cargo test -p relgraph-authz --test authz_page_contract`;
`cargo test -p relgraph-authz --test authz_relations --test authz_conditions`;
`cargo fmt --all -- --check`; `git diff --check`.

**Execution record:** 2026-10-04
- `cargo test -p relgraph-authz --test authz_page_contract` — passed (25 passed, 0 failed).
- `cargo test -p relgraph-authz --test authz_relations --test authz_conditions` — passed (21 passed, 0 failed).
- `cargo fmt --all -- --check` — passed.
- `git diff --check` — passed.
- The malformed stored bool fixture uses `"not-a-bool"`; `"true"` is an accepted string representation for CEL bool parameters.

## Task 4 — Define exact large allowed construction workloads and stress cases [TODO]

**Dependency:** task 3. **Commit:** `test(authz): stress construction at supported limits`.

**Owned files:** new `relgraph-authz/tests/support/construction_models.rs` and
existing `relgraph-authz/tests/construction_depth.rs`.

The new support file uses only the standard library. Define:

```rust
pub struct ConstructionCase {
    pub name: &'static str,
    pub source: String,
    pub declarations: usize,
    pub maximum_relation_units: usize,
}

pub fn construction_cases() -> Vec<ConstructionCase>;
pub fn union_model(terms: usize, direct_root: bool) -> String;
pub fn intersection_model(terms: usize) -> String;
pub fn nested_model(depth: usize) -> String;
pub fn target_fanout_model(targets: usize) -> String;
pub fn wide_index_model(types: usize) -> String;
pub fn edge_fanout_model(targets: usize) -> String;
pub fn repeated_expression_model(relations: usize) -> String;
```

Generate `model\nschema 1.1\n` headers. Use these literal type/relation names
and formulas; all fixtures must have unique declarations and be semantically
valid, acyclic, and condition-free:

- `union_model`: user and document types; document has `base: [user]` and
  `viewer`. If `direct_root` is false, viewer is `terms` copies of `base` joined
  with ` or `. If true, first term is `[user]`, remaining terms are `base`.
  Budgets are `2*terms-1` and `2*terms`, respectively; four declarations total.
- `intersection_model`: same types/base/viewer, all `base` terms joined with
  ` and `; `2*terms-1` units, four declarations.
- `nested_model`: user/document plus viewer; exactly `depth` parentheses around
  `[user]`; two units, three declarations. Parentheses affect parsing stack,
  not compiled-expression depth.
- `target_fanout_model`: types `s0000` through `s{targets-1:04}`, then document
  with `viewer: [s0000, ...]`; `targets+1` units and `targets+2` declarations.
- `wide_index_model`: user plus types `bucket0000` through
  `bucket{types-1:04}`, each with `member: [user]`; two units per relation and
  `1+2*types` declarations. No reference/dependency chain.
- `edge_fanout_model`: user; `node0000` through `node{targets-1:04}`, each with
  `member: [user]`; document with `parent: [node0000, ...]` and
  `viewer: member from parent`. `targets+1` maximum units, `2*targets+4`
  declarations, and exactly `targets` compiled tuple-to-userset edges.
- `repeated_expression_model`: user/document, `base: [user]`, then relations
  `viewer0000` through `viewer{relations-1:04}`, each `[user]` followed by 255
  ` or base` terms. Exactly 512 units per viewer, `relations+3` declarations.

`construction_cases()` returns these cases in this exact order:

| Name | Generator | Declarations | Maximum relation units |
| --- | --- | ---: | ---: |
| `union_32` | `union_model(32, false)` | 4 | 63 |
| `union_128` | `union_model(128, false)` | 4 | 255 |
| `union_256` | `union_model(256, false)` | 4 | 511 |
| `union_exact_512` | `union_model(256, true)` | 4 | 512 |
| `intersection_256` | `intersection_model(256)` | 4 | 511 |
| `nested_128` | `nested_model(128)` | 3 | 2 |
| `targets_511` | `target_fanout_model(511)` | 513 | 512 |
| `wide_indexes_2047` | `wide_index_model(2047)` | 4095 | 2 |
| `edges_511` | `edge_fanout_model(511)` | 1026 | 512 |
| `repeated_128` | `repeated_expression_model(128)` | 131 | 512 |

In construction_depth.rs add
`#[path = "support/construction_models.rs"] mod construction_models;`.
Add `allowed_construction_cases_compile_in_child_processes`. Follow the existing
subprocess pattern, using new constant
`ALLOWED_CASE_ENV: &str = "RELGRAPH_ALLOWED_CONSTRUCTION_CASE"` and the exact
test filter `allowed_construction_cases_compile_in_child_processes`. The parent
starts one child per case, checks success, and includes stdout/stderr on failure.
The child selects the case by `name` and calls new helper
`compile_allowed_case(case: &construction_models::ConstructionCase)`, which
parses, validates, calls `FgaAuthz::new`, and drops the constructed object. Keep
object destruction in the child: recursive AST destruction must also survive.
No timing assertions and no unspecified small thread-stack size.

Add `construction_unit_boundaries_are_exact`: assert `union_model(256, true)`
and `target_fanout_model(511)` compile; `union_model(257, false)` and
`target_fanout_model(512)` fail through `FgaAuthz::new` with
`ConstructionError::Parse` / `ParseErrorCode::ConstructionLimitExceeded`.
Check nesting 128 accepted/129 rejected through the same public constructor.
Check `wide_index_model(2047)` accepted/2048 rejected. Existing excessive-depth
and dependency-chain subprocess regressions stay intact.

**Acceptance:** all ten allowed cases construct and drop successfully in
isolated processes; exact-limit and over-limit assertions use public API error
variants. Do not change parser limits or recursive compilation in this task.

**Verification:** `cargo test -p relgraph-authz --test construction_depth`;
`cargo test -p relgraph-authz --release --test construction_depth`;
`cargo fmt --all -- --check`; `git diff --check`.

**Execution record:** unstarted.

## Task 5 — Add a reproducible private construction measurement harness [TODO]

**Dependency:** task 4. **Commit:** `perf(authz): add construction cost measurement harness`.

**Owned files:** existing `relgraph-authz/src/authz/model.rs`, new
`relgraph-authz/src/authz/model/construction_costs.rs`, and new
`CONSTRUCTION_COSTS.md`. No Cargo manifest/dependency changes.

Add `#[cfg(test)] mod construction_costs;` to model.rs. The new module accesses
private `CompiledModel` through `super`. Include the task 4 workload generators
in nested module `construction_models` using
`include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/construction_models.rs"));`.
This remains test-only; no public benchmarking escape hatch.

Define these symbols in construction_costs.rs:

```rust
const WARMUP_SAMPLES: usize = 3;
const MEASURED_SAMPLES: usize = 21;
const MEASUREMENT_CASE_ENV: &str = "RELGRAPH_CONSTRUCTION_COST_CASE";

#[derive(Clone, Copy)]
enum ConstructionPhase { Parse, Validate, Compile, Indexes, Full, Drop }

struct ConstructionMeasurement {
    case: &'static str,
    phase: ConstructionPhase,
    source_bytes: usize,
    declarations: usize,
    maximum_relation_units: usize,
    samples_ns: Vec<u128>,
}

#[test]
#[ignore = "manual construction cost measurement"]
fn measure_construction_costs();
fn measure_case(case: &construction_models::ConstructionCase) -> Vec<ConstructionMeasurement>;
fn measure_phase(case: &construction_models::ConstructionCase, phase: ConstructionPhase) -> ConstructionMeasurement;
fn measure_sample(case: &construction_models::ConstructionCase, phase: ConstructionPhase) -> u128;
fn print_measurement(measurement: &ConstructionMeasurement);
```

`measure_construction_costs` selects all cases if the environment variable is
absent, or the exact named case if present; unknown names fail. Before measuring
each case, construct it once and assert private compiled lengths: the four
union cases have `2*terms` expressions including base; exact-512 has 512
expressions including base; intersection has 512 expressions; nested/targets
have one expression; wide indexes has 2047 expressions/relations; edge fanout
has 513 expressions, 513 relations, 1022 targets, and 511 edges; repeated has
65,409 expressions, 129 relations, and 129 targets. Verify type/relation index
entry counts align with source declarations. Do not estimate costs from these
counts alone.

Measure phases in the enum order. Each sample performs exactly one operation
using `Instant` and `std::hint::black_box`. Build source, preparse/prevalidate
required inputs, and clone ASTs **before** starting the clock. Stop the clock
before dropping outputs except for the explicit Drop phase:

| Phase | Timed operation |
| --- | --- |
| Parse | `parse_fga_schema(source)` |
| Validate | `validate_schema(&parsed_schema)` |
| Compile | `CompiledModel::compile_validated(owned_validated_schema)`; includes capability/dependency checks, empty condition compilation, and indexes. |
| Indexes | `CompiledModel::compile_indexes(owned_validated_schema, HashMap::new())`; condition-free cases only. |
| Full | `FgaAuthz::new(source)`; parse + validation + compilation. |
| Drop | `drop(black_box(compiled_model))` prepared before timing. |

Discard three warmup samples per phase, then collect 21 samples. Sort measured
durations and print median (index 10), p95 (index 19), and maximum (index 20).
Print a CSV header and exactly these fields:
`case,phase,source_bytes,declarations,maximum_relation_units,samples,median_ns,p95_ns,max_ns`.
Phase names are `parse`, `validate`, `compile`, `indexes`, `full`, `drop`.
Measurements are observations, not pass/fail thresholds. Do not subtract phase
medians to derive another phase; phases have different setup and allocation states.

CONSTRUCTION_COSTS.md must initially contain: purpose; exact workload table;
timed boundaries; warmup/sample methodology; commands below; empty result tables
headed **Not measured yet**; caveats about timer overhead, noise, retained source
AST, empty CEL compilation, and whole-process peak RSS. State that no runtime
speed or platform support claim follows until task 6 supplies observations.

**Acceptance:** the ignored test compiles in default and Axum configurations;
normal tests skip it; explicit execution emits the specified CSV rows. Index
count assertions validate that the intended workload reached compilation.

**Verification:** `cargo check -p relgraph-authz --all-targets --all-features`;
`RELGRAPH_CONSTRUCTION_COST_CASE=union_exact_512 cargo test -p relgraph-authz --release --lib authz::model::construction_costs::measure_construction_costs -- --ignored --exact --nocapture --test-threads=1`;
`cargo fmt --all -- --check`; `git diff --check`.

**Execution record:** unstarted.

## Task 6 — Measure costs and record evidence on available platforms [TODO]

**Dependency:** task 5. **Commit:** `docs(perf): record construction cost measurements`.

**Owned file:** existing `CONSTRUCTION_COSTS.md` only. Temporary command output
may be stored under `/private/tmp`, never added to the repository.

Run the debug/release child stress suite from task 4 on the available host.
Record `rustc -Vv`, `cargo -V`, `uname -sm`, CPU model, RAM, power mode when
available, profile, feature set, Git revision, and exact commands. On macOS,
CPU/RAM can be read with `sysctl -n machdep.cpu.brand_string hw.memsize`.
Record denied/unavailable metadata as such; do not invent it.

Run all release measurement cases three times, with no concurrent build/test
process started by the agent:

```sh
cargo test -p relgraph-authz --release --lib authz::model::construction_costs::measure_construction_costs -- --ignored --exact --nocapture --test-threads=1
```

Keep each run's reported median, p95, and max in the document. Present tables
grouped by phase, with workloads as rows and three runs as columns. For the
union scaling cases, report ratios of observed medians relative to union_32;
do not assert linear complexity from three sizes. Discuss exact-512 chain
compilation, wide indexes, target/edge fanout, repeated large expressions, and
destruction separately.

Measure peak RSS in a fresh **test executable** process for `union_exact_512`,
`wide_indexes_2047`, `edges_511`, and `repeated_128`. First obtain the executable
path from
`cargo test -p relgraph-authz --release --lib --no-run --message-format=json`:
use the compiler-artifact record with the relgraph-authz library test target
and its `executable` field, not a guessed hashed filename. On macOS run:

```sh
RELGRAPH_CONSTRUCTION_COST_CASE=union_exact_512 /usr/bin/time -l "$construction_test_executable" authz::model::construction_costs::measure_construction_costs --ignored --exact --nocapture --test-threads=1
```

Repeat with the other three exact case names. `construction_test_executable`
is a task-specific shell variable holding that discovered executable path.
On Linux use `/usr/bin/time -v` with the same test command. Record units:
macOS maximum resident set size is bytes; GNU time reports kilobytes. This
whole-process peak includes fixture preparation, test harness, and all six
phases for one case. It is not index-only allocation or live evaluator memory.
Do not time `cargo` itself for RSS or convert peak RSS into allocation counts.

Platform handling is fixed: run on the current host; also run on a Linux x86_64
host only if one is already available through the authorized environment. No
new CI workflow, remote credentials, cloud instance, or cross-platform emulation.
If unavailable, record **Linux x86_64 not measured** and restrict conclusions to
the actual host. Mention the absent declared MSRV and avoid a blanket supported-
platform claim. Stress success is deterministic evidence; timing is descriptive.

If a child aborts or compilation fails for an allowed workload, stop this task
with `[PROGRESS]`, report case/platform/profile and output, and request a concrete
plan amendment. Do not mark construction costs comfortable or silently replace
recursive compilation. A slow case must be reported with its measured values;
the current scope measures costs rather than promising a latency target.

**Acceptance:** all local allowed-input subprocesses succeed; all three timing
runs and four RSS observations are recorded with metadata and limitations.
Every platform claim matches an actual run. Unavailable optional second-host
measurements are explicitly identified and do not block a local evidence report.

**Verification:** inspect recorded tables against captured output;
`git diff --check`. No implementation or optimization changes in this commit.

**Execution record:** unstarted.

## Task 7 — Validate the completed follow-ups and publish their documented scope [TODO]

**Dependency:** task 6. **Commit:** `docs(authz): document streaming and construction evidence`.

**Owned files:** `relgraph-authz/README.md`, `CONSTRUCTION_COSTS.md`, and this plan.
If verification identifies a code defect, amend the responsible earlier task
with its exact file/symbol fix before implementing it; no unspecified fixes here.

Add README subsection **Construction cost measurements** after **Errors and
execution limits**, linking to `../CONSTRUCTION_COSTS.md`. Summarize only actual
host results, near-limit stress coverage, and the distinction between parser
limits, expression compilation depth, and whole-model index volume. Include
the measurement command from task 5. Review the streaming contract for agreement
with tests, especially skipped late errors, whole-page stored-context preparation,
and per-active-traversal memory bounds. Preserve independent-project and partial-
OpenFGA-compatibility language.

Run these final gates and record outcomes, distinguishing database/environment
blocks from implementation failures:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo test -p relgraph-authz --all-targets --no-default-features
cargo test -p relgraph-authz --all-targets --features axum
cargo test -p relgraph_dsl -p relgraph-authz --all-targets --all-features
cargo test -p relgraph-authz-postgres --lib
cargo test --workspace --doc --all-features
git diff --check
```

The ignored measurement harness must remain ignored during ordinary gates.
Run `cargo test --workspace --all-targets --all-features` only when the already
configured `OPENFGA_POSTGRES_TEST_URL` identifies a disposable server with the
documented privileges. Never print the URL or use an arbitrary database. If
unavailable, record the full/live PostgreSQL gate as unrun and do not claim full
workspace test success. Compilation and PostgreSQL library tests are still
required; this work does not change the adapter API or SQL.

Run `python3 relgraph-authz/tools/openfga-differential.py` if the documented
Python/Docker prerequisites are already available. Record fresh results separately
from offline fixture tests. If prerequisites are unavailable, record the
external gate as unrun. Custom-store corruption/page precedence is a local
contract, not asserted OpenFGA compatibility. Parser syntax is unchanged, so a
fresh ANTLR syntax differential run is not required for these follow-ups.

Finish by checking task statuses, scoped diffs, and commit boundaries. Record
any remaining environment-only gates in this task's execution record. Both
follow-ups are complete only when streaming acceptance and the construction
measurement report are complete; a benchmark harness alone is insufficient.

**Acceptance:** all required local gates pass; README and evidence report agree
with implemented/tested behavior; optional unavailable live/external gates are
clearly stated; all seven task headings are `[DONE]` with execution evidence.

**Execution record:** unstarted.
