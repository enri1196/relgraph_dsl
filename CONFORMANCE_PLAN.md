# OpenFGA conformance plan

Goal: run OpenFGA's own test corpora for **DSL syntax/validation** and **Check
semantics** against Relgraph, offline, as ordinary `cargo test` targets. Success
means a pinned upstream corpus runs unmodified and every case either passes or
is listed in a reviewed, justified skip list that only ever shrinks.

State when this plan was written (2026-10-18): 64 hand-written syntax fixtures
checked against the pinned ANTLR grammar, and 40 hand-written Check cases plus 5
model-acceptance entries checked against an `openfga/openfga:v1.21.0` container.
Neither replays upstream's own tests.

## How to work this plan

Every task below has a status marker in its title: `[TODO]`, `[PROGRESS]` or
`[DONE]`.

1. Pick a `[TODO]` task whose **Depends on** tasks are all `[DONE]`, and whose
   **Blocked by** decisions (if any) are recorded in the Decisions section.
2. Claim it first: change its title marker to `[PROGRESS]`, and commit only that
   change (`chore(plan): claim task N`). Do not start work on a task that is
   already `[PROGRESS]`.
3. Do the work. Commit in coherent steps with conventional messages
   (`feat(...)`, `test(...)`, `docs(...)`, `chore(...)`), one concern per commit.
4. Finish only when every **Acceptance** item holds. Then change the marker to
   `[DONE]`, add a short `Result:` line under the task (pass rates, files added,
   anything a later task needs to know), and commit that update.
5. If a task turns out to need a change to the plan (new task, wrong
   assumption), edit this file in a separate `docs(plan)` commit and say why.

Rules for every task:

- Navigate Rust code with the CodeGraph MCP (`codegraph_context`, then
  `codegraph_explore` / `codegraph_node`). Use ordinary reads only for
  manifests, SQL, YAML fixtures and documentation.
- Follow `AGENTS.md`: keep parser acceptance, semantic validity, runtime
  support and upstream compatibility as separate claims; preserve tenant
  isolation, snapshot consistency, stored-context precedence and the
  error-versus-deny rules; do not touch `.codegraph` or vendored upstream
  files; no compatibility wrappers (pre-1.0).
- Validation (run what applies; claim "workspace clean" only after all of it):

  ```sh
  cargo fmt --all -- --check
  cargo check --workspace --all-targets --all-features
  cargo test -p relgraph_dsl -p relgraph-authz --all-targets --all-features
  cargo test -p relgraph-authz --all-targets            # no features
  cargo test -p relgraph-authz --all-targets --features axum
  cargo test --workspace --doc --all-features
  cargo test --workspace --all-targets --all-features
  ```

  The live PostgreSQL tests are `#[ignore]`d and need a disposable server; do
  not run them against an arbitrary database.

## Pins (already chosen)

- `openfga/language` @ `fbc62984d02fc8ff7e2a924e0b9c34193233007c` (already the
  syntax pin): `tests/data/dsl-syntax-validation-cases.yaml`,
  `dsl-semantic-validation-cases.yaml`, `fga-mod-transformer-cases.yaml`.
- `openfga/openfga` @ `v1.21.0` (already the Docker differential pin):
  `assets/tests/consolidated_1_1_tests.yaml`, `assets/tests/abac_tests.yaml`.
- Both repositories are Apache-2.0. Bumping a pin is a deliberate change that
  updates the files and checksums together and reviews the skip-list diff.

## Shared conventions

**Upstream formats (verified at the pins).**

- Check YAMLs: top-level `tests:`, each with `name` and `stages`. A stage has
  `model` (**DSL text**, not JSON), `tuples`, `checkAssertions`,
  `listObjectsAssertions`, `listUsersAssertions`. A check assertion has
  `tuple{user,relation,object}`, optional `context`, optional `contextualTuples`,
  and `expectation` (bool) or `errorCode`. Tuples may carry
  `condition{name, context}`. The ABAC file also contains inline-expression
  conditions and `ipaddress` / `in_cidr`.
- Language YAMLs: `name`, `dsl`, optional `expected_errors` (each `msg`,
  `line{start,end}`, `column{start,end}`, `metadata{symbol, errorType}`), and
  `skip: true` in some semantic cases. The syntax file mixes parser errors
  (ANTLR-style text) with semantic ones (duplicates, `extend` outside a modular
  model); its errors carry no `errorType` (`metadata` has only `symbol`, and
  four errors have no `metadata`), so its runner classifies them from the
  message. `fga-mod-transformer-cases.yaml` has `modFile`, `json`,
  `expected_errors`.
- Where this plan and a vendored file disagree, the file wins; fix the plan.

**Case IDs.** `file::test-name::stage-index::kind::index` where `kind` is
`check`, `ctxCheck`, `listObjects`, `listUsers` or `model`. `ctxCheck` (added
by Task 7) is upstream's `_ctxTuples` replay of a single-stage test's check
assertions with the stage tuples sent as contextual tuples; stage entries
cover it, case entries name it separately. For language files:
`file::case-name`. The pinned syntax file repeats one case name (`mixed
operators with mixed operations and paren sets`, with different DSL), so a name
that repeats within a file gets `#n` appended from its second occurrence
(`…#2`, `…#3`). The harness fails on duplicate IDs after that rule.

**Skip list.** One YAML file per crate, sorted and deterministically serialized.
Each entry is one of: a single case ID, a stage (`…::stage-index`), or a rule
(for example every `listObjects` / `listUsers` case, or a file such as the JSON
transformer data). Every entry has `reason` (one of `unsupported-feature`,
`semantic-divergence`, `harness-gap`), a `tag` from that reason's vocabulary
(`SkipReason::TAGS` in the test support; for `semantic-divergence` it is `bug`
or `deliberate`), a free-text `justification`, and
`task` (the plan task that is expected to remove it, or `permanent`). The test
fails on (a) any failing case not covered by an entry, and (b) any entry
whose covered cases all pass. The logic is small; implement it in each crate's
test support rather than adding a shared crate.

**Error mapping tables.** Each runner keeps one table in code: upstream
`errorType` → Relgraph `ValidationError` kind (semantic), and upstream
`errorCode` (2000, 2021, 2027, and any others that appear) → `AuthorizationError`
/ `ConstructionError` variant (Check). A case with no table entry is a
`harness-gap`, not a pass or a fail.

## Task 1 [DONE]: Vendor the pinned upstream corpora

**Depends on:** none.

**Files:**

- `relgraph-dsl/tests/fixtures/openfga/upstream/` (add alongside the existing
  grammars): the three `language` YAMLs above.
- `relgraph-authz/tests/fixtures/authz/upstream/` (new): the two `openfga`
  YAMLs.
- A `CHECKSUMS` file in each directory (SHA-256, same style as
  `tools/conformance/README.md`) and the upstream `LICENSE` text for `openfga`
  (the `language` licence is already vendored).
- Update `relgraph-dsl/tests/fixtures/openfga/upstream/README.md` and
  `relgraph-authz/tests/fixtures/authz/README.md` with source URLs at the
  pinned revisions.

**Steps:**

1. Download each file from the pinned revision; never edit the contents.
2. Record checksums; add a test that recomputes them (a small SHA-256 in test
   code is fine; use an existing dev-dependency if one is available, otherwise
   a documented `shasum` verification step instead of a new dependency).
3. Do not vendor the `stores/` or `transformer*/` directories (out of scope).

**Acceptance:** files present and byte-identical to upstream; checksums
documented; `cargo fmt` and the workspace tests unaffected.

Result: the three language YAMLs are in `relgraph-dsl/tests/fixtures/openfga/upstream/`,
and `consolidated_1_1_tests.yaml`, `abac_tests.yaml` and the openfga `LICENSE` are in
`relgraph-authz/tests/fixtures/authz/upstream/`. Byte identity was checked
against the GitHub Git blob IDs at the pins (`v1.21.0` resolves to
`ab557c5592670c899de35297e7aa067015f06502`). Each directory has a
`shasum -a 256`-format `CHECKSUMS` (the DSL one also covers the grammars and
language `LICENSE`). A new `upstream_checksums` test in each crate recomputes
the digests with a small SHA-256 in the test code (no new dependency) and fails
on any unlisted file except `README.md` / `CHECKSUMS`, so later tasks must keep
skip lists and runners outside `upstream/`. Both READMEs give source URLs.
`cargo fmt --check`, `cargo check --workspace --all-targets --all-features` and
all plan test commands pass (the live PostgreSQL tests were not run).

## Task 2 [DONE]: Language corpus runner (syntax, semantic, fga.mod)

**Depends on:** Task 1.

**Files:** new `relgraph-dsl/tests/upstream_corpus.rs` (plus
`tests/support/` helpers) and `relgraph-dsl/tests/fixtures/openfga/upstream-skip.yaml`.
`serde` and `serde_yaml` are already dependencies of `relgraph-dsl`; add nothing
that makes the DSL crate depend on `relgraph-authz`.

**Steps:**

1. Deserialize the three language YAMLs with Serde.
2. Syntax and semantic cases: run `parse_fga_schema`, then `validate_schema`
   (use the modular path for `module` / `extend` cases). Gate on accept versus
   reject. For rejected cases compare the multiset of `(errorType, symbol)`
   through the mapping table, never the `msg` text. Honor `skip: true`.
3. Positions: compute whether line/column match and report the match rate as a
   printed metric only. Do not gate on it (ANTLR error recovery positions
   differ, and manifest errors carry no spans).
4. `fga-mod-transformer-cases.yaml`: run `modFile` through `parse_model_manifest`
   and gate on accept/reject only; skip the expected `json` output by rule
   (`unsupported-feature`, task: permanent until JSON models exist).
5. Implement the skip-list mechanism from Shared conventions.
6. Initially list every failing case with a provisional reason; Task 4
   classifies them properly.

**Acceptance:** `cargo test -p relgraph_dsl --test upstream_corpus` is green
with the skip list in place and prints per-file totals (pass / skipped / metric);
the existing 64-fixture `conformance` test is untouched and green.

Result: `relgraph-dsl/tests/upstream_corpus.rs`, `tests/support/skip_list.rs`
and `tests/fixtures/openfga/upstream-skip.yaml` added (plus a fixtures README
section). Baseline (`-- --nocapture`): syntax 76/81 pass, 5 skip-listed (3
fail, 2 harness-gap), position metric 46/74; semantic 35/86 run cases pass, 51
skip-listed (50 fail, 1 harness-gap), 7 upstream `skip: true`, position metric
0/53 (Relgraph validation spans cover the whole declaration); fga.mod 7/9 pass,
2 fail (`schema: "1.1"` and a non-`.fga` path are accepted), plus the `json`
output rule. The skip list has 58 entries marked `provisional: true` (29
semantic-divergence, 26 unsupported-feature, 3 harness-gap) and one final rule
`fga-mod-json-output` (permanent); Task 4 must clear the `provisional` flags.
Notes for later tasks: `ValidationError` has no symbol, so symbols are a metric
(substring of a Relgraph span), not gated; one `ValidationIssue` may map to
several upstream types (`UnknownRelation` → `missing-definition` /
`invalid-relation-type`), so the multiset comparison is a bipartite matching;
syntax errors compare the stage only (ANTLR recovers, Relgraph stops at the
first); `EmptyModel` and `UnknownExtensionType` have no table entry (harness
gaps); the syntax corpus's two `extend` diagnostics use harness-local types
`syntax-file:*`. A lone `module` document is composed as the only file of a
1.2 manifest, so upstream's `schema-version-required` cases fail. Eight cases
show a parser divergence: Relgraph rejects comments trailing a header, schema
or type line (e.g. `schema 1.5 # a comment`) and an indented comment between
`model` and `schema`, which the pinned corpus parses. Validation: all plan
commands pass; `conformance` unchanged and green; clippy clean on the crate.

## Task 3 [DONE]: Check corpus runner

**Depends on:** Task 1.

**Files:** new `relgraph-authz/tests/upstream_check.rs` (plus
`tests/support/` helpers) and `relgraph-authz/tests/fixtures/authz/upstream-skip.yaml`.
Add `serde` (with `derive`) and `serde_yaml` to `relgraph-authz`'s
`[dev-dependencies]` only.

**Steps:**

1. Find the Go test driver in `openfga/openfga@v1.21.0` that loads
   `assets/tests/*.yaml` and record in the test's module docs how it treats
   stages: whether tuples accumulate across stages or each stage starts from an
   empty store. Mirror that.
2. For each stage: `FgaAuthz::new(model)`; construction errors make the stage a
   skip candidate. Bind an `InMemoryRelationshipStore`. Write tuples through the
   validating `FgaAuthz<Bound<S>>::write_tuple` / `apply_changes` (not direct
   store inserts), using one fixed `TenantId`. Map `condition{name,context}` to
   the stored condition context.
3. Run every `checkAssertions` entry: `context` → global request context;
   compare allow/deny, or `errorCode` through the table. Assertions with
   `contextualTuples` are skipped by rule (`unsupported-feature`, task 7) until
   Task 7. Parse, but skip by rule, `listObjectsAssertions` and
   `listUsersAssertions` (`unsupported-feature`, task: deferred list-API plan).
4. Replay each stage's checks as a `batch_check` as well, as
   `authz_compatibility.rs` does for the hand-written fixtures.
5. Implement the same skip-list mechanism as Task 2.

**Acceptance:** `cargo test -p relgraph-authz --test upstream_check` is green
with the skip list in place and prints per-file totals; it passes without
features and with `--features axum`; existing authz tests unchanged.

Result: `relgraph-authz/tests/upstream_check.rs`, `tests/support/skip_list.rs`
(a copy of the DSL crate's; keep them in sync) and
`tests/fixtures/authz/upstream-skip.yaml` added, plus a fixtures README section;
`serde`/`serde_yaml` are dev-dependencies only. Upstream driver
(`tests/check/check.go` at `v1.21.0`): one store per test, stages in order,
**tuples accumulate across stages**, each stage checks against its own model;
upstream also skips stages whose `modelgraph.New` fails and replays every
single-stage test with its tuples as contextual tuples (`_ctxTuples`). Neither
is replayed (the second is a candidate for Task 7). Case IDs add a
`model::0` case per stage; a failed construction or rejected tuple write leaves
that stage's (and, for missing tuples, later stages') checks not run.
Baseline (`-- --nocapture`): consolidated 1094 cases, 481 pass (check 323/364,
model 158/161, list 0/569); ABAC 368 cases, 147 pass (check 120/152, model
27/37, list 0/179). Run error-code checks: 2000 29/29, 2002 1/1; 2027 occurs
only with contextual tuples. `batch_check` agreed with individual checks on all
467 replayed items. The skip list has 3 rules (`contextual-tuples` task 7,
`list-objects-assertions` / `list-users-assertions` deferred list-API plan) and
43 provisional case entries: 24 semantic-divergence checks where a tuple
written under an earlier stage's model no longer fits the current one (Relgraph
reads are strict, upstream ignores such tuples; `AGENTS.md` records strict
reads as a maintainer decision), 3 `RecursiveDifference` stages (task 10), 9
inline-condition stages (task 10), 1 `ipaddress` stage (task 8), and 6 userset
or wildcard check subjects that `CheckRequest` cannot express. Check maps
unknown types/relations to 2000, not 2021/2022 (those occur only in list
assertions). Validation: all plan commands pass (live PostgreSQL tests not run);
clippy clean on the crate.

## Task 4 [DONE]: Baseline classification and published pass rates

**Depends on:** Tasks 2 and 3.

**Steps:**

1. Replace every provisional skip reason with a final one: `unsupported-feature`
   (tagged contextual-tuples, cel, inline-condition, ipaddress, list-api,
   json-model, or the Phase 1 area), `semantic-divergence` (bug versus
   deliberate difference, with written justification), or `harness-gap`.
2. Verify that relation depth 25 and the error-code table agree with the corpus
   (the 25 default already landed in `09b63bc`); fix mapping errors in the
   harness, not in the evaluator, unless a real divergence is found, in which
   case record it as a `semantic-divergence` and open a new task.
3. Record the numbers in a table in each fixtures README: total, passing,
   skipped by reason, per corpus file.
4. Reorder or add tasks 5-9 in this plan if the numbers show a different
   priority (separate `docs(plan)` commit).

**Acceptance:** no skip entry has a provisional reason; both READMEs list the
pass rates; the plan reflects the measured priorities.

Result: `provisional` is gone from the skip-list format (an unknown field now
fails the load); every entry carries a `tag` checked against
`SkipReason::TAGS`, and both runners print non-passing cases per reason/tag.
The language runner now mirrors upstream `validateDSL` staging (lone module:
file-local composition issues, else `ModuleRequiresComposition` =
`schema-version-required`; listener-stage issues compared alone), which cleared
all 3 harness gaps and 1 divergence: syntax 78/81, semantic 37/86 run (7
upstream skips), fga.mod 7/9 + JSON rule; 55 entries. Check corpora unchanged:
consolidated 481/1094, ABAC 147/368; 46 entries. Classification: DSL 40
`unsupported-feature/validation` (Task 5), 8 comment `semantic-divergence/bug`
(new Task 12), 4 `deliberate`/permanent (EmptyModel x2, cascade diagnostics,
TTU granularity), 2 `manifest` (Task 6); authz 24 strict-read and 3
negation-cycle stages `deliberate`/permanent, 9 `inline-condition` stages
permanent, 1 `ipaddress` stage (Task 9), 6 `userset-subject` checks (new Task
13). Task 10 still has to document the permanent entries in the authz README's
compatibility boundary. Error-code table agrees with the corpus (2000 29/29,
2002 1/1; 2027 only with contextual tuples; 2021/2022 only in list
assertions); no harness or evaluator mapping change was needed. Depth: the
corpus result is identical for limits 7-26 and fails from 27, so 25 agrees.
Side finding (not a corpus failure): with the limit set to 6 (5 also fails the
batch comparison),
`three_prong_relation_possible_exclusion::0::check::5` allows in `batch_check`
but errors `RelationDepthExceeded` individually, because a batch reuses
memoized allows from earlier items. Pass-rate tables are in both fixtures
READMEs. Validation: `cargo fmt --check`, `cargo check --workspace
--all-targets --all-features`, all plan test commands and clippy on both
crates pass (live PostgreSQL tests not run).

## Measured priorities (from Task 4)

Non-passing cases by owner after Task 4 (see the fixtures READMEs for the
tables). Task numbers are kept stable because skip entries reference them;
work them in roughly this order of corpus impact:

| Owner | Cases | Area |
| --- | ---: | --- |
| Deferred list-API plan | 748 | every `listObjects` / `listUsers` assertion |
| Task 5 | 40 | missing DSL validation rules (17 entry-point, 14 repeated operand/restriction, 4 reserved names, 3 unused condition, 2 naming rule) |
| Task 12 (new) | 8 | comments the upstream DSL pipeline strips before parsing |
| Task 7 | 9 | contextual tuples (plus upstream's `_ctxTuples` replay of every single-stage test, not yet counted) |
| Task 13 (new) | 6 | userset / wildcard check subjects |
| Task 6 | 2 | manifest tightening |
| Tasks 8-9 | 4 | one `ipaddress` stage; no other CEL feature fails in the corpora, so CEL work is low priority by corpus numbers |
| permanent | 72 | deliberate divergences (24 strict-read checks, 13 negation-cycle cases, 4 DSL) and 30 inline-condition cases, 1 JSON-output rule case |

## Task 5 [DONE]: Semantic validation parity

**Depends on:** Task 4.

**Steps:**

1. Work through the `semantic-divergence` / `unsupported-feature` entries that
   point at validation (cycles OpenFGA rejects at model write, tuple-to-userset
   tupleset restrictions, invalid wildcard use, relations with no entry point,
   conditions declared but unused, and so on), a few error types per commit.
2. Extend `relgraph-dsl/src/validation.rs` and `ValidationError` as needed; keep
   spans on new diagnostics. Update the error-type mapping table in Task 2.
3. Remove skip entries as cases start passing (the test enforces it).
4. Check that no previously accepted model in the 64 syntax fixtures,
   `modular/` fixtures, examples or authz fixtures becomes rejected without a
   justification; new rejections are a user-visible change, so note them in the
   DSL README.
5. Keep `validate_schema` free of CEL compilation and runtime concerns.

**Acceptance:** semantic corpus skip list shrinks (record before/after counts);
all existing DSL and authz tests green; DSL README documents new diagnostics.

Result: seven `ValidationIssue` rules, following `pkg/js/validator/validate-dsl.ts`
at the language pin: `ReservedTypeName` / `ReservedRelationName` (`self`,
`this`), `InvalidName` (type 1-254, relation 1-50 characters, no `:#@*` or
whitespace), `DuplicateTypeRestriction`, `DuplicateOperand` (top-level
operator only; a left-nested chain of one operator counts as one, so
`(a or b) or a` is stricter than upstream), `UnusedCondition`, and
`NoEntryPoint` (least fixed point; difference needs both operands, as
upstream; runs only when every other rule passed, like upstream). All map in
the runner's table; `UPSTREAM_TYPES_WITHOUT_COUNTERPART` is now empty. Semantic
corpus: 37 to 77 of 86 run cases pass, skip list 55 to 15 entries (the 40
`unsupported-feature/validation` entries are gone; 7 Task 12 comment bugs and
2 permanent deliberate entries remain in that file). Check corpora unchanged
(481/1094, 147/368). User-visible rejections, each checked: the
`valid/cyclic.fga` validation fixture (a cycle with no entry point) moved to
`invalid/no-entry-point-cycle.fga` and was replaced by a cycle with an entry
point; the main `modular/` fixture now uses its two conditions and is asserted
to validate; authz tests that used `member or member`, a no-entry-point cycle,
and the construction stress workloads (`base or base ...`) now use distinct
relations (construction counts updated; `union_exact_512` / `repeated_128`
remeasured in the authz README). Grammar fixtures `valid/computed-userset.fga`
and `valid/types-before-conditions.fga` (syntax-only) now fail validation;
noted in the fixtures README. Examples, authz fixtures and
`recursion_models.json` models still validate. The DSL crate has no README of
its own, so the rules are documented in the crate docs (`lib.rs`); `AGENTS.md`'s
validator summary was updated. Validation: `cargo fmt --check`,
`cargo check --workspace --all-targets --all-features`, all plan test commands
and clippy (workspace, all features) pass; live PostgreSQL tests not run.

## Task 6 [DONE]: Manifest (`fga.mod`) parity

**Depends on:** Task 4.

Current behavior (`relgraph-dsl/src/manifest.rs`): the schema may be any ASCII
`major.minor`, module paths need not end in `.fga`, and percent-encoded
traversal is not rejected.

**Steps:**

1. Compare each `fga-mod-transformer-cases.yaml` error case with
   `parse_model_manifest` / `validate_manifest_value`: schema must be exactly
   `1.2`, contents items must be `.fga` paths, percent-encoded and backslash
   traversal rejected, wrong YAML types rejected.
2. Decide per divergence whether to tighten the parser or record a justified
   skip. Tightening changes accepted input (for example `schema: "1.1"`
   manifests); check the existing manifest and modular fixtures and tests first
   and update them deliberately.
3. Manifest error positions stay out of scope (`serde_yaml` nodes carry no
   spans); keep that as a permanent skip reason for position metrics.

**Acceptance:** `fga-mod` cases pass or have justified skip entries; manifest
and modular tests green; README documents any tightened behavior.

Result: `parse_model_manifest` now follows upstream's `TransformModFile` /
`transformModFileToJSON` (`pkg/go/transformer/mod-to-json.go`,
`pkg/js/transformer/modules/mod-to-json.ts` at the language pin): `schema`
must be exactly `1.2` (`InvalidSchemaVersion`, also applied to constructed
manifests by `assemble_modular_model`, so modular `UnsupportedSchemaVersion`
is now only a defensive check), every path must end in `.fga`, any `..`
component is rejected instead of normalized, and any `%` is rejected (upstream
percent-decodes, differently in Go and JS; Relgraph reads paths literally).
fga.mod corpus: 7 to 9 of 9 manifests pass; the 2 `unsupported-feature/manifest`
entries are gone (DSL skip list 15 to 13 entries; only the permanent JSON-output
rule remains for that file). Wrong YAML types were already rejected. Remaining
differences are deliberate and documented in the DSL fixtures README ("fga.mod
manifest policy"): Relgraph is stricter on `%`, every backslash, unknown
fields, empty `contents`, duplicate paths, explicit tags and multiple
documents, and drops `.` / empty components. Manifest positions stay a
permanent non-metric (`serde_yaml` has no spans). `tests/manifest.rs` replays
each entry of upstream's multi-path case on its own. User-visible changes,
updated deliberately: manifest fixtures (`ordered.yaml`, `aliases.yaml`,
`normalized_paths.yaml`) no longer use non-`.fga` paths, version `2.0` or
in-root `..`; modular tests that composed `9.7` / `01.02` / `1.1` manifests now
assert `InvalidSchemaVersion`. Authz `from_modular_model` tests and examples
were unaffected. `AGENTS.md` manifest summary updated. Validation:
`cargo fmt --check`, `cargo check --workspace --all-targets --all-features`,
all plan test commands and clippy on the DSL crate pass (live PostgreSQL tests
not run).

## Task 7 [DONE]: Contextual tuples

**Depends on:** Task 4.

**Design requirements (do not skip any):**

- Add `contextual_tuples` to the internal `CheckScope` in
  `relgraph-authz/src/authz/request.rs`, exposed through `CheckRequest` and
  `BatchCheckRequest` builders, so memoized decisions and the request-value
  cache stay valid only for an unchanged scope and a batch shares them across
  its items. `filter_objects` stays context-free.
- Merge them inside the evaluator's tuple loading
  (`load_tuple_page` / `prepare_assignment_page` / `prepare_tupleset_page` in
  `relgraph-authz/src/authz/evaluator.rs`), not with a wrapper
  `RelationshipReadSession`: store cursors are session- and query-bound and a
  continuing page may not be empty, so a wrapper would need its own cursor
  scheme. Index the contextual tuples by (object, relation) once per scope.
- Validate at request construction or first use: tenant equals the request
  tenant (`validate_tuple` does not check tenants), `CompiledModel::validate_tuple`
  succeeds, no duplicates within the set, and the count is within the limit.
  Confirm OpenFGA's limit from the `v1.21.0` source (believed to be 100) and
  put it in `EvaluationLimits` or a documented constant.
- Deduplicate against stored tuples by identity. Define and document whether
  contextual tuples count toward the scanned-tuple and work budgets (default:
  yes). Condition context precedence is unchanged (tuple context → condition
  scoped request → global request).
- Security: contextual tuples are caller-asserted facts. Do not add a
  `ContextBinding` / `RoutePolicy` / Axum path that fills them from HTTP input.
  Document them as trusted-input only.

**Steps:** implement; add integration tests through the public API (tenant
mismatch, invalid tuple, duplicates, dedup with stored, conditions on contextual
tuples, batch sharing, limit, memo isolation between different contextual
sets); wire `contextualTuples` into the Task 3 runner and remove the rule skip.

**Acceptance:** contextual-tuple corpus cases pass or have justified entries;
new tests green; README (authz) documents the API and trust boundary; Axum and
no-feature builds green.

Result: `CheckRequest` / `BatchCheckRequest::with_contextual_tuples` and
`contextual_tuples()`; the tuples live in `CheckScope`, so a batch shares them
and its memo, and different sets never share an evaluator. `ContextualTuples::prepare`
(`evaluator.rs`) validates once per check or batch, after object/relation/
subject-type resolution and before `begin_read` (as upstream validates the
tuple key, then contextual tuples): at most `MAX_CONTEXTUAL_TUPLES` = 100
(confirmed: `ContextualTupleKeys.tuple_keys` `max_items: 100` in `openfga/api`
at the revision `v1.21.0` pins), request tenant, `CompiledModel::validate_tuple`,
no exact repeat. Errors: `AuthorizationError::ContextualTupleLimitExceeded`,
`InvalidContextualTuple { index, reason: ContextualTupleError::{TenantMismatch,
Duplicate, Model(Box<AuthorizationError>)} }` (outer errors in a batch; Axum's
catch-all maps them to 500, though no middleware path sets contextual tuples).
`load_tuple_page` now returns tuples: a relation's contextual tuples are its
first page (charged to tuple-scan and work budgets, not store calls), and
stored tuples equal to one of that query's contextual tuples are dropped after
being counted as scanned. Deliberate differences from upstream, documented:
repeats are rejected (OpenFGA accepts them) and the tenant is checked. Tests:
`tests/authz_contextual_tuples.rs` (12: tenant mismatch before store read,
model-invalid tuples carrying the `validate_tuple` error, repeats, equal-to-
stored, condition precedence and missing context, limit for check and batch,
tuple budget, batch sharing vs individual checks, memo isolation, userset/
tupleset/`but not` combinations) and an evaluator unit test for page order,
dedup and accounting. Runner: `contextualTuples` are sent (invalid ones map to
2027 via `InvalidContextualTuple`), the `contextual-tuples` rule is gone, and
upstream's `_ctxTuples` replay is mirrored as `ctxCheck` cases (single-stage
tests with at most 100 tuples; none exceeds it). All 9 contextual assertions
pass; consolidated 481/1094 to 767/1380 (check 329/364, ctxCheck 280/286),
ABAC 147/368 to 261/505 (check 123/152, ctxCheck 111/137); 2000 58/58, 2002
2/2, 2027 14/14 across both replays; the only new skip entries are the 6
`ctxCheck` replays of the Task 13 userset/wildcard subjects (stage entries
cover the rest). Authz README, fixtures README and `AGENTS.md` updated.
Validation: `cargo fmt --check`, `cargo check --workspace --all-targets
--all-features`, clippy (workspace, all features), and all plan test commands
pass, including `relgraph-authz` without features and with `axum` and
`cargo test -p relgraph-authz-postgres --lib` (live PostgreSQL tests not run).

## Task 8 [PROGRESS]: CEL route evaluation (produces Decision D1)

**Depends on:** Task 4.

`cel-core` is pinned with `=0.5.1`. It has no `ipaddress` type or `in_cidr`
function, and no `list.contains` overload (standard CEL has none either; list
membership is `in`). Comprehension macros, `bytes` parameters and nested
containers are rejected by Relgraph's own construction profile
(`inspect_expression` / `parameter_profile.rs`), not by the crate, whose
checker and evaluator accept them. This task makes no production change.

**Steps:**

1. Count the CEL-related skip entries from Task 4, grouped by missing feature.
2. In a scratch branch or the scratchpad directory (not committed to the
   workspace), evaluate: upgrading `cel-core`; another Rust CEL crate; adding
   OpenFGA's extension functions (`ipaddress`, `in_cidr`) on top of the current
   crate. For each, record: corpus cases that would newly pass, new dependency
   footprint, maintenance status, impact on `conditions.rs` /
   `parameter_profile.rs` / README profile / cost accounting.
3. Write the comparison and a recommendation under Decision D1 below, and ask
   the maintainer to confirm.

**Acceptance:** D1 contains the comparison and a recommendation; maintainer
sign-off recorded in D1 before Task 9 starts.

## Task 9 [TODO]: CEL coverage implementation

**Depends on:** Task 8. **Blocked by:** Decision D1 recorded and approved.

Scope is whatever D1 selects; at minimum update `conditions.rs`,
`parameter_profile.rs`, the supported-profile text in the authz README and
`AGENTS.md`, and add a fixture for each newly supported surface (per the authz
fixtures README), including the Docker differential fixtures where the server is
available. Remove corpus skip entries as cases pass. Keep stored-context
precedence and the "CEL must compile to bool" rule. Note: local cost
accounting is not OpenFGA cost accounting; only align it where the corpus
asserts a cost limit.

**Acceptance:** CEL skip entries shrink as recorded in D1; all authz tests and
no-feature / `axum` builds green; docs updated.

## Task 10 [TODO]: Record permanent divergences

**Depends on:** Task 4.

**Steps:**

1. Negation cycles: `RecursiveDifference` rejection stays (the evaluator's
   memoization soundness relies on construction rejecting it; see
   `AGENTS.md`). Ensure every affected corpus case has a `semantic-divergence`
   entry with `task: permanent` and a justification referencing OpenFGA
   accepting such models.
2. Inline conditions: the ABAC corpus contains inline-expression conditions.
   Confirm those cases are listed as `unsupported-feature` and document that
   runtime construction rejects them.
3. Document the permanent entries in the authz README's compatibility boundary.

**Acceptance:** no permanent divergence lacks a justification; README lists them.

## Task 11 [TODO]: Documentation and maintenance procedure

**Depends on:** Tasks 4 and 10 (rerun at the end of the plan).

**Steps:**

1. Fix the stale `AGENTS.md` statement that no public constructor accepts a
   modular model: `FgaAuthz::from_modular_model` exists
   (`relgraph-authz/src/authz/mod.rs`, test `tests/modular_authorizer.rs`).
   Add the new test targets and skip-list files to its validation and fixtures
   sections.
2. Write the version-bump procedure into the fixtures READMEs: update both
   pins, refresh files and checksums, rerun, review the skip-list diff in the
   PR.
3. Replace prose compatibility claims in the READMEs with the measured pass
   rates and the skip-list summary per corpus.
4. State in the READMEs that the Docker differential runner covers only the
   hand-written fixtures; running it over OpenFGA's own corpus at the same tag
   would be circular.

**Acceptance:** docs match the code; links and commands in them work.

## Task 12 [TODO]: DSL comment handling parity

**Depends on:** Task 4.

Added by Task 4. Upstream's `parseDSL` (`pkg/js/transformer/dsltojson.ts` at
the language pin) blanks every line whose first non-space character is `#` and
cuts every other line at its first ` #` before running the ANTLR grammar.
Relgraph parses the raw text with the pinned grammar and rejects a comment
after a header, schema or type line and an indented comment between `model`
and `schema` (8 `semantic-divergence/bug` entries in the language skip list).

**Steps:**

1. Decide with the maintainer how far to follow upstream: the preprocessing is
   lossy (it also cuts ` #` inside a condition's CEL body), and `AGENTS.md`
   requires keeping original UTF-8 spans and exact CEL bytes. Prefer accepting
   comments in these positions in the lexer/parser (as hidden tokens) over
   rewriting the input.
2. Update the compatibility contract and the 64-fixture syntax corpus metadata
   deliberately: the grammar-differential runner in `tools/conformance` checks
   the raw grammar, which rejects these documents.
3. Remove the skip entries as cases pass; note the accepted syntax in the DSL
   README.

**Acceptance:** the 8 entries are gone or re-justified as `deliberate`;
span and CEL-byte preservation tests green; syntax fixtures updated.

## Task 13 [TODO]: Userset and wildcard check subjects

**Depends on:** Task 4.

Added by Task 4. Six corpus checks ask about a userset (`group:x#member`) or a
typed wildcard (`user:*`) subject, which `CheckRequest` cannot express
(`unsupported-feature/userset-subject`). Two of them expect a
`validation_error` for a userset whose type or relation is not in the model.

**Steps:** decide whether `Subject` / `CheckRequest` should accept these
subjects (OpenFGA semantics: a userset subject is allowed when the userset
itself is granted; a wildcard subject only by a wildcard tuple). If yes,
design it with the evaluator's memo key and the Axum principal mapping in
mind (an HTTP principal must stay a concrete subject); otherwise mark the
entries `permanent` with a justification.

**Acceptance:** the 6 entries pass or are permanent with a justification.

## Decisions

- **D1 (CEL route):** _undecided_. Written by Task 8; needs maintainer approval.
- **D2 (CI):** the repository has no CI today (`.github/` is absent). The corpus
  runners are plain `cargo test` targets. Whether to add a workflow that runs
  the validation commands is _undecided_; it is not part of this plan.
- **D3 (JSON models):** _undecided_. Whether the OpenFGA JSON `AuthorizationModel`
  becomes a first-class input (`Schema` ↔ JSON, `FgaAuthz::from_json_model`,
  and a DSL printer for the transformer corpus) or stays out. The Check corpora
  do not need it; only the language transformer and `json-validation` data do.

## Deferred to separate plans

- ListObjects, ListUsers and Expand. They need a reverse-lookup extension of the
  store contract (a breaking change for custom stores), a PostgreSQL migration,
  and tenant/snapshot/budget semantics that this plan does not define. Plan them
  once Task 4 shows how many `listObjects` / `listUsers` assertions exist. The
  corpora have no Expand assertions.
- JSON model support (see D3).

## Out of scope

The OpenFGA server API surface: stores and model versioning, ReadChanges,
authentication, gRPC/HTTP endpoints, and consistency preferences beyond the
existing snapshot semantics. Relgraph stays an embedded library.
