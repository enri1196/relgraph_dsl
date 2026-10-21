# Upstream skip-list plan

Goal: account for every entry in the two reviewed skip lists, so that each
remaining skipped upstream case either becomes a passing test or has a recorded
decision that justifies keeping it skipped.

- Authz list: `relgraph-authz/tests/fixtures/authz/upstream-skip.yaml`
  (38 entries when this plan was written, 49 after Tasks 1 to 10; checked by
  `cargo test -p relgraph-authz --test upstream_check`)
- DSL list: `relgraph-dsl/tests/fixtures/openfga/upstream-skip.yaml`
  (5 entries, unchanged; checked by `cargo test -p relgraph_dsl --test upstream_corpus`)

Each entry has `reason`, `tag`, `task` and `justification`. The runners fail on
any non-passing case with no entry, and on any entry whose cases all pass. So
the list can only shrink, and this plan describes how to shrink it or justify
what stays.

## How to work this plan

Every task below has a status marker in its title: `[TODO]`, `[PROGRESS]` or
`[DONE]`.

1. Pick a `[TODO]` task whose **Depends on** tasks are all `[DONE]`, and whose
   **Blocked by** decisions (if any) are recorded in the Decisions section.
2. Claim it first: change its title marker to `[PROGRESS]` and commit only that
   change (`chore(plan): claim task N`). Do not start a task already marked
   `[PROGRESS]`.
3. Do the work in coherent commits with conventional messages (`feat(...)`,
   `test(...)`, `docs(...)`, `chore(...)`), one concern per commit.
4. Finish only when every **Acceptance** item holds. Then mark the task
   `[DONE]`, add a `Result:` line (entries removed or kept, pass rates, files
   added), and commit that update.
5. If a task needs a change to this plan, edit the plan in a separate
   `docs(plan)` commit and say why.

Rules for every task:

- Navigate Rust code with the CodeGraph MCP (`codegraph_context`, then
  `codegraph_explore` / `codegraph_node`). Ordinary reads are for YAML, SQL,
  and documentation.
- Follow `AGENTS.md`. Preserve tenant isolation, snapshot consistency, stored
  context precedence, strict tuple identity, and error-versus-deny rules. Do not
  touch `.codegraph` or the vendored upstream files. No compatibility wrappers.
- Never remove a skip entry by weakening a check. An entry goes away only when
  its cases pass against the same upstream expectations.
- Validation (run what applies; claim a clean workspace only after all of it):

  ```sh
  cargo fmt --all -- --check
  cargo check --workspace --all-targets --all-features
  cargo test -p relgraph_dsl -p relgraph-authz --all-targets --all-features
  cargo test -p relgraph-authz --all-targets            # no features
  cargo test -p relgraph-authz --all-targets --features axum
  cargo test --workspace --doc --all-features
  cargo test --workspace --all-targets --all-features
  ```

## Inventory

Authz list (49 entries, 75 skip-listed cases; recounted by Task 11):

| Group | Entries | Cases | Reason / tag | Current task | Decision | Plan task |
| --- | ---: | ---: | --- | --- | --- | --- |
| Strict stored-tuple reads, check assertions (tuples that no longer fit the model) | 24 | 24 | semantic-divergence / `deliberate` | permanent | S1 | Task 1 |
| Strict stored-tuple reads, list assertions (consolidated 4 `listObjects` + 10 `listUsers`, ABAC 2 + 2) | 18 | 18 | semantic-divergence / `deliberate` | permanent | S1 | Task 8 |
| `but not` negation cycles (`*_butnot_cycle_*`, `list_objects_expands_wildcard_tuple::2`; stage entries) | 3 | 29 | semantic-divergence / `deliberate` | permanent | S2 | Task 2 |
| ListUsers branch errors (`relation_through_ttu_with_condition::0::listUsers::1`, `::2`) | 2 | 2 | semantic-divergence / `deliberate` | permanent | S4f | Task 8 |
| Invalid contextual tuple in list APIs (`condition_bound_to_correct_type_restriction_facet::1::listObjects::0`, `::listUsers::0`) | 2 | 2 | semantic-divergence / `deliberate` | permanent | S4g | Task 8 |

Removed since the plan was written: the 9 `inline-condition` stage entries
(Task 3, S3: all 51 cases pass) and the 2 `list-api` rules (Task 8, S4: 712 of
the 748 list assertions pass; the other 36 are the 18 S1 list entries, the 14
list assertions in the 3 S2 stages, and the 4 S4f/S4g entries). Every remaining
entry is `semantic-divergence/deliberate` with `task: permanent` and cites a
decision recorded under "Maintainer decisions" in `AGENTS.md` (S1, S2, S4f,
S4g). No `unsupported-feature`, `bug` or `harness-gap` entry is left. The 29 S2
cases are 3 models, 10 checks, 2 `ctxCheck` replays and 14 list assertions.
ABAC holds 11 of the 75 cases (S1 7, S4f 2, S4g 2), consolidated 64 (S1 35,
S2 29).

DSL list (5 entries, 5 cases; unchanged by Tasks 1 to 10 apart from wording):

| Entry | Reason / tag | Current task | Decision | Plan task |
| --- | --- | --- | --- | --- |
| `dsl-semantic-validation-cases.yaml::duplicate in type name` | semantic-divergence / `deliberate` | permanent | S6 | Task 9 |
| `…::model 1.1 should raise error if none of the children has such relation` | semantic-divergence / `deliberate` | permanent | S6 | Task 9 |
| `dsl-syntax-validation-cases.yaml::valid syntax (1)` | semantic-divergence / `deliberate` | permanent | none (record in the DSL fixtures README) | Task 9 |
| `…::valid syntax (2): comment preceding model` | semantic-divergence / `deliberate` | permanent | none (record in the DSL fixtures README) | Task 9 |
| rule `fga-mod-json-output` | unsupported-feature / `json-model` | permanent | S5 | Task 10 |

The two `EmptyModel` entries cite no decision ID. Their justification points to
the record in `relgraph-dsl/tests/fixtures/openfga/README.md` (the OpenFGA API
requires at least one type definition), which Task 9 step 3 kept. S6 does not
cover them, because upstream accepts these models and Relgraph rejects them
(Task 9 Result). The DSL runner does not require a decision ID; giving these
entries one needs a maintainer decision.

## Decisions

- **S1 (strict stored reads):** Relgraph errors when a stored tuple no longer
  fits the current model. Upstream ignores such tuples. This is a maintainer
  decision (AGENTS.md). Task 1 records it and keeps the entries.
- **S2 (negation cycles):** construction rejects cycles through `but not`, as
  the least-fixed-point evaluator depends on it. Task 2 records it.
- **S3 (inline conditions):** **approved by the maintainer on 2026-10-19: support
  inline condition expressions** (`[user with $expression]`). The syntax is in
  the pinned openfga/language grammar and the pinned openfga/openfga v1.21.0
  corpus exercises it, so it is part of the standard, not a Relgraph extension.
  Task 3 implements it. Its scope is set by the classification in Task 3 step 1.
- **S4 (list APIs):** **approved 2026-10-19: add ListObjects and ListUsers
  (option A).** Requirement from the maintainer: the list operations must share
  the check algorithm, not reimplement it. Proposed design (Task 4 records it
  as final): the store supplies only a candidate generator, and every candidate
  is then decided by the existing check path.
  - *Candidate generation.* A reverse index over stored tuples produces a
    superset of the objects (or users) that could be granted. It walks the
    model's reverse edges: direct tuples, computed usersets, and
    tuple-to-userset. It is the only list-specific code, and it may over-include,
    but it must never miss a grant.
  - *Decision.* Each candidate goes through `batch_check` (already one evaluator,
    shared memo and budgets). That keeps wildcards, usersets, contextual tuples,
    conditions, strict reads, and the error-versus-deny rules identical to
    `check`. Conditions are never used to prune candidates.
  - *Consequence.* Correctness of list results reduces to the candidate
    generator's completeness, which is tested by comparing against brute-force
    `check` over a small store. Cost is bounded by the candidate limit, so a list
    that would exceed it returns an error rather than a partial list.
- **S5 (JSON models):** same question as D3 in `CONFORMANCE_PLAN.md`.
  **Approved 2026-10-19: keep JSON models out** (Relgraph input stays DSL
  text). The `fga-mod-json-output` rule stays permanent and cites S5 (Task 10).
  See the Decision log.

## Task 1 [DONE]: Make the strict-read decision auditable

**Depends on:** none. **Blocked by:** none (S1 is already decided).

**Why.** The 24 strict-read entries have justifications, but each one repeats a
long paragraph. Nothing ties the entries to a single decision record, so a
future reader cannot tell whether a new entry follows the same rule.

**Steps.**

1. Add a short decision record to `AGENTS.md` (or `CONFORMANCE_PLAN.md`
   Decisions), with ID `S1`. It states: stored tuples that drift from the model
   are errors on read; repair goes through the store; upstream's tolerant
   behaviour is not copied. Name the maintainer approval and the date.
2. In each of the 24 entries, shorten `justification` to a reference such as
   `S1: upstream expects <allow|deny>; Relgraph errors <InvalidTuple variant>`.
   Keep the upstream expectation and the Relgraph error text, since those are
   the facts a reviewer checks.
3. Extend the skip-list check in each crate's test support
   (`tests/support/skip_list.rs`) only if needed to reject an unknown decision
   ID. Prefer a plain test over a new schema field.
4. Confirm the canonical serialized form still matches (the test prints the
   expected form on mismatch).

**Acceptance.**

- Every `deliberate` entry in the authz list cites a decision ID that exists.
- `cargo test -p relgraph-authz --test upstream_check` passes with the same
  set of covered cases (no entry added or removed).

**Result:** all 38 authz entries kept (no entry added or removed); the runner
passes with unchanged totals (consolidated 775/1380 pass, abac 272/505).
`AGENTS.md` gains a "Maintainer decisions" section recording S1 and S2 (both
first recorded there on 2026-10-18). The 24 strict-read justifications now read
`S1: upstream expects <allow|deny>; Relgraph errors InvalidTuple("…")`, and the
three negation-cycle ones start with `S2: ` (Task 2 still adds the test name).
New plain test `deliberate_entries_cite_a_recorded_decision` in
`relgraph-authz/tests/upstream_check.rs` reads the IDs from `AGENTS.md` and
rejects a `deliberate` entry citing none or an unknown one; `skip_list.rs` and
the DSL list are unchanged. Decision IDs cited: S1, S2.

## Task 2 [DONE]: Pin the negation-cycle rejection with a direct test

**Depends on:** none. **Blocked by:** none (S2 is already decided).

**Why.** Three entries (`false_butnot_cycle_return_false::0`,
`true_butnot_cycle_return_false::0`, `list_objects_expands_wildcard_tuple::2`)
depend on construction rejecting a cycle through a `but not` operand. The skip
justification is the only place that claim is written down.

**Steps.**

1. Open the existing negation-cycle tests in `tests/authz_recursion.rs` and
   confirm they build the same shapes as the three upstream models. Use
   CodeGraph to find `RecursiveDifference` and the SCC code in
   `relgraph-authz/src/authz/model.rs`.
2. If a shape is not covered, add it to `tests/authz_recursion.rs` as an
   `assert!` that construction returns `RecursiveDifference`, using the public
   API only.
3. Keep the three entries. Update each `justification` to cite the test name.

**Acceptance.** The new test fails if the classifier stops rejecting a
`but not` cycle. The three entries still cover non-passing cases.

**Result:** The direct negation-cycle tests were in `tests/authz_model.rs`
(`rejects_relation_cycles_through_a_subtracted_operand`), not
`tests/authz_recursion.rs`. Its `group#member`/`banned` model has the same
shape as the two `*_butnot_cycle_*` models; the complex
`list_objects_expands_wildcard_tuple::2` model (cycle
`group#member -> group#blocked -> group#member`, sharing its component with
positive tuple-to-userset cycles, base an intersection) was not covered. New
test `upstream_negation_cycle_models_are_rejected_at_construction` in
`tests/authz_recursion.rs` builds both upstream models verbatim through
`FgaAuthz::new` and asserts exactly one `RecursiveDifference` diagnostic each
(`document#viewer`, `group#member`); a temporary mutation disabling the
subtracted-edge check made it fail. The three entries are kept with
reason/tag/task unchanged; their `S2: ` justifications now cite the test.
Validation: `cargo fmt --all -- --check` clean; `cargo test -p relgraph-authz
--test authz_recursion` 7 passed; `cargo test -p relgraph-authz --test
upstream_check -- --nocapture` 4 passed with totals unchanged (abac 272/505
pass, 233 skip-listed; consolidated 775/1380 pass, 605 skip-listed,
deliberate 36).

## Task 3 [DONE]: Support inline condition expressions

**Depends on:** none. **Blocked by:** none (S3 approved 2026-10-19).

**Why.** The standard allows `define viewer: [user with $expression]`, with the
CEL source and parameter types carried on the tuple. The parser already accepts
the syntax (the grammar is pinned). Relgraph rejects it at runtime construction
(`InlineConditionExpression`), so nine ABAC stages (51 cases) fail, and their
entries are skipped.

**Steps.**

1. **Classify the nine stages.** Read each model and tuple in
   `abac_tests.yaml` (`inline_expression_*`). For each, note the CEL constructs
   and parameter types it uses, and whether the existing profile in
   `authz/conditions.rs` (and the README profile) already covers them. Record
   the table in this task's `Result:` line. If any stage needs a construct
   outside the profile (for example comprehension macros or nested containers),
   stop, record it, and ask the maintainer before adding that construct. Do not
   widen the profile silently.
2. **DSL and AST.** Confirm `relgraph-dsl` parses `[user with $expression]`
   (the grammar says yes; add a syntax fixture under
   `relgraph-dsl/tests/fixtures/openfga/` if none exists). Add an AST form for an
   inline type restriction, distinct from a named `RelationCondition`. Enforce
   the reserved name `$expression` in `validation.rs`, using the expectations of
   the pinned semantic cases that mention it.
3. **Stored form.** A tuple with an inline condition carries
   `condition.name = "$expression"` and a context with `expression` (the CEL
   source) and `parameters` (name to type). Check `authz/store.rs`,
   `relgraph-authz-postgres/src/mapping.rs`, and the tuple identity encoding. The
   identity must cover the expression text and parameter types, so two tuples
   differing only in expression are distinct. A migration is needed only if the
   current encoding cannot hold the expression; verify before writing one.
4. **Compile and evaluate.** Compile the stored expression in
   `authz/conditions.rs` when it is first needed, and cache the result by
   expression and parameter types for the lifetime of the check or batch. Use
   the same expression-profile checks, the `bool` result rule, and the existing
   cost estimate. Expression parse or type errors are `InvalidTuple` on write
   (`validate_tuple`) and a strict read error on read, as for named conditions.
5. **Context precedence.** Declared parameters come from the stored tuple. The
   stored-grant rule still holds: a request value must not override a stored
   value. Keep the limits: 65,536 serialized bytes and 10,000 collection entries.
6. **Tests.** Add unit tests in `relgraph-authz/tests/` for: a valid inline
   condition allowed and denied; an undeclared parameter; a parameter type
   mismatch; a non-`bool` expression; an invalid expression at write time; and
   two tuples differing only in expression. Then run the nine corpus stages.
7. **Skip list.** Remove each `inline-condition` entry whose cases pass. Any
   case that still fails keeps its entry with a `task` naming the reason.
8. **Docs.** Update the README profile, the `AGENTS.md` statement that inline
   conditions are rejected, and the measured-priorities table in
   `CONFORMANCE_PLAN.md`.

**Acceptance.** Every stage that the step 1 classification says is in scope
passes. The `inline-condition` tag is gone from the authz skip list, except for
any case kept with a stated reason. Existing named-condition behaviour is
unchanged (its tests still pass). Commits follow the plan's rules: a separate
commit for the parser, another for the runtime, and another for the tests.

**Result:** classification (S3 scope): all nine stages are in the existing
profile, so nothing was widened. `exclusion_subtract_missing_param`: literal
`true` and string `==` on a `group#member` restriction in a `but not`
subtrahend (missing parameter must error); `basic`, `userset_subject`, `ttu`:
string `==` (plain, userset-subject and tupleset restrictions);
`inferred_string_param`: string `==` with no declaration (OpenFGA v1.21.0
`internal/condition/inline.go` infers undeclared identifiers as `string`);
`alongside_named_condition`: string `==` beside named `emp: bool`; `int_param`:
int `>`; `timestamp_param`: `<` with `timestamp(string)`; `ipaddress_param`:
`in_cidr` (D1). The DSL already parsed `$expression` to
`RelationCondition::InlineExpression` (fixture `relation-conditions`, parser
tests); validation now reserves the name (`ReservedConditionName`). The stored
form fits the existing PostgreSQL row and identity digest (no migration).
Skip list: all 9 `inline-condition` entries removed, none kept; the
tag has no entries. Rates: ABAC 272 to 323 of 505 (check 149/152, ctxCheck
137/137, model 37/37); consolidated unchanged at 775/1380; 2000 68/68.
Files: `relgraph-dsl/src/{validation,lib}.rs`, `relgraph-dsl/tests/validation.rs`,
`relgraph-authz/src/authz/{conditions,evaluator,model,policy,request}.rs`,
`relgraph-authz/tests/{authz_inline_conditions,modular_authorizer}.rs`,
`relgraph-authz-postgres/src/mapping.rs` (test), the skip list, `AGENTS.md`,
`README.md`, `CONFORMANCE_PLAN.md`, both fixtures READMEs and the authz README.
Commits: 2b5ada3 (DSL), 3ef3d2c (runtime, skip list), 6e8d30e (tests),
c1e1beb (docs). Validation: fmt clean; workspace check clean; DSL+authz all
features 257 passed; authz no features 169, axum 179; postgres lib 21; doc 8;
workspace all targets 279 passed (12 ignored, live PostgreSQL not run).

## Task 4 [DONE]: Design ListObjects and ListUsers

**Depends on:** Tasks 1 and 2 (their decisions are recorded). **Blocked by:** S4.

**Why.** `list-objects-assertions` and `list-users-assertions` cover every
`listObjectsAssertions` and `listUsersAssertions` entry. The 748 cases in
`CONFORMANCE_PLAN.md` are the largest group of non-passing cases. Relgraph has
no list API. `filter_objects` (`relgraph-authz/src/authz/mod.rs`) only filters
a candidate list the caller provides. It cannot enumerate objects.

**Steps.**

1. Read the upstream shape. In `consolidated_1_1_tests.yaml`,
   `listObjectsAssertions` entries have `request{user, type, relation}` and
   `expectation` (a list of object IDs). `listUsersAssertions` entries have
   `request{filters, object, relation}` and `expectation` (a list of user
   IDs). Some carry contextual tuples and context. Record the exact field set
   from both corpora, including error expectations if any.
2. Write a design section (in this plan, under Decisions S4) that answers:
   - **Object enumeration.** Either a reverse traversal over stored tuples
     (from the subject, through the model's computed-userset and
     tuple-to-userset edges in reverse) or a forward check over every object of
     the requested type. Forward checking needs an object listing the store
     does not provide. Compare both with the existing budgets (10,000 scanned
     tuples, 100,000 work units, 1,024 store pages).
   - **Store contract.** A new `RelationshipReadSession` method (or a separate
     reverse-lookup trait) that returns tuples by subject or by object type.
     It must be tenant-scoped and snapshot-consistent. This is a breaking
     change for custom stores, which the plan must justify.
   - **Semantics.** Behaviour with wildcards, usersets, contextual tuples,
     conditions (the strict-read rule and context precedence still apply), and
     the error-versus-deny rules.
   - **Limits.** Result size, page size and what happens when a budget is hit
     (error, not a partial list).
3. Record the chosen design as decision S4 and get maintainer approval. Only
   then start Task 5.

**Acceptance.** S4 records the algorithm, the store change, the semantics and
the limits. The design is reviewed.

**Result:** design recorded below (cites S1, S4, S4a, S4b). Mismatches M1 to M4
resolved by the maintainer on 2026-10-19 as S4c, S4d and S4e in the Decision log.

- *Upstream shape (748 = 272 + 297 consolidated, 82 + 97 ABAC).* Fields are
  `request`, `expectation` (list; YAML null = empty), `errorCode`,
  `contextualTuples` (`{user, relation, object}`, 34 assertions) and `context`
  (ABAC only, 142), all beside `request`. ListObjects: `request{user, type,
  relation}`; users concrete, userset (7) or `user:*` (1); errors 2000, 2021,
  2022, 2027. ListUsers: `request{filters, object, relation}`, always one filter
  `type` or `type#relation`; results may be `type:id`, `obj#rel` (including the
  requested object's own userset) or `type:*`; errors 2000, 2002, 2021, 2022,
  2027. Quirk: `simple_computeduserset_indirect_ref::0` puts a null
  `expectation` inside `request`.
- *Enumeration (S4): reverse traversal.* ListObjects seeds the keys
  `(relation, object)` that hold the subject: stored tuples whose subject is the
  subject or its type wildcard (a wildcard subject matches only the equal
  wildcard; a userset subject also seeds its own key). It then walks reverse
  edges to a fixpoint over a visited set: computed usersets (same object;
  union and intersection operands, the base of a difference), userset tuples
  (`subject = obj#rel`) and tuple-to-userset (tupleset tuples naming the
  object). Candidates are the reached objects of the requested type. ListUsers
  expands forward from the object with the existing `tuples_page`, yielding
  subjects and usersets matching the filter. Forward checking every object of
  the type is rejected: no store lists objects, cost grows with the type's
  population (each check up to 100,000 work units) rather than with the
  subject's grants, and the candidate limit would trip on population.
- *Store (S4a).* `ReverseLookupStore: RelationshipStore` whose session adds
  `tuples_by_subject_page(object_type, relation, subject, cursor, maximum)`:
  same tenant-scoped snapshot as `begin_read`, same cursor rules as
  `tuples_page`. Not breaking: check-only stores are unchanged.
- *Semantics (S4).* The generator never decides and never evaluates CEL, so
  conditions do not prune. It reads the prepared contextual tuples as extra
  edges and follows stored tuples only after `validate_tuple`, so drift is an
  error (S1). Each candidate is decided by `Evaluator::check_item` on one read
  session, so wildcards, usersets, context precedence and three-valued rules
  match `check`. Allowed candidates are returned sorted; denied ones are
  omitted; any candidate error fails the whole list (unlike `filter_objects`).
- *Limits (S4b).* New `max_list_candidates` on `EvaluationLimits` (default
  1,000) bounds distinct candidates; exceeding it is an error. The generator
  has one set of check budgets (10,000 tuples, 1,024 page calls, 100,000
  work units); each decision has its own, as batch items do. Pages use the
  check's page sizing. Any budget hit is an error, never a partial list.
- *Mismatches with the code.* M1: `batch_check` rejects more than
  `max_batch_items` (default 100, hard maximum 1,000), so lists reuse its
  internal loop bounded by `max_list_candidates` instead. M2: S4 says budgets
  are shared; they reset per item (only memo and request values persist). M3:
  a scope fixes one subject, so ListUsers runs one `Evaluator` per candidate
  on a shared session and needs no reverse trait, unlike Task 6's wording. M4:
  `ContextualTuples::prepare` rejects exact repeats (`Duplicate`), but
  `list_objects_ignores_duplicate_contextual_tuples` expects them ignored;
  proposed: list methods drop exact repeats first, `check` unchanged.

## Task 5 [DONE]: Implement ListObjects in the authz crate

**Depends on:** Task 4. **Blocked by:** S4 approved.

**Steps.**

1. Add the store method(s) from S4 to `authz/store.rs` with a default that
   returns a clear "unsupported" `StoreError` (`InvalidInput` or a new kind
   decided in S4), so existing custom stores still compile. If S4 chose a
   breaking change, implement it instead and update every adapter in the same
   commit.
2. Add the in-memory implementation in `InMemoryRelationshipStore`, reading the
   snapshot. Keep the snapshot consistency rule: old readers do not see later
   writes.
3. Add the evaluator traversal in `authz/evaluator.rs`, reusing
   `EvaluationKey`, the memo, and the cycle-handling rules. Do not add a second
   cycle algorithm. Relations are evaluated by compiled ID.
4. Expose `FgaAuthz<Bound<S>>::list_objects(&ListObjectsRequest)` returning
   `Result<Vec<ObjectRef>, AuthorizationError>`. Validate tenant, subject and
   relation the same way `check` does. Add the request type to
   `authz/request.rs`.
5. Add unit tests in `relgraph-authz/tests/` covering: direct tuples,
   computed usersets, tuple-to-userset, wildcard subjects, a userset subject,
   an unknown type (error), and a budget hit (error).

**Acceptance.** The new unit tests pass. `cargo test -p relgraph-authz
--all-targets --all-features` passes. Public-API docs and a compile-checked
example exist for the new method.

**Result:** implemented as designed (S4, S4a to S4e, S1); no skip entry
changed (list corpora are Task 8). Store (S4a): `ReverseLookupSession:
RelationshipReadSession` adds `tuples_by_subject_page(object_type, relation,
subject, cursor, maximum)` (exact subject match, `tuples_page` cursor rules);
`ReverseLookupStore: RelationshipStore<ReadSession: ReverseLookupSession>` is
blanket-implemented, so step 1's "unsupported" default is not needed and
check-only stores are untouched. `InMemoryReadSession` scans its immutable
snapshot with session/query-bound cursors; PostgreSQL is not implemented
(Task 7). `FgaAuthz<Bound<S: ReverseLookupStore>>::list_objects(&ListObjectsRequest)`
validates type, relation, subject and contextual tuples as `check` does
(`ContextualTuples::prepare_for_list` drops exact repeats, S4e), runs the
reverse traversal in new `authz/evaluator/list.rs` (one budget set, visited
`EvaluationKey` set, no cycle algorithm), then `check_item` per sorted
candidate on the same session; any error fails the list. `EvaluationLimits`
gains `max_list_candidates` (default 1,000, maximum 10,000, a value the plan
left open) and `AuthorizationError::ListCandidateLimitExceeded` (Axum's
catch-all maps it to 500; the middleware never lists). Files changed:
`relgraph-authz/src/{lib.rs,authz/{mod,store,request,evaluator}.rs}`, added
`relgraph-authz/src/authz/evaluator/list.rs`; docs in `AGENTS.md`, `README.md`
and the authz README. Tests: new `relgraph-authz/tests/authz_list_objects.rs`
(16 tests: direct, computed, tuple-to-userset, wildcard and userset subjects,
intersection/difference, unknown type/relation/subject, candidate limit, tuple/
work/store-call budget hits, per-candidate budgets, conditions not pruning,
drifted tuples, contextual edges and duplicates, brute-force `check`
comparison over 10 subjects and 3 types, in-memory paging/snapshot/cursor
rules); a temporary mutation dropping the tuple-to-userset edge failed the
brute-force test. Commits: 3f471b7 (store), ab64005 (traversal, request type,
API; one commit so every commit builds warning-free), d089334 (tests), 3f58ea9
(docs). Validation: `cargo fmt --all -- --check` clean; `cargo check
--workspace --all-targets --all-features` clean; `cargo test -p relgraph-authz
--all-targets --all-features` 195 passed (1 ignored); no features 185; axum
195; `--doc --all-features` 4 (the `list_objects` example runs); `cargo test
--workspace --all-targets --all-features` 295 passed (12 ignored, live
PostgreSQL not run); `upstream_check -- --nocapture` 4 passed, totals unchanged
(consolidated 775/1380, ABAC 323/505).

## Task 6 [DONE]: Implement ListUsers in the authz crate

**Depends on:** Task 5. **Blocked by:** S4 approved.

**Steps.**

1. Add `FgaAuthz<Bound<S>>::list_users(&ListUsersRequest)`. It uses the same
   store extension as Task 5 in the reverse direction. Support the `user`
   filter the corpus uses. Reject other filters with a clear error.
2. Handle wildcards and usersets as S4 specifies. Users listed through a
   wildcard tuple are reported as the wildcard form only where upstream does.
3. Add unit tests mirroring Task 5's list, plus a userset filter case.

**Acceptance.** Same validation as Task 5. The unit tests pass.

**Result:** implemented per S4e (superseding step 1's reverse-direction
wording; cites S1, S4, S4b, S4d, S4e); no skip entry changed (Task 8).
`FgaAuthz<Bound<S: RelationshipStore>>::list_users(&ListUsersRequest)` returns
the allowed `TupleSubject`s sorted by type, ID (wildcard as `*`) and relation;
no reverse trait. `ListUsersRequest` carries object, relation, one
`UserFilter` (`type` or `type#relation`; `FromStr` rejects other forms with
`UserFilterError`), contexts and contextual tuples (repeats dropped). Unknown
object type/relation fail as for `check`; an unknown filter type or relation is
`UnknownSubjectType`/`UnknownSubjectRelation`. New `user_candidates` in
`authz/evaluator/list.rs` expands forward over `tuples_page` (granting operands
only, visited key set, one `Budget` now shared with the ListObjects traversal,
`max_list_candidates`); a type filter collects named subjects and wildcards
(wildcard-only grants are listed as `type:*`), a userset filter every reached
key of its relation including the object's own. Each candidate gets its own
`Evaluator` on the shared session (`Evaluator::into_parts`). Files changed:
`relgraph-authz/src/{lib.rs,authz/{mod,request,evaluator}.rs,authz/evaluator/list.rs}`,
`AGENTS.md`, `relgraph-authz/README.md`; added
`relgraph-authz/tests/authz_list_users.rs` (17 tests: direct, computed,
tuple-to-userset, wildcards, userset filters and own userset,
intersection/difference, unknown type/relation/filter, filter parsing,
candidate limit, tuple/work/store-call/depth budgets, per-candidate budgets,
conditions, drift, contextual edges and duplicates, tenant scope, brute-force
`check` comparison over 6 filters; mutations dropping tuple-to-userset or
userset candidates failed it). A scratch replay (not committed) of the
listUsers corpora passed consolidated 283/293 (10 fail: S1 strict reads) and
ABAC 93/97 (2 S1; 2 in `relation_through_ttu_with_condition` where upstream
errors on a missing parameter in a branch that `check` short-circuits), input
for Task 8. Commits: 3cb2e7f (feature), c399842 (tests), d1c22b8 (docs).
Validation: `cargo fmt --all -- --check` clean; `cargo check --workspace
--all-targets --all-features` clean; `cargo test -p relgraph-authz
--all-targets --all-features` 212 passed (1 ignored); no features 202; axum
212; `--doc --all-features` 5 (the `list_users` example runs); `cargo test
--workspace --all-targets --all-features` 312 passed (12 ignored, live
PostgreSQL not run); `upstream_check -- --nocapture` 4 passed, totals
unchanged (consolidated 775/1380, ABAC 323/505).

## Task 7 [DONE]: Add PostgreSQL support for the list queries

**Depends on:** Tasks 5 and 6. **Blocked by:** none beyond S4.

**Steps.**

1. Implement the new store method(s) in `relgraph-authz-postgres/src/read.rs`.
   Queries must bind to the session's tenant and snapshot, as `query_page`
   does. Keyset paging by `tuple_id` and the cursor codec still apply.
2. If S4 needs an index, add `migrations/0002_*.sql` with a single index. Do
   not change existing migrations. Check the index against the plan with
   `EXPLAIN` on a disposable database.
3. Extend `tests/support/store_contract.rs` so the in-memory and PostgreSQL
   adapters run the same list assertions.
4. Run the live tests only against a disposable server with
   `OPENFGA_POSTGRES_TEST_URL`. Do not print the URL. Record the commands run in
   the `Result:` line.

**Acceptance.** `cargo test -p relgraph-authz-postgres --lib` passes. The live
contract tests pass on a disposable server, or the task says they were not run.

**Result:** implemented per S4a (cites S4, S4e); no skip entry changed (Task 8).
`PostgresReadSession` implements `ReverseLookupSession`, so the blanket
`ReverseLookupStore` covers `PostgresRelationshipStore`; check-only behaviour
is unchanged. `tuples_by_subject_page` runs on the session's repeatable-read
transaction with its tenant, matches the exact subject columns, and pages by
`tuple_id > $after ORDER BY tuple_id`; one `PageQuery`-driven `query_page` and
cursor codec serve both queries, and a subject cursor (own magic) binds
session, tenant, object type, relation and subject. Ordering: PostgreSQL
returns `tuple_id` order, the in-memory store its snapshot scan order; both are
stable within a session, which is all the contract promises, so the shared
contract compares results order-independently (list results are sorted).
Migration `0002_subject_lookup_index.sql` (`MIGRATION_0002`, 0001 unchanged)
adds one index `(tenant, object_type, relation, subject_kind, subject_type,
COALESCE(subject_id, ''), COALESCE(subject_relation, ''), tuple_id)`: every
predicate before `tuple_id` is an equality (missing ID/relation as `''`, which
no stored value can be), so a page is one range scan in keyset order. `EXPLAIN`
on a scratch database (200,000 rows, PostgreSQL 13.23) showed `Limit -> Index
Scan using relationship_tuples_subject_lookup_idx` with all eight predicates as
index conditions and no sort, for generic and custom plans. Files: added the
migration; changed `relgraph-authz-postgres/src/{read,mapping,lib}.rs`,
`relgraph-authz-postgres/tests/postgres.rs` (applies both migrations),
`relgraph-authz/tests/support/store_contract.rs` (reverse-lookup paging,
cursor binding, tenant/snapshot scope, and the same ListObjects/ListUsers
assertions, one list spanning two store pages), `AGENTS.md` and both READMEs;
9 new `--lib` tests (query shape, subject keys, cursor round trip/binding/
malformed input, cursor kinds not interchangeable, index entry budget). Live
tests: `OPENFGA_POSTGRES_TEST_URL` was set; `cargo test -p
relgraph-authz-postgres --test postgres -- --ignored` ran, but all 11 failed at
the harness guard "PostgreSQL 14 or newer is required" (server 13.23), so the
live contract was not run against PostgreSQL. Commits: ae6d079 (migration),
bfee728 (reverse lookup), 188c1c5 (contract tests), 03c1f64 (docs).
Validation: `cargo fmt --all -- --check` clean; `cargo check --workspace
--all-targets --all-features` clean; `cargo test -p relgraph-authz-postgres
--lib` 30 passed; `cargo test -p relgraph-authz --all-targets --all-features`
212 passed (1 ignored; in-memory contract passes); no features 202; axum 212;
`--workspace --doc --all-features` 10; `cargo test --workspace --all-targets
--all-features` 321 passed (12 ignored); `upstream_check -- --nocapture` 4
passed, totals unchanged (consolidated 775/1380, ABAC 323/505).

## Task 8 [DONE]: Replay the list corpora and retire the list-api entries

**Depends on:** Tasks 5, 6 and 7.

**Steps.**

1. In `relgraph-authz/tests/upstream_check.rs`, stop skipping the
   `listObjectsAssertions` and `listUsersAssertions` kinds. Map each upstream
   error code to the list error variant in the error table
   (`CONFORMANCE_PLAN.md` shared conventions). A case with no mapping is a
   `harness-gap`, not a pass.
2. Run `cargo test -p relgraph-authz --test upstream_check -- --nocapture`.
   Remove the two `list-api` rules from `upstream-skip.yaml` only when their
   cases pass. Keep any case that still fails, with an entry whose `task`
   names the reason.
3. Update the fixtures README pass rates and `CONFORMANCE_PLAN.md`'s measured
   priorities table.

**Acceptance.** The `list-api` tag no longer appears in the authz skip list
unless a specific case is kept with a justification. Both runners pass.

**Result (complete; the 4 kept cases are deliberate under S4f and S4g):**
the runner now replays every list assertion (cites S1, S2, S4, S4a to S4e)
through `list_objects` / `list_users` against the stage's store, compared with
`expectation` as a sorted set, with one error-code table per kind
(`CHECK_ERROR_CODES` unchanged; `LIST_OBJECTS_ERROR_CODES` 2000 for an unknown
user, 2021/2022 for an unknown object type/relation, 2027; and
`LIST_USERS_ERROR_CODES` 2000, 2002, 2021/2022 also for the filter's type or
relation, 2027); unmapped codes are harness gaps (none occur). Both
`list-api` rules removed; 22 case entries added. 18 are S1
(`deliberate`/permanent; consolidated 4 listObjects + 10 listUsers, ABAC 2 + 2,
all in stages that already had S1 check entries); 14 list cases in the three
S2 stages are covered by the existing stage entries. 4 were first kept as
`semantic-divergence/bug`, `task: '8'`, because no recorded decision covered
them; all four are now `semantic-divergence/deliberate`, `task: permanent`,
with justifications starting `S4f: ` ((a)) or `S4g: ` ((b)), and Task 8 is
complete: (a) `abac_tests.yaml::relation_through_ttu_with_condition::0::listUsers::1`
and `::2`: two tupleset branches, one allows and the other lacks its
condition parameter; upstream Check allows (check::1, check::2) but upstream
ListUsers errors 2000; Relgraph decides candidates by check (a decisive allow
masks a branch error) and lists `user:jon`; S4f (2026-10-21) keeps S4's rule
that a listed subject is exactly one whose check allows. (b)
`abac_tests.yaml::condition_bound_to_correct_type_restriction_facet::1::listObjects::0`
and `::listUsers::0`: a contextual tuple's condition on a facet that does not
declare it; Relgraph errors `InvalidContextualTuple` (2027, as upstream Check
does for the same tuple), upstream's list APIs report 2000; S4g (2026-10-21)
keeps 2027 as the one invalid-input error across check and list. (Task 6's scratch replay
had only (a) and S1 for ListUsers; (b) is new.) Pass rates: consolidated 775
to 1316/1380 (listObjects 258/272, listUsers 283/297); ABAC 323 to 494/505
(listObjects 79/82, listUsers 92/97); 712 of 748 list assertions pass. List
error codes (both files): listObjects 2000 21/22, 2021 3/3, 2022 3/3, 2027
8/8; listUsers 2000 24/27, 2002 1/1, 2021 3/3, 2022 2/2, 2027 8/8. Files:
`relgraph-authz/tests/upstream_check.rs` (new test
`list_error_codes_compare_through_their_own_tables`), the skip list, both
READMEs of the authz crate, `README.md`, `CONFORMANCE_PLAN.md`. Commits:
da3a457 (runner, skip list), e18aa31 (docs), 03ddc1d (S4f, S4g recorded),
b8e10b9 (four entries deliberate). Validation: `cargo fmt --all --
--check` clean; `cargo check --workspace --all-targets --all-features` clean;
`upstream_check -- --nocapture` 5 passed; `upstream_corpus` 4 passed (semantic
84/93, syntax 79/81, fga.mod 9/10, unchanged); `cargo test -p relgraph-authz
--all-targets --all-features` 213 passed (1 ignored); no features 203; axum
213. Closing (S4f, S4g): `cargo fmt --all -- --check` clean; `upstream_check
-- --nocapture` 5 passed, totals unchanged, all 75 skip-listed cases
`semantic-divergence/deliberate` (ABAC 11, consolidated 64);
`deliberate_entries_cite_a_recorded_decision` passed; `upstream_corpus` 4
passed (unchanged); `cargo test -p relgraph-authz --all-targets
--all-features` 213 passed (1 ignored).

## Task 9 [DONE]: Review the DSL semantic-divergence entries

**Depends on:** none. **Blocked by:** none.

**Why.** Four DSL entries are deliberate differences in validation. One has a
granularity difference (one error per tuple-to-userset reference versus one per
type). The two `valid syntax` entries are about `EmptyModel`.

**Steps.**

1. Confirm each entry's justification against the current code, using CodeGraph
   on `validate_schema` and `Validator` in `relgraph-dsl/src/validation.rs`.
2. For the duplicate-type entry and the granularity entry, keep Relgraph's
   diagnostics (S6, approved 2026-10-19: option A). Update each entry's
   `justification` to cite S6, and do not change the validator.
3. For the two `EmptyModel` entries, record the decision (already documented
   as matching the OpenFGA API) and keep the entries.

**Acceptance.** Each DSL entry's justification matches the code, and any change
to diagnostics has its test updated.

**Result:** all four DSL `deliberate` entries kept (reason/tag/task unchanged;
`fga-mod-json-output` untouched for Task 10); validator and diagnostics
unchanged, so no test changed. Each justification was confirmed against
`relgraph-dsl/src/validation.rs`: `validate_schema_with_context` reports
`DuplicateType` plus `DuplicateRelation` and `UnknownTuplesetRelation` for the
second `account` block (only the first declaration resolves references);
`Validator::check_tuple_to_userset` pushes one `UnknownComputedRelation` per
reference when no tupleset target type defines the relation; its
`base_type_count == 0` check yields `EmptyModel` for both `valid syntax`
models. The first two entries now start with `S6: `; the two `EmptyModel`
entries cite the record in `relgraph-dsl/tests/fixtures/openfga/README.md` and
that check. Note: S6 says the accept/reject outcome already matches upstream,
which holds for the S6 entries but not the `EmptyModel` ones (upstream
accepts). Validation: `cargo fmt --all -- --check` clean; `cargo test -p
relgraph_dsl --test upstream_corpus -- --nocapture` 4 passed, totals unchanged
(semantic 84/93 pass, syntax 79/81, fga.mod 9/10); `cargo test -p relgraph_dsl
--all-targets` 77 passed, 0 failed.

## Task 10 [DONE]: Cite S5 on the JSON model rule

**Depends on:** none. **Blocked by:** none (S5 approved 2026-10-19: keep JSON
models out).

**Steps.**

1. In `relgraph-dsl/tests/fixtures/openfga/upstream-skip.yaml`, update the
   `fga-mod-json-output` entry's `justification` to cite S5 (Relgraph input
   stays DSL text). Keep `task: permanent`.
2. Run `cargo test -p relgraph_dsl --test upstream_corpus` and confirm the file is
   still in canonical form.

**Acceptance.** The rule cites S5, and the DSL corpus test passes.

**Result:** the `fga-mod-json-output` entry kept (reason/tag unchanged, `task:
permanent`); its `justification` now starts with `S5: ` (JSON models stay out,
Relgraph input stays DSL text; S5 settles D3 of `CONFORMANCE_PLAN.md`) and
drops the "revisit if D3 adopts JSON models" note. No code changed.
Validation: `cargo fmt --all -- --check` clean; `cargo test -p relgraph_dsl
--test upstream_corpus -- --nocapture` 4 passed (skip file still canonical),
totals unchanged (semantic 84/93 pass, syntax 79/81, fga.mod 9/10).

## Task 11 [DONE]: Close out the skip lists

**Depends on:** Tasks 1 to 10.

**Steps.**

1. Recount both skip lists. Compare them against the Inventory table above and
   update it.
2. Confirm every remaining entry has a decision ID or a live plan task in its
   `task` field, and that the test printed no mismatch.
3. Update the "Measured priorities" table in `CONFORMANCE_PLAN.md` so it shows
   the new counts.

**Acceptance.** Both runners pass. Every entry cites a decision or a task that
still exists.

**Result:** no skip entry, covered case or check changed; docs only (cites
S1, S2, S3, S4, S4f, S4g, S5, S6). Authz list: 49 entries (38 when the plan was
written: 9 `inline-condition` removed by Task 3, 2 `list-api` rules replaced by
22 case entries in Task 8), all `semantic-divergence/deliberate` with `task:
permanent`, covering 75 cases (ABAC 11, consolidated 64). They are 42 S1
entries (24 check, 18 list), 3 S2 stage entries (29 cases), and 2 each for S4f
and S4g. DSL list: 5 entries, all `task: permanent`. 4 are
`semantic-divergence/deliberate` (2 cite S6, and 2 `EmptyModel` cite the DSL
fixtures README record with no decision ID). 1 is the
`unsupported-feature/json-model` rule citing S5. No entry has a numeric `task`,
so none points to a missing or `[TODO]` task. Every authz `deliberate` entry
cites an ID recorded in `AGENTS.md`. The only gap is the two `EmptyModel`
entries, which have no decision ID: they need a maintainer decision, so no ID
was invented and their wording was left unchanged. The Inventory was updated,
and the S5 bullet in Decisions, which still said undecided, now matches the
Decision log. `CONFORMANCE_PLAN.md` was also updated: its measured-priorities
table now shows the current pass rates and the 80 permanent cases by decision,
and D3 is marked as settled by S5. Commits: 4d78902 (Inventory, S5 wording),
3fe52a5 (`CONFORMANCE_PLAN.md`). Validation: `cargo fmt --all -- --check`
clean. `cargo test -p relgraph-authz --test upstream_check -- --nocapture`: 5
passed (consolidated 1316/1380, with listObjects 258/272 and listUsers
283/297; ABAC 494/505, with listObjects 79/82 and listUsers 92/97; all 75
skip-listed cases deliberate; no harness gaps). `deliberate_entries_cite_a_recorded_decision`
passed. `cargo test -p relgraph_dsl --test upstream_corpus -- --nocapture`: 4
passed (semantic 84/93, syntax 79/81, fga.mod 9/10).

## Decision log

Record each maintainer decision here with its ID and date. Each `Result:` line
cites the IDs it relies on.

- S1 (strict stored reads): decided in AGENTS.md (maintainer).
- S2 (negation-cycle rejection): decided in AGENTS.md (maintainer).
- S3 (inline conditions): approved 2026-10-19, support them; Task 3.
- S4 (list APIs): approved 2026-10-19, option A with a shared check path; Task 4.
- S4a (store contract): approved 2026-10-19, option 2: a separate
  `ReverseLookupStore` trait, required only by the list methods; check-only
  stores are unchanged.
- S4b (candidate limit): approved 2026-10-19: default 1,000 candidates (matching
  the OpenFGA server default, which is a deployment setting, not part of the
  standard), configurable on `EvaluationLimits`; exceeding it returns an error,
  never a partial list (the server truncates silently, which Relgraph does not
  copy).
- S5 (JSON models): approved 2026-10-19, keep JSON models out (Relgraph input
  stays DSL text); the `fga-mod-json-output` rule stays permanent and cites S5.
  Revisit if users need to import models directly from an OpenFGA server.
  Same question as D3 in `CONFORMANCE_PLAN.md`.
- S6 (DSL diagnostic granularity): approved 2026-10-19, option A: keep Relgraph's
  diagnostics and mark the four entries deliberate; the accept/reject outcome
  already matches upstream. Task 9.
- S7 (empty models): approved 2026-10-21: keep rejecting a model with no types as
  `EmptyModel`, matching the OpenFGA write API. The two `valid syntax` DSL entries cite S7
  (recorded in AGENTS.md, Maintainer decisions).
- S4c (list candidate cap, resolves M1): approved 2026-10-19: ListObjects reuses
  the check loop, bounded by `max_list_candidates` (default 1,000). `max_batch_items`
  and `batch_check` are unchanged.
- S4d (list budgets, resolves M2): approved 2026-10-19: each candidate decision has
  its own budgets, as batch items do. The candidate generator has one set of
  budgets. Any budget hit is an error, never a partial list. S4's wording
  "shared budgets" is superseded by this.
- S4e (ListUsers scope and duplicates, resolves M3 and M4): approved 2026-10-19:
  ListUsers runs one `Evaluator` per candidate on a shared session and needs no
  reverse trait. List methods drop exact duplicate contextual tuples before use;
  `check` stays strict.
- S4f (ListUsers branch errors, resolves Task 8 question (a)): approved
  2026-10-21, deliberate divergence: ListUsers keeps S4's rule that a subject
  is listed exactly when its check allows, so a decisive allow masks another
  branch's error as in `check`. For
  `abac_tests.yaml::relation_through_ttu_with_condition::0::listUsers::1` and
  `::2`, upstream Check allows, upstream ListUsers errors 2000 because it
  evaluates a branch that lacks a condition parameter, and Relgraph lists
  `user:jon`. Both cases are deliberate (recorded in AGENTS.md).
- S4g (invalid contextual tuple in list APIs, resolves Task 8 question (b)):
  approved 2026-10-21, deliberate divergence: list APIs return
  `InvalidContextualTuple` (2027) for an invalid contextual tuple, as upstream
  Check does, so check and list share one invalid-input error. For
  `abac_tests.yaml::condition_bound_to_correct_type_restriction_facet::1::listObjects::0`
  and `::listUsers::0`, upstream ListObjects and ListUsers return 2000. Both
  cases are deliberate (recorded in AGENTS.md).

## Out of scope

- Expand. The corpora have no Expand assertions.
- Changing the upstream pins. A pin bump is its own change, with checksums and
  a skip-list diff, as described in `CONFORMANCE_PLAN.md`.
- Server API surface (see `CONFORMANCE_PLAN.md`, Out of scope).
