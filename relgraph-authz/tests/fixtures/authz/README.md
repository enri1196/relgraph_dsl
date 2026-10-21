# OpenFGA authorization compatibility fixtures

Run the offline evaluator cases with:

```sh
cargo test -p relgraph-authz --test authz_compatibility
```

Run the differential reference checks with Docker and Python 3:

```sh
python3 relgraph-authz/tools/openfga-differential.py
```

The differential runner starts a temporary `openfga/openfga:v1.21.0` container with the in-memory datastore, verifies the server version and release commit, waits for `/healthz`, creates a separate store and model for each fixture, writes its tuples, and submits each check. It stops and removes the container on exit. The fixtures record the pinned image, version, release commit, JSON authorization model, tuple data including persisted condition context, request context, and expected allow/deny or error outcome. The matching `.fga` file is parsed by the local runtime. OpenFGA's HTTP API accepts model JSON while the Rust runtime starts from DSL, so both representations are checked into each fixture and are compared against the same named cases.

The run used for Task 7 executed OpenFGA `v1.21.0`, commit `ab557c5592670c899de35297e7aa067015f06502`, image digest `sha256:2113c664a486b5da8d7a2cdab479e0d4e30639c80fd2c000540f645c1dbc1e55` on `linux/arm64`. The runner prints the selected platform digest because it can vary by host architecture. The three original fixture groups cover direct, group/userset, typed wildcard, computed userset, tuple-to-userset inheritance, union, intersection, difference, supported condition parameter types, stored-over-request context precedence, missing context, and branch errors.

`recursion.json` (added 2026-10-18 with the same server version and digest) covers nested groups, same-type folder hierarchies, mutual recursion across two types, data cycles for members and non-members, recursion through conditioned tuples (including missing context), recursion under intersection, and an open cycle whose provisional denial must not be memoized. `recursion_models.json` records model acceptance instead of one shared model. Each entry carries its DSL `definition`, its JSON `model`, the expected server model-write outcome, and `local_capabilities`, the diagnostics local construction must report. For the negation cycles that OpenFGA accepts, the entry also records the server's decisions on data cycles. The runner checks those decisions against the server, and the offline test checks only that local construction rejects the model. OpenFGA rejects the implicit self tuple `group:x#member@group:x#member` at write time, so the self-cycle case is covered only by local tests.

`ipaddress.json` (added 2026-10-19 by plan Task 9, same server version and digest; the runner passed all 72 cases, 20 of them from this fixture) covers OpenFGA's `ipaddress` extension: `in_cidr` with a stored and a request CIDR, IPv4-mapped addresses and prefixes, host bits, IPv4 versus IPv6 families, stored `ipaddress`, `list<ipaddress>` and `map<ipaddress>` context with stored-over-request precedence, `ipaddress(...)` literals with `!=`, and the missing, malformed-address and malformed-CIDR errors. One case records a deliberate difference with separate expectations: an IPv6 zone identifier (`fe80::1%eth0`) is `InvalidConditionContext` locally and a deny on the server. Before writing it, a scratch probe of 600 address/CIDR/function cases against the same server agreed with the local runtime on every case except the 28 that use zone identifiers.

## Vendored upstream Check corpora

`upstream/` holds unmodified copies from `openfga/openfga` tag `v1.21.0` (commit
`ab557c5592670c899de35297e7aa067015f06502`, the same release as the Docker
reference image):

- [`assets/tests/consolidated_1_1_tests.yaml`](https://github.com/openfga/openfga/blob/v1.21.0/assets/tests/consolidated_1_1_tests.yaml)
- [`assets/tests/abac_tests.yaml`](https://github.com/openfga/openfga/blob/v1.21.0/assets/tests/abac_tests.yaml)
- [`LICENSE`](https://github.com/openfga/openfga/blob/v1.21.0/LICENSE), Apache License 2.0

`cargo test -p relgraph-authz --test upstream_check` replays them (see
[Upstream Check corpora](#upstream-check-corpora)). SHA-256 checksums
(lowercase hex, `shasum -a 256` format) are in
[`upstream/CHECKSUMS`](upstream/CHECKSUMS). `cargo test -p relgraph-authz --test
upstream_checksums` recomputes them and fails if a file differs or a vendored
file is unlisted. To check by hand:

```sh
cd relgraph-authz/tests/fixtures/authz/upstream && shasum -a 256 -c CHECKSUMS
```

Raw downloads were also compared with the Git blob IDs reported by the GitHub
contents API at the tag. Never edit these files; a pin bump replaces the files
and `CHECKSUMS` together.

## Upstream Check corpora

`cargo test -p relgraph-authz --test upstream_check` replays the vendored
corpora offline. It mirrors upstream's `tests/check/check.go` driver: one
in-memory store per test, stages run in order with tuples accumulating across
them, each stage's model constructed with `FgaAuthz::new` and its tuples
written through the validating `write_tuple`. Check assertions send their
`contextualTuples` as the request's contextual tuples and compare allow/deny,
or an upstream `errorCode` through the runner's error-code table. Like
upstream's `_ctxTuples` run, every single-stage test is replayed a second time
(`ctxCheck` cases) against an empty store, with the stage tuples sent as
contextual tuples. Each stage's checks are also replayed through
`batch_check`, which must agree with the individual checks. Each
`listObjectsAssertions` / `listUsersAssertions` entry runs through
`list_objects` / `list_users` against the stage's store and is compared with
`expectation` as a set, or its `errorCode` through that list kind's own table
(the list APIs report an unknown type or relation as 2021 / 2022). The
runner's module docs describe case IDs. Run with `-- --nocapture` for per-file
totals.

Every case that does not pass is covered by a reviewed entry in
[`upstream-skip.yaml`](upstream-skip.yaml); the test also fails when an entry no
longer covers a non-passing case, so the list only shrinks. Each entry has a
`reason` and a `tag` from a fixed vocabulary checked by the test (see
`tests/support/skip_list.rs`). This replay is separate from the Docker
differential runner, which covers only the hand-written fixtures above.
Running that runner over OpenFGA's own corpus at the same tag would be
circular: the corpus expectations are already the `v1.21.0` server's answers,
so the server would only be compared with itself.

Measured at `v1.21.0` (2026-10-20, after skip-list plan Task 8, `-- --nocapture`). Cases are per stage: one
`model` case, then one case per check, `ctxCheck` (single-stage tests only),
`listObjects` or `listUsers` assertion. No single-stage test has more than 100
tuples, so no `ctxCheck` replay is skipped for the contextual tuple limit.

| Corpus file | Tests / stages | Cases | Pass | Pass by kind | Skip-listed by reason/tag |
| --- | ---: | ---: | ---: | --- | --- |
| `consolidated_1_1_tests.yaml` | 138 / 161 | 1380 | 1316 | check 333/364, ctxCheck 284/286, listObjects 258/272, listUsers 283/297, model 158/161 | semantic-divergence/deliberate 64 |
| `abac_tests.yaml` | 33 / 37 | 505 | 494 | check 149/152, ctxCheck 137/137, listObjects 79/82, listUsers 92/97, model 37/37 | semantic-divergence/deliberate 7, semantic-divergence/bug 4 |

Before the list replay (skip-list plan Task 8) every list assertion was
skip-listed by the two `unsupported-feature/list-api` rules, and the files
passed 775 / 323 cases.

Before contextual tuples (Task 7) the files had 1094 / 368 cases with 481 / 147
passing: the 9 assertions with `contextualTuples` were skip-listed by rule and
the `ctxCheck` replay did not exist. All 9 now pass.

What the skip-listed groups are:

- `semantic-divergence/deliberate` (permanent): 24 checks and 18 list
  assertions (consolidated 4 listObjects and 10 listUsers, ABAC 2 and 2)
  that read a tuple written under an earlier stage's model which no longer
  fits the current one; upstream ignores such tuples, Relgraph reads are
  strict and report `InvalidTuple` (decision S1). 29 cases of three
  negation-cycle models that construction rejects as `RecursiveDifference`
  (decision S2), which the evaluator's memoization relies on: the 3 models,
  their 10 checks, the `ctxCheck` replays of the single-stage ones (2) and
  their 14 list assertions (10 listObjects, 4 listUsers).
- `semantic-divergence/bug` (task 8, a maintainer decision is needed; 4 ABAC
  list cases). `relation_through_ttu_with_condition::0::listUsers::1` and
  `::2`: one tuple-to-userset branch allows and the other lacks its condition
  parameter; upstream Check allows the same inputs, but upstream ListUsers
  reports the missing parameter (2000), while Relgraph decides each candidate
  with the check path, where a decisive allow masks a branch error, and lists
  `user:jon`. `condition_bound_to_correct_type_restriction_facet::1::listObjects::0`
  and `::listUsers::0`: a contextual tuple carries a condition on a type
  restriction facet that does not declare it; Relgraph reports
  `InvalidContextualTuple` (2027, as upstream Check does for the same tuple),
  upstream's list APIs `validation_error` (2000).
- Skip-list plan Task 8 replayed the list corpora with `list_objects` and
  `list_users` (decisions S4, S4a to S4e), which removed both
  `unsupported-feature/list-api` rules: 712 of the 748 list assertions pass.
  The `list-api` tag stays in the vocabulary with no entries.
- Skip-list plan Task 3 added inline condition expressions (decision S3),
  which cleared the 9 former `unsupported-feature/inline-condition` stage
  entries: the `inline_expression_*` models, their 21 checks and 21 `ctxCheck`
  replays (51 cases; ABAC 272 to 323 passing). Their list assertions ran
  from Task 8 on. The `inline-condition` tag stays in the vocabulary with no
  entries.
- Plan Task 13 made `CheckRequest` accept userset and typed-wildcard
  subjects, which cleared all 12 former `unsupported-feature/userset-subject`
  entries (6 checks and their 6 `ctxCheck` replays, two of them expecting
  `validation_error` for a userset whose type or relation is not in the
  model).
- Plan Task 9 added OpenFGA's `ipaddress` extension (Decision D1, option D),
  which cleared the only `unsupported-feature/ipaddress` entry: the ABAC
  `nested_indirect_relation_with_condition` stage (its model, 3 checks and 3
  `ctxCheck` replays; ABAC 265 to 272 passing). The `ipaddress` tag stays in
  the vocabulary with no entries. `inline_expression_ipaddress_param` also
  uses `ipaddress`; it passes since Task 3.

Error codes (run `check` and `ctxCheck` cases together): every case expecting
`validation_error` (2000) passes (68/68), as do the
`authorization_model_resolution_too_complex` (2002) cases (2/2) and the
`invalid_tuple` (2027) cases (14/14). 2027 occurs in Check assertions only
for an invalid contextual tuple, which Relgraph reports as
`InvalidContextualTuple`; 2021 / 2022 occur only in list assertions. Run list
cases (both files): listObjects 2000 21/22, 2021 3/3, 2022 3/3, 2027 8/8;
listUsers 2000 24/27, 2002 1/1, 2021 3/3, 2022 2/2, 2027 8/8. The four
failures are the `semantic-divergence/bug` cases above. The 2002 check
needs a chain of about 27 usersets; the corpus result is unchanged for any
relation-depth limit from 7 through 26, so the default of 25 (OpenFGA's
resolve depth) agrees with it.

### Bumping the OpenFGA pin

The Check corpora and the Docker reference server share one pin (`v1.21.0`,
commit `ab557c5592670c899de35297e7aa067015f06502`). A bump is one deliberate
change, reviewed in a single pull request:

1. Pick the new tag and resolve its commit. Download
   `assets/tests/consolidated_1_1_tests.yaml`, `assets/tests/abac_tests.yaml`
   and `LICENSE` from that tag into `upstream/`, replacing the old files
   without editing them; compare each with the Git blob ID the GitHub contents
   API reports at the tag.
2. Regenerate `upstream/CHECKSUMS` (`cd upstream && shasum -a 256
   LICENSE abac_tests.yaml consolidated_1_1_tests.yaml > CHECKSUMS`, keeping
   the existing file order) and the source URLs in this README.
3. Update the Docker pin together: `PINNED_VERSION`, `PINNED_IMAGE` and
   `PINNED_COMMIT` in `relgraph-authz/tools/openfga-differential.py`, the
   `server` block of every fixture JSON, the assertions in
   `tests/authz_compatibility.rs`, and rerun the differential runner to record
   the new image digest above.
4. Recheck the upstream facts pinned in code and docs: the Check driver's
   stage semantics (`tests/check/check.go`, module docs of
   `tests/upstream_check.rs`), the error-code table, the resolve depth behind
   the default relation depth of 25, and `MAX_CONTEXTUAL_TUPLES`
   (`openfga/api` at the revision the new tag pins).
5. Run `cargo test -p relgraph-authz --test upstream_checksums` and
   `cargo test -p relgraph-authz --test upstream_check -- --nocapture`. New
   failures need a skip entry with a reason, tag, justification and task;
   entries that no longer cover a failure must be deleted (the test enforces
   both). Review the `upstream-skip.yaml` diff in the pull request.
6. Update the pass-rate table above, the measured numbers in the crate and
   workspace READMEs, and every `v1.21.0` reference (`grep -rn v1.21.0`),
   including `AGENTS.md` and `CONFORMANCE_PLAN.md`.

## Compatibility boundary

- The server is used as an evaluator reference for the checked-in acyclic model profile; this does not add a remote OpenFGA store adapter to the Rust library.
- The local runtime evaluates recursive models as least fixed points. It rejects cycles through a `but not` subtracted operand and same-object computed-userset cycles, as well as unsupported CEL types/functions, during construction. It supports the scalar types and one-level `list<T>` / `map<T>` declarations recorded in Task 4, plus `ipaddress` and OpenFGA's `ipaddress` / `in_cidr` extension (plan Task 9, `ipaddress.json`); bytes, `any`, nested containers, custom/message types, other extension functions, and comprehension macros remain outside its profile. IPv6 zone identifiers are rejected locally where OpenFGA parses them.
- Task 7 found that `cel-core = 0.5.1` rejects `list.contains(value)` during model construction. It is therefore excluded from the supported profile. The list fixture verifies typed list conversion with `size(tags)` and the map fixture verifies typed lookup. This does not claim parity for every CEL standard-library overload.
- The condition fixture raises the local condition-cost limit to 512 so the full typed input can be evaluated. Local cost estimates are a separate resource budget and are not asserted to equal OpenFGA's CEL cost accounting.
- OpenFGA error text can change between releases. Error fixtures require a non-success HTTP status and the stable `context` category text; decisions are compared exactly.
- Permanent divergences in the upstream Check corpora (every one a `task: permanent` entry with a written justification in `upstream-skip.yaml`; rationale in the crate README's "Permanent differences from OpenFGA"): negation-cycle models rejected as `RecursiveDifference` (`semantic-divergence/deliberate`, 3 stage entries, 29 cases: 3 models, 10 checks, 2 `ctxCheck` replays, 14 list assertions), and strict reads of tuples that no longer fit a later stage's model (`semantic-divergence/deliberate`, 42 case entries: 24 checks, 18 list assertions).

The harness must fail on any decision or error-category mismatch. Do not increase the declared compatibility profile from these cases alone; add a fixture for each newly supported semantic surface.
