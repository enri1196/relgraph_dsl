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
`batch_check`, which must agree with the individual checks. The runner's
module docs describe case IDs and what is not run (list assertions, userset or
wildcard check subjects). Run with `-- --nocapture` for per-file totals.

Every case that does not pass is covered by a reviewed entry in
[`upstream-skip.yaml`](upstream-skip.yaml); the test also fails when an entry no
longer covers a non-passing case, so the list only shrinks. Each entry has a
`reason` and a `tag` from a fixed vocabulary checked by the test (see
`tests/support/skip_list.rs`). This replay is separate from the Docker
differential runner, which covers only the hand-written fixtures above.

Measured at `v1.21.0` (2026-10-18, `-- --nocapture`). Cases are per stage: one
`model` case, then one case per check, `ctxCheck` (single-stage tests only),
`listObjects` or `listUsers` assertion. No single-stage test has more than 100
tuples, so no `ctxCheck` replay is skipped for the contextual tuple limit.

| Corpus file | Tests / stages | Cases | Pass | Pass by kind | Skip-listed by reason/tag |
| --- | ---: | ---: | ---: | --- | --- |
| `consolidated_1_1_tests.yaml` | 138 / 161 | 1380 | 767 | check 329/364, ctxCheck 280/286, model 158/161, list 0/569 | unsupported-feature/list-api 569, semantic-divergence/deliberate 36, unsupported-feature/userset-subject 8 |
| `abac_tests.yaml` | 33 / 37 | 505 | 261 | check 123/152, ctxCheck 111/137, model 27/37, list 0/179 | unsupported-feature/list-api 179, unsupported-feature/inline-condition 51, unsupported-feature/ipaddress 7, semantic-divergence/deliberate 3, unsupported-feature/userset-subject 4 |

Before contextual tuples (Task 7) the files had 1094 / 368 cases with 481 / 147
passing: the 9 assertions with `contextualTuples` were skip-listed by rule and
the `ctxCheck` replay did not exist. All 9 now pass.

What the skip-listed groups are:

- `unsupported-feature/list-api` (rules; deferred list-API plan): every
  `listObjectsAssertions` / `listUsersAssertions` entry.
- `semantic-divergence/deliberate` (permanent): 24 checks that read a tuple
  written under an earlier stage's model which no longer fits the current
  one; upstream ignores such tuples, Relgraph reads are strict and report
  `InvalidTuple` (a recorded maintainer decision). 13 cases (3 models and
  their 10 checks) of three negation-cycle models that construction rejects
  as `RecursiveDifference`, which the evaluator's memoization relies on, and
  the `ctxCheck` replays of those that are single-stage tests.
- `unsupported-feature/inline-condition` (permanent): 9 ABAC stages (all
  single-stage tests) whose models use inline condition expressions, which
  runtime construction rejects; their 21 checks and 21 `ctxCheck` replays are
  not run.
- `unsupported-feature/userset-subject` (plan Task 13): 6 checks whose subject
  is a userset (`group:x#member`) or a wildcard (`user:*`), which
  `CheckRequest` cannot express, and their 6 `ctxCheck` replays.
- `unsupported-feature/ipaddress` (plan Tasks 8 and 9): one ABAC stage whose
  condition takes an `ipaddress` parameter (its model, 3 checks and 3
  `ctxCheck` replays).

Error codes (run `check` and `ctxCheck` cases together): every case expecting
`validation_error` (2000) passes (58/58), as do the
`authorization_model_resolution_too_complex` (2002) cases (2/2) and the
`invalid_tuple` (2027) cases (14/14). 2027 occurs in Check assertions only
for an invalid contextual tuple, which Relgraph reports as
`InvalidContextualTuple`; 2021 / 2022 occur only in list assertions. The 2002 check
needs a chain of about 27 usersets; the corpus result is unchanged for any
relation-depth limit from 7 through 26, so the default of 25 (OpenFGA's
resolve depth) agrees with it.

## Compatibility boundary

- The server is used as an evaluator reference for the checked-in acyclic model profile; this does not add a remote OpenFGA store adapter to the Rust library.
- The local runtime evaluates recursive models as least fixed points. It rejects cycles through a `but not` subtracted operand and same-object computed-userset cycles, as well as unsupported CEL types/functions, during construction. It supports the scalar types and one-level `list<T>` / `map<T>` declarations recorded in Task 4; bytes, `any`, IP addresses, nested containers, custom/message types, extension functions, and comprehension macros remain outside its profile.
- Task 7 found that `cel-core = 0.5.1` rejects `list.contains(value)` during model construction. It is therefore excluded from the supported profile. The list fixture verifies typed list conversion with `size(tags)` and the map fixture verifies typed lookup. This does not claim parity for every CEL standard-library overload.
- The condition fixture raises the local condition-cost limit to 512 so the full typed input can be evaluated. Local cost estimates are a separate resource budget and are not asserted to equal OpenFGA's CEL cost accounting.
- OpenFGA error text can change between releases. Error fixtures require a non-success HTTP status and the stable `context` category text; decisions are compared exactly.

The harness must fail on any decision or error-category mismatch. Do not increase the declared compatibility profile from these cases alone; add a fixture for each newly supported semantic surface.
