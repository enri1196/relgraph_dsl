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

## Compatibility boundary

- The server is used as an evaluator reference for the checked-in acyclic model profile; this does not add a remote OpenFGA store adapter to the Rust library.
- The local runtime evaluates recursive models as least fixed points. It rejects cycles through a `but not` subtracted operand and same-object computed-userset cycles, as well as unsupported CEL types/functions, during construction. It supports the scalar types and one-level `list<T>` / `map<T>` declarations recorded in Task 4; bytes, `any`, IP addresses, nested containers, custom/message types, extension functions, and comprehension macros remain outside its profile.
- Task 7 found that `cel-core = 0.5.1` rejects `list.contains(value)` during model construction. It is therefore excluded from the supported profile. The list fixture verifies typed list conversion with `size(tags)` and the map fixture verifies typed lookup. This does not claim parity for every CEL standard-library overload.
- The condition fixture raises the local condition-cost limit to 512 so the full typed input can be evaluated. Local cost estimates are a separate resource budget and are not asserted to equal OpenFGA's CEL cost accounting.
- OpenFGA error text can change between releases. Error fixtures require a non-success HTTP status and the stable `context` category text; decisions are compared exactly.

The harness must fail on any decision or error-category mismatch. Do not increase the declared compatibility profile from these cases alone; add a fixture for each newly supported semantic surface.
