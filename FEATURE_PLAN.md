# Feature plan: recursion, batch checks, writes, dynamic policies, key operations

This is an implementation plan, not an implementation report. Source was
inspected through CodeGraph MCP on 2026-10-11 at commit `96f6495`. Tasks are
unstarted unless marked otherwise.

## Execution rules

- Change a task heading from `[TODO]` to `[PROGRESS]` before editing and to
  `[DONE]` only after its acceptance criteria pass. Each numbered subtask group
  is one reviewable commit unless the task says otherwise.
- Use CodeGraph MCP before changing Rust (context first, then targeted node or
  trace calls). Preserve unrelated changes and `.codegraph` state.
- Every task ends with the full validation set from AGENTS.md:
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
  --all-features` (zero warnings), `cargo test --workspace --all-targets
  --all-features`, `cargo test --workspace --doc --all-features`, and
  `cargo test -p relgraph-authz` without features.
- A task that changes a compatibility surface also runs the authorization
  differential harness (`relgraph-authz/tools`, OpenFGA v1.21.0) and adds the
  resulting cases to the offline fixtures. If Docker is unavailable, record the
  blocker and keep the task `[PROGRESS]`.
- Items marked **Decision** need an answer from the maintainer before that
  subtask starts. Each lists a recommendation.
- Update `relgraph-authz/README.md`, AGENTS.md, and compile-checked examples in
  the same commit as the behavior they describe.

## Dependency order

```text
1 Recursive models ──────────────┐
2A Batch check ──────────────────┼─► 2B List objects ◄── 5B Reverse reads
3 Model-aware writes ─► 5A Key identity and delete by key
4 Dynamic route policies (uses 2A only for the drive example list route)
```

Tasks 1, 2A, 3, and 4 are independent and can run in parallel. 2B depends on
2A and 5B. 5A should follow 3 so the write wrapper and conflict errors exist.

## Current state relevant to this plan

| Location | Behavior today |
| --- | --- |
| `model.rs::recursive_dependencies`, `visit_dependencies` | Builds a relation dependency graph and reports every cycle as an `UnsupportedCapabilities` diagnostic, so `define member: [user, group#member]` and same-type `viewer from parent` fail construction. |
| `evaluator.rs::Evaluator` | One check per evaluator. Memo key is `(relation_id, object_id)`; the subject and request context are fixed per evaluator. No in-flight cycle detection (removed in `96f6495`); the depth limit bounds traversal. |
| `evaluator.rs::check` | Opens one read session per check; Postgres holds one connection and one repeatable-read transaction for its duration. |
| `mod.rs::FgaAuthz::validate_tuple` | Done in `76c4312`: model-aware tuple validation sharing the evaluator's checks. Nothing calls it on the write path. |
| `store.rs::RelationshipWriteStore` | `insert_tuple` / `remove_tuple` only. Identity includes the condition context, so removal needs the exact context. Duplicates and tenant mismatches are both `StoreErrorKind::CorruptData`. |
| `store.rs::RelationshipReadSession` | Forward reads by `(object, relation)` only, with cursors bound to one session. No reverse (by subject) reads. |
| `policy.rs::RoutePolicy` | Fixed `object_type` and `relation`; `ObjectIdSource` supplies only the ID. `validate_policy` validates one requirements graph. |
| `examples/drive-api` | Calls `check` by hand for each route and runs N sequential checks in `list_items`; keeps a share ledger only to remember exact tuples for revocation; rolls back multi-tuple inserts by hand. |

---

## Task 1 — Recursive models [TODO]

Goal: accept models whose relation dependencies are cyclic through monotone
operators (union, intersection, direct userset assignment, tuple-to-userset),
evaluate them with least-fixed-point semantics, and match OpenFGA decisions on
nested groups and same-type hierarchies.

### 1.1 Pin the target semantics (no production code)

- [ ] Write differential cases for: nested groups (`member: [user, group#member]`),
  folder hierarchies (`viewer: [user] or viewer from parent`, `parent: [folder]`),
  mutual recursion across two types, a data cycle (group A in B in A) for a
  non-member, recursion combined with a condition, recursion under intersection,
  and a cycle through the subtracted operand of `but not`.
- [ ] Run them against OpenFGA v1.21.0 and record, per case, the decision or the
  model-write/check error. Expected: data cycles return deny, not an error.
- [ ] **Decision:** which cyclic shapes to accept. Recommendation: accept cycles
  through union, intersection, userset assignment, and tuple-to-userset; reject
  at construction any cycle that passes through the subtracted operand of a
  difference, because assume-false evaluation is unsound under negation. Match
  OpenFGA wherever it accepts a shape we also accept.

### 1.2 Construction: classify cycles instead of rejecting them

- [ ] Change `recursive_dependencies` / `collect_relation_edges` to label each
  edge with its polarity (positive, or subtracted operand of a difference).
- [ ] Report a diagnostic only for cycles containing a subtracted edge (or the
  shapes rejected in 1.1). Keep the existing `CapabilityDiagnostic` type and
  add a `RuntimeCapability` variant naming the rejected shape.
- [ ] Tests in `relgraph-authz/tests/authz_model.rs`: the accepted shapes from
  1.1 construct; each rejected shape returns the new diagnostic with its
  relation location and span.

### 1.3 Evaluator: least-fixed-point traversal

- [ ] Reintroduce in-flight tracking as `HashMap<EvaluationKey, usize>` mapping
  each in-flight key to its stack position.
- [ ] Reaching an in-flight key returns a provisional `Ok(false)` and records
  the lowest stack position reached (the frame's "cycle floor") on the caller.
- [ ] Memoization rules: always memoize `true` (sound for monotone operators);
  memoize `false` only when the frame's cycle floor is not below its own stack
  position; never memoize errors. Propagate the floor up through
  `evaluate_expression` results (return a small struct instead of `bool`).
- [ ] Keep the three-valued union, intersection, and difference rules unchanged
  for non-provisional results.
- [ ] Unit test the soundness case the memo rules guard against: `A = B or x`,
  `B = A or y` with `x` true and `y` false must allow both A and B within one
  check.
- [ ] Document that unmemoized provisional results can repeat work; the work
  budget bounds it. Add a stress test (wide nested groups) that stays inside
  default limits.

### 1.4 Limits, policy, and docs

- [ ] Confirm `build_requirements` terminates on cyclic graphs (it uses a
  visited set) and add a requirements test for a recursive model.
- [ ] Decide whether `DEFAULT_MAX_RELATION_DEPTH` (64) should change for deep
  group nesting; OpenFGA's resolve depth default is 25. Recommendation: keep 64.
- [ ] Add the 1.1 cases to `relgraph-authz/tests/fixtures/authz/relationships.json`
  (or a new `recursion.json`) and to `authz_compatibility.rs`.
- [ ] Update the README's supported-profile section and AGENTS.md (remove
  "recursive model dependencies are rejected", describe the cycle-floor rules).
- [ ] Optional: let the drive example nest folders.

**Acceptance:** nested groups and same-type hierarchies construct and evaluate;
a data cycle denies a non-member without error; differential cases match
OpenFGA; rejected shapes fail construction with a clear diagnostic.

---

## Task 2A — Batch check [TODO]

Goal: evaluate many `(object, relation)` pairs for one subject and context in
one read session, sharing memoized decisions, so callers get one consistent
snapshot and fewer store reads.

### 2A.1 API

- [ ] Add `BatchCheckRequest` in `request.rs`: tenant, subject, global context,
  condition-scoped contexts, and `Vec<(ObjectRef, RelationName)>` items. One
  subject and context per batch keeps the memo valid across items.
- [ ] Add `FgaAuthz<Bound<S>>::batch_check(&self, &BatchCheckRequest) ->
  Result<Vec<Result<AuthorizationDecision, AuthorizationError>>, AuthorizationError>`.
  The outer error covers request validation and `begin_read`; inner results are
  per item, in request order.
- [ ] Add `EvaluationLimits::max_batch_items` (default 100, hard maximum 1,000)
  with the existing builder and error pattern.
- [ ] **Decision:** budget scope. Recommendation: tuple, store-call, and work
  budgets reset per item (the item's error stays isolated), memo and request
  value cache are shared, and the batch is additionally bounded by
  `max_batch_items`.

### 2A.2 Evaluator refactor

- [ ] Split the fixed per-check inputs out of `CheckRequest` into an internal
  `CheckScope` (tenant, subject, contexts) that both `check` and `batch_check`
  build. `Evaluator` keeps `completed` and `request_values` across items and
  resets counters per item.
- [ ] Reimplement `check` as the one-item case without changing its behavior or
  error mapping.

### 2A.3 Convenience, example, and tests

- [ ] Add `filter_objects(tenant, subject, relation, candidates)` returning the
  allowed subset plus per-candidate errors, built on `batch_check`.
- [ ] Replace the N sequential checks in `examples/drive-api/src/api.rs::list_items`.
- [ ] Tests: per-item error isolation; shared memo lowers store calls (use the
  scripted page store in `authz_page_contract.rs`); writes made during a batch
  are not observed by later items (in-memory and Postgres store-contract
  tests); `max_batch_items` enforcement.
- [ ] Document in the Postgres README that a batch holds one connection and
  transaction for its full duration.

**Acceptance:** `batch_check` results equal individual `check` results on the
existing relation and condition test models, with fewer store calls when items
share subgraphs.

---

## Task 2B — List objects [TODO]

Depends on 2A and 5B. Goal: return the objects of a type on which a subject has
a relation, without the caller supplying candidates.

### 2B.1 Algorithm

- [ ] Reverse expansion over the compiled graph: start from the subject, find
  relations whose direct targets admit it (direct, typed wildcard, or a
  userset the subject is a member of), and walk computed-userset and
  tuple-to-userset edges backwards to the requested `(object_type, relation)`.
- [ ] Treat intersection and difference conservatively: reverse expansion
  yields candidates from the positive side, then confirm every candidate with
  the shared-memo batch evaluator from 2A. The result set must equal
  `filter_objects` over all objects of the type.
- [ ] With Task 1, reuse the cycle-floor rules for reverse traversal.

### 2B.2 API and limits

- [ ] `FgaAuthz<Bound<S>>::list_objects(ListObjectsRequest)` where the store's
  session implements the reverse-read trait from 5B.
- [ ] Add `max_list_results` and per-request reverse-read budgets; return a
  truncation indicator rather than silently dropping results.

### 2B.3 Tests and compatibility

- [ ] Property-style test: for generated small models and tuple sets,
  `list_objects` equals `filter_objects` over every object of the type.
- [ ] Differential cases against OpenFGA's ListObjects on the Task 1 and
  relationship fixtures.

**Acceptance:** list results match the brute-force filter and OpenFGA on
fixtures; truncation is explicit.

---

## Task 3 — Model-aware writes [PROGRESS]

`FgaAuthz::validate_tuple` is done (`76c4312`). Remaining work wires it into
writes and fixes write error categories.

### 3.1 Write error categories

- [x] Add `StoreErrorKind::Conflict` (duplicate insert) and
  `StoreErrorKind::InvalidInput` (tenant mismatch, oversized context on write).
  Classify them in `InMemoryRelationshipStore` and in
  `relgraph-authz-postgres/src/write.rs` (unique violation → `Conflict`).
- [x] Keep Axum mapping: these kinds only occur on writes, but map them to 500
  if they ever surface from a read.
- [x] Update `tests/support/store_contract.rs` so both stores assert the new kinds.

### 3.2 Validating write wrapper

- [x] Add `FgaAuthz<Bound<S>>::write_tuple(&tenant, &tuple)` and
  `delete_tuple(&tenant, &tuple)` for `S: RelationshipWriteStore`. They check
  the tenant, call `validate_tuple`, then delegate. Return a new `WriteError`
  enum with `Validation(AuthorizationError)` and `Store(StoreError)`.
- [x] Document that the wrapper validates against the bound model only; it does
  not authorize the caller to write.

### 3.3 Atomic multi-tuple changes

- [ ] Add `RelationshipWriteStore::apply_changes(&tenant, inserts, deletes)`,
  applied atomically (single snapshot publish in memory, single transaction in
  Postgres). Pre-1.0: make it a required method rather than a default shim.
- [ ] Add the validating `FgaAuthz::apply_changes` counterpart.
- [ ] Replace the manual rollback in `examples/drive-api/src/drive.rs::add_item`.

### 3.4 Read-time drift policy

- [ ] **Decision:** what checks do with stored tuples that no longer fit the
  model after a model change. Recommendation: keep reads strict (fail closed),
  and add an audit helper in 5B (`find_invalid_tuples`) that runs
  `validate_tuple` over stored tuples so operators can repair data before
  switching models. Skipping invalid tuples like OpenFGA can grant access when a
  "blocked" tuple is ignored under `but not`.

**Acceptance:** the drive example writes only through the validating wrapper;
duplicates surface as `Conflict`; multi-tuple creation is atomic in both stores.

---

## Task 4 — Dynamic object type in route policies [TODO]

Goal: one policy can authorize routes whose object type depends on the request
(the drive example's folders and files), so apps can use `FgaAuthzLayer`.

### 4.1 Policy model

- [ ] Add `ObjectSource` alongside `ObjectIdSource`: either a fixed type plus an
  ID source (today's behavior), or a resolver returning a full `ObjectRef` from
  request parts, synchronous (`RequestPartsExtractor`) or asynchronous (reuse
  the `AsyncContextResolver` pattern so it can consult application state).
- [ ] Add `RoutePolicy::for_object_types(types, relation)`. Policies must
  declare the finite set of types the resolver may return.
- [ ] `validate_policy` checks every declared type exists and defines the
  relation, builds one requirements graph per type, and validates context
  bindings against the union of their condition parameters.
  `ValidatedRoutePolicy::requirements` becomes a per-type map (pre-1.0 change).

### 4.2 Middleware

- [ ] `authorize_request` resolves the object, rejects a type outside the
  declared set as an internal error (trusted resolver bug), maps resolver
  "not found" to 404 when the resolver says so, and otherwise keeps the
  existing 400/401/403/500/503 mapping.
- [ ] `Authorized` carries the resolved `ObjectRef` so handlers do not resolve
  it twice.

### 4.3 Example and tests

- [ ] Move the drive example's item routes to `FgaAuthzLayer` with an async
  resolver that looks up the item kind.
- [ ] Axum tests: declared-type enforcement, resolver errors, context bindings
  that differ per type, and unchanged behavior for fixed-type policies.

**Acceptance:** the drive example's item routes are authorized by the middleware
with no hand-written `check` calls except listing (which uses 2A).

---

## Task 5A — Tuple key identity and delete by key [TODO]

Depends on 3. Goal: revoke a relationship by its key without knowing its exact
condition context.

### 5A.1 Identity decision

- [ ] **Decision:** tuple identity. Recommendation: align with OpenFGA — a tuple
  is identified by `(tenant, object, relation, subject)` and the condition is
  payload. Inserting the same key with any condition returns `Conflict`. The
  alternative keeps today's identity and adds a `remove_by_key` that deletes
  every conditioned variant and returns a count.

### 5A.2 Implementation (recommended option)

- [ ] Add a public `RelationshipKey` type and `RelationshipTuple::key()`.
- [ ] In-memory store: index by key, duplicate key → `Conflict`.
- [ ] Postgres: migration `0002` adding a key digest column and unique index,
  backfilling from existing rows, and failing with a clear message if existing
  data already holds conditioned variants of one key. Bump the canonical
  identity encoding version in `mapping.rs`; keep reads verifying both digests.
- [ ] Add `RelationshipWriteStore::remove_by_key(&tenant, &key) -> bool` and the
  validating `FgaAuthz::delete_by_key`.
- [ ] Store-contract tests for key conflicts and key removal in both stores;
  migration test on a database seeded with duplicate variants.

### 5A.3 Example

- [ ] Drop the drive example's share ledger tuple field; revoke by key.

**Acceptance:** revocation needs only the key; both stores enforce one tuple
per key; the migration is safe on existing data or fails loudly.

---

## Task 5B — Reading tuples outside a check [TODO]

Goal: admin tooling and list objects can read tuples without opening a check.

### 5B.1 Forward listing

- [ ] Add a `RelationshipListStore` trait:
  `list_tuples(&tenant, TupleFilter, Option<ListCursor>, limit)` where
  `TupleFilter` has an object type, optional object ID, optional relation, and
  optional subject. Cursors must stay valid across sessions (keyset on
  `tuple_id` in Postgres; the in-memory store needs a per-tuple insertion
  sequence number, because its current offsets are session-local).
- [ ] Document the consistency level: each page is a fresh snapshot.

### 5B.2 Reverse reads

- [ ] Add a reverse-read session trait used by 2B: tuples by subject (direct,
  typed wildcard, or userset), optionally narrowed by object type and relation.
- [ ] Postgres: migration index on
  `(tenant, subject_type, subject_id, subject_relation, object_type, relation, tuple_id)`.
  In-memory: a secondary index maintained on write.

### 5B.3 Tooling

- [ ] `find_invalid_tuples(model, store, filter)` built on `list_tuples` and
  `validate_tuple` (see 3.4).
- [ ] Tests: cursor stability across writes, tenant isolation, filter
  combinations, both stores through `store_contract.rs`.

**Acceptance:** an operator can page through a tenant's tuples by object or by
subject and list the tuples that fail validation against a candidate model.

---

## Execution record

Record commands, results, and blockers here per task.
