# PostgreSQL Relationship Store Plan

## Review outcome (2026-09-27)

**Original plan: changes required.** The separate adapter boundary is sound. The corrections below address implementation gaps, not stylistic changes; all implementation tasks remain TODO.

1. **Cursor migration missed its main consumer.** `Evaluator::load_tuples` (`evaluator.rs:465–509`) compares numeric cursors using `<=`. An opaque cursor cannot support that check. Migrate the evaluator, test stores, exports, and default page adapter together; detect repeated cursors without imposing database ordering on the public type.
2. **Duplicate insertion changes existing behavior.** `InMemoryRelationshipStore::insert` (`store.rs:242–259`) currently returns `CorruptData` for duplicates. Keep that behavior for this backend addition; use the same strict insert contract in both stores. Idempotent insertion would be a separate, explicitly breaking feature.
3. **The schema was not defined sufficiently to preserve tuples.** `RelationshipTuple` equality includes condition context, and `TupleSubject` has Direct, Userset, and TypedWildcard variants. Nullable subject fields alone do not distinguish these. Define a subject discriminator, exact context encoding, bounded identity key, and concurrent uniqueness behavior before implementing SQL. Ordinary nullable unique columns do not enforce the proposed identity; unbounded context is unsuitable for a composite B-tree key.
4. **The read implementation omitted required APIs and ownership.** `RelationshipReadSession::tuples` is required, and both read methods take `&self` and return `Send` futures. A SQLx transaction needs mutable access. Use an owned pool transaction behind a per-session async mutex and implement complete reads as well as pages.
5. **Starting a transaction does not freeze its snapshot immediately.** Establish the snapshot before `begin_read` returns so a write between session creation and the first page cannot change that session. Test multiple object/relation queries, not just successive pages. Drop/cancellation cleanup is asynchronous and must be tested, not described as an immediate release guarantee.
6. **The blanket error guarantee conflicts with evaluation semantics.** The evaluator deliberately combines branch results using three-valued union/intersection/difference rules (`evaluate_expression`, `evaluator.rs:161–229`). Stores must never convert failures into empty data; preserve the evaluator's existing error-combination behavior instead of promising every branch error always determines the final result.
7. **Build and live-test instructions were not executable.** Fix dependency/features, preserve root `default-members`, specify a shared test harness location without reverse crate dependencies, and use an explicit ignored-test command that fails when DB configuration is missing. Pin a snapshot before testing visibility; a single wrapping test transaction cannot isolate operations using other pooled connections.

External behavior checked against [PostgreSQL snapshot semantics](https://www.postgresql.org/docs/14/transaction-iso.html), [PostgreSQL JSON representations](https://www.postgresql.org/docs/current/datatype-json.html), [PostgreSQL unique indexes](https://www.postgresql.org/docs/current/indexes-unique.html), and [SQLx 0.8.6 pool transactions](https://docs.rs/sqlx/0.8.6/sqlx/struct.Pool.html).

## Goal

Add a production-usable PostgreSQL-backed relationship store in a **separate workspace crate** while keeping `openfga-authz` and authorization evaluation independent of database libraries. The adapter crate will support tenant-scoped tuple reads and writes, conditional tuples, per-check read consistency, and bounded pagination. The in-memory store remains in `openfga-authz` as the dependency-free default and reference implementation.

## Current state and design boundary

- `openfga-authz/src/authz/store.rs` defines `RelationshipStore::begin_read` and `RelationshipReadSession::tuples_page`.
- A read session is tenant-scoped and is intended to represent one check's consistent snapshot. The evaluator reads pages for an object and relation; store failures propagate as authorization errors.
- The current page cursor is `Option<usize>`, suitable for vectors but not a good stable database cursor contract.
- `InMemoryRelationshipStore` also provides `insert` and `remove`, but mutation is not part of a backend-neutral interface.
- The crate currently has no database dependency. Keep the core build independent of PostgreSQL and `sqlx`.
- The PostgreSQL implementation belongs in a new workspace package, tentatively `openfga-authz-postgres`, which depends on `openfga-authz`; the core crate must not depend on the adapter crate.

## Scope and decisions

1. Ship one concrete backend first: a separate `openfga-authz-postgres` workspace crate using PostgreSQL through `sqlx`. Do not add PostgreSQL dependencies or features to `openfga-authz`, and do not add a generic ORM abstraction or multiple database implementations in this plan.
2. Keep the existing read abstraction backend-neutral. Add a separate write capability so read-only/custom stores do not need to implement mutations.
3. Replace numeric page offsets with an opaque cursor contract before the PostgreSQL adapter. PostgreSQL should use deterministic keyset pagination rather than unbounded `OFFSET` scans.
4. Begin each authorization check in a read-only `REPEATABLE READ` transaction, establish its snapshot before returning the session, and retain its transaction for the session's lifetime. Rely on SQLx rollback-on-drop cleanup; do not claim an async rollback completes synchronously in `Drop`.
5. Make tenant part of every query predicate and tuple identity. A request tenant must never be inferred from tuple data or omitted from a database operation.
6. Expose schema setup as an explicit migration or documented SQL migration artifact. Do not run DDL implicitly when constructing the store.
7. Do not include a remote OpenFGA client, connection-string management framework, or application-specific authentication in this work.

## Planned work

### Task 1 — Define storage pagination and mutation contracts [DONE]

**Affected code:** `openfga-authz/src/authz/store.rs`, `openfga-authz/src/authz/evaluator.rs`, `openfga-authz/src/authz/mod.rs`, `openfga-authz/src/lib.rs`, `openfga-authz/tests/authz_relations.rs`, store contract tests and any custom page implementations/examples.

**Changes:**

- Introduce `StoreCursor` wrapping private bytes, deriving `Clone`, `Debug`, `PartialEq`, `Eq`, and `Hash`, with public `from_bytes(Vec<u8>)` and `as_bytes()` for external adapter authors. Callers must not interpret it; it is not a security credential. Use `Option<StoreCursor>` by value in `tuples_page` and `RelationshipPage::next_cursor`. Do not derive ordering or `Copy`.
- Document cursor validity: it is only valid for the read session and object/relation query that created it; callers treat it as opaque.
- Require stable ordering within a snapshot, not identical ordering across backends. Keep in-memory insertion order. Its cursor encodes a session identity, object/relation, and offset; validate all of these on reuse. Use a process-unique session identity with checked exhaustion, never a reusable pointer address.
- Replace `load_tuples`' numeric progress comparison with a set of returned cursors per object/relation load. Reject repeated tokens (including A/B/A loops) and empty pages with continuations as `InvalidTuple`; retain tuple/store-call/work budgets to bound malicious stores that mint fresh tokens. Clone the incoming cursor as needed. The default complete-read adapter still rejects any continuation and now also rejects a zero page maximum.
- Add `RelationshipWriteStore: Send + Sync` separately from `RelationshipStore`, with `insert_tuple<'a>(&'a self, tenant: &'a TenantId, tuple: &'a RelationshipTuple) -> StoreFuture<'a, Result<(), StoreError>>` and analogous `remove_tuple` returning `Result<bool, StoreError>`. Reject tenant/tuple mismatch as `CorruptData` before I/O. New names avoid shadowing the existing synchronous in-memory methods; preserve those methods and implement the trait by validating tenant then delegating to them.
- Preserve duplicate insertion as `CorruptData`, exact-tuple removal, and missing removal as `Ok(false)`. Identity is current `RelationshipTuple::PartialEq`: tenant, object, relation, subject variant and fields, condition presence/name, and all condition values. Context-only differences are distinct tuples. No implicit replacement/upsert.
- Preserve `StoreError` categories so serialization, unavailable database, and incomplete-read failures cannot become a deny or allow silently.
- Document the cursor signature as a source-breaking migration for external paged stores; migrate every workspace implementation atomically. Complete-read-only stores retain the default page implementation. No compatibility shim or numeric cursor API is needed.

**Acceptance criteria:**

- Existing evaluator behavior is unchanged apart from the cursor type.
- In-memory reads and writes satisfy the documented contracts, including empty pages, page boundaries, duplicate writes, and tenant isolation.
- Public exports and Rust documentation describe cursor/session ownership and write semantics.

**Verification:** focused store and authorization tests; `cargo check -p openfga-authz --all-targets`; `cargo fmt --check`.

### Task 2 — Create the adapter crate and add schema/data mapping [DONE]

**Affected code:** workspace `Cargo.toml`, new `openfga-authz-postgres/Cargo.toml`, new `openfga-authz-postgres/src/lib.rs` and adapter modules, migration under `openfga-authz-postgres/migrations/`, crate exports, adapter documentation.

**Changes:**

- Add `openfga-authz-postgres` to workspace `members`, retaining the two current `default-members`; update `Cargo.lock`. Use `openfga-authz` with default features disabled, SQLx `=0.8.6` with `default-features = false` and `postgres`, `runtime-tokio`, `tls-rustls-ring`, plus Tokio 1 `sync` and an adapter-local SHA-256 implementation dependency. Use runtime `query`/`query_as` APIs, not DB-dependent query macros. This avoids requiring a database for compilation. Tests additionally enable Tokio macros/runtime/time. Keep Axum out of the adapter dependency graph.
- The workspace declares edition 2024 but no MSRV. Record the toolchain used for validation (review environment: Rust 1.94.0); do not invent a lower support claim. Document PostgreSQL 14+ for this initial schema and verify on an available supported release.
- Add adapter-local `serde_json = { version = "1", features = ["float_roundtrip"] }` for context serialization/deserialization, and test difficult finite floating values for exact equality after round-trip. Do not enable `arbitrary_precision` or change the core's JSON representation in this task.
- Expose cloneable `PostgresRelationshipStore::new(PgPool) -> Self`; construction performs no I/O or DDL. Implement modules `mapping.rs`, `read.rs`, `write.rs`; keep schema/table identifiers fixed as `openfga_authz.relationship_tuples`.
- Ship `migrations/0001_relationship_tuples.sql`, creating the dedicated schema and a table with `tuple_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY`; non-null tenant/object_type/object_id/relation; non-null subject_kind/subject_type; nullable subject_id/subject_relation; nullable condition_name/context_json; and non-null `identity_digest BYTEA` with length 32 and a unique constraint. Use byte-exact deterministic text collation (`COLLATE "C"`) for identity/filter text columns. `context_json` is TEXT containing JSON, decoded in Rust, to retain Rust numeric representation and escaped NUL values without JSONB normalization/rejection. No condition means both condition columns are NULL; present conditions require a context object, including `{}`. Add CHECK constraints for this pairing and subject shapes: direct requires ID/no relation; userset requires both; wildcard requires neither. A direct subject whose ID is `*` remains distinct from TypedWildcard.
- Define a versioned canonical identity encoding of every tuple field, with explicit variant/presence tags and length-delimited strings. Recursively sort JSON object keys, preserve array order and integer-versus-floating-number representation, and normalize floating signed zero for equality. Compute SHA-256 over these bytes; never truncate or concatenate ambiguous delimiters. Preserve original context JSON separately. Equality tests against `RelationshipTuple::PartialEq` are a prerequisite to finalizing the migration. This bounds the unique index even for large context. On a digest conflict, strict insertion returns `CorruptData` (including the theoretical hash-collision case), never silently aliases or overwrites a tuple. Removal must additionally compare the decoded tuple for exact equality before deletion. Document that direct SQL writers must follow this codec; schema constraints alone cannot verify its digest.
- Add the lookup index `(tenant, object_type, object_id, relation, tuple_id)` and use `tuple_id` as the immutable ascending page key. Do not index context or duplicate this index's prefix. Verify current identifier byte maxima fit the lookup index using maximum-length, multibyte fixtures.
- Implement validated conversion between persisted rows and `RelationshipTuple`, including condition context. Malformed persisted data returns a store error.
- Row decoding uses public identifier/tuple/condition constructors, validates the subject/condition shape, context object, and identity digest. Persisted corruption is `CorruptData`. Do not add model validation or CEL evaluation to the store; the evaluator owns those checks. Serialization and codec implementation failures are `Internal`.
- Export migration text as `MIGRATION_0001: &str` via `include_str!`. Applications run it once transactionally using their migration ledger; do not mask a mismatched existing table with `CREATE TABLE IF NOT EXISTS`. There is no existing PostgreSQL data to migrate. No migration framework, automatic DDL, public schema selector, or down-migration API is needed.

**Acceptance criteria:**

- `openfga-authz-postgres` builds as its own package; `openfga-authz` has no dependency on it and default/core builds do not pull in `sqlx`.
- All `RelationshipTuple` variants round-trip through the selected schema without loss, including userset subjects and conditional context.
- The migration can be applied to an empty PostgreSQL database and is safe to apply through the project's chosen migration runner.

**Verification:** `cargo check -p openfga-authz`; `cargo check -p openfga-authz-postgres`; schema/mapping tests that do not require a live DB where feasible.

### Task 3 — Implement consistent paged reads [DONE]

**Affected code:** `openfga-authz-postgres` read store/session and the existing evaluator/store contract tests.

**Changes:**

- Implement `RelationshipStore::begin_read` with `PgPool::begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")`, then execute a snapshot-establishing query such as `SELECT pg_current_snapshot()` before returning. The owned `Transaction<'static, Postgres>` lives in `tokio::sync::Mutex` in `PostgresReadSession`, alongside the tenant and unique session identity. Lock per read and query via the underlying mutable connection; no mutex across different sessions, unsafe lifetime extension, or self-referential connection/transaction struct. Preserve `Send` futures and verify the bound authorizer compiles in a spawned Tokio task.
- Implement page lookup with bound SQL parameters for tenant, object type, object ID, and relation. Never interpolate these values into SQL.
- Use stable keyset ordering and encode/decode the last-seen key through `StoreCursor`; reject malformed or query/session-mismatched cursors as `IncompleteRead`.
- Enforce `maximum > 0` for pages. Fetch `min(maximum, 128) + 1` rows ordered by `tuple_id`, using `tuple_id > last_id` when continuing; return at most the page size and use the extra row only to establish continuation. Encode version/session/tenant/object/relation/last-returned-ID into the cursor and reject malformed, oversized, wrong-query, wrong-session, or invalid-key tokens as `IncompleteRead`. Bound decoding before allocation; never interpolate cursor bytes into SQL. Checked conversions must also handle `usize::MAX` without overflow.
- Implement required `tuples`: collect pages within the same session up to `maximum`; if any continuation remains at that bound, return `TupleLimitExceeded`, not a partial vector. For `maximum == 0`, probe for existence and return empty only when no matches exist, preserving the current complete-read contract. Factor a private query helper to avoid recursively acquiring the session mutex.
- Map pool/connectivity/query timeouts to `Unavailable`, malformed rows to `CorruptData`, invalid paging to `IncompleteRead`, and other SQL/configuration failures to `Internal`, with fixed sanitized messages. Missing migration/permissions must error, not look like an empty store. External future cancellation cannot return an error from the dropped future; it triggers resource cleanup instead. Do not format raw SQLx errors, rows, credentials, or context into public error messages.
- Ensure the transaction snapshot stays stable across pages, then releases its connection when the session ends.

**Acceptance criteria:**

- A check observes one consistent database snapshot across all pages.
- Pagination has no duplicates or omissions when multiple tuples share leading sort fields.
- Tenant A cannot read tenant B tuples, including when tuple identifiers otherwise match.
- Query errors and malformed stored rows become store errors, never empty data. Preserve `map_store_error` and the evaluator's existing three-valued branch combination; do not change union/intersection/exclusion semantics.
- Dropping a session after success, failure, or check cancellation eventually releases/replaces its pooled connection within the test deadline. A later borrower must never inherit an active read transaction. Do not automatically retry individual reads in a new snapshot.

**Verification:** live PostgreSQL integration cases for single and multi-page reads, tenant isolation, snapshot consistency, malformed cursor, and DB failure propagation.

### Task 4 — Implement tuple writes [TODO]

**Affected code:** `openfga-authz-postgres` write implementation and migration/schema constraints.

**Changes:**

- Implement tenant-aware insert and remove using bound parameters and the same tuple identity definition as Task 2.
- Insert with bound parameters and the unique digest constraint; map only that constraint's unique violation to the existing duplicate `CorruptData` result. Concurrent identical inserts must produce exactly one success. Context variants and different tenants remain independent rows.
- Remove inside a transaction: select by explicit tenant and digest `FOR UPDATE`, decode and compare exact tuple equality, then delete by tenant and tuple_id and commit. Return false if absent, and `CorruptData` on a digest collision or malformed row. Locking makes concurrent removals return exactly one true. Never delete using digest alone.
- Use transactions for any multi-statement operation and keep condition JSON serialization lossless for supported values.
- Document that read sessions already in progress retain their snapshot while later checks see committed writes.

**Acceptance criteria:**

- Writes preserve all tuple fields and enforce tenant-scoped uniqueness.
- Repeated inserts and removal of absent tuples match the contract from Task 1.
- A committed write is visible to a newly opened read session; an earlier read session remains snapshot-consistent.

**Verification:** PostgreSQL integration tests for insert/read/remove, duplicate behavior, conditional and userset tuples, transaction visibility, and cross-tenant tuple identity.

### Task 5 — Share store contract tests across implementations [TODO]

**Affected code:** `openfga-authz/tests/` and `openfga-authz-postgres/tests/` shared contract-test support.

**Changes:**

- Put generic async contract functions in `openfga-authz/tests/support/store_contract.rs`, included by both integration-test targets using a test-only relative path. They depend only on public core traits/types, accept a fresh backend, and exercise `insert_tuple`/`remove_tuple`; no core dev-dependency on the adapter and no new production test-support crate/feature. Keep in-memory synchronous API tests too.
- Cover evaluator-level allow/deny behavior using database-backed tuples, conditions, unions/intersections/exclusions supported by the current runtime, and error propagation.
- Put live tests in adapter `tests/postgres.rs` and mark each `#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]`. The explicit ignored-test command requires that variable and fails if absent or invalid; ordinary and all-feature workspace runs compile but do not execute these tests. No new feature is needed.
- Use a fresh uniquely named database per live test with a separately configured admin pool, apply the actual migration, and create the application pool against that database. The test URL must belong to a disposable server/account allowed to create databases. Drop all sessions and close application pools before cleanup; drop only the generated test database. A test-owned transaction cannot isolate this adapter's independently acquired connections. No production schema interpolation is added for the harness.
- Contract coverage: empty/zero/exact-limit/over-limit complete reads; page boundaries and multiple pages; huge maximum; invalid/cross-session/cross-tenant/cross-object/relation cursors; tenant mismatch writes; strict duplicate and missing removal; context-only variants; all subject variants including direct `*`; snapshot before first page and across different queries; insert/remove after session creation; evaluator repeated-token loops, empty continuation pages, and tuple/store-call/work limits.
- Codec/DB coverage: nested JSON objects/arrays and reordered keys, null/bool/string, escaped NUL, Unicode, signed zero, integer versus float, integer extremes, large context exceeding normal B-tree entry size, malformed rows, missing migrations/permissions, concurrent inserts/removals, pool exhaustion/closed pool, statement timeout, drop and cancellation with pool size one. Use deterministic barriers/locks and deadlines, not timing sleeps. Force cancellation while a query is blocked, release the blocker, and verify a fresh acquisition and usable transaction state. Simulate digest collisions via a test seam to prove insert/delete fail safely.
- Evaluator integration covers direct/userset/wildcard/computed/tuple-to-userset relations, conditional context precedence, all set operators, and existing decisive/nondecisive error combinations. Use at least two connections for concurrent snapshot tests. Apply migrations and validate read-only mode/isolation on the real database, not mocks.

**Acceptance criteria:**

- The same backend-neutral contract suite passes against both stores.
- PostgreSQL tests are visibly ignored by ordinary commands; the opt-in command fails clearly for missing or invalid database configuration. Release/merge validation requires an actual live run, not a skipped suite.
- No test or example silently starts a local database or depends on network access.

**Verification:** focused default tests, explicitly invoked ignored PostgreSQL tests with a configured database, all-feature authz tests, workspace/doc tests, and formatting.

### Task 6 — Document setup and runnable usage [TODO]

**Affected code:** `openfga-authz/README.md`, new `openfga-authz-postgres/README.md` or crate rustdoc, optionally a small database-backed example.

**Changes:**

- Document adding `openfga-authz-postgres`, constructing a Tokio/SQLx pool, applying `MIGRATION_0001` once with an application migration ledger, and binding with `FgaAuthz::new(dsl)?.with_store(store.clone(), EvaluationLimits::default())`; demonstrate trait writes on the retained store handle and checks on the bound authorizer. Compile-check the snippet without connecting to a database.
- Explain pool sizing/timeouts, snapshot lifetime (one authorization check), tenant isolation, and how DB errors map to authorization failures.
- Document that database migrations are application-managed and that credentials/secrets must come from the application environment.
- Require a trusted tenant source and restrict write handles to authorized application code: tenant predicates are data isolation, not caller authentication. Use separate DDL and runtime roles; document runtime SELECT/INSERT/DELETE and identity-sequence privileges, verified TLS for remote connections, and a trusted dedicated schema with no untrusted CREATE privilege. Do not add RLS or an HTTP management API in this feature.
- Give concrete pool acquisition and PostgreSQL statement/idle-in-transaction timeout configuration, plus an application check deadline. Evaluation work limits alone do not bound wall-clock DB waits or idle snapshot lifetime. The supplied pool owns transport/security/timeouts; the adapter reads no environment variables. Document uncertain write outcomes after transport failure/cancellation and no automatic write retries.
- Add an example only if it can be kept credential-free by default and does not introduce runtime setup requirements to ordinary tests.

**Acceptance criteria:**

- A user can follow the documented path from an empty PostgreSQL database to an authorization check without relying on undocumented APIs.
- The in-memory quick-start remains usable with no additional features or services.

**Verification:** run the documented package build and the documented integration invocation. A missing database blocks live verification, not the package build.

Final validation commands (there is no adapter feature toggle):

```sh
cargo fmt --all -- --check
cargo check -p openfga-authz --all-targets --no-default-features
cargo tree -p openfga-authz --edges normal
cargo check -p openfga-authz-postgres --all-targets
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc --all-features
cargo test -p openfga-authz-postgres --test postgres -- --ignored
git diff --check
```

Inspect the normal core dependency tree to verify it contains no SQLx/PostgreSQL/Tokio dependency introduced by this feature. Supply `OPENFGA_POSTGRES_TEST_URL` out of band for the ignored suite; never print it. If PostgreSQL is unavailable, report live verification as blocked and leave the DB acceptance criteria incomplete.

## Dependency order

```text
Task 1 -> Task 2 -> Task 3 --+
                 \-> Task 4 --+-> Task 5 -> Task 6
```

Tasks 3 and 4 both depend on Tasks 1–2 and can be implemented independently. Task 3's live tests may seed rows with the adapter codec before the write API exists. Task 5 depends on both; Task 6 finalizes verified usage. Add focused tests alongside each task rather than postponing correctness to Task 5. The adapter is complete when all six tasks are `[DONE]`, `openfga-authz-postgres` is a separate workspace crate, and both default-workspace and PostgreSQL integration verification pass.

## Risks and decisions to revisit

- **Tuple identity:** equality includes condition context. The canonical encoding and exact-equality fixtures in Task 2 must be proven before the schema is treated as stable; future encoding changes need an explicit data migration.
- **Opaque cursor encoding:** cursor contents must not permit SQL injection and must be validated against the current tenant/query/session. Prefer a compact internal encoding and avoid exposing backend-specific details in the public API.
- **Transaction lifetime:** a read session holds a pooled connection for the duration of one authorization check. Evaluation limits bound reads, but applications still need pool sizing and statement/connection timeouts.
- **Dependency policy:** Tokio already backs core tests, but stays adapter-local as a production dependency. Validate the selected SQLx features/toolchain and record resolved versions; do not expand the core runtime dependency boundary.
- **Migration ownership:** applications may use different migration tools. Ship plain versioned SQL and do not require a particular migration framework unless repository conventions establish one.
- **Database portability:** this first adapter is PostgreSQL-specific. Future adapters should implement the backend-neutral cursor and store traits; they should not add database-specific branches to the evaluator.
