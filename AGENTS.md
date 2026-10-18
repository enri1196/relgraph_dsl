# Agent guide to Relgraph

This guide describes the architecture inspected on 2026-10-03. Verify the current code before relying on a symbol or dependency version.

## Project and ownership boundaries

Relgraph is an independent Rust implementation of part of the OpenFGA DSL and authorization semantics. Compatibility is deliberately partial and pinned by fixtures. It is a library workspace, not an OpenFGA server, authentication service, or relationship-management HTTP API.

| Directory / Cargo package | Responsibility | Dependencies and boundary |
| --- | --- | --- |
| `relgraph-dsl` / `relgraph_dsl` | Syntax, AST, diagnostics, bounded semantic validation, YAML manifests, modular composition | `nom` 8, Serde, `serde_yaml`; no authorization runtime, CEL evaluator, Axum, or SQLx dependency |
| `relgraph-authz` / `relgraph-authz` | Compile supported models, evaluate tuple graphs and CEL conditions, in-memory storage, route policies | Depends on DSL and pinned `cel-core = 0.5.1`; optional `axum` feature enables pinned Axum/Tower |
| `relgraph-authz-postgres` / `relgraph-authz-postgres` | Durable implementation of the backend-neutral read/write contracts | SQLx 0.9, PostgreSQL, Tokio synchronization, SHA-256 tuple identity |
| `tools/conformance` | Maintainer-only syntax differential runner | Vendored ANTLR grammar, Java 17, ANTLR 4.13.2; outside Cargo runtime dependencies |
| `relgraph-authz/tools` | Maintainer-only authorization differential runner | Python and Docker, pinned OpenFGA reference server |

The workspace uses edition 2024 and resolver 3. `default-members` contains only DSL and authorization: plain `cargo test` omits the PostgreSQL crate. Use `--workspace` when claiming workspace validation. The workspace does not declare an MSRV.

## DSL architecture

`relgraph-dsl/src/lib.rs` is the public facade. The internal parser is divided into:

- `parser/lexer.rs`: `lex`, `Token`, `TokenKind`; context-sensitive tokenization with original byte spans and hidden tokens. `#` comments follow the OpenFGA tooling's `parseDSL` (a line whose first non-blank character is `#`, or a ` #` tail) and become hidden `Comment` tokens, never inside a condition body; `schema.rs` `visible_tokens` joins the line breaks around comment lines into one `Newline`, whose text supplies `comments_before`.
- `parser/common.rs`: `TokenInput`, token combinators, identifier/whitespace handling, `Res`.
- `parser/schema.rs`: document headers, types, relation sections, and public `parse_fga_schema`.
- `parser/relation.rs`: targets, restrictions, named/inline conditions, rewrite expressions.
- `parser/condition.rs`: condition declarations, parameter types, preservation of CEL source.

The pipeline is `parse_fga_schema` → `lex` → visible `TokenInput` → all-consuming schema parser → `Schema` or `ParseError`. Parsing does **not** perform semantic validation.

Important public types in `ast.rs`:

| Type | Meaning |
| --- | --- |
| `Schema`, `SchemaHeader` | Model/module header, types, and conditions |
| `TypeDefinition`, `Relation`, `RelationDefinitionBody` | Type declarations and their relation definitions |
| `RelationExpression` | `DirectAssignment`, `ComputedUserset`, `TupleToUserset`, `Union`, `Intersection`, `Difference` |
| `RelationTarget`, `RelationCondition` | Subject type restriction, userset/wildcard restriction, optional named or inline condition |
| `ConditionDefinition`, `ConditionParameter`, `ParameterType` | CEL source and scalar or one-level generic parameter declarations |

`diagnostics.rs` owns `SourceSpan`, `SourceLocation`, `ParseError`, and `ValidationError`. Spans are half-open **UTF-8 byte offsets into unmodified input**. Manually constructed AST nodes may omit spans. Modular locations add source path/module information.

`validation.rs` exposes `validate_schema`; `Validator` checks schema versions, reserved and malformed type/relation names, duplicate declarations, reference resolution, empty assignments, condition parameter declarations, tuple-to-userset structure, repeated type restrictions and top-level operands, and unused conditions; when all of those pass it also rejects relations without an entry point (least fixed point, following the pinned `openfga/language` validator). It intentionally does not compile CEL or provide complete server-side model validation. Standalone validation accepts exactly schema 1.1/1.2; modular validation requires 1.2. A cycle with an entry point can pass DSL validation and still fail authorization construction.

`manifest.rs` exposes `ModelManifest` and `parse_model_manifest`. Parsing performs YAML/lexical path validation without filesystem access. As in OpenFGA's `fga.mod` transformer, `schema` must be exactly `1.2` (also enforced on constructed manifests by `assemble_modular_model`) and every path must end in `.fga`. Paths are ordered, normalized relative paths (`.` and empty components dropped); absolute paths, backslashes, any `..` component, `%` (paths are never percent-decoded), and duplicate normalized paths are rejected. Lexical normalization is not filesystem sandboxing or symlink containment.

`modular.rs` exposes:

- `ModuleSource`: source path plus parsed module schema.
- `ModularModel`: manifest, retained modules, composed schema, and aligned origin vectors.
- `assemble_modular_model`: pure structural composition; processes all base types before extensions and preserves deterministic origins/order.
- `load_modular_model`: synchronous reads of the manifest and its listed files, followed by parsing/composition.
- `validate_modular_model`: recomposes retained public inputs, checks schema/origin invariants, then validates cross-file semantics.

Loading and assembly do **not** implicitly validate semantics. `ModularModel` fields are public and mutable, which explains the recomposition checks. `FgaAuthz::from_modular_model` (`relgraph-authz/src/authz/mod.rs`, tested by `tests/modular_authorizer.rs`) is the public authorization constructor for a modular model: it takes the whole `ModularModel`, runs `validate_modular_model` (keeping file/module locations in validation errors), then compiles the composed schema. No constructor takes a bare composed `Schema`.

## Authorization architecture

`relgraph-authz/src/lib.rs` re-exports the core API and policy types; optional middleware is in `axum_authz/mod.rs`.

`authz/mod.rs` implements the lifecycle:

```text
DSL text                              ModularModel
  → FgaAuthz<Unbound>::new              → FgaAuthz<Unbound>::from_modular_model
  → parse_fga_schema                    → validate_modular_model
  → CompiledModel::compile              → ModularModel::into_schema
      → validate_schema
  → CompiledModel::compile_validated (both paths)
      → capability checks + cycle-shape classification
      → conditions::compile_all
      → type/relation indexes
  → with_store(store, EvaluationLimits)
  → FgaAuthz<Bound<S>>::check(CheckRequest) / batch_check(&BatchCheckRequest)
  → one tenant-scoped read session + one Evaluator per check or batch
  → Allow / Deny / AuthorizationError (per item for a batch)
```

`FgaAuthz<State>` shares an immutable `CompiledModel` through `Arc`. `Unbound` and `Bound<S>` prevent checks before store binding. Bound clones share the store and limits. `ModelIdentity` identifies a compiled instance within one process; it is neither a persistent version nor an authentication credential.

`authz/model.rs` owns `CompiledModel`, type/relation indexes, conditions, runtime capability diagnostics, and dependency graph cycle detection. Dependency edges carry their kind (same-object computed userset/tupleset vs. userset or tuple-to-userset hop) and polarity. Iterative Tarjan SCCs reject cycles through a `but not` subtracted operand (`RecursiveDifference`) and same-object computed-userset cycles (`SameObjectRelationCycle`, which OpenFGA also rejects); all other cycles are accepted.

`authz/request.rs` owns:

- Validated identifier types: `TenantId`, `TypeName`, `EntityId`, `RelationName`, `ConditionName`.
- `Subject`, `ObjectRef`, `CheckRequest`, `BatchCheckRequest`, `FilteredObjects`, `AuthorizationDecision`. Both requests wrap an internal `CheckScope` (tenant, subject, global and condition-scoped context, contextual tuples) that the evaluator holds. `MAX_CONTEXTUAL_TUPLES` (100, OpenFGA's limit) and `ContextualTupleError` live here too.
- Construction/runtime errors and `EvaluationLimits`.

Identifier constructors enforce shape; they do not authenticate tenants or subjects. `CheckRequest` carries a tenant, concrete subject, object, relation, global context, condition-scoped context, and contextual tuples. `BatchCheckRequest` carries the same scope plus ordered `(ObjectRef, RelationName)` items; `batch_check` returns an outer error for a batch above `max_batch_items`, an unknown subject type, invalid contextual tuples, or `begin_read`, and otherwise one result per item. `filter_objects` is a context-free batch (no request context, no contextual tuples) that splits allowed candidates from per-candidate errors. Contextual tuples are trusted, caller-asserted input: never add a `ContextBinding`, `RoutePolicy`, or Axum path that fills them from HTTP input.

`authz/evaluator.rs` owns per-scope traversal state: `Evaluator`, `EvaluationKey` (relation ID plus object ID), memoized completed decisions, Tarjan-style unresolved-key tracking for least-fixed-point evaluation, the request-value cache, and tuple/page/work counters. Relations are always evaluated by compiled relation ID. Reaching an unresolved key (in flight, or finished `false` inside an open cycle) returns a provisional `false` and lowers the frame's low link. `true` is always memoized. A `false` cycle root memoizes its whole unresolved suffix as `false`. A `false` frame whose low link points below it stays unresolved. Errors are never memoized, and allowing or erroring frames discard their unresolved suffix. These rules rely on construction having rejected negation cycles. Keep them, and the soundness tests in `tests/authz_recursion.rs`, when changing the evaluator. A batch reuses one evaluator: `check_item` resets the tuple/page/work counters per item while the memo and request-value cache persist; every root frame finishes, so no unresolved key survives an item. Contextual tuples are validated once per scope by `ContextualTuples::prepare` before `begin_read` (limit, tenant, `CompiledModel::validate_tuple`, no exact repeats) and indexed by object and relation; `load_tuple_page` serves a relation's contextual tuples as its first page and drops stored tuples equal to one of them, without wrapping the read session (store cursors stay session- and query-bound). They count toward the tuple-scan and work budgets, not store calls; their condition context is tuple context. Main functions are `check`, `batch_check`, `check_item`, `evaluate_relation`, `evaluate_expression`, `evaluate_direct_assignment`, `evaluate_tuple_to_userset`, `load_tuple_page`, `prepare_assignment_page`, `prepare_tupleset_page`, `validate_tuple`, and `evaluate_tuple_condition`.

Boolean expressions use deliberate three-valued rules. A decisive allow can mask a union branch error; a decisive deny can mask an intersection error. Difference must not allow when the subtraction branch has an unresolved error. Preserve and test these rules rather than treating every error as a deny or making every branch error fatal. Tuple validation failures are handled more strictly than branch evaluation errors; `CompiledModel::validate_tuple` (public as `FgaAuthz::validate_tuple`) shares those checks so writers can reject tuples up front. `authz/write.rs` adds `WriteError` and, for `S: RelationshipWriteStore`, the validating `FgaAuthz<Bound<S>>::write_tuple` / `delete_tuple` / `apply_changes`: tenant check, then `validate_tuple`, then the store. They do not authorize the caller. Reads stay strict on stored tuples that drift from the model (maintainer decision); repair goes through the store directly. Tuple-to-userset targets whose type lacks the computed relation are skipped, not errors.

`authz/conditions.rs` owns `CompiledCondition`, `compile_all`, `compile_one`, expression-profile checks, `validate_stored_context`, `evaluate`, JSON-to-CEL conversion, and cost estimation. Context precedence is stored tuple → condition-scoped request → global request. Stored grant values must not be overridden by request inputs. CEL must compile to a boolean result.

The runtime profile supports the six relation-expression forms on acyclic dependencies; CEL scalar bool/int/uint/double/string/duration/timestamp and one-level scalar lists/maps. Map keys are strings. Inline conditions, IP-address parameters, nested containers, comprehension macros, and other unsupported features are rejected by runtime construction even where DSL syntax accepts them. Consult the authz README and fixtures before extending this profile.

Default limits: 10,000 scanned tuples, depth 25 (OpenFGA's resolve depth), 1,024 store page calls, 100,000 work units per check (per item in a batch), condition cost 100 per condition evaluation, and 100 batch items (maximum 1,000). Stored condition contexts are limited to 65,536 serialized JSON bytes and 10,000 collection entries; evaluation applies the same limits to each custom-store context and request value. Request values are converted once per check or batch (`RequestValueCache`). Context conversion and condition evaluations, including failed attempts, are charged to the check's work budget. These are local accounting limits, not OpenFGA-equivalent CEL cost accounting or a wall-clock timeout.

## Store contracts and adapters

`authz/store.rs` owns `RelationshipTuple`, `TupleSubject` (direct, userset, typed wildcard), `ConditionContext`, `StoreError`, `StoreCursor`, `RelationshipPage`, and boxed `StoreFuture`.

`RelationshipStore::begin_read` creates a tenant-scoped immutable snapshot. `RelationshipReadSession::tuples` returns a complete bounded result; `tuples_page` supports opaque continuation cursors. A cursor belongs to its session and object/relation query. A continuing page cannot be empty. The default page adapter only supports one complete read. `RelationshipWriteStore` provides strict insert, exact removal, and a required atomic `apply_changes(tenant, inserts, deletes)` (deletions first; missing deletion or duplicate insertion is `Conflict` and applies nothing) with explicit tenant ownership. Write errors use `StoreErrorKind::Conflict` (duplicate insert) and `InvalidInput` (tenant mismatch, oversized context); `CorruptData` is reserved for malformed stored data. The Axum middleware maps the write-only kinds to 500 if a read ever reports them.

`InMemoryRelationshipStore` shares `Arc<RwLock<Arc<RelationshipSnapshot>>>`. Read sessions cheaply retain an immutable snapshot; current writes clone the snapshot before publishing it. Old readers do not observe later writes. Both synchronous insert/remove and async write-trait methods exist.

PostgreSQL modules:

| File | Main elements |
| --- | --- |
| `src/lib.rs` | `PostgresRelationshipStore` wraps `PgPool`; `MIGRATION_0001` embeds SQL; construction performs no I/O |
| `src/read.rs` | `PostgresReadSession`, `begin_read`, `query_page`, cursor codec, SQLx error classification |
| `src/write.rs` | `insert_tuple`, `remove_tuple`, transactional `apply_changes` over shared `insert_row` / `remove_row`, tenant checks, duplicate classification; exact delete locks and validates its matching row |
| `src/mapping.rs` | `TupleRow`, `from_tuple`, `into_tuple`, versioned canonical identity encoding, SHA-256 digest, exact JSON preservation |
| `migrations/0001_relationship_tuples.sql` | Fixed schema/table, field/subject/condition constraints, identity uniqueness, lookup index |

PostgreSQL checks and batches use one read-only repeatable-read transaction and establish its snapshot before returning the session. Keyset pages order by `tuple_id`; cursors bind to session/tenant/query. Each check holds a pool connection. Applications own migrations, trusted tenant selection, write authorization, pool configuration, deadlines, and credentials. A cancelled or failed write may have committed; the adapter does not promise retry/idempotency semantics. The documented PostgreSQL minimum is 14, matching the live-test version guard.

## Route policy and Axum

`authz/policy.rs` is HTTP request-parts based but available without the Axum feature. `RoutePolicy` fixes object type/relation and supplies `PrincipalSource`, `TenantSource`, `ObjectIdSource`, and `ContextBinding` entries. `ContextValueType`, `ContextValue`, and `ContextValueProvider` describe typed inputs. `RequestPartsExtractor` and `AsyncContextResolver` support application-specific trusted mappings.

`FgaAuthz::requirements` derives an `AuthorizationRequirements` graph of `RelationKey`, `RelationRequirements`, and `RequirementExpression` nodes. `validate_policy` produces `ValidatedRoutePolicy`, checking relation existence and binding declarations/types. It does not prove authentication or that stored tuples provide every condition value.

With `axum`, `middleware` builds `FgaAuthzLayer<S>` / `FgaAuthzService`. `authorize_request` resolves authenticated principal and tenant first, then path/object/context, runs the check, and attaches `Authorized` only after allow. The original body is preserved. Authentication must run before authorization. HTTP outcomes are 401 for missing principal, 403 for deny, 400 for relevant client input errors, 503 for availability/budget failures, and 500 for trusted-state/internal failures. Do not leak raw SQL or condition error details to clients.

## Navigation and change discipline

- Prefer CodeGraph MCP for Rust architecture/symbol analysis: context first, then targeted node/trace calls. Use narrow source reads only for omitted exports, ambiguous same-name methods, or other confirmed tool gaps. Ordinary reads are appropriate for manifests, SQL, fixtures, and documentation.
- Use public-API integration tests to validate behavior across crate boundaries. Keep parser acceptance, semantic validity, runtime support, and upstream compatibility as separate claims.
- With `nom` 8, invoke parser combinators via `.parse(input)`.
- Preserve original UTF-8 byte spans and exact CEL body bytes. The pinned grammar ends a condition at its first visible closing brace; it does not balance CEL braces. Parameter newlines also follow the pinned lexer restriction. Do not casually “fix” these without changing the compatibility contract and fixtures. `#` comments deliberately follow the tooling's stripping rather than the bare grammar (plan Task 12); a syntax fixture whose raw-grammar outcome differs records it as `grammar_parse`, which `tests/conformance.rs` checks against the recorded ANTLR results.
- Preserve tenant isolation, snapshot consistency, stored context precedence, strict tuple identity, cancellation cleanup, and error-versus-deny behavior when simplifying internals.
- Update README examples and compile-checked examples together with dependency/API changes. Avoid compatibility wrappers unless the task calls for them; this is pre-1.0 code.
- Do not alter generated `.codegraph` state, unrelated user changes, or vendored upstream files incidentally.

## Validation commands and fixtures

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo test -p relgraph_dsl -p relgraph-authz --all-targets --all-features
cargo test -p relgraph-authz-postgres --lib
cargo test --workspace --doc --all-features
cargo test --workspace --all-targets --all-features
```

For feature isolation, check/test `relgraph-authz` without features as well as with `--features axum`. Do not claim a clean workspace baseline by running only default members.

DSL tests cover parser behavior, validation, manifests, modular composition/origins, and a 64-case syntax corpus in `relgraph-dsl/tests/fixtures/openfga`. Authz tests cover model construction, conditions, relation operators, batch checks, contextual tuples, policy mapping, paging, store contracts, Axum, and offline compatibility fixtures (also replayed as batches). `relgraph-authz/tests/support/store_contract.rs` is shared by in-memory and PostgreSQL adapter tests.

Upstream corpora are replayed offline as ordinary test targets (see `CONFORMANCE_PLAN.md`):

| Test target | Vendored corpus | Skip list |
| --- | --- | --- |
| `cargo test -p relgraph_dsl --test upstream_corpus` | `relgraph-dsl/tests/fixtures/openfga/upstream/` (`openfga/language` syntax, semantic and `fga.mod` cases) | `relgraph-dsl/tests/fixtures/openfga/upstream-skip.yaml` |
| `cargo test -p relgraph-authz --test upstream_check` | `relgraph-authz/tests/fixtures/authz/upstream/` (`openfga/openfga` `v1.21.0` Check corpora) | `relgraph-authz/tests/fixtures/authz/upstream-skip.yaml` |

`upstream_checksums` in each crate recomputes the vendored files' SHA-256 `CHECKSUMS` and rejects unlisted files, so keep runners and skip lists outside `upstream/`. A runner fails on a non-passing case without a skip entry and on an entry that no longer covers a non-passing case: remove entries as cases start passing. Every entry has a `reason`, a `tag` from `SkipReason::TAGS` in `tests/support/skip_list.rs` (the two crates keep copies that differ only in a header paragraph), a `justification` and a `task`. Run with `-- --nocapture` for per-file totals; the fixtures READMEs record the pass rates and the pin-bump procedure.

Live PostgreSQL tests in `relgraph-authz-postgres/tests/postgres.rs` require `OPENFGA_POSTGRES_TEST_URL` pointing to a disposable server with database-creation privileges. They create/drop generated databases and may create roles; they fail on missing configuration, rather than silently skipping. Do not run them against an arbitrary user database or print the URL. They are `#[ignore]`d, so a plain workspace test run does not exercise them.

External compatibility checks are separately documented in `tools/conformance/README.md` and `relgraph-authz/tests/fixtures/authz/README.md`. Syntax is pinned to vendored `openfga/language` revision `fbc62984d02fc8ff7e2a924e0b9c34193233007c`; authorization references OpenFGA v1.21.0. Offline fixture success does not prove fresh upstream/server parity. Run the documented differential harness when changing a compatibility surface and suitable local prerequisites are available.
