# Agent guide to Relgraph

This guide describes the architecture inspected on 2026-10-03. Verify the current code before relying on a symbol or dependency version. The separate [adversarial review](ADVERSARIAL_REVIEW.md) records findings and validation results from that snapshot; it is not a list of implemented changes.

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

- `parser/lexer.rs`: `lex`, `Token`, `TokenKind`; context-sensitive tokenization with original byte spans and hidden tokens.
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

`validation.rs` exposes `validate_schema`; `Validator` checks schema versions, duplicate declarations, reference resolution, empty assignments, condition parameter declarations, and tuple-to-userset structure. It intentionally does not compile CEL or provide complete server-side model validation. Standalone validation accepts exactly schema 1.1/1.2; modular validation requires 1.2. A locally resolved cycle can pass DSL validation and still fail authorization construction.

`manifest.rs` exposes `ModelManifest` and `parse_model_manifest`. Parsing performs YAML/lexical path validation without filesystem access. Paths are ordered, normalized relative paths; absolute paths, backslashes, above-root traversal, and duplicate normalized paths are rejected. Lexical normalization is not filesystem sandboxing or symlink containment.

`modular.rs` exposes:

- `ModuleSource`: source path plus parsed module schema.
- `ModularModel`: manifest, retained modules, composed schema, and aligned origin vectors.
- `assemble_modular_model`: pure structural composition; processes all base types before extensions and preserves deterministic origins/order.
- `load_modular_model`: synchronous reads of the manifest and its listed files, followed by parsing/composition.
- `validate_modular_model`: recomposes retained public inputs, checks schema/origin invariants, then validates cross-file semantics.

Loading and assembly do **not** implicitly validate semantics. `ModularModel` fields are public and mutable, which explains the recomposition checks. There is currently no public authorization constructor accepting its composed `Schema` directly.

## Authorization architecture

`relgraph-authz/src/lib.rs` re-exports the core API and policy types; optional middleware is in `axum_authz/mod.rs`.

`authz/mod.rs` implements the lifecycle:

```text
DSL text
  → FgaAuthz<Unbound>::new
  → parse_fga_schema
  → CompiledModel::compile
      → validate_schema
      → capability checks + recursive dependency rejection
      → conditions::compile_all
      → type/relation indexes
  → with_store(store, EvaluationLimits)
  → FgaAuthz<Bound<S>>::check(CheckRequest)
  → one tenant-scoped read session + per-check Evaluator
  → Allow / Deny / AuthorizationError
```

`FgaAuthz<State>` shares an immutable `CompiledModel` through `Arc`. `Unbound` and `Bound<S>` prevent checks before store binding. Bound clones share the store and limits. `ModelIdentity` identifies a compiled instance within one process; it is neither a persistent version nor an authentication credential.

`authz/model.rs` owns `CompiledModel`, type/relation indexes, conditions, runtime capability diagnostics, and dependency graph cycle detection. Recursive model dependencies are rejected; fixed-point evaluation is not implemented.

`authz/request.rs` owns:

- Validated identifier types: `TenantId`, `TypeName`, `EntityId`, `RelationName`, `ConditionName`.
- `Subject`, `ObjectRef`, `CheckRequest`, `AuthorizationDecision`.
- Construction/runtime errors and `EvaluationLimits`.

Identifier constructors enforce shape; they do not authenticate tenants or subjects. `CheckRequest` carries a tenant, concrete subject, object, relation, global context, and condition-scoped context.

`authz/evaluator.rs` owns per-check traversal state: `Evaluator`, `EvaluationKey`, memoized completed decisions, in-flight keys, tuple/page/work/CEL counters. Main functions are `evaluate_relation`, `evaluate_expression`, `evaluate_direct_assignment`, `evaluate_tuple_to_userset`, `load_tuples`, `validate_tuple`, and `evaluate_tuple_condition`.

Boolean expressions use deliberate three-valued rules. A decisive allow can mask a union branch error; a decisive deny can mask an intersection error. Difference must not allow when the subtraction branch has an unresolved error. Preserve and test these rules rather than treating every error as a deny or making every branch error fatal. Tuple validation failures are handled more strictly than branch evaluation errors; `CompiledModel::validate_tuple` (public as `FgaAuthz::validate_tuple`) shares those checks so writers can reject tuples up front. Tuple-to-userset targets whose type lacks the computed relation are skipped, not errors.

`authz/conditions.rs` owns `CompiledCondition`, `compile_all`, `compile_one`, expression-profile checks, `validate_stored_context`, `evaluate`, JSON-to-CEL conversion, and cost estimation. Context precedence is stored tuple → condition-scoped request → global request. Stored grant values must not be overridden by request inputs. CEL must compile to a boolean result.

The runtime profile supports the six relation-expression forms on acyclic dependencies; CEL scalar bool/int/uint/double/string/duration/timestamp and one-level scalar lists/maps. Map keys are strings. Inline conditions, IP-address parameters, nested containers, comprehension macros, and other unsupported features are rejected by runtime construction even where DSL syntax accepts them. Consult the authz README and fixtures before extending this profile.

Default limits: 10,000 scanned tuples, depth 64, 1,024 store page calls, 100,000 work units per check, and condition cost 100 per condition evaluation. Stored condition contexts are limited to 65,536 serialized JSON bytes and 10,000 collection entries; evaluation applies the same limits to each custom-store context and request value. Request values are converted once per check (`RequestValueCache`). Context conversion and condition evaluations, including failed attempts, are charged to the check's work budget. These are local accounting limits, not OpenFGA-equivalent CEL cost accounting or a wall-clock timeout; other resource-bound concerns are recorded in the review.

## Store contracts and adapters

`authz/store.rs` owns `RelationshipTuple`, `TupleSubject` (direct, userset, typed wildcard), `ConditionContext`, `StoreError`, `StoreCursor`, `RelationshipPage`, and boxed `StoreFuture`.

`RelationshipStore::begin_read` creates a tenant-scoped immutable snapshot. `RelationshipReadSession::tuples` returns a complete bounded result; `tuples_page` supports opaque continuation cursors. A cursor belongs to its session and object/relation query. A continuing page cannot be empty. The default page adapter only supports one complete read. `RelationshipWriteStore` provides strict insert and exact removal with explicit tenant ownership.

`InMemoryRelationshipStore` shares `Arc<RwLock<Arc<RelationshipSnapshot>>>`. Read sessions cheaply retain an immutable snapshot; current writes clone the snapshot before publishing it. Old readers do not observe later writes. Both synchronous insert/remove and async write-trait methods exist.

PostgreSQL modules:

| File | Main elements |
| --- | --- |
| `src/lib.rs` | `PostgresRelationshipStore` wraps `PgPool`; `MIGRATION_0001` embeds SQL; construction performs no I/O |
| `src/read.rs` | `PostgresReadSession`, `begin_read`, `query_page`, cursor codec, SQLx error classification |
| `src/write.rs` | `insert_tuple`, `remove_tuple`, tenant checks, duplicate classification; exact delete locks and validates its matching row |
| `src/mapping.rs` | `TupleRow`, `from_tuple`, `into_tuple`, versioned canonical identity encoding, SHA-256 digest, exact JSON preservation |
| `migrations/0001_relationship_tuples.sql` | Fixed schema/table, field/subject/condition constraints, identity uniqueness, lookup index |

PostgreSQL checks use one read-only repeatable-read transaction and establish its snapshot before returning the session. Keyset pages order by `tuple_id`; cursors bind to session/tenant/query. Each check holds a pool connection. Applications own migrations, trusted tenant selection, write authorization, pool configuration, deadlines, and credentials. A cancelled or failed write may have committed; the adapter does not promise retry/idempotency semantics. The README's documented PostgreSQL minimum is 14; its live-test version guard currently differs (see review).

## Route policy and Axum

`authz/policy.rs` is HTTP request-parts based but available without the Axum feature. `RoutePolicy` fixes object type/relation and supplies `PrincipalSource`, `TenantSource`, `ObjectIdSource`, and `ContextBinding` entries. `ContextValueType`, `ContextValue`, and `ContextValueProvider` describe typed inputs. `RequestPartsExtractor` and `AsyncContextResolver` support application-specific trusted mappings.

`FgaAuthz::requirements` derives an `AuthorizationRequirements` graph of `RelationKey`, `RelationRequirements`, and `RequirementExpression` nodes. `validate_policy` produces `ValidatedRoutePolicy`, checking relation existence and binding declarations/types. It does not prove authentication or that stored tuples provide every condition value.

With `axum`, `middleware` builds `FgaAuthzLayer<S>` / `FgaAuthzService`. `authorize_request` resolves authenticated principal and tenant first, then path/object/context, runs the check, and attaches `Authorized` only after allow. The original body is preserved. Authentication must run before authorization. HTTP outcomes are 401 for missing principal, 403 for deny, 400 for relevant client input errors, 503 for availability/budget failures, and 500 for trusted-state/internal failures. Do not leak raw SQL or condition error details to clients.

## Navigation and change discipline

- Prefer CodeGraph MCP for Rust architecture/symbol analysis: context first, then targeted node/trace calls. Use narrow source reads only for omitted exports, ambiguous same-name methods, or other confirmed tool gaps. Ordinary reads are appropriate for manifests, SQL, fixtures, and documentation.
- Use public-API integration tests to validate behavior across crate boundaries. Keep parser acceptance, semantic validity, runtime support, and upstream compatibility as separate claims.
- With `nom` 8, invoke parser combinators via `.parse(input)`.
- Preserve original UTF-8 byte spans and exact CEL body bytes. The pinned grammar ends a condition at its first visible closing brace; it does not balance CEL braces. Parameter newlines also follow the pinned lexer restriction. Do not casually “fix” these without changing the compatibility contract and fixtures.
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

For feature isolation, check/test `relgraph-authz` without features as well as with `--features axum`. The full workspace currently has known failures documented in the review; do not claim a clean baseline by running only default members.

DSL tests cover parser behavior, validation, manifests, modular composition/origins, and a 64-case syntax corpus in `relgraph-dsl/tests/fixtures/openfga`. Authz tests cover model construction, conditions, relation operators, policy mapping, paging, store contracts, Axum, and offline compatibility fixtures. `relgraph-authz/tests/support/store_contract.rs` is shared by in-memory and PostgreSQL adapter tests.

Live PostgreSQL tests in `relgraph-authz-postgres/tests/postgres.rs` require `OPENFGA_POSTGRES_TEST_URL` pointing to a disposable server with database-creation privileges. They create/drop generated databases and may create roles; they fail on missing configuration, rather than silently skipping. Do not run them against an arbitrary user database or print the URL. At this snapshot they fail to compile before database access.

External compatibility checks are separately documented in `tools/conformance/README.md` and `relgraph-authz/tests/fixtures/authz/README.md`. Syntax is pinned to vendored `openfga/language` revision `fbc62984d02fc8ff7e2a924e0b9c34193233007c`; authorization references OpenFGA v1.21.0. Offline fixture success does not prove fresh upstream/server parity. Run the documented differential harness when changing a compatibility surface and suitable local prerequisites are available.
