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

`validation.rs` exposes `validate_schema`; `Validator` checks schema versions, reserved and malformed type/relation names, the reserved condition name `$expression` (`ReservedConditionName`, only reachable from constructed trees), duplicate declarations, reference resolution, empty assignments, condition parameter declarations, tuple-to-userset structure, repeated type restrictions and top-level operands, and unused conditions; when all of those pass it also rejects relations without an entry point (least fixed point, following the pinned `openfga/language` validator). It intentionally does not compile CEL or provide complete server-side model validation. Standalone validation accepts exactly schema 1.1/1.2; modular validation requires 1.2. A cycle with an entry point can pass DSL validation and still fail authorization construction.

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
      / list_users(&ListUsersRequest)
      / list_objects(&ListObjectsRequest) (S: ReverseLookupStore only)
  → one tenant-scoped read session + one Evaluator per check, batch,
    list_objects, or list_users candidate
  → Allow / Deny / AuthorizationError (per item for a batch; sorted allowed
    objects or subjects, or one error, for a list)
```

`FgaAuthz<State>` shares an immutable `CompiledModel` through `Arc`. `Unbound` and `Bound<S>` prevent checks before store binding. Bound clones share the store and limits. `ModelIdentity` identifies a compiled instance within one process; it is neither a persistent version nor an authentication credential.

`authz/model.rs` owns `CompiledModel`, type/relation indexes, conditions, runtime capability diagnostics, and dependency graph cycle detection. Dependency edges carry their kind (same-object computed userset/tupleset vs. userset or tuple-to-userset hop) and polarity. Iterative Tarjan SCCs reject cycles through a `but not` subtracted operand (`RecursiveDifference`) and same-object computed-userset cycles (`SameObjectRelationCycle`, which OpenFGA also rejects); all other cycles are accepted.

`authz/request.rs` owns:

- Validated identifier types: `TenantId`, `TypeName`, `EntityId`, `RelationName`, `ConditionName`.
- `Subject`, `ObjectRef`, `CheckRequest`, `BatchCheckRequest`, `ListObjectsRequest`, `ListUsersRequest`, `UserFilter`, `UserFilterError`, `FilteredObjects`, `AuthorizationDecision`. The check, batch and ListObjects requests wrap an internal `CheckScope` (tenant, subject, global and condition-scoped context, contextual tuples) that the evaluator holds; `ListUsersRequest` has no subject and builds one scope per candidate (`scope_for`). `MAX_CONTEXTUAL_TUPLES` (100, OpenFGA's limit) and `ContextualTupleError` live here too.
- Construction/runtime errors and `EvaluationLimits`.

Identifier constructors enforce shape; they do not authenticate tenants or subjects. `CheckRequest` carries a tenant, a `TupleSubject` (concrete, userset or typed wildcard; `Subject` converts into it, and the Axum middleware always passes the concrete principal), object, relation, global context, condition-scoped context, and contextual tuples. `BatchCheckRequest` carries the same scope plus ordered `(ObjectRef, RelationName)` items; `batch_check` returns an outer error for a batch above `max_batch_items`, an unknown subject type or userset relation, invalid contextual tuples, or `begin_read`, and otherwise one result per item. `filter_objects` is a context-free batch (no request context, no contextual tuples) that splits allowed candidates from per-candidate errors. `ListObjectsRequest` carries the same scope plus an object type and relation; `list_objects` (S4 in `SKIP_LIST_PLAN.md`) returns the allowed objects sorted by ID, or one error: any candidate error, an unknown type/relation/subject, invalid contextual tuples, or any limit hit, never a partial list. `ListUsersRequest` carries a tenant, object, relation, one `UserFilter` (a type, or `type#relation`; its `FromStr` rejects other forms) and the same contexts and contextual tuples; `list_users` returns the allowed subjects sorted by type, ID (wildcard as `*`) and relation, with the same single-error rule, and fails on a filter type or relation absent from the model (`UnknownSubjectType`/`UnknownSubjectRelation`). Contextual tuples are trusted, caller-asserted input: never add a `ContextBinding`, `RoutePolicy`, or Axum path that fills them from HTTP input.

`authz/evaluator.rs` owns per-scope traversal state: `Evaluator`, `EvaluationKey` (relation ID plus object ID), memoized completed decisions, Tarjan-style unresolved-key tracking for least-fixed-point evaluation, the request-value cache, and tuple/page/work counters. Relations are always evaluated by compiled relation ID. Reaching an unresolved key (in flight, or finished `false` inside an open cycle) returns a provisional `false` and lowers the frame's low link. `true` is always memoized. A `false` cycle root memoizes its whole unresolved suffix as `false`. A `false` frame whose low link points below it stays unresolved. Errors are never memoized, and allowing or erroring frames discard their unresolved suffix. These rules rely on construction having rejected negation cycles. The checked subject is fixed per scope and may be a userset or typed wildcard (OpenFGA semantics, `prepare_assignment_page`): wildcard tuples grant concrete subjects of their type and the equal wildcard only, a tuple naming the checked userset grants it, and `resolve_subject` supplies the userset's own key, which `evaluate_relation` allows without a frame (OpenFGA's `IsSelfDefining`). Keep them, and the soundness tests in `tests/authz_recursion.rs`, when changing the evaluator. A batch reuses one evaluator: `check_item` resets the tuple/page/work counters per item while the memo and request-value cache persist; every root frame finishes, so no unresolved key survives an item. Contextual tuples are validated once per scope by `ContextualTuples::prepare` before `begin_read` (limit, tenant, `CompiledModel::validate_tuple`, no exact repeats) and indexed by object and relation; `load_tuple_page` serves a relation's contextual tuples as its first page and drops stored tuples equal to one of them, without wrapping the read session (store cursors stay session- and query-bound). They count toward the tuple-scan and work budgets, not store calls; their condition context is tuple context. `list_objects` and `list_users` prepare them with `ContextualTuples::prepare_for_list`, which drops exact repeats instead of rejecting them (S4e); `check` and `batch_check` stay strict. Its candidates come from `evaluator/list.rs` (`object_candidates`): a reverse traversal, with its own one set of tuple/page/work budgets, that seeds the keys holding the subject (tuples naming it or, for a concrete subject, its type's wildcard, via `tuples_by_subject_page`; a userset subject's own key) and follows `ReverseEdges` (same-object computed usersets in union/intersection operands and difference bases, userset tuples, tupleset tuples) to a fixpoint over a visited `EvaluationKey` set. It reads contextual tuples as edges, validates stored tuples before following them (S1), never evaluates conditions, and fails on more than `max_list_candidates` candidates. Every candidate is then decided by `check_item` on the same session, so list results equal brute-force `check` (`tests/authz_list_objects.rs`); keep the generator complete (it may over-include, never miss) when changing evaluator edges. `list_users` (S4e) needs no reverse lookup: `user_candidates` in `evaluator/list.rs` expands forward from the listed key over `tuples_page`, with one `Budget` (shared type with `object_candidates`), following the granting operands (computed usersets, userset tuples, tuple-to-userset targets; never a subtracted operand) to a fixpoint over a visited key set. A type filter collects the concrete subjects and typed wildcards that assignment tuples name, so a subject granted only by a wildcard tuple is listed as the wildcard; a userset filter collects every reached key of its relation, the listed key included. Each candidate is decided by its own `Evaluator` (fresh memo and budgets, the candidate as subject) on the one session, handed on with `Evaluator::into_parts`; `tests/authz_list_users.rs` compares the results with brute-force `check`. Main functions are `check`, `batch_check`, `list_objects`, `list_users`, `check_item`, `evaluate_relation`, `evaluate_expression`, `evaluate_direct_assignment`, `evaluate_tuple_to_userset`, `load_tuple_page`, `prepare_assignment_page`, `prepare_tupleset_page`, `validate_tuple`, and `evaluate_tuple_condition`.

Boolean expressions use deliberate three-valued rules. A decisive allow can mask a union branch error; a decisive deny can mask an intersection error. Difference must not allow when the subtraction branch has an unresolved error. Preserve and test these rules rather than treating every error as a deny or making every branch error fatal. Tuple validation failures are handled more strictly than branch evaluation errors; `CompiledModel::validate_tuple` (public as `FgaAuthz::validate_tuple`) shares those checks so writers can reject tuples up front. `authz/write.rs` adds `WriteError` and, for `S: RelationshipWriteStore`, the validating `FgaAuthz<Bound<S>>::write_tuple` / `delete_tuple` / `apply_changes`: tenant check, then `validate_tuple`, then the store. They do not authorize the caller. Reads stay strict on stored tuples that drift from the model (maintainer decision); repair goes through the store directly. Tuple-to-userset targets whose type lacks the computed relation are skipped, not errors.

`authz/conditions.rs` owns `CompiledCondition`, `compile_all`, `compile_one`, expression-profile checks, `validate_stored_context`, `evaluate`, JSON-to-CEL conversion, and cost estimation. Context precedence is stored tuple → condition-scoped request → global request. Stored grant values must not be overridden by request inputs. CEL must compile to a boolean result. It also owns inline condition expressions (`[user with $expression]`, decision S3 of `SKIP_LIST_PLAN.md`): `InlineConditionSource` reads a tuple's stored `{expression, parameters}` context (no other keys, so no stored values; the stored-context limits apply), infers undeclared identifiers as `string` as OpenFGA's `inline.go` does, and compiles through `compile_one` with the same profile, bool rule and cost estimate. `validate_inline_condition` serves `CompiledModel::validate_tuple` (writes, contextual tuples); `InlineConditionCache` (held by the `Evaluator`) compiles each distinct source once per check or batch and caches failures. A malformed context or failing expression is `InvalidTuple`. `RequestValueCache` slots are keyed per compiled condition (`ConditionCacheKey`), since all inline conditions share the name `$expression`. Targets record `CompiledTargetCondition` (unconditioned, named, inline).

The runtime profile supports the six relation-expression forms on acyclic dependencies; CEL scalar bool/int/uint/double/string/duration/timestamp/ipaddress and one-level scalar lists/maps. Map keys are strings. `authz/ipaddress.rs` implements OpenFGA's `ipaddress` extension locally on `cel-core` (plan Decision D1): `ipaddress(string)`, `<ipaddress>.in_cidr(string)` and address equality, with addresses and IPv4-mapped prefixes unmapped as upstream; IPv6 zone identifiers are rejected (a documented difference). Inline condition expressions are supported within the same CEL profile (see `authz/conditions.rs` above). Nested containers, comprehension macros, and other unsupported features are rejected by runtime construction (or, inside an inline expression, as `InvalidTuple`) even where DSL syntax accepts them. The pinned checker accepts mixed-type `==` that OpenFGA rejects at model write. Consult the authz README and fixtures before extending this profile.

Default limits: 10,000 scanned tuples, depth 25 (OpenFGA's resolve depth), 1,024 store page calls, 100,000 work units per check (per item in a batch), condition cost 100 per condition evaluation, 100 batch items (maximum 1,000), and 1,000 list candidates (maximum 10,000). Stored condition contexts are limited to 65,536 serialized JSON bytes and 10,000 collection entries; evaluation applies the same limits to each custom-store context and request value. Request values are converted once per check or batch (`RequestValueCache`). Context conversion and condition evaluations, including failed attempts, are charged to the check's work budget. These are local accounting limits, not OpenFGA-equivalent CEL cost accounting or a wall-clock timeout.

## Store contracts and adapters

`authz/store.rs` owns `RelationshipTuple`, `TupleSubject` (direct, userset, typed wildcard), `ConditionContext`, `StoreError`, `StoreCursor`, `RelationshipPage`, and boxed `StoreFuture`.

`RelationshipStore::begin_read` creates a tenant-scoped immutable snapshot. `RelationshipReadSession::tuples` returns a complete bounded result; `tuples_page` supports opaque continuation cursors. A cursor belongs to its session and object/relation query. A continuing page cannot be empty. The default page adapter only supports one complete read. `ReverseLookupSession::tuples_by_subject_page(object_type, relation, subject, cursor, maximum)` pages stored tuples by exact subject under the same snapshot and cursor rules (a cursor belongs to its session and object-type/relation/subject query); `ReverseLookupStore` is blanket-implemented for stores whose session implements it and is required only by `list_objects` (S4a), so check-only stores are unchanged. The in-memory store implements it by scanning its immutable snapshot (stable order within a session); PostgreSQL by a keyset query in `tuple_id` order on the session transaction, served by migration 0002's subject index. Adapters may order differently, so the shared contract compares reverse-lookup results order-independently. `RelationshipWriteStore` provides strict insert, exact removal, and a required atomic `apply_changes(tenant, inserts, deletes)` (deletions first; missing deletion or duplicate insertion is `Conflict` and applies nothing) with explicit tenant ownership. Write errors use `StoreErrorKind::Conflict` (duplicate insert) and `InvalidInput` (tenant mismatch, oversized context); `CorruptData` is reserved for malformed stored data. The Axum middleware maps the write-only kinds to 500 if a read ever reports them.

`InMemoryRelationshipStore` shares `Arc<RwLock<Arc<RelationshipSnapshot>>>`. Read sessions cheaply retain an immutable snapshot; current writes clone the snapshot before publishing it. Old readers do not observe later writes. Both synchronous insert/remove and async write-trait methods exist.

PostgreSQL modules:

| File | Main elements |
| --- | --- |
| `src/lib.rs` | `PostgresRelationshipStore` wraps `PgPool`; `MIGRATION_0001` and `MIGRATION_0002` embed SQL; construction performs no I/O |
| `src/read.rs` | `PostgresReadSession`, `begin_read`, `ReverseLookupSession` impl, `PageQuery` (object or exact-subject query), `query_page`, cursor codec (per-query magic), SQLx error classification |
| `src/write.rs` | `insert_tuple`, `remove_tuple`, transactional `apply_changes` over shared `insert_row` / `remove_row`, tenant checks, duplicate classification; exact delete locks and validates its matching row |
| `src/mapping.rs` | `TupleRow`, `from_tuple`, `into_tuple`, versioned canonical identity encoding, SHA-256 digest, exact JSON preservation |
| `migrations/0001_relationship_tuples.sql` | Fixed schema/table, field/subject/condition constraints, identity uniqueness, lookup index |
| `migrations/0002_subject_lookup_index.sql` | Subject lookup index `(tenant, object_type, relation, subject_kind, subject_type, COALESCE(subject_id, ''), COALESCE(subject_relation, ''), tuple_id)` for `tuples_by_subject_page` |

PostgreSQL checks, batches and list calls use one read-only repeatable-read transaction and establish its snapshot before returning the session. Keyset pages order by `tuple_id`; cursors bind to session/tenant/query. Each check holds a pool connection. Applications own migrations, trusted tenant selection, write authorization, pool configuration, deadlines, and credentials. A cancelled or failed write may have committed; the adapter does not promise retry/idempotency semantics. The documented PostgreSQL minimum is 14, matching the live-test version guard.

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

DSL tests cover parser behavior, validation, manifests, modular composition/origins, and a 64-case syntax corpus in `relgraph-dsl/tests/fixtures/openfga`. Authz tests cover model construction, conditions (including the `ipaddress` extension), relation operators, batch checks, list objects (against brute-force check), contextual tuples, policy mapping, paging, store contracts, Axum, and offline compatibility fixtures (also replayed as batches). `relgraph-authz/tests/support/store_contract.rs` is shared by in-memory and PostgreSQL adapter tests.

Upstream corpora are replayed offline as ordinary test targets (see `CONFORMANCE_PLAN.md`):

| Test target | Vendored corpus | Skip list |
| --- | --- | --- |
| `cargo test -p relgraph_dsl --test upstream_corpus` | `relgraph-dsl/tests/fixtures/openfga/upstream/` (`openfga/language` syntax, semantic and `fga.mod` cases) | `relgraph-dsl/tests/fixtures/openfga/upstream-skip.yaml` |
| `cargo test -p relgraph-authz --test upstream_check` | `relgraph-authz/tests/fixtures/authz/upstream/` (`openfga/openfga` `v1.21.0` Check corpora) | `relgraph-authz/tests/fixtures/authz/upstream-skip.yaml` |

`upstream_checksums` in each crate recomputes the vendored files' SHA-256 `CHECKSUMS` and rejects unlisted files, so keep runners and skip lists outside `upstream/`. A runner fails on a non-passing case without a skip entry and on an entry that no longer covers a non-passing case: remove entries as cases start passing. Every entry has a `reason`, a `tag` from `SkipReason::TAGS` in `tests/support/skip_list.rs` (the two crates keep copies that differ only in a header paragraph), a `justification` and a `task`. An authz entry tagged `deliberate` starts its `justification` with the ID of a decision under "Maintainer decisions" (`S1: …`). Run with `-- --nocapture` for per-file totals; the fixtures READMEs record the pass rates and the pin-bump procedure.

Live PostgreSQL tests in `relgraph-authz-postgres/tests/postgres.rs` require `OPENFGA_POSTGRES_TEST_URL` pointing to a disposable server with database-creation privileges. They create/drop generated databases and may create roles; they fail on missing configuration, rather than silently skipping. Do not run them against an arbitrary user database or print the URL. They are `#[ignore]`d, so a plain workspace test run does not exercise them.

External compatibility checks are separately documented in `tools/conformance/README.md` and `relgraph-authz/tests/fixtures/authz/README.md`. Syntax is pinned to vendored `openfga/language` revision `fbc62984d02fc8ff7e2a924e0b9c34193233007c`; authorization references OpenFGA v1.21.0. Offline fixture success does not prove fresh upstream/server parity. Run the documented differential harness when changing a compatibility surface and suitable local prerequisites are available.

## Maintainer decisions

These divergences from upstream are approved by the maintainer. Authz skip entries tagged `deliberate` cite them by ID; `deliberate_entries_cite_a_recorded_decision` in `relgraph-authz/tests/upstream_check.rs` reads the IDs from this list and rejects an entry that cites none of them. Record a decision here before citing it.

- **S1 (strict stored reads).** A stored tuple that drifts from the current model (its subject, tupleset subject or condition no longer fits the relation) is an `InvalidTuple` error on read, not a tuple to ignore. Repair goes through the store directly. Upstream's tolerant behaviour, which ignores such tuples, is not copied. Maintainer decision, first recorded in this guide on 2026-10-18 (see "Authorization architecture").
- **S2 (negation cycles).** Model construction rejects a dependency cycle through a `but not` subtracted operand (`RecursiveDifference`), which upstream accepts. The least-fixed-point evaluator is sound only because such cycles are rejected. Maintainer decision, first recorded in this guide on 2026-10-18 (see `authz/model.rs` under "Authorization architecture").
- **S4f (ListUsers branch errors).** A subject is listed exactly when its check allows (S4 of `SKIP_LIST_PLAN.md`), so a decisive allow masks another branch's error in `list_users` as it does in `check`. Upstream ListUsers instead errors (2000) when any branch it expands lacks a condition parameter, even where upstream Check allows the same inputs (`abac_tests.yaml::relation_through_ttu_with_condition::0::listUsers::1` and `::2`); that behaviour is not copied. Maintainer decision, approved 2026-10-21.
- **S4g (invalid contextual tuples in list APIs).** `list_objects` and `list_users` report an invalid contextual tuple as `InvalidContextualTuple` (2027), as upstream Check does, so one invalid-input error covers check and list. Upstream ListObjects and ListUsers report the same tuple as 2000 (`abac_tests.yaml::condition_bound_to_correct_type_restriction_facet::1::listObjects::0` and `::listUsers::0`); that code is not copied. Maintainer decision, approved 2026-10-21.
- **S7 (empty models).** The DSL rejects a model with no type definitions as `EmptyModel`, matching the OpenFGA write API (`WriteAuthorizationModelRequest.type_definitions` has `min_items: 1`). The language validator accepts it, so the two `valid syntax` cases in `dsl-syntax-validation-cases.yaml` are kept as deliberate differences. Maintainer decision, approved 2026-10-21.
