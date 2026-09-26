# OpenFGA authorization for Axum

Status: in progress; Tasks 1–7 are complete and Task 8 is TODO.

## 1. Goal and architecture decision

Start by creating `FgaAuthz` from an OpenFGA DSL definition. Construction parses the definition, validates its semantics and runtime compatibility, and compiles an immutable authorization model. Derive route middleware from that object. For each request, resolve the authenticated principal, target object, relation, and condition context; evaluate the model against relationship tuples; invoke the handler only when authorized.

Planning assumption: evaluation runs locally, using an asynchronous, pluggable relationship store. An OpenFGA server adapter is a separate future integration. This assumption makes the evaluator an explicit deliverable rather than assuming the parser already supplies authorization decisions.

A definition describes possible relationships and rules. It does not establish that a particular user has a relationship with an object. For example, `define viewer: [user]` still needs a tuple such as `(user:anne, viewer, document:42)` before Anne can read document 42. OpenFGA's check operation is expressed in terms of user, relation, and object. [OpenFGA Check documentation](https://openfga.dev/docs/getting-started/perform-check)

The application supplies authentication, relationship persistence, and the mapping from HTTP inputs to model inputs. The library owns model validation, evaluation, parameter checking, and enforcement.

## 2. Current repository foundation

Inspected on 2026-09-26 using the repository's CodeGraph index and tracked metadata. The workspace now has a parser package (`openfga_dsl`) and an authorization package (`openfga-authz`):

- `src/parser/schema.rs`: `parse_fga_schema(&str) -> Result<Schema, ParseError>` consumes the whole definition.
- `src/validation.rs`: `validate_schema(&Schema) -> Result<(), Vec<ValidationError>>` performs bounded semantic validation. Diagnostics include duplicate declarations, unknown references, invalid tupleset relations, and invalid parameter types.
- `src/ast.rs`: `Schema`, `RelationExpression`, `ConditionDefinition`, `ConditionParameter`, and `ParameterType` represent model rules and declared condition inputs. Relation expressions include direct assignment, computed usersets, tuple-to-userset, union, intersection, and difference. Condition expressions are stored as strings.
- Standalone semantic validation recognizes schema 1.1 and 1.2. A standalone module requires composition before validation; modular loading already has dedicated source and tests.
- `tests/fixtures/validation/README.md` explicitly documents that locally resolved cycles pass the current validator. Successful parsing and validation therefore do not establish that a model is executable by a new runtime.
- The `openfga_dsl` package depends on `nom`, `serde`, and `serde_yaml`; it remains parser-only with no authorization, Axum, or CEL runtime dependencies. The `openfga-authz` package depends on `openfga_dsl` and owns runtime construction and evaluation. Existing parser, validation, manifest, modular, and conformance tests provide regression coverage.

Reuse these facilities. Keep runtime capability validation separate from parser acceptance so the parser can continue representing definitions the initial runtime cannot execute.

## 3. Public lifecycle, beginning with FgaAuthz

Proposed API sketch; names and signatures below are design targets, not existing APIs:

```rust
// 1. Parse, validate, and compile once at application startup.
let model = FgaAuthz::new(include_str!("authorization.fga"))?;

// 2. Bind relationship data and runtime limits; no implicit empty store.
let authz = model.with_store(store, EvaluationLimits::default());

// 3. Validate a fixed route permission and its input bindings.
let read_document = authz.middleware(
    RoutePolicy::new("document", "viewer")
        .principal(PrincipalSource::extension::<AuthenticatedPrincipal>())
        .tenant(TenantSource::extension::<AuthenticatedPrincipal>())
        .object_id(ObjectIdSource::path("document_id"))
)?;

// 4. Register the middleware returned by the object.
let app = Router::new()
    .route(
        "/documents/{document_id}",
        get(read_document_handler).route_layer(read_document),
    )
    .layer(authentication_layer); // Executes before authorization.
```

Use a generic state transition: `FgaAuthz<Unbound>` is produced by `new`; `with_store` consumes it and returns `FgaAuthz<Bound<S>>`. Only the bound type exposes `check` and `middleware`. Construction must not silently authorize against missing relationship data. Cloning shares the compiled model and store through `Arc`.

Core operations:

| Operation | Contract |
| --- | --- |
| `FgaAuthz::new(definition)` | Parse, run existing semantic validation, perform runtime capability checks, compile condition programs, and build indexes. Return structured startup errors on failure. |
| `with_store(store, limits)` | Bind a validated tuple source and bounded execution configuration. |
| `requirements(object_type, relation)` | Describe candidate subject types and reachable condition parameter signatures; preserve alternative branches and condition identity. |
| `check(CheckRequest)` | Async `Result<AuthorizationDecision, AuthorizationError>` with `Allow` and `Deny` decisions. Errors remain distinct from denial. |
| `middleware(RoutePolicy)` | Validate schema references and binding declarations, then return a cloneable Axum-compatible Tower layer. |

Keep construction synchronous and free of store I/O. Reject standalone module fragments in `new`; a later explicit constructor can accept a composed model with origin diagnostics. No implicit filesystem resolution from a definition string.

`CheckRequest` holds structured `Subject`, `ObjectRef`, relation, and typed context values. Do not concatenate unchecked HTTP strings into `type:id` or `type:id#relation` identifiers. HTTP checks initially accept a concrete authenticated subject; usersets and wildcards remain available as stored tuple subjects.

## 4. What “parameters expected by the schema” means

The schema defines types, relations, and condition parameter names/types. It does not define URL paths, JWT claim locations, query keys, or body layouts. `RoutePolicy` explicitly maps application inputs to the schema. A model loaded at runtime produces runtime descriptors, not newly generated Rust types.

| Input | Origin | Validation |
| --- | --- | --- |
| Principal | Trusted authentication extension | Concrete subject type and valid identifier; never accept an arbitrary user ID header as identity. |
| Object type | Fixed in route registration | Type exists in compiled model. |
| Object ID | Named path capture or application resolver | Nonempty, bounded, valid ID; resolver failures retain their origin. |
| Relation | Fixed in route registration | Exists on object type; clients cannot choose another relation through query parameters. |
| Condition values | Explicit named providers from trusted claims, server clock, application data, or permitted request inputs | Match each condition's declared types, including numeric ranges and container element types. |
| Relationship tuples | Bound store | Validate object/relation/subject restriction and condition attachment before use. |

Provide `ContextBinding` declarations keyed by condition and parameter, plus a typed `ContextValue`. Define exact conversion rules for supported OpenFGA scalar and collection types. Reject lossy numeric conversions, malformed timestamps/durations, and unsupported generic shapes. If a global input name feeds conditions with different types, require explicit per-condition mappings.

Registration verifies references and declared provider types. Runtime validates actual values. Reachability through computed usersets and tupleset traversal must be reflected in `requirements`; direct assignment restrictions alone do not describe all subjects that may be authorized through a relation.

Condition inputs may come from the tuple's stored context or request context. A reachable condition is only potentially required: do not require every parameter of every branch before evaluation. Resolve required values when evaluating an applicable conditional tuple. OpenFGA documents combining stored tuple context with request context for condition checks. [OpenFGA conditions](https://openfga.dev/docs/modeling/conditions)

For the local runtime, tuple-bound values take precedence; request bindings may supply missing declared values but may not override persisted grant metadata. Pin and test this merge behavior against an OpenFGA server before claiming compatibility. Preserve each condition's namespace and reject undeclared provider bindings at startup. An unconditional successful union branch must not fail solely because an unused conditional branch lacks context.

Default extraction uses request parts and leaves the body intact. Body-dependent authorization requires an explicit future buffered-body integration with limits; it is not part of the initial adapter.

## 5. Runtime and enforcement contracts

### Model compilation

Compile AST references into stable type/relation/condition IDs and immutable lookup tables. Preserve source spans in startup diagnostics. Validate the evaluator's supported feature set before exposing an object capable of producing middleware.

The first runtime supports all six existing relation-expression variants on acyclic model dependencies, including userset tuples and typed wildcards. Reject relation dependency cycles at startup with an explicit `UnsupportedRecursiveModel` diagnostic; this is a documented runtime restriction even though the existing semantic validator accepts locally resolved cycles. Recursive-model support is a separate extension requiring defined fixed-point semantics.

Compile and type-check CEL condition bodies against declared parameters. Select a CEL implementation only after checking the required types, functions, and evaluation limits against fixtures. Reject unsupported expressions, functions, and types during construction. Never substitute string matching or Rust expression evaluation for CEL. The supported condition profile must be documented before implementation is considered complete.

### Relationship store

Define an async `RelationshipStore` contract returning tuples for an object/relation, with pagination or a bounded stream. Include userset subjects, wildcards, optional condition names, and stored condition context. Provide an in-memory implementation for examples and tests; applications implement database-backed stores.

Create a read session per check. Store adapters must document snapshot/consistency guarantees, and per-check memoization must use that session. Namespace or tenant scope comes from trusted application state and must be included in reads and memoization keys. Scope is not proof of membership: tenant access must also be represented by the model's relationships.

Store errors, invalid persisted tuples, incomplete page reads, and resource exhaustion never become successful empty results. Tuple writers should validate on ingestion; evaluator reads must still reject incompatible data.

### Evaluation

Implement direct tuple matching, computed relations, userset membership, typed wildcard membership, tuple-to-userset traversal, union, intersection, and difference. For difference, evaluate `base AND NOT subtract`; a failed subtract lookup cannot establish absence.

Use explicit internal outcomes `Allow`, `Deny`, and `Error`. Union allows if any branch allows, otherwise returns an encountered error before deny. Intersection denies if any branch denies, otherwise returns an encountered error before allow. Difference denies when base denies or subtract allows; otherwise any unresolved operand error prevents allow. Branch order must not change the result.

Bound elapsed time, relation depth, tuples scanned, store calls, CEL cost, and concurrent work. Track in-flight checks separately from completed memoized decisions to detect tuple graph cycles. If safe termination cannot establish a decision within the configured profile, return an error. Cache only within one check initially; persistent decision caching would require revocation and context invalidation rules.

### Axum adapter

Expose a concrete `FgaAuthzLayer`/`FgaAuthzService` with immutable shared state and a route policy. Verify Tower readiness, clone behavior, `Send` bounds, cancellation, and compatibility with Axum router state. `Service::Error` should be infallible at the HTTP boundary: map authorization errors into responses.

Attach protection to the intended route or method after declaring it. Authentication must execute first, and the protected handler must receive the original request body. Axum documents route middleware and the execution order of stacked layers. [Axum middleware documentation](https://docs.rs/axum/latest/axum/middleware/)

Allow responses may attach an `Authorized` extension containing the checked subject, object, relation, and model identity for handler use. Avoid exposing full tuples or sensitive context. The handler must use the same resource identity that was checked.

| Outcome | HTTP behavior |
| --- | --- |
| Allow | Call the handler exactly once. |
| Deny | 403; handler is not called. |
| Missing/invalid authentication | 401 through the application's authentication contract. |
| Malformed client-controlled bound input | 400 with a stable, nonsensitive error code. |
| Unknown route schema reference or invalid provider declaration | Fail registration/startup. |
| Missing trusted extension/provider, invalid persisted tuple, internal invariant violation | 500; handler is not called. |
| Store unavailable, evaluation timeout, or work limit exceeded | 503; handler is not called. |

A missing condition value is an error only if it remains relevant to the final decision. Classify it according to its declared provider: client input can produce 400; missing trusted state produces 500. Log diagnostic details internally with request/model identifiers, without logging credentials or complete authorization context.

## 6. Module and dependency boundaries

Preserve the `openfga_dsl` package and its public parser API as parser-only. Put authorization runtime code and its non-web dependencies in `openfga-authz`, which depends on `openfga_dsl`. Make Axum/Tower optional behind the `axum` feature of `openfga-authz`. The parser-only package must remain usable without a web runtime or CEL engine.

| File/module | Responsibility |
| --- | --- |
| `openfga-authz/src/authz/mod.rs` | `FgaAuthz`, bound/unbound states, public exports. |
| `openfga-authz/src/authz/model.rs` | Parser/validator integration, compiled indexes, capability diagnostics. |
| `openfga-authz/src/authz/request.rs` | Structured subjects/objects, checks, decisions, errors, typed values. |
| `openfga-authz/src/authz/store.rs` | Store/read-session contracts, validated tuples, in-memory implementation. |
| `openfga-authz/src/authz/evaluator.rs` | Relation evaluation, limits, per-check memoization. |
| `openfga-authz/src/authz/conditions.rs` | CEL adapter, compilation, typed context merge and evaluation. |
| `openfga-authz/src/authz/policy.rs` | Schema requirements and route/provider declarations. |
| `openfga-authz/src/axum_authz/mod.rs` | HTTP extraction, Tower layer/service, response mapping. |
| `openfga-authz/src/lib.rs`, `openfga-authz/Cargo.toml` | Authorization exports and runtime/optional web dependencies. |
| `openfga-authz/tests/authz_*.rs`, `openfga-authz/tests/axum_authz.rs` | Public API and HTTP behavior tests. |
| `openfga-authz/examples/axum_authz.rs`, `openfga-authz/examples/authorization.fga`, `openfga-authz/README.md` | Runnable registration and model/data examples. |
| Root `Cargo.toml` | Workspace membership and resolver only; keep parser dependencies in the root `openfga_dsl` package. |

Pin compatible Axum/Tower versions when implementing the adapter; do not assume unbounded compatibility with every release. Keep HTTP status decisions out of the core evaluator.

## 7. Ordered implementation tasks

Every task is a separate committable slice. Mark DONE only when its acceptance checks pass. A restricted intermediate runtime must reject features it has not implemented yet.

### Task 1 — [DONE] Create FgaAuthz and the construction contract

Dependencies: none. First available task.

Files: `openfga-authz/Cargo.toml`, `openfga-authz/src/lib.rs`, `openfga-authz/src/authz/{mod,model,request}.rs`, `openfga-authz/tests/authz_model.rs`.

Implement `FgaAuthz::new(definition)`, parse/semantic diagnostic propagation, immutable indexed model storage, and explicit capability validation. Initially accept only the documented unconditional direct-assignment profile; reject other executable constructs until later tasks implement them. Define bound/unbound states without exposing middleware before store binding.

Acceptance/tests: valid definition constructs; malformed syntax and unresolved references preserve diagnostics; relation expressions outside unconditional direct assignment, wildcard/condition restrictions, and relation dependency cycles are rejected; cloning shares compiled data; construction takes only definition text and performs no store I/O. Verified with `cargo test -p openfga-authz --all-targets` and `cargo test --workspace --all-targets`; the latter preserves parser-only regression coverage.

### Task 2 — [DONE] Bind relationship data and deliver the first check

Dependencies: Task 1.

Files: `openfga-authz/src/authz/{mod,store,request,evaluator}.rs`, `openfga-authz/tests/authz_store.rs`, `openfga-authz/tests/authz_check.rs`.

Implement `RelationshipStore`, read sessions, tuple validation, in-memory storage, binding, and `check`. Evaluate unconditional direct membership for concrete subjects. Establish structured identifiers, tenant scoping, limits, and error contracts. The store contract uses a typed associated read-session and bounded asynchronous futures; the in-memory store provides immutable read snapshots and keeps tenants separate. Tuples can retain userset, wildcard, and condition/context data, while the current evaluator rejects those tuple forms until their model capabilities are implemented. The first evaluation limit bounds returned tuples (1–100,000; default 10,000); graph depth and broader work budgets are introduced with traversal tasks.

Acceptance/tests: matching tuple allows; absent tuple denies; invalid tuple and store failure return errors; unknown check relation/type is rejected; empty store is an explicit valid store; bound state is required to call `check`; identical IDs in different namespaces do not share decisions. Store tests cover immutable sessions, tuple-limit exhaustion, and persisted condition-context preservation; check tests cover clone-shared store state. Verified with `cargo fmt --all -- --check`, `cargo check -p openfga-authz --all-targets`, `cargo test -p openfga-authz --all-targets`, and `cargo test --workspace --all-targets`.

### Task 3 — [DONE] Execute compound relations and graph traversal

Dependencies: Task 2.

Files: `openfga-authz/src/authz/{model,evaluator,store,request}.rs`, `openfga-authz/src/{lib.rs,authz/mod.rs}`, `openfga-authz/tests/{authz_model,authz_relations}.rs`.

Implement computed usersets, group membership, typed wildcards, tuple-to-userset, union, intersection, and difference. Expand the construction capability profile to match. Add paged reads, relation-depth/store-call/work/tuple bounds, in-flight detection, cancellation-safe per-check state, and completed-decision memoization. Legacy stores can use the bounded complete-read adapter; stores can override it for incremental pages.

Acceptance/tests: positive and negative cases cover all six expression forms; nested group membership; inherited document access; unrelated wildcard type denies; subtraction errors never grant; boolean error handling is branch-order invariant; tuple graph cycles and exhausted limits return errors safely. A runtime cycle regression test constructs an internal cyclic graph directly because public construction rejects recursive model dependencies. Conditional rules remain rejected until Task 4. Verified with `cargo fmt --all -- --check`, `cargo check -p openfga-authz --all-targets`, `cargo test -p openfga-authz --all-targets`, and `cargo test --workspace --all-targets`.

### Task 4 — [DONE] Compile conditions and validate schema-driven context

Dependencies: Task 3.

Files: `openfga-authz/Cargo.toml`, `openfga-authz/src/authz/{model,conditions,request}.rs`, `openfga-authz/tests/authz_conditions.rs`.

Choose and record a CEL dependency and supported capability profile. Compile/type-check condition programs at construction; implement typed values, lazy context resolution, tuple/request merge, and evaluation budgets. Expand runtime acceptance only for implemented types and functions.

The runtime pins `cel-core = 0.5.1` and compiles/type-checks each named condition during model construction. Its supported declaration types are `bool`, `int`, `uint`, `double`, `string`, `duration`, `timestamp`, and one-level `list<T>` / `map<T>` containers over those scalar types (map keys are strings). Durations use CEL/OpenFGA duration strings and timestamps use RFC3339. The accepted expression profile includes boolean/numeric/string comparisons and arithmetic, field and index access, `has`, `size`, `startsWith`, `endsWith`, `matches`, and the standard scalar/time conversions `int`, `uint`, `double`, `string`, `bytes`, `duration`, and `timestamp`. `list.contains(value)` is rejected by the pinned `cel-core = 0.5.1` compiler and is outside the supported profile. Bytes, `any`, IP addresses, nested containers, custom/message types, extension functions, and comprehension macros are rejected at construction. The evaluator lazily resolves only parameters referenced by a condition; persisted tuple values take precedence over request context, which may fill missing values but cannot replace them. A per-check deterministic local cost estimate is enforced (default limit 100, configurable up to 100,000); this limit is an explicit local resource budget and is not claimed to reproduce OpenFGA server CEL cost accounting.

Acceptance/tests: invalid CEL or undeclared variables fail construction; valid scalar/container/time values evaluate correctly; wrong types and missing relevant values produce typed errors; stored grant metadata cannot be overridden; an unconditional allow branch survives an unrelated missing condition input; expired conditional grant denies; evaluation cost limits are enforced.

Verified with `cargo fmt --all -- --check`, `cargo check -p openfga-authz --all-targets`, `cargo test -p openfga-authz --all-targets`, and `cargo test --workspace --all-targets`.

### Task 5 — [DONE] Derive route policies from the compiled schema

Dependencies: Task 4.

Files: `openfga-authz/src/authz/policy.rs`, `openfga-authz/src/authz/{mod,model,request}.rs`, `openfga-authz/tests/authz_policy.rs`.

Implement requirements descriptors and route policies with fixed object type/relation and explicit input providers. Resolve reachable relation/condition dependencies without flattening alternatives into a universal required-parameter list. Define synchronous request-parts extraction and an async custom resolver contract for application data.

The public `requirements` descriptor preserves the full relation-expression tree and a keyed graph of computed userset, userset-subject, and tuple-to-userset dependencies. Direct-assignment conditions carry their condition identity and declared typed parameter signatures at the original alternative. Route policies fix the object type and relation, require trusted principal, tenant, and object-ID sources, and bind context providers by both condition and parameter. Provider declarations are checked at registration; request-parts providers resolve synchronously and custom application resolvers use an async future contract. Typed context values reject lossy integer-to-double conversions. Check requests now support per-condition request context, with stored tuple context taking precedence over scoped request values and the existing global fallback.

Acceptance/tests: missing object type/relation and undeclared context bindings fail registration; provider type mismatches fail early; inherited/group access accepts applicable subjects; same parameter name with incompatible condition types requires separate bindings; clients cannot override fixed relation/type or trusted principal.

Verified with `cargo fmt --all -- --check`, `cargo check -p openfga-authz --all-targets`, `cargo check --workspace --all-targets`, `cargo test -p openfga-authz --all-targets` (45 tests), and `cargo test --workspace --all-targets` (all package and parser/conformance tests passed).

### Task 6 — [DONE] Derive and register Axum middleware

Dependencies: Task 5.

Files: `openfga-authz/Cargo.toml`, `openfga-authz/src/lib.rs`, `openfga-authz/src/axum_authz/mod.rs`, `openfga-authz/src/authz/mod.rs`, `openfga-authz/tests/axum_authz.rs`.

Implement `authz.middleware(policy)`, Tower layer/service, named path extraction, trusted principal extension resolution, HTTP mapping, and `Authorized` extension. Integrate with application router state without requiring the application to replace its state type.

Acceptance/tests: `Router::oneshot` verifies allow, deny, unauthenticated, bad input, and store outage; handler call counter remains zero on rejection; body is preserved; authentication executes first; custom state and nested routers work; GET/HEAD, POST, OPTIONS, unmatched paths, and method mismatches have explicit tested behavior; only deliberately protected routes are gated.

Implementation: `openfga-authz` exposes the optional `axum` feature with exact dependencies `axum = 0.8.9` and `tower = 0.5.3`. The bound authorization object validates each fixed route policy at registration and returns a cloneable Tower layer/service. The service extracts named Axum path captures from request parts, resolves trusted principal and tenant extensions plus configured context, checks the model, and inserts an `Authorized` extension only on allow. It maps denial to 403, missing principal to 401, invalid request-bound input to 400, store/resource limits to 503, and trusted-state/internal failures to 500. `Authorized` carries the checked subject/object/relation and an opaque model-instance identity shared by model clones.

Axum's [`route_layer` and middleware documentation](https://docs.rs/axum/0.8.9/axum/middleware/) describes matched-route behavior and layer ordering. The integration tests verify unmatched paths remain 404, method mismatches remain 405 even without an authentication extension, and an outer authentication middleware runs before authorization.

Verified with `cargo fmt --all -- --check`, `cargo check --workspace --all-targets`, `cargo check --workspace --all-targets --features openfga-authz/axum`, and `cargo test --workspace --all-targets --features openfga-authz/axum` (including all 8 Axum integration tests and existing parser/runtime tests); `git diff --check` passed.

### Task 7 — [DONE] Establish semantic compatibility and isolation evidence

Dependencies: Task 6.

Files: `openfga-authz/tests/authz_compatibility.rs`, `openfga-authz/tests/fixtures/authz/`, `openfga-authz/tests/axum_authz.rs`, maintainer tooling under `openfga-authz/tools/`.

Create a reproducible differential harness against a pinned OpenFGA server for the supported runtime profile. Record server version, models, tuples, contexts, expected decisions/errors, and known unsupported features. Keep ordinary Cargo tests offline by checking in fixtures. Grammar conformance alone is not evaluator conformance.

Implementation: `openfga-authz/tools/openfga-differential.py` starts a temporary OpenFGA `v1.21.0` container with memory storage, verifies release commit `ab557c5592670c899de35297e7aa067015f06502`, and runs the JSON API models and tuples in `openfga-authz/tests/fixtures/authz/`. The `.fga` companions provide the local runtime models. Fixtures record decisions/errors and context inputs; the fixture README documents the offline and differential commands, image digest, local condition-cost override, and compatibility boundary. Task 7 exposed that `cel-core = 0.5.1` rejects `list.contains(value)` despite the earlier plan wording; the supported CEL profile above now excludes it.

Acceptance/tests: direct/group/public/inherited access, compound rules, condition types, context precedence, missing context, and branch errors agree within the declared profile; mismatches block a compatibility claim. Concurrent checks isolate principals, tenants, and condition context; revocation is reflected by the next independent store session; store failures and cancellation/timeouts never run handlers. Tower readiness and cancellation regressions are covered. The pinned server run passed all 17 fixture cases. Verified with `cargo fmt --all -- --check`, `cargo check -p openfga-authz --all-targets`, `cargo check --workspace --all-targets --features openfga-authz/axum`, `cargo test --workspace --all-targets --features openfga-authz/axum`, `python3 openfga-authz/tools/openfga-differential.py` (17 cases), and `git diff --check`.

### Task 8 — [TODO] Publish a runnable example and complete feature validation

Dependencies: Task 7.

Files: `openfga-authz/examples/axum_authz.rs`, `openfga-authz/examples/authorization.fga`, `openfga-authz/README.md`, `openfga-authz/Cargo.toml`, this plan.

Provide a complete example beginning with `FgaAuthz::new`, explicit tuple insertion, authentication, derived middleware, and protected Axum routes. Show both a normal viewer check and a conditional grant with server-provided current time. Document input mappings, tuple ownership, errors, limits, and unsupported recursive/CEL features.

Acceptance/tests: example compiles and documented requests demonstrate allow and deny; `openfga_dsl` parser-only, `openfga-authz` core runtime, and `openfga-authz` with `axum` compile and pass their appropriate tests; rustdoc examples compile. Run `cargo fmt --check`, package/feature-specific `cargo check` and `cargo test`, and `cargo test --workspace --all-targets --all-features`. Run existing conformance tooling only when parser behavior is changed; record exact checks and results before marking the plan complete.

## 8. Completion criteria

The work is complete when an application can construct and validate `FgaAuthz` from a definition at startup, bind relationship data, obtain schema-checked middleware from it, register that middleware with Axum, and receive correct allow/deny behavior for the documented runtime profile. Invalid definitions fail before serving requests; runtime failures do not invoke protected handlers. Tests and compatibility fixtures substantiate the supported semantics.

Deferred extensions: recursive-model evaluation, additional CEL capabilities, modular-source constructors, remote OpenFGA checks, persistent decision caching, database store implementations, and body-based request extraction. These extensions must not be silently accepted by an implementation that cannot execute them.
