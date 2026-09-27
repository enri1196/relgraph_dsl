# `openfga-authz`

`openfga-authz` compiles an OpenFGA DSL model into a local authorization
runtime. The application provides authentication, relationship tuples, and
explicit mappings from request inputs to condition parameters. The optional
`axum` feature adds a Tower middleware layer for protected routes.

## In-memory quick start

The core crate works without PostgreSQL, Axum, or another external service.
Add `openfga-authz` and a Tokio runtime to the application, then bind an
in-memory store to a compiled model:

```toml
[dependencies]
openfga-authz = { version = "0.1", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use std::error::Error;

use openfga_authz::{
    CheckRequest, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore,
    ObjectRef, RelationName, RelationshipTuple, Subject, TenantId,
};

const MODEL: &str = r#"
model
  schema 1.1

type user

type document
  relations
    define viewer: [user]
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new("acme")?;
    let subject = Subject::new("user", "anne")?;
    let object = ObjectRef::new("document", "42")?;
    let relation = RelationName::new("viewer")?;

    let store = InMemoryRelationshipStore::new();
    store.insert(RelationshipTuple::new(
        tenant.clone(),
        object.clone(),
        relation.clone(),
        subject.clone(),
    ))?;

    let authorizer = FgaAuthz::new(MODEL)?
        .with_store(store, EvaluationLimits::default());
    let request = CheckRequest::new(tenant, subject, object, relation);
    let _decision = authorizer.check(request).await?;
    Ok(())
}
```

The in-memory store is suitable for tests, examples, and small local
deployments. Use a durable adapter such as `openfga-authz-postgres` when
relationships must be shared across application processes or survive restarts.
The matching crate-level `no_run` example is compile-checked by
`cargo test -p openfga-authz --doc` without running a Tokio runtime.

## Runnable Axum example

Run the example with:

```sh
cargo run -p openfga-authz --example axum_authz --features axum
```

It listens on `127.0.0.1:3000`. The example embeds
[`examples/authorization.fga`](examples/authorization.fga), inserts an
unconditional `viewer` tuple for Anne and a 30-minute `time_limited_viewer`
tuple for Bob, then protects `GET /documents/{document_id}` with a policy for
`document#can_view`. Its authentication middleware maps the fixed demo tokens
to trusted `Subject` and `TenantId` extensions; callers cannot select an
arbitrary subject ID.

Try the normal viewer grant:

```sh
curl -i -H 'Authorization: Bearer anne-demo' \
  http://127.0.0.1:3000/documents/42
```

Try Bob's conditional grant while it is active:

```sh
curl -i -H 'Authorization: Bearer bob-demo' \
  http://127.0.0.1:3000/documents/42
```

Both requests return `200 OK`. A subject without a tuple is denied:

```sh
curl -i -H 'Authorization: Bearer anne-demo' \
  http://127.0.0.1:3000/documents/99
```

That request returns `403 Forbidden`; a missing or unrecognized demo token
returns `401 Unauthorized`. The example's hard-coded tokens and in-memory
store are for demonstration. Replace them with the application's authentication
and relationship-store implementations.

## Input mapping and tuple ownership

The model defines the possible relationships; it does not grant access by
itself. The example explicitly inserts `(user:anne, viewer, document:42)` and
`(user:bob, time_limited_viewer, document:42)`. A production relationship
store owns and returns these grants. Every tuple is scoped to the trusted
tenant selected by the application; tenant scope is not itself proof of a
relationship.

The route policy fixes `document` and `can_view`, gets the document ID from the
named `document_id` path capture, and obtains the principal and tenant from
authentication extensions. It binds only
`valid_grant.current_time` as request context, using the server's current UTC
time for each check. The conditional tuple stores `grant_time` and
`grant_duration` under the `valid_grant` condition. Tuple context takes
precedence over request context; request bindings can fill missing condition
values but cannot replace stored grant values. The body is not read for
authorization.

Use `ContextBinding` for each condition and parameter whose value comes from
trusted request or application state. Its `ContextValueProvider` declares the
expected schema type at route registration. Registration rejects unknown
relations, undeclared parameters, and provider type mismatches. Runtime values
are checked again and lossy numeric conversions are rejected.

## Errors and execution limits

`FgaAuthz::new` parses the model, runs semantic and runtime capability checks,
and compiles its conditions before the application starts serving requests.
Construction errors identify invalid or unsupported models. Authorization
middleware responds with:

| Result | HTTP status |
| --- | ---: |
| No matching relationship | `403 Forbidden` |
| Missing authenticated principal | `401 Unauthorized` |
| Invalid path ID or request-bound condition input | `400 Bad Request` |
| Relationship-store failure or exhausted evaluation budget | `503 Service Unavailable` |
| Invalid trusted server state or internal failure | `500 Internal Server Error` |

Authorization errors remain distinct from a normal deny decision. A failed
store read, malformed tuple, missing applicable condition value, or exhausted
budget cannot become an allow. The protected handler runs only after an allow.

`EvaluationLimits::default()` bounds each check to 10,000 tuples scanned, 64
relation traversal steps, 1,024 store page reads, 100,000 expression/tuple work
units, and CEL condition cost 100. Applications can configure these limits
when binding a store; the condition-cost limit can be raised up to 100,000.
These local budgets bound this runtime's work and do not claim to reproduce
OpenFGA server CEL cost accounting.

## Supported runtime profile

The runtime supports all six relation-expression forms represented by the
parser, on acyclic relation dependencies. Cyclic or recursive model dependencies
are rejected during construction with an unsupported-recursion diagnostic;
fixed-point recursive evaluation is not implemented. This restriction is
separate from parser acceptance.

The pinned CEL implementation is `cel-core = 0.5.1`. The supported condition
types are `bool`, `int`, `uint`, `double`, `string`, `duration`, `timestamp`,
and one-level `list<T>` or `map<T>` containers over those scalar types (map
keys are strings). Timestamps use RFC3339 and durations use CEL/OpenFGA
duration strings. The expression profile includes boolean, numeric, and string
comparisons and arithmetic; field and index access; `has`, `size`,
`startsWith`, `endsWith`, and `matches`; and scalar/time conversions `int`,
`uint`, `double`, `string`, `bytes`, `duration`, and `timestamp`.

`list.contains(value)` is not supported by the pinned compiler. Bytes as
declared values, `any`, IP addresses, nested containers, custom/message types,
extension functions, and comprehension macros are rejected during model
construction. Parser support for a syntax form does not imply that the local
authorization runtime can execute it.

## Feature checks

The parser crate has no authorization, Axum, or CEL runtime dependency. The
authorization crate's core runtime is available without default features;
Axum integration is enabled explicitly:

```sh
cargo check -p openfga_dsl --all-targets
cargo test -p openfga_dsl --all-targets
cargo check -p openfga-authz --all-targets
cargo test -p openfga-authz --all-targets
cargo check -p openfga-authz --all-targets --features axum
cargo test -p openfga-authz --all-targets --features axum
cargo test --workspace --doc --all-features
```
