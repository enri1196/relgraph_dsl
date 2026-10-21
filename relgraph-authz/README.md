# `relgraph-authz`

`relgraph-authz` compiles an OpenFGA DSL model into a local authorization
runtime. The application provides authentication, relationship tuples, and
explicit mappings from request inputs to condition parameters. The optional
`axum` feature adds a Tower middleware layer for protected routes.

## In-memory quick start

The core crate works without PostgreSQL, Axum, or another external service.
Add `relgraph-authz` and a Tokio runtime to the application, then bind an
in-memory store to a compiled model:

```toml
[dependencies]
relgraph-authz = { version = "0.1", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use std::error::Error;

use relgraph_authz::{
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
deployments. Use a durable adapter such as `relgraph-authz-postgres` when
relationships must be shared across application processes or survive restarts.
The matching crate-level `no_run` example is compile-checked by
`cargo test -p relgraph-authz --doc` without running a Tokio runtime.

## Runnable Axum example

A complete Axum application that protects a route with `document#can_view`,
including a conditional grant, is documented in
[`examples/README.md`](examples/README.md). Run it with
`cargo run -p relgraph-authz --example axum_authz --features axum`.

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

For an ordinary route that checks a relation without request-sourced condition
values, the minimum policy is just the principal, tenant, and path object ID:

```rust
struct AuthenticatedPrincipal(Subject);
impl PrincipalIdentity for AuthenticatedPrincipal {
    fn subject(&self) -> &Subject { &self.0 }
}

struct AuthenticatedTenant(TenantId);
impl TenantIdentity for AuthenticatedTenant {
    fn tenant_id(&self) -> &TenantId { &self.0 }
}

let viewer = authz.middleware(
    RoutePolicy::new("document", "viewer")
        .principal(PrincipalSource::extension::<AuthenticatedPrincipal>())
        .tenant(TenantSource::extension::<AuthenticatedTenant>())
        .object_id(ObjectIdSource::path("document_id")),
)?;
let app = Router::new()
    .route("/documents/{document_id}", get(read_document))
    .route_layer(viewer);
```

The [runnable example](examples/README.md) has seven route/demo declarations: these two extension
types and their two identity trait implementations, its authentication
middleware, route handler, and `main`. Four declarations adapt the principal
and tenant; `ObjectIdSource::path` reads Axum's named path capture without an
application-defined path type. The existing authentication middleware inserts
the two trusted extensions before authorization runs. If an application
already defines compatible extension types and identity implementations, it
only needs the policy chain.

Add a `ContextBinding` only when a condition parameter must come from explicit
request or application context. Tuple-stored condition values need no route
binding. The bundled `can_view` demonstration binds `current_time` because its
`valid_grant` condition needs the current time; its grant time and duration are
already stored with the tuple. `ContextValueProvider::from_request_parts` and
`from_async` are for custom synchronous extraction or asynchronous resolution
of those request-context values. Registration checks the declared condition
parameter type, and runtime values are checked again with lossy numeric
conversions rejected.

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

Authorization errors remain distinct from a normal deny decision. Tuple reads
are processed in pages of at most 128 tuples, further limited by the remaining
tuple budget. Before membership is evaluated, every tuple in the fetched page
must pass ownership, condition-context, and relation-restriction validation.
An invalid tuple or preparation-budget error anywhere in that page defeats a
possible grant from the same page. Stores do not know the model, so write
through `FgaAuthz::write_tuple` and `delete_tuple` on a bound authorizer whose
store implements `RelationshipWriteStore`, or call `FgaAuthz::validate_tuple`
before writing directly. Validation applies the same model checks (object
type, relation, declared subject targets and conditions, and stored context
types) and rejects tuples that would make such checks fail with
`WriteError::Validation`; the tenant check and store outcomes, including
`Conflict` for a duplicate, are `WriteError::Store`. `FgaAuthz::apply_changes`
validates every tuple of a change set, then applies its deletions and
insertions atomically through `RelationshipWriteStore::apply_changes`: the
in-memory store publishes one snapshot and PostgreSQL commits one transaction.
A missing deletion or a duplicate insertion returns `Conflict` and applies
nothing; deleting and re-inserting a tuple in one set replaces its condition
context. These wrappers validate
against the bound model only: they do not authorize the caller to write, so
the application still decides who may create or remove a relationship. Checks
fail closed on a stored tuple that no longer fits the model after a model
change; remove such a tuple through the store directly, because the validating
delete rejects it too.
For a tuple-to-userset relation, tupleset targets whose type does not define
the computed relation cannot grant and are skipped.

After a page passes preparation, tuples are evaluated in returned order. A
successful membership check and any applicable true condition grant access
immediately, so the evaluator does not request a later page. A malformed tuple
or store error that exists only in an unrequested later page cannot defeat that
grant. Without a grant, evaluation continues through the required pages and
propagates a requested store error. A membership or condition evaluation error
can be masked by a later grant; if evaluation reaches the end without a grant,
it returns the first such error or a normal deny. For a corrupt custom store,
the decision can therefore depend on its page boundaries; the evaluator does
not scan later pages as an integrity check. This behavior makes no
upstream-equivalence claim for malformed custom-store results. The protected
handler runs only after an allow.

`EvaluationLimits::default()` bounds each check to 10,000 tuples scanned, 25
relation traversal steps (OpenFGA's default resolve depth), 1,024 store page reads, and 100,000 expression/tuple
work units, and bounds each condition evaluation to an estimated CEL cost of
100. Applications can configure these limits when binding a store; the
condition-cost limit can be raised up to 100,000. A condition's estimated cost
counts its expression nodes, its input values (one unit per scalar or
collection entry, one per 10 string bytes), and `matches` calls (input string
cost times one unit per 4 pattern bytes), after the cost factors used by
cel-go. Condition contexts accepted by the in-memory and PostgreSQL stores are
limited to 65,536 serialized JSON bytes and 10,000 collection entries; the same
limits apply to each custom-store context and request value during evaluation.
Request values are converted once per check or batch. Context conversion and every
condition evaluation, including failed attempts, also consume the check's work
budget, which bounds condition work across the whole check.
Tuple, store-call, and work budgets are shared across nested traversals.
Every tuple in a fetched page counts against the tuple and work budgets, even
when an earlier tuple in that page grants access. Each active traversal holds
at most one tuple page and its prepared metadata, plus bounded cursor history;
parent pages can remain live while nested checks run. Backend snapshot memory
is outside this bound. These local budgets bound this runtime's work and do not
claim to reproduce OpenFGA server CEL cost accounting.

## Batch checks

`batch_check` evaluates many `(object, relation)` pairs for one tenant, subject,
and request context in one read session:

```rust,no_run
use relgraph_authz::{
    AuthorizationDecision, BatchCheckRequest, EvaluationLimits, FgaAuthz,
    InMemoryRelationshipStore, ObjectRef, RelationName, Subject, TenantId,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let authorizer = FgaAuthz::new(
    "model\n  schema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n",
)?
.with_store(InMemoryRelationshipStore::new(), EvaluationLimits::default());
let viewer = RelationName::new("viewer")?;
let request = BatchCheckRequest::new(
    TenantId::new("acme")?,
    Subject::new("user", "anne")?,
    [
        (ObjectRef::new("document", "1")?, viewer.clone()),
        (ObjectRef::new("document", "2")?, viewer),
    ],
);
for result in authorizer.batch_check(&request).await? {
    let _allowed = result? == AuthorizationDecision::Allow;
}
# Ok(())
# }
```

Results follow item order. Every item reads the same snapshot, so a write made
while the batch runs is not observed by later items, and items share memoized
relation decisions (for example a group membership or parent folder reached by
several items) and converted request values. An item's error, including an
unknown object type or relation, stays in that item's result; the outer error
reports a batch larger than `max_batch_items`, an unknown subject type or
userset relation, invalid contextual tuples, or a failure to open the read
session. Each item gets fresh tuple, store-call, and
work budgets. A memoized decision spends no budget, so an item can succeed in a
batch where a separate check would exceed a limit. `max_batch_items` defaults
to 100 and accepts up to 1,000. `filter_objects(tenant, subject, relation,
candidates)` runs one batch without request context or contextual tuples and
returns the allowed
candidates and per-candidate errors separately; candidates may mix object types
that define the relation. A durable store may hold one connection and
transaction for the whole batch.

## Listing objects

`list_objects` answers OpenFGA's ListObjects: the objects of one type on which
a subject holds a relation, sorted by object ID. It needs a store whose read
session implements `ReverseLookupSession` (`ReverseLookupStore` is implemented
for every such store); the in-memory store does. Check-only stores are
unaffected. The same example is compile-checked in the `list_objects`
documentation:

```rust,no_run
use relgraph_authz::{
    EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ListObjectsRequest,
    ObjectRef, RelationName, RelationshipTuple, Subject, TenantId, TypeName,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let tenant = TenantId::new("acme")?;
let anne = Subject::new("user", "anne")?;
let store = InMemoryRelationshipStore::new();
for id in ["2", "1"] {
    store.insert(RelationshipTuple::new(
        tenant.clone(),
        ObjectRef::new("document", id)?,
        RelationName::new("editor")?,
        anne.clone(),
    ))?;
}
let authorizer = FgaAuthz::new(
    "model\n  schema 1.1\ntype user\ntype document\n  relations\n    define editor: [user]\n    define viewer: [user] or editor\n",
)?
.with_store(store, EvaluationLimits::default());

let request = ListObjectsRequest::new(
    tenant,
    anne,
    TypeName::new("document")?,
    RelationName::new("viewer")?,
);
let objects = authorizer.list_objects(&request).await?;
assert_eq!(
    objects,
    [ObjectRef::new("document", "1")?, ObjectRef::new("document", "2")?]
);
# Ok(())
# }
```

The list does not reimplement the check. A reverse traversal from the subject
finds candidates: tuples naming the subject (and, for a concrete subject, its
type's wildcard) through `ReverseLookupSession::tuples_by_subject_page`, a
userset subject's own key, and then, to a fixpoint, the same-object relations
that compute a reached relation (union and intersection operands, the base of
a difference), tuples naming a reached userset, and tupleset tuples naming a
reached object. Contextual tuples are read as extra edges; stored tuples are
validated before they are followed, so one that drifted from the model fails
the list. Conditions never prune candidates. Each candidate is then decided by
the check evaluator on the same read session, sharing memoized decisions as a
batch does, so subjects, wildcards, usersets, contexts and the
error-versus-deny rules are exactly those of `check`. Denied candidates are
omitted.

A list never returns a partial result. Any candidate's check error fails it,
and so does a hit on any limit: more distinct candidates than
`EvaluationLimits::max_list_candidates` (default 1,000, at most 10,000;
`AuthorizationError::ListCandidateLimitExceeded`), or a tuple, store-call,
depth or work budget. The traversal has one set of those budgets and each
candidate's check has its own. An unknown object type, relation or subject
fails as it does for `check`. Unlike `check`, a list drops an exact repeat
among its contextual tuples instead of rejecting it, as OpenFGA's ListObjects
does. Both bundled stores implement reverse lookup: the in-memory store scans
its snapshot, and `relgraph-authz-postgres` pages by `tuple_id` over its
`MIGRATION_0002` subject index.

## Listing users

`list_users` answers OpenFGA's ListUsers: the subjects selected by one filter
that hold a relation on one object, sorted by type, ID (a typed wildcard as
`*`) and userset relation. It needs only a `RelationshipStore`, no reverse
lookup. The filter is a `UserFilter`: a type (`user`, built with
`UserFilter::new` or parsed from `"user"`) or a userset relation
(`group#member`, `UserFilter::userset` or `"group#member"`). Parsing rejects
any other form, such as `user:anne`, `user:*` or `a#b#c`, with
`UserFilterError`; a filter type or relation absent from the model fails with
`AuthorizationError::UnknownSubjectType` or `UnknownSubjectRelation`. The same
example is compile-checked in the `list_users` documentation:

```rust,no_run
use relgraph_authz::{
    EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ListUsersRequest, ObjectRef,
    RelationName, RelationshipTuple, Subject, TenantId, TupleSubject, TypeName,
    UserFilter,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let tenant = TenantId::new("acme")?;
let document = ObjectRef::new("document", "1")?;
let store = InMemoryRelationshipStore::new();
store.insert(RelationshipTuple::new(
    tenant.clone(),
    document.clone(),
    RelationName::new("editor")?,
    Subject::new("user", "bob")?,
))?;
store.insert(RelationshipTuple::new(
    tenant.clone(),
    document.clone(),
    RelationName::new("viewer")?,
    TupleSubject::TypedWildcard(TypeName::new("user")?),
))?;
let authorizer = FgaAuthz::new(
    "model\n  schema 1.1\ntype user\ntype document\n  relations\n    define editor: [user]\n    define viewer: [user, user:*] or editor\n",
)?
.with_store(store, EvaluationLimits::default());

let request = ListUsersRequest::new(
    tenant,
    document,
    RelationName::new("viewer")?,
    "user".parse::<UserFilter>()?,
);
let users = authorizer.list_users(&request).await?;
assert_eq!(
    users,
    [
        TupleSubject::TypedWildcard(TypeName::new("user")?),
        Subject::new("user", "bob")?.into(),
    ]
);
# Ok(())
# }
```

As for ListObjects, the list does not reimplement the check. A forward
expansion from the object finds candidates with `tuples_page`, following to a
fixpoint the operands that can grant (union and intersection operands, the
base of a difference, never its subtracted operand): computed usersets on the
same object, the usersets that assignment tuples name, and the
tuple-to-userset targets that tupleset tuples name. A type filter collects the
concrete subjects and typed wildcards of its type that assignment tuples name.
A subject granted only through a wildcard tuple is therefore listed as the
wildcard (`user:*`), not by ID, as upstream does. A userset filter collects
every reached userset of its relation, including the object's own userset when
the filter names the listed relation (`group:eng#member` is a `member` of
`group:eng`). Contextual tuples are read as extra edges, stored tuples are
validated before they are followed, and conditions never prune candidates.

A check scope fixes one subject, so each candidate is decided by its own check
evaluator on the one read session: wildcards, usersets, contexts and the
error-versus-deny rules are exactly those of a separate `check` with that
subject. Denied candidates are omitted. The limits and failure rules are those
of `list_objects`: no partial result, one budget set for the expansion, one
per candidate decision, at most `max_list_candidates` distinct candidates, and
exact repeats among the contextual tuples dropped.

Because each candidate's decision is a check, a decisive allow masks an error
in another branch, as in `check`. Upstream ListUsers instead reports a missing
condition parameter from any branch it expands, even where upstream Check
allows the same inputs, so for such inputs Relgraph lists the subject and
OpenFGA errors (two ABAC corpus cases). Whether ListUsers should follow
upstream here awaits a maintainer decision (`SKIP_LIST_PLAN.md` Task 8).

## Userset and wildcard check subjects

`CheckRequest::new` and `BatchCheckRequest::new` take any `TupleSubject`. A
concrete `Subject` converts into one, so the usual call is unchanged. As in
OpenFGA's Check, the subject may also be a userset or a typed wildcard:

- A userset subject (`group:eng#member`) is allowed by a tuple naming that
  exact userset, by membership of another userset (a tuple
  `group:staff#member@group:eng#member`), through computed usersets and
  tuple-to-userset as usual, and on its own object and relation
  (`group:eng#member` is a `member` of `group:eng`, OpenFGA's
  `IsSelfDefining`). A wildcard tuple never allows it.
- A wildcard subject (`user:*`) is allowed only by a wildcard tuple of its
  type, directly or through a userset; a tuple for a concrete user never
  allows it.

An unknown subject type fails with `AuthorizationError::UnknownSubjectType`
and a userset relation its type does not define with
`AuthorizationError::UnknownSubjectRelation` (the outer error of a batch).
These subjects answer questions such as "can every member of this group view
the document?". The Axum middleware and `RoutePolicy` always check the
authenticated principal as a concrete subject.

## Contextual tuples

`CheckRequest::with_contextual_tuples` and
`BatchCheckRequest::with_contextual_tuples` add relationship tuples that exist
only for that check or batch, like OpenFGA's `contextual_tuples`. They are
read together with the stored tuples of the request's tenant snapshot and are
never written. The same example is compile-checked in the
`CheckRequest::with_contextual_tuples` documentation:

```rust,no_run
use relgraph_authz::{
    CheckRequest, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore,
    ObjectRef, RelationName, RelationshipTuple, Subject, TenantId,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let authorizer = FgaAuthz::new(
    "model\n  schema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype document\n  relations\n    define viewer: [group#member]\n",
)?
.with_store(InMemoryRelationshipStore::new(), EvaluationLimits::default());
let tenant = TenantId::new("acme")?;
let anne = Subject::new("user", "anne")?;
// Membership asserted by the application for this check only, for example
// from the authenticated user's verified identity-provider groups.
let membership = RelationshipTuple::new(
    tenant.clone(),
    ObjectRef::new("group", "eng")?,
    RelationName::new("member")?,
    anne.clone(),
);
let request = CheckRequest::new(
    tenant,
    anne,
    ObjectRef::new("document", "42")?,
    RelationName::new("viewer")?,
)
.with_contextual_tuples([membership]);
let _decision = authorizer.check(request).await?;
# Ok(())
# }
```

**Trust boundary.** Contextual tuples are facts the caller asserts, with the
same authority as a stored tuple: whoever controls them controls the decision.
Build them only from trusted application state, never directly from
unauthenticated request input. The Axum middleware and `RoutePolicy` have no
way to fill them from an HTTP request (no `ContextBinding` source exists for
them), and `filter_objects` never carries any; an application that needs them
calls `check`, `batch_check`, `list_objects` or `list_users` itself.

Validation happens once per check or batch, after the request's object,
relation and subject type are resolved and before the store is read. The whole
request fails with `AuthorizationError::ContextualTupleLimitExceeded` for more
than `MAX_CONTEXTUAL_TUPLES` (100, OpenFGA's limit at `v1.21.0`), or with
`AuthorizationError::InvalidContextualTuple { index, reason }` for the first
tuple (in request order) that names another tenant, fails
`FgaAuthz::validate_tuple` (the error is kept in `ContextualTupleError::Model`),
or exactly repeats an earlier contextual tuple. In a batch these are outer
errors. OpenFGA has no tenants and accepts repeated contextual tuples; Relgraph
rejects both, except that `list_objects` and `list_users` drop a repeat.

During evaluation, a relation's contextual tuples are read before its stored
tuples, and a stored tuple equal to a contextual one (the same tenant, object,
relation, subject and condition context) is read only once. Contextual tuples
count toward the tuple-scan and work budgets like stored tuples but use no
store call. A contextual tuple's condition context is tuple context: it keeps
precedence over condition-scoped and global request context. A batch shares
its contextual tuples, memoized decisions and converted request values across
items; requests with different contextual tuples never share memoized
decisions.

## Construction cost measurements

The parser's construction guards bound three different model shapes: 128
nested parentheses, 512 expression or target units in one relation, and 4,096
declarations across a model. The expression-unit limit constrains the input
shape presented to the recursive compiler; it is not a general compiler-stack
guarantee. The declaration limit bounds model-wide index volume independently
of the per-relation limit.

On the measured macOS Apple M1 host, all ten accepted construction workloads
compiled and dropped in isolated child processes in both debug and release
profiles. This includes a left-deep relation at the 512-unit boundary and
`nested_128`, whose 128 parentheses produce only two expression units. The
`wide_indexes_2047` case compiled a model with 2,047 independent relations and
4,095 declarations; `repeated_128` compiled 128 relations with 512 units each
and 65,663 compiled expressions. Union and intersection workloads use a
distinct `[user]` relation per computed-userset operand, because validation
rejects a repeated operand as OpenFGA does. These stress results apply to the
tested workloads and host.

Across three release runs, full-construction medians for `union_exact_512`
were 450,542 / 444,708 / 445,584 ns; `wide_indexes_2047` measured
3,445,000 / 3,498,417 / 3,724,417 ns; and `repeated_128` measured
16,830,666 / 16,799,333 / 16,890,042 ns. Their measured whole-process peak
RSS was 10,469,376, 17,383,424, and 239,321,088 bytes, respectively. The
`union_exact_512` and `repeated_128` figures were remeasured after the
distinct-operand change (2026-10-18); `wide_indexes_2047` is unchanged. RSS
includes the test harness, fixture preparation, and all measurement phases;
it is not an index allocation or live evaluator measurement. Linux x86_64 was
not measured, and the workspace declares no MSRV, so these observations make
no general platform-support claim.

The ignored measurement test can be run for the exact-limit union case with:

```sh
RELGRAPH_CONSTRUCTION_COST_CASE=union_exact_512 cargo test -p relgraph-authz --release --lib authz::model::construction_costs::measure_construction_costs -- --ignored --exact --nocapture --test-threads=1
```

The timings are descriptive construction observations; they do not set a latency target or claim runtime
authorization speed.

## Supported runtime profile

The runtime supports all six relation-expression forms represented by the
parser, including recursive models such as nested groups
(`define member: [user, group#member]`), same-type hierarchies
(`define viewer: [user] or viewer from parent`), and mutual recursion across
types. Recursive relations are evaluated as least fixed points: a relationship
cycle in the stored data (group A in B in A) denies a non-member without an
error. Construction rejects two cyclic shapes with a capability diagnostic:

- `RecursiveDifference`: a cycle through the subtracted operand of `but not`.
  Assume-false evaluation is unsound under negation. OpenFGA v1.21.0 accepts
  these models when the cycle crosses a tuple-to-userset or userset hop, but it
  then answers data cycles inconsistently (both `viewer` and `blocked` deny on
  the same object).
- `SameObjectRelationCycle`: relations on one object that depend on each other
  only through computed usersets, such as `define a: b or x` with
  `define b: a or y`. OpenFGA rejects these models too.

Cycles through union, intersection, a difference's base operand, userset
restrictions, and tuple-to-userset are accepted. Within one check or batch, `true`
results are memoized immediately. A `false` result inside an open cycle stays
provisional until the cycle's first-entered relation finishes, and then the
whole cycle is memoized as `false`. Errors are never memoized. Work that is
discarded and repeated stays within the check's work budget. These rules are
separate from parser acceptance.

The pinned CEL implementation is `cel-core = 0.5.1`. The supported condition
types are `bool`, `int`, `uint`, `double`, `string`, `duration`, `timestamp`,
`ipaddress`, and one-level `list<T>` or `map<T>` containers over those scalar
types (map keys are strings). Timestamps use RFC3339, durations use CEL/OpenFGA
duration strings, and IP addresses are strings. The expression profile includes
boolean, numeric, and string comparisons and arithmetic; field and index
access; `has`, `size`, `startsWith`, `endsWith`, and `matches`; and scalar/time
conversions `int`, `uint`, `double`, `string`, `bytes`, `duration`, and
`timestamp`.

OpenFGA's `ipaddress` extension is implemented locally on top of `cel-core`
(plan Decision D1), following `internal/condition/types/ipaddress.go` at
OpenFGA `v1.21.0`. Every condition can use `ipaddress(string)`,
`<ipaddress>.in_cidr(string)`, and `==` / `!=` between addresses (also through
`in` on a `list<ipaddress>`). Addresses are unmapped, so `::ffff:192.0.2.1`
equals `192.0.2.1` and matches IPv4 CIDRs. A CIDR may have host bits set; its
prefix length is decimal without a sign or leading zero; an IPv4-mapped IPv6
prefix of at least 96 bits is treated as the matching IPv4 prefix; IPv4
addresses never match IPv6 prefixes and vice versa. A malformed address in a
context is `InvalidConditionContext`, a malformed `ipaddress(...)` argument or
CIDR is `ConditionEvaluationFailed`, and a missing value is
`MissingConditionContext`. The `ipaddress.json` differential fixture checks
these decisions against the pinned server. One difference is deliberate: IPv6
zone identifiers such as `fe80::1%eth0` are rejected as malformed, while
OpenFGA parses them (a zoned address there matches no CIDR unless it is
IPv4-mapped). For condition cost, an address counts like its source string and
each extension call like any other expression node; there is no OpenFGA cost
parity.

Inline condition expressions (`define viewer: [user with $expression]`,
decision S3) follow OpenFGA `v1.21.0` (`internal/condition/inline.go`). A
tuple for such a restriction has the condition name `$expression` and a
context with two keys: `expression`, the CEL source (a non-empty string), and
the optional `parameters`, a map from parameter name to type name such as
`int` or `list<string>`. An identifier the expression uses without declaring
it is a `string` parameter, as upstream infers. The expression is compiled with
the same profile, `bool` result rule and cost estimate as a model condition:
when `validate_tuple` / `write_tuple` checks the tuple, and on first use in a
check or batch, which caches each distinct source for the rest of that check
or batch. A malformed context, a type outside the profile, or an expression
that does not compile to `bool` is `InvalidTuple`, both on write and as a
strict read error. Parameter values come from the request (global context, or
condition-scoped context under `$expression`); the stored context holds none,
and any key other than `expression` and `parameters` is rejected (upstream
ignores extra keys). The stored-context byte and element limits apply as for
named conditions. Tuples that differ only in expression or parameter types are
distinct tuples. `requirements` reports an inline restriction as the condition
`$expression` with no parameters, and a `ContextBinding` cannot name it.

`list.contains(value)` is not supported by the pinned compiler. Bytes as
declared values, `any`, nested containers, custom/message types, other
extension functions, and comprehension macros are rejected during model
construction. Parser support for a syntax form does not imply that the local
authorization runtime can execute it. The pinned checker is also more
permissive than OpenFGA's in one known way: it accepts `==` / `!=` between
operands of unrelated types (verified for an `ipaddress` and a string, and for
an `int` and a string), which OpenFGA rejects when the model is written;
locally an address compared with a string is simply unequal.

## Permanent differences from OpenFGA

These differences are deliberate and are not planned to change. Each one is a
`task: permanent` entry in the Check corpus skip list
([`tests/fixtures/authz/upstream-skip.yaml`](tests/fixtures/authz/upstream-skip.yaml));
the [fixtures README](tests/fixtures/authz/README.md#upstream-check-corpora)
gives the measured case counts at OpenFGA `v1.21.0`.

- **Negation cycles.** Construction rejects a dependency cycle through the
  subtracted operand of `but not` (`RuntimeCapability::RecursiveDifference`),
  which OpenFGA accepts when the cycle crosses a userset or tuple-to-userset
  hop. The evaluator's least-fixed-point memoization is sound only because
  such cycles never reach it (see
  [Supported runtime profile](#supported-runtime-profile)). Corpus impact:
  three models, their checks and list assertions (29 cases).
- **Strict reads of tuples that no longer fit the model.** When a stored tuple
  stops matching the current model (its type restriction, condition or
  tupleset target was removed), OpenFGA silently ignores it during Check;
  Relgraph reports `AuthorizationError::InvalidTuple`, so drift is visible
  instead of changing decisions. Repair goes through the store directly.
  The list APIs decide candidates with the same check, so they fail the same
  way. Corpus impact: 24 checks and 18 list assertions in multi-stage tests
  that change the model after writing tuples.

Two smaller deliberate differences have no corpus case: contextual tuples are
checked against the request tenant and an exact repeat is rejected (see
[Contextual tuples](#contextual-tuples)).

## Feature checks

The parser crate has no authorization, Axum, or CEL runtime dependency. The
authorization crate's core runtime is available without default features;
Axum integration is enabled explicitly:

```sh
cargo check -p relgraph_dsl --all-targets
cargo test -p relgraph_dsl --all-targets
cargo check -p relgraph-authz --all-targets
cargo test -p relgraph-authz --all-targets
cargo check -p relgraph-authz --all-targets --features axum
cargo test -p relgraph-authz --all-targets --features axum
cargo test --workspace --doc --all-features
```
