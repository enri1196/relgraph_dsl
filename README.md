# Relgraph

Relgraph is an independent, Rust implementation of parts of the OpenFGA
language and authorization model. It provides a parser and semantic validator
for `.fga` models, a local authorization runtime that evaluates relationship
tuples and CEL conditions, an optional Axum middleware integration, and a
PostgreSQL-backed relationship store.

Relgraph aims for compatibility with OpenFGA model syntax and authorization
semantics within the documented feature profile. Compatibility is partial and
version-specific: the parser and runtime document their supported behavior and
limitations, and parser acceptance alone does not mean the runtime can execute
every model. This project is not affiliated with, endorsed by, or sponsored by
the OpenFGA project or its maintainers. OpenFGA is referenced only to describe
the compatibility target.

## Crates

- `relgraph-dsl` parses, validates, and loads single-file or modular `.fga`
  models.
- `relgraph-authz` compiles supported models and checks whether a subject may
  access an object through a relationship store. It includes an in-memory
  store and optional Axum middleware.
- `relgraph-authz-postgres` implements the relationship-store interfaces on
  PostgreSQL.

See each crate's README and API documentation for usage, supported features,
and runtime limits.

## Application examples

The [Drive API](examples/drive-api/README.md) is a runnable Axum application
demonstrating workspace, folder, and file permissions, team sharing, inherited
access, revocation, and revision-checked editing. Run `cargo run -p drive-api`.
