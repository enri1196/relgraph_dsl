# Relgraph

Relgraph is an independent, Rust implementation of parts of the OpenFGA
language and authorization model. It provides a parser and semantic validator
for `.fga` models, a local authorization runtime that evaluates relationship
tuples and CEL conditions, an optional Axum middleware integration, and a
PostgreSQL-backed relationship store.

Compatibility with OpenFGA is partial, version-specific and measured: parser
acceptance, semantic validity and runtime support are separate claims, and
parser acceptance alone does not mean the runtime can execute every model.
This project is not affiliated with, endorsed by, or sponsored by the OpenFGA
project or its maintainers. OpenFGA is referenced only to describe the
compatibility target.

## Measured compatibility

OpenFGA's own test corpora are vendored unmodified and replayed offline by
`cargo test` (`relgraph-dsl` target `upstream_corpus`, `relgraph-authz` target
`upstream_check`). Every case that does not pass has a reviewed skip-list
entry with a reason; the tests fail on an unlisted failure and on a stale
entry. Measured on 2026-10-18:

| Corpus (pin) | Cases | Pass | Not passing, by reason |
| --- | ---: | ---: | --- |
| `openfga/language` syntax cases (`fbc6298`) | 81 | 79 | 2 deliberate |
| `openfga/language` semantic cases (`fbc6298`) | 93 (7 skipped upstream) | 84 | 2 deliberate |
| `openfga/language` `fga.mod` cases (`fbc6298`) | 10 | 9 | 1 unsupported (JSON model output) |
| `openfga/openfga` `consolidated_1_1_tests.yaml` (`v1.21.0`) | 1380 | 767 | 569 ListObjects/ListUsers (no list API), 36 deliberate, 8 userset/wildcard check subjects |
| `openfga/openfga` `abac_tests.yaml` (`v1.21.0`) | 505 | 261 | 179 ListObjects/ListUsers, 51 inline conditions, 7 `ipaddress`, 3 deliberate, 4 userset check subjects |

Counting only Check, `ctxCheck` (upstream's contextual-tuple replay) and model
cases, the Check corpora pass 767 of 811 and 261 of 326. The per-corpus tables
and every skip reason are in
[`relgraph-dsl/tests/fixtures/openfga/README.md`](relgraph-dsl/tests/fixtures/openfga/README.md#upstream-language-corpora)
and
[`relgraph-authz/tests/fixtures/authz/README.md`](relgraph-authz/tests/fixtures/authz/README.md#upstream-check-corpora);
the deliberate differences are listed in the `relgraph-authz` README.

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
