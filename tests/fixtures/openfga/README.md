# OpenFGA syntax fixtures

Syntax fixtures live in `valid/` and `invalid/`. Every `.fga` source is paired
with same-stem `.json` metadata; fixture IDs match the file stems. The metadata
loader in `tests/conformance.rs` rejects unknown fields, missing pairs, duplicate
IDs, and malformed expected diagnostic spans. At this initial checkpoint, the
Rust test checks acceptance and verifies the typed error code and byte span for
rejected syntax fixtures.

Fixtures in the initial checkpoint exercise the canonical multiline header,
direct assignment, computed userset, tuple-to-userset, union, intersection,
difference, simple condition, unknown character, and missing header. Those were
executed against the pinned grammar; `upstream-results.jsonl` records the runner
output. Task 2 adds grammar-derived lexer/parser fixtures for token priority,
multiline headers, module-name identifiers, and ASCII identifier boundaries.

Task 3 adds grammar-derived fixtures for numeric version spellings, header-only
documents, declaration order/comments, module identifiers and extensions,
restriction-list boundaries, homogeneous rewrite chains, grouping, and
newline-sensitive declaration structure. Its fixtures have not yet been
executed by the pinned Java runner; they remain `grammar-derived` until Task 10.

The pinned grammar and reference checksums are in `upstream/`. Maintainer tooling
that executes the fixtures against the pinned grammar is in `../../../../tools/conformance/`.
