# OpenFGA syntax fixtures

Syntax fixtures live in `valid/` and `invalid/`. Every `.fga` source is paired
with same-stem `.json` metadata; fixture IDs match the file stems. The metadata
loader in `tests/conformance.rs` rejects unknown fields, missing pairs, duplicate
IDs, and malformed expected diagnostic spans. At this initial checkpoint, the
Rust test checks acceptance and verifies the typed error code and byte span for
rejected syntax fixtures.

Fixtures in this checkpoint exercise the canonical multiline header, direct
assignment, computed userset, tuple-to-userset, union, intersection, difference,
simple condition, unknown character, and missing header. All were executed
against the pinned grammar; `upstream-results.jsonl` records the runner output.
Task 2 adds grammar-derived lexer/parser fixtures for token priority, multiline
headers, module-name identifiers, and ASCII identifier boundaries.

The pinned grammar and reference checksums are in `upstream/`. Maintainer tooling
that executes the fixtures against the pinned grammar is in `../../../../tools/conformance/`.
