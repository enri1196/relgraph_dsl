# Semantic validation fixtures

- `valid/forward-references.fga` verifies that type, relation, and condition
  references resolve even when declarations appear later.
- `valid/cyclic.fga` records the bounded validator's intentional cycle
  boundary: a locally resolved cycle passes static validation.
- `invalid/reference-cascade.fga` verifies deterministic diagnostics and
  suppression of dependent errors after a missing type or tupleset.

These fixtures exercise crate validation policy. They are not parser-grammar
conformance fixtures.
