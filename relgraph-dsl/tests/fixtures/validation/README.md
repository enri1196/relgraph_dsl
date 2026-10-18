# Semantic validation fixtures

- `valid/forward-references.fga` verifies that type, relation, and condition
  references resolve even when declarations appear later.
- `valid/cyclic.fga` records the validator's cycle boundary: a cycle with an
  entry point (`[user] or second`) passes static validation, although the
  authorization runtime rejects this same-object cycle at construction.
- `invalid/no-entry-point-cycle.fga` is a cycle without an entry point; every
  relation in it is reported as `NoEntryPoint`, as OpenFGA does.
- `invalid/reference-cascade.fga` verifies deterministic diagnostics and
  suppression of dependent errors after a missing type or tupleset.

These fixtures exercise crate validation policy. They are not parser-grammar
conformance fixtures.
