# Manifest fixtures

These YAML samples exercise manifest-only parsing. The parser does not open the
listed files.

- `ordered.yaml` keeps manifest entry order and accepts paths containing spaces.
- `aliases.yaml` accepts YAML anchors on the schema, the contents list and an
  entry. A resolved alias is checked like the value it names; the alias case is
  in `tests/manifest.rs`, because a valid manifest cannot reuse a value (the
  schema is not a `.fga` path and repeated paths are duplicates).
- `normalized_paths.yaml` demonstrates lexical `.` and empty-component
  normalization before paths are stored. `..` components are rejected, not
  resolved.

Error precedence and rejected forms are covered by `tests/manifest.rs` so the
expected error code and field can be asserted for every case.
