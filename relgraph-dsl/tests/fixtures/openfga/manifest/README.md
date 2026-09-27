# Manifest fixtures

These YAML samples exercise manifest-only parsing. The parser does not open the
listed files.

- `ordered.yaml` keeps manifest entry order, accepts paths containing spaces,
  and does not require a `.fga` suffix.
- `aliases.yaml` resolves a YAML scalar alias and accepts the well-formed but
  unsupported modular schema version `2.0` for later validation.
- `normalized_paths.yaml` demonstrates lexical `.` and internal `..`
  normalization before paths are stored.

Error precedence and rejected forms are covered by `tests/manifest.rs` so the
expected error code and field can be asserted for every case.
