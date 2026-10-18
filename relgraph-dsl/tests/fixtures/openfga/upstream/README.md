# Pinned upstream sources

These files are unmodified copies from `openfga/language` commit
`fbc62984d02fc8ff7e2a924e0b9c34193233007c`:

- [`OpenFGALexer.g4`](https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/OpenFGALexer.g4)
- [`OpenFGAParser.g4`](https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/OpenFGAParser.g4)
- [`LICENSE`](https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/LICENSE), Apache License 2.0
- [`dsl-syntax-validation-cases.yaml`](https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/tests/data/dsl-syntax-validation-cases.yaml)
- [`dsl-semantic-validation-cases.yaml`](https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/tests/data/dsl-semantic-validation-cases.yaml)
- [`fga-mod-transformer-cases.yaml`](https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/tests/data/fga-mod-transformer-cases.yaml)

The grammars are used by the maintainer-only ANTLR runner in
`tools/conformance/`. The three YAML files are upstream's language test
corpora (syntax, semantic and `fga.mod` cases); they are vendored as data only.
The other `tests/data/` entries at the pin (`json-syntax-transformer-validation-cases.yaml`,
`json-validation-cases.yaml`, `object-id-validation-cases.yaml`, and the
`stores/`, `transformer/` and `transformer-module/` directories) are not
vendored.

SHA-256 checksums (lowercase hex, `shasum -a 256` format) for every vendored
file are in [`CHECKSUMS`](CHECKSUMS). `cargo test -p relgraph_dsl --test
upstream_checksums` recomputes them and fails if a file differs or a vendored
file is unlisted. To check by hand from this directory:

```sh
shasum -a 256 -c CHECKSUMS
```

Raw downloads were also compared with the Git blob IDs reported by the GitHub
contents API at the pinned commit. Never edit these files; a pin bump replaces
the files and `CHECKSUMS` together.
