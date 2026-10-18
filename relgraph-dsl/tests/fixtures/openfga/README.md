# Pinned OpenFGA DSL syntax fixtures

Syntax fixtures are split between `valid/` and `invalid/` by Relgraph's parse
outcome. Every `.fga` file has same-stem JSON metadata with an ID, task owner,
pinned source URL, production or token family, expected syntax acceptance,
evidence status, and notes. Rejected fixtures also record the parser error code
and half-open byte span. Where the raw pinned grammar decides differently,
`grammar_parse` records its outcome: Relgraph strips `#` comments as the
OpenFGA tooling does (plan Task 12), so `hash-inside-rewrite` and
`trailing-hash-prose` parse although the bare grammar rejects them. The
conformance test checks pairs, unique IDs, metadata fields, parser acceptance,
rejected-fixture diagnostics, and that the recorded ANTLR results agree with
each fixture's raw-grammar outcome.

The syntax target is `openfga/language` revision
`fbc62984d02fc8ff7e2a924e0b9c34193233007c`. The grammars and upstream license
are vendored in `upstream/`; the runner and jar checksum are documented in
`tools/conformance/README.md`. Valid/invalid fixtures classify syntax only:
several `valid/` documents fail semantic validation (for example
`computed-userset.fga` has no entry point and `types-before-conditions.fga`
declares an unused condition). Semantic, manifest, and modular fixtures
exercise crate-specific policies.

## Parser production matrix

Every parser rule in the pinned `OpenFGAParser.g4` has at least one paired
syntax fixture. Fixture names are IDs shared by `.fga` and `.json` files.

| Pinned parser production | Representative fixtures |
| --- | --- |
| `main` | `multiline-header`, `module-simple-identifier`, `missing-header`, `multiple-model-headers`, `trailing-hash-prose` |
| `modelHeader` | `multiline-header`, `header-only-version-spelling`, `same-line-model-header`, `version-suffix-garbage` |
| `moduleHeader` | `module-simple-identifier`, `module-extension`, `module-dotted-name`, `module-extended-name` |
| `typeDefs` | `types-before-conditions`, `type-after-condition` |
| `typeDef` | `declaration-order-and-extensions`, `module-extension`, `same-line-relations`, `empty-relations` |
| `relationDeclaration` | `direct-assignment`, `attached-declaration-comments`, `same-line-relation-declaration`, `empty-relations` |
| `relationName` | `keyword-and-extended-names`, `identifier-hyphens-and-single-b` |
| `relationDef` | `direct-assignment`, `computed-userset`, `tuple-to-userset`, `union` |
| `relationDefNoDirect` | `direct-assignment-on-right`, `grouped-direct-assignment-on-right`, `nested-direct-assignment-on-right` |
| `relationDefPartials` | `union`, `intersection`, `difference`, `homogeneous-rewrite-chains`, `mixed-rewrite-chain`, `repeated-difference`, `missing-rewrite-operand` |
| `relationDefGrouping` | `computed-userset`, `tuple-to-userset`, `grouped-rewrite-expression` |
| `relationRecurse` | `grouped-rewrite-expression`, `grouped-left-direct-assignment` |
| `relationRecurseNoDirect` | `grouped-direct-assignment-on-right`, `nested-direct-assignment-on-right` |
| `relationDefDirectAssignment` | `direct-assignment`, `restriction-list`, `relation-conditions`, `empty-restriction-list`, `restriction-trailing-comma` |
| `relationDefRewrite` | `computed-userset`, `tuple-to-userset` |
| `relationDefTypeRestriction` | `restriction-list`, `multiline-restriction-list`, `relation-conditions` |
| `relationDefTypeRestrictionBase` | `restriction-list`, `restriction-colon-relation`, `restriction-stacked-suffix`, `restriction-wildcard-userset` |
| `conditions` | `simple-condition`, `types-before-conditions`, `condition-parameter-types` |
| `condition` | `simple-condition`, `condition-parameter-types`, `cel-token-boundaries`, `cel-token-families` |
| `conditionName` | `simple-condition`, `condition-parameter-types` |
| `conditionParameter` | `condition-parameter-types`, `condition-newline-in-parameters`, `condition-parameter-trailing-comma` |
| `parameterName` | `condition-parameter-types` |
| `parameterType` | `condition-parameter-types`, `condition-unsupported-parameter-type` |
| `multiLineComment` | `attached-declaration-comments`, `hash-inside-rewrite`, `trailing-hash-prose` |
| `identifier` | `module-simple-identifier`, `keyword-and-extended-names`, `module-dotted-name`, `reserved-operator-name` |
| `extended_identifier` | `keyword-and-extended-names`, `identifier-hyphens-and-single-b`, `unicode-identifier` |
| `conditionExpression` | `simple-condition`, `cel-token-boundaries`, `cel-token-families`, `cel-nested-map-braces` |

## Lexer token-family matrix

The representative syntax fixtures exercise each lexer family used by the
parser, including the condition-definition mode and hidden-channel comments.
`cel-token-families` intentionally checks syntax only; its CEL text is not
compiled, evaluated, or type-checked.

| Lexer family | Representative fixtures |
| --- | --- |
| Header/version tokens: `MODEL`, `SCHEMA`, `SCHEMA_VERSION` | `multiline-header`, `header-only-version-spelling`, `version-three-components`, `version-suffix-garbage` |
| Module and declaration tokens: `MODULE`, `EXTEND`, `TYPE`, `RELATIONS`, `RELATION`, `DEFINE`, `CONDITION`, `KEYWORD_WITH` | `module-simple-identifier`, `module-extension`, `declaration-order-and-extensions`, `direct-assignment`, `relation-conditions`, `simple-condition` |
| Rewrite keywords: `AND`, `OR`, `BUT_NOT`, `FROM` | `union`, `intersection`, `difference`, `tuple-to-userset`, `homogeneous-rewrite-chains` |
| Names and reserved marker: `IDENTIFIER`, `EXTENDED_IDENTIFIER`, `DOLLAR_EXPRESSION` | `identifier-token-priority`, `keyword-and-extended-names`, `identifier-hyphens-and-single-b`, `relation-conditions`, `unicode-identifier` |
| Visible comments and hidden CEL comments: `HASH`, `CEL_COMMENT` | `attached-declaration-comments`, `hash-inside-rewrite`, `cel-token-boundaries`, `cel-token-families`, `trailing-hash-prose` |
| Restriction and grouping punctuation: `COLON`, `COMMA`, `LBRACKET`, `RPRACKET`, `LPAREN`, `RPAREN`, `LBRACE`, `RBRACE`, `STAR` | `restriction-list`, `multiline-restriction-list`, `grouped-rewrite-expression`, `condition-parameter-types`, `cel-token-families`, `cel-nested-map-braces` |
| CEL operators: `EQUALS`, `NOT_EQUALS`, `IN`, `LESS`, `LESS_EQUALS`, `GREATER`, `GREATER_EQUALS`, `LOGICAL_AND`, `LOGICAL_OR`, `DOT`, `MINUS`, `EXCLAM`, `QUESTIONMARK`, `PLUS`, `SLASH`, `PERCENT` | `cel-token-families`, `simple-condition` |
| CEL literals: `CEL_TRUE`, `CEL_FALSE`, `NUL`, `NUM_FLOAT`, `NUM_INT`, `NUM_UINT`, `STRING`, `BYTES` and escape fragments | `cel-token-families`, `cel-token-boundaries`, `simple-condition` |
| Condition lexer mode `CONDITION_DEF`: end/pop token, parameter container/type, delimiters, whitespace, and identifier remapping | `condition-parameter-types`, `condition-newline-in-parameters`, `condition-unsupported-parameter-type`, `condition-parameter-trailing-comma` |
| Whitespace and line endings: `WHITESPACE`, `NEWLINE` | `multiline-header`, `multiline-restriction-list`, `condition-newline-in-parameters`, `newline-where-whitespace-required`, `unicode-whitespace` |
| Longest match and invalid-character handling | `identifier-token-priority`, `identifier-hyphens-and-single-b`, `unknown-character` |

The condition-parameter newline case follows executable upstream behavior: the
parser production makes `NEWLINE` optional, but `CONDITION_DEF` mode does not
emit a `NEWLINE` token. Consequently, a line break before a condition parameter
is rejected.

## Executed upstream evidence

`upstream-results.jsonl` contains sorted results from the pinned ANTLR runner
for every syntax fixture. The Task 10 audit executed **64 fixtures**: **26
accepted** with zero diagnostics and **38 rejected**. All 64 results were
present and each acceptance value matched its metadata. Every syntax metadata
record is marked `upstream-executed`; none is labeled from inspection alone.
The file was regenerated on 2026-10-18 for plan Task 12 with the same JDK and
jar (SHA-256 verified) after two fixtures moved to `valid/`; the grammar
results are unchanged (still 26 / 38), only the path order moved. The
`recorded_grammar_results_match_fixture_metadata` test checks the file against
`grammar_parse` / `expected_parse`.

The parser preserves condition-body bytes and stops at the first visible
`RBRACE` token. It does not balance braces: a nested map's first unquoted `}`
ends the condition, while an unmatched opening `{` can remain syntax-valid.
The `$expression` condition marker is accepted by syntax and bounded static
validation; `relgraph-authz` runtime construction rejects it
(`InlineConditionExpression`, a permanent difference listed in that crate's
README). Measured agreement with upstream's own language tests is in
[Upstream language corpora](#upstream-language-corpora) below.

Manifest YAML examples are under `manifest/`; modular composition examples are
under `modular/`. Cross-file semantic fixtures are under
`modular/validation/`.

## Upstream language corpora

`cargo test -p relgraph_dsl --test upstream_corpus` replays the three vendored
`openfga/language` corpora in `upstream/` (syntax, semantic and `fga.mod`
cases). The runner's module docs describe what is compared: accept versus
reject, then the stage (syntax) or the multiset of error types mapped to
`ValidationIssue` codes, never message text. Positions and symbols are printed
as metrics only (`-- --nocapture`). Every case that does not pass is covered by
a reviewed entry in `upstream-skip.yaml`; the test also fails when an entry no
longer covers a non-passing case, so the list only shrinks.

Each entry has a `reason` and a `tag` from a fixed vocabulary (checked by the
test; see `tests/support/skip_list.rs`): `unsupported-feature` entries name the
missing area (the `validation` and `manifest` tags have no entries since
Tasks 5 and 6), `semantic-divergence` entries are either a `bug` owned by a plan task or
a `deliberate`, `permanent` difference, and `harness-gap` entries are harness
limitations. Like upstream's `validateDSL`, the runner stops at upstream's
parse-listener stage (`extend` outside a module, a type extended twice in one
file) and validates a lone `module` document standalone, which yields
`schema-version-required`.

Measured at the pinned revision (2026-10-18 after plan Task 12, `-- --nocapture`):

| Corpus file | Cases | Pass | Upstream `skip: true` | Skip-listed | Skip-listed by reason/tag |
| --- | ---: | ---: | ---: | ---: | --- |
| `dsl-syntax-validation-cases.yaml` | 81 | 79 | 0 | 2 | semantic-divergence/deliberate 2 |
| `dsl-semantic-validation-cases.yaml` | 93 | 84 | 7 | 2 | semantic-divergence/deliberate 2 |
| `fga-mod-transformer-cases.yaml` | 10 (9 manifests, 1 `json` output) | 9 | 0 | 1 | unsupported-feature/json-model 1 |

What the skip-listed groups are:

- Plan Task 5 added the validation rules the semantic corpus expected
  (relation entry points, repeated type restrictions and operands, `self` /
  `this` names, unused conditions, and upstream's type and relation naming
  rules), which cleared all 40 former `unsupported-feature/validation` entries
  (37 to 77 passing semantic cases).
- Plan Task 12 made `#` comments follow upstream's `parseDSL` (comment lines
  and ` #` tails are hidden tokens, never inside a condition body; see the
  crate docs), which cleared all 8 former `semantic-divergence/bug` entries
  (comments after a header, schema or type line, and an indented comment
  between `model` and `schema`): syntax 78 to 79, semantic 77 to 84 passing.
- `semantic-divergence/deliberate` (permanent): a model with no type is
  rejected (`EmptyModel`, as the OpenFGA API requires at least one type
  definition; 2 cases), Relgraph also reports follow-on issues after a
  duplicate type (1), and it reports one tuple-to-userset diagnostic per
  reference rather than per tupleset target type (1).
- Plan Task 6 aligned `parse_model_manifest` with upstream's `fga.mod`
  transformer (`pkg/go/transformer/mod-to-json.go` and
  `pkg/js/transformer/modules/mod-to-json.ts` at the pin), which cleared both
  `unsupported-feature/manifest` entries (7 to 9 passing manifests). See
  "fga.mod manifest policy" below.
- `unsupported-feature/json-model` (permanent rule): the transformer's
  expected JSON output is not compared (Decision D3).

Position and symbol matches are metrics, not gates: syntax 46/74 positions and
40/58 symbols, semantic 2/108 positions and 50/50 symbols (Relgraph validation
spans cover the owning declaration). Manifest errors have no position metric,
permanently: `serde_yaml` values carry no source positions, so a
`ManifestError` names a field (`schema`, `contents[2]`) instead of a span.

### Bumping the `openfga/language` pin

The grammars, the 64 syntax fixtures' source URLs and the three language
corpora share one pin (`fbc62984d02fc8ff7e2a924e0b9c34193233007c`). Bump them
together in one reviewed pull request:

1. Download `OpenFGALexer.g4`, `OpenFGAParser.g4`, `LICENSE` and
   `tests/data/{dsl-syntax-validation-cases,dsl-semantic-validation-cases,fga-mod-transformer-cases}.yaml`
   from the new commit into `upstream/`, replacing the old files without
   editing them; compare each with the Git blob ID the GitHub contents API
   reports at that commit.
2. Regenerate `upstream/CHECKSUMS` with `shasum -a 256` (same file order) and
   update the source URLs in `upstream/README.md` and
   `tools/conformance/README.md` (including its grammar checksums).
3. Rerun the ANTLR runner (`tools/conformance/README.md`) over the 64 syntax
   fixtures, refresh `upstream-results.jsonl`, and update each fixture's
   metadata `source_url`; a changed acceptance is a syntax change to review.
4. Run `cargo test -p relgraph_dsl --test upstream_checksums`,
   `cargo test -p relgraph_dsl --test conformance` and
   `cargo test -p relgraph_dsl --test upstream_corpus -- --nocapture`. New
   failures need a skip entry with a reason, tag, justification and task;
   entries that no longer cover a failure must be deleted (the test enforces
   both). Recheck the runner's error-type table against the new
   `pkg/js/validator/validate-dsl.ts` and `fga.mod` transformers. Review the
   `upstream-skip.yaml` diff in the pull request.
5. Update the pass-rate table above, the workspace README's measured numbers,
   and every reference to the old commit (`AGENTS.md`, `CONFORMANCE_PLAN.md`).

### fga.mod manifest policy

The `fga.mod` gate is accept versus reject per manifest. Upstream reports one
error per bad entry, while `parse_model_manifest` stops at the first, so
`tests/manifest.rs` also replays each entry of the multi-path upstream case on
its own. Since Task 6 Relgraph matches upstream on:

- `schema` must be the YAML string `1.2` (previously any ASCII `major.minor`
  was accepted and only modular validation required `1.2`);
  `assemble_modular_model` applies the same check to a constructed
  `ModelManifest`;
- every entry must end in `.fga`;
- a `..` component is rejected even when it stays inside the root
  (`team2/../team3/board.fga`), as upstream rejects any `../`; previously such
  paths were normalized;
- backslash traversal and absolute paths are rejected (unchanged).

Deliberate differences, none of which occur in the pinned corpus:

- Stricter: Relgraph never percent-decodes paths and rejects any `%`
  (upstream's Go transformer URL-decodes every entry, its JavaScript one
  decodes only `%2e`, `%2f` and `%5c`, and both then use the decoded path). It
  rejects every backslash (upstream converts `\` to `/` and accepts
  `dir\a.fga`). It rejects unknown fields, empty `contents`, duplicate
  normalized paths, every explicit YAML tag (upstream accepts `!!str`) and
  multi-document input (upstream's Go transformer reads the first document).
- Laxer or different: `.` and empty components are dropped (`./a.fga` is
  stored as `a.fga`, upstream keeps the text), and a component that merely ends
  in `..` (`x../a.fga`) is accepted, while upstream's `../` substring check
  rejects it.
