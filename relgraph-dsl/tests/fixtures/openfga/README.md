# Pinned OpenFGA DSL syntax fixtures

Syntax fixtures are split between `valid/` and `invalid/`. Every `.fga` file has
same-stem JSON metadata with an ID, task owner, pinned source URL, production or
token family, expected syntax acceptance, evidence status, and notes. Rejected
fixtures also record the parser error code and half-open byte span. The
conformance test checks pairs, unique IDs, metadata fields, parser acceptance,
and rejected-fixture diagnostics.

The syntax target is `openfga/language` revision
`fbc62984d02fc8ff7e2a924e0b9c34193233007c`. The grammars and upstream license
are vendored in `upstream/`; the runner and jar checksum are documented in
`tools/conformance/README.md`. Valid/invalid fixtures classify syntax only.
Semantic, manifest, and modular fixtures exercise crate-specific policies.

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

The parser preserves condition-body bytes and stops at the first visible
`RBRACE` token. It does not balance braces: a nested map's first unquoted `}`
ends the condition, while an unmatched opening `{` can remain syntax-valid.
The `$expression` condition marker is accepted by syntax and bounded static
validation, but a server may reject inline conditions in a particular context.
These are documented compatibility boundaries, not full server-validation
claims.

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
longer covers a non-passing case, so the list only shrinks. Entries marked
`provisional: true` still await classification. Measured pass rates are
recorded by the conformance plan (`CONFORMANCE_PLAN.md`).
