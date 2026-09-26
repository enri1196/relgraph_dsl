# OpenFGA DSL Compliance Implementation Contract

## 1. Objective and authority

Implement single-document DSL parsing, explicitly bounded static validation, and schema 1.2 modular-model loading/composition. This is the implementation specification: the interfaces, acceptance rules, error policies, dependencies, and completion gates below are mandatory.

### Pinned compatibility target

Use `openfga/language` commit **`fbc62984d02fc8ff7e2a924e0b9c34193233007c`**, reviewed 2026-09-25, rather than a moving branch or unspecified CLI release:

- [Parser grammar](https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/OpenFGAParser.g4).
- [Lexer grammar](https://github.com/openfga/language/blob/fbc62984d02fc8ff7e2a924e0b9c34193233007c/OpenFGALexer.g4).
- [Modular models](https://openfga.dev/docs/modeling/modular-models), reviewed 2026-09-25: manifest shape, repeated module names across files, and the three documented extension constraints.
- [Conditions](https://openfga.dev/docs/modeling/conditions) and [configuration language](https://openfga.dev/docs/configuration-language) provide context, not permission to widen the pinned syntax.

Syntax acceptance means the pinned lexer **and** parser complete with zero diagnostics and consume EOF. ANTLR recovery producing a tree is not acceptance. Lexer modes, longest-token matching, rule priority, and hidden-channel tokens are part of the target. Higher-level CLI transformation or server rejection does not change syntax acceptance.

The grammar is authoritative for syntax; the explicit tables below define this crate's static-validation and manifest policies. Label crate-specific policies in documentation. If executable upstream evidence contradicts an explicit rule here, stop the affected task and report the exact input, revision, and diagnostics for a plan correction. Do not silently choose different behavior.

### Fixed scope boundary

- Parse any numeric `major.minor` version token. Validate only exact `1.1` and `1.2` for standalone models and exact `1.2` for modular models.
- Preserve CEL body bytes and recognize DSL lexical boundaries. Do not compile, evaluate, or type-check CEL.
- Implement exactly the static rules in §5. Cycle/entrypoint analysis, server resource limits, runtime tuple checks, JSON/API conversion, serialization, formatting, and model writes are outside this delivery. Do not claim complete server validation.
- `$expression` is supported syntax, not a promise that every server accepts inline conditions. Static validation accepts it without a named-condition lookup in both supported versions.
- Filesystem loading is synchronous. No network access, global cache, directory discovery, glob expansion, or environment-variable substitution in library APIs.

## 2. Repository baseline and execution rules

The crate is version `0.1.0`, edition 2024, with `nom = "8.0.0"`. Current files are `src/ast.rs`, `src/lib.rs`, `src/parser/{mod,common,schema,relation,condition}.rs`, seven tests in `tests/parser.rs`, and `examples/demo.rs`.

Known incompatibilities to fix:

1. Headers accept same-line `model schema` and hard-code `1.1`.
2. Module names use extended identifiers; upstream uses `identifier`.
3. General whitespace/comment skipping erases grammar-significant token distinctions.
4. Empty restrictions, repeated ungrouped differences, and direct restrictions inside right-hand grouped operands are over-accepted.
5. Parameters allow zero arguments; CEL bodies are trimmed and stop at the first raw `}` rather than the first `RBRACE` token.
6. Condition restrictions have no `$expression` AST variant.
7. Typed diagnostics, validation, manifests, and composition are absent.

Execute Tasks 1–10 sequentially. Do not implement tasks concurrently against shared AST/parser files. All tasks start TODO. Mark DONE only after deliverables and gates pass; fill in **Completion evidence** with changed files and command outcomes. Add feature fixtures with the feature. Do not ignore tests, weaken expectations, or change these contracts to obtain a green checkpoint.

Keep implementation and regression tests together. Commit only when explicitly requested by the user; then use one commit per completed task and exclude unrelated work.

### Dependency policy

- Retain `nom`; use it for private token-stream parsing after Task 2. No parser generator in the Rust build.
- Task 1 adds dev dependencies `serde = "1"` with `derive` and `serde_json = "1"` for fixture metadata.
- Task 7 moves `serde` to runtime dependencies and adds `serde_yaml = "0.9.34"`. This is the selected YAML implementation for this delivery, not an implementor decision.
- Task 8 adds dev dependency `tempfile = "3"`.
- Update `Cargo.lock` with dependency changes. No other dependencies are authorized by this plan.

## 3. Public API and diagnostics

Export all new public types from the crate root. Keep `pub mod ast`; add public `diagnostics`, `validation`, `manifest`, and `modular` modules. Parser internals remain private.

```rust
pub fn parse_fga_schema(input: &str) -> Result<Schema, ParseError>;
pub fn validate_schema(schema: &Schema) -> Result<(), Vec<ValidationError>>;
pub fn parse_model_manifest(input: &str) -> Result<ModelManifest, ManifestError>;
pub fn assemble_modular_model(
    manifest: ModelManifest,
    modules: Vec<ModuleSource>,
) -> Result<ModularModel, ModularModelError>;
pub fn load_modular_model(manifest_path: &std::path::Path)
    -> Result<ModularModel, ModularModelError>;
pub fn validate_modular_model(model: &ModularModel)
    -> Result<(), Vec<ValidationError>>;
```

The `String` → `ParseError` return-type change and added AST fields are intentional pre-1.0 breaking changes. Update callers and document migration; do not add a legacy API. Parsing and loading do not automatically run semantic validation.

### AST changes

- Add `RelationCondition { Named(String), InlineExpression }`; change `RelationTarget.condition` to `Option<RelationCondition>`.
- Keep `ParameterType::{Simple(String), Generic { container: String, inner: String }}` and all expression variants. Do not add recursive generics or new parameter variants.
- Add public `span: Option<SourceSpan>` fields to `TypeDefinition`, `Relation`, `ConditionDefinition`, and `ConditionParameter`; add `header_span: Option<SourceSpan>` to `Schema`. Do not add spans to expression variants or `RelationTarget`.
- Define `SourceSpan { pub start: usize, pub end: usize }` in `diagnostics.rs`. Offsets are half-open UTF-8 byte offsets into the unmodified original document. Spans cover first through last significant token, excluding preceding comments/trailing whitespace. Parameter spans cover name through type. Parsed nodes always use `Some`; manually constructed nodes may use `None`.
- Preserve existing derives. New value types derive `Debug, Clone, PartialEq, Eq` where fields permit. Implement error `Display` and `std::error::Error` manually.
- Keep `comments_before`: store grammar-attached `#` lines in order, without `#`, trimmed at both ends. Discard header comments. Hidden `//` comments are not attached. Parentheses are not AST nodes; union/intersection chains fold left.

### Diagnostic types and ordering

Define in `diagnostics.rs`, with all fields public:

```rust
pub struct ParseError {
    pub code: ParseErrorCode,
    pub span: SourceSpan,
    pub message: String,
}
pub enum ParseErrorCode { InvalidToken, UnexpectedToken, UnexpectedEof }
pub struct SourceLocation {
    pub file: Option<PathBuf>,
    pub module: Option<String>,
    pub span: Option<SourceSpan>,
}
pub struct ValidationError {
    pub issue: ValidationIssue,
    pub location: SourceLocation,
    pub related: Vec<SourceLocation>,
    pub message: String,
}
```

`ValidationIssue` lives in `validation.rs` and contains exactly the variants in §5 and §7. Every diagnostic code/issue enum exposes `code(&self) -> &'static str`, returning its PascalCase variant name. Messages are descriptive but not stable API; tests assert codes, spans, and related locations.

Lex the entire input before parsing; report the earliest lexical failure first. Invalid-token spans cover one UTF-8 scalar, unexpected-token spans cover that token, and EOF is `len..len`. For a failed string token, report its opening quote. Return one syntax error at the furthest failed token position; ties follow grammar-alternative order. Never trim input before calculating offsets.

Validation errors locate the owning declaration: parameter for duplicate parameters, header for version/header errors, relation for reference errors. Duplicate errors locate the later declaration and put the first declaration in `related`. This declaration-level granularity is intentional.

Standalone locations have no file/module. Modular locations use normalized manifest-relative paths and declared module names. Sort errors by manifest index (standalone = 0), span start (`None` last), issue code, then message; retain related-location order. Deduplicate identical `(issue, location, message)` triples. Hash-map iteration must not affect output. Messages must include the offending name for reference errors, distinguishing different missing symbols in the same relation.

## 4. Syntax behavior contract

Add private `src/parser/lexer.rs`; translate the pinned lexer, including `CONDITION_DEF`, longest match, and declaration-order ties. Tokens carry kind and byte span and refer to original text. Hidden tokens remain available for source slicing but are omitted from the visible parser stream. Convert existing private parsers to token-slice parsers using `nom`. Translate parser productions literally rather than applying global whitespace skipping.

Required regression cases, in addition to production coverage:

| Area | Accept | Reject / required distinction |
| --- | --- | --- |
| Headers | `model\n  schema 1.1`; versions `1.2`, `2.0`, `01.02`, preserving spelling | Same-line `model schema 1.1`; `1`, `1.`, `.1`, `1.1.0`, `v1.1`; suffix garbage |
| Module names | `module team-access`, `module model` | `module team/access`, `module team.access` |
| Names | ASCII identifiers; extended type/relation names such as `team/access`; keyword tokens only where listed in the production | Unicode letters, leading digits, bare reserved operators; no keyword-prefix matching |
| Lexer priority | `modelx` is one identifier; plain identifiers may have repeated/trailing hyphens under `IDENTIFIER` | Do not impose the stricter extended-name regex on an accepted identifier token |
| Structure | Header-only syntax; types then conditions; `extend type` syntax with either header | Type after condition; multiple headers; empty `relations`; declarations sharing a line where `NEWLINE` is required |
| Restrictions | `[user]`, `[group#member]`, `[user:*]`, multiple entries | `[]`, trailing comma, `user#*`, `user:member`, stacked `#member:*` |
| Restricted conditions | `with can_view`, `with $expression` on plain/wildcard/userset targets | Missing name, `$foo`, `$expression_suffix`; names follow grammar token rules |
| Rewrites | Computed userset; `editor from parent`; `a or b or c`; `a and b and c`; `a but not b` | `a and b or c`; `a but not b but not c`; missing operand |
| Grouping | `(a and b) or c`; `[user] or a`; `([user] or a)` | `a or [user]`; `a or ([user])`; recursively nested direct assignments on the right |
| Whitespace | Exact lexer `WHITESPACE`/`NEWLINE`, including LF/CRLF/CR/form feed and indentation | Newlines where only `WHITESPACE` is permitted; arbitrary Unicode whitespace |
| Comments | `multiLineComment` in permitted positions; hidden `//` through LF or EOF | Treating all `#` tokens as comments; arbitrary trailing `#` prose outside grammar |
| Parameters | At least one argument; eight types below; exact container syntax | Zero arguments; trailing comma; type prefixes such as `integer`; arbitrary types |

Parameter types are exactly `bool`, `string`, `int`, `uint`, `double`, `duration`, `timestamp`, `ipaddress`. Both `list<T>` and `map<T>` take one of those eight types. Reject `any`, `float`, `bytes`, bare containers, `map<string,int>`, nested generics, and spaces inside `list< string >`. Do not borrow API enum names as DSL syntax.

**Parameter newlines:** the pinned lexer has no newline rule in `CONDITION_DEF`, despite parser references to `NEWLINE`. With zero lexical errors required, reject actual line breaks between the `condition` keyword and its parameter-list closing `)`. Spaces/tabs remain accepted where grammar permits. Document this lexer/parser mismatch with a fixture.

### CEL boundary policy: not balanced braces

`conditionExpression` ends at the first visible `RBRACE` token. Braces inside valid `STRING`, `BYTES`, or hidden `CEL_COMMENT` tokens do not terminate it. Port single/double/triple quoted, raw `r`/`R`, byte `b`/`B`, and escape rules exactly. `//` is a comment; `/* ... */` is not a block-comment token.

- Store the exact substring between the outer `{` and first visible `}`, including whitespace/comments.
- Empty and whitespace-only bodies parse; the validator does not compile them.
- Do not balance braces/brackets/parentheses. A complete nested map with two unquoted closing braces is rejected: the first closes the condition, the second is unexpected.
- An unmatched opening brace within a body can be syntactically accepted; preserve upstream behavior.
- Missing closing braces, unterminated strings, invalid escapes, and invalid lexer characters fail cleanly.
- Put token-based extraction in private `src/parser/cel.rs`; do not build a second competing string scanner.

## 5. Static validation contract

Build symbol tables before references so forward references resolve. Traverse expressions recursively left-to-right. First declarations win lookup when duplicated; still diagnose later declarations. Skip dependent checks after missing prerequisites, while retaining independent errors.

| `ValidationIssue` | Rule |
| --- | --- |
| `UnsupportedSchemaVersion` | Exact standalone `1.1`/`1.2`, exact modular `1.2`. |
| `ModuleRequiresComposition` | `validate_schema` on a module returns only this issue; use modular validation for cross-file resolution. |
| `ExtensionOutsideModule` | Standalone model contains an extension. Exclude it from symbols and dependent checks. |
| `EmptyModel` | No base types in the standalone/composed model; syntax still accepts a header-only file. |
| `DuplicateType` | Repeated base type name. |
| `DuplicateRelation` | Repeated relation within a type, including extensions. |
| `DuplicateCondition` | Repeated condition in the model-wide namespace. |
| `DuplicateParameter` | Repeated parameter within one condition. |
| `UnknownType` | Direct restriction targets nonexistent type; suppress its userset-relation lookup. |
| `UnknownRelation` | Computed userset missing on owning type, or `type#relation` missing on target type. |
| `UnknownCondition` | `Named` restriction has no definition; inline form requires no lookup. |
| `UnknownTuplesetRelation` | `from` relation missing on owning type; skip remaining checks for that tuple-to-userset. |
| `InvalidTuplesetRelation` | Tupleset's entire expression is not a nonempty `DirectAssignment`, or any target has `relation_or_wildcard != None`. Conditions on plain targets are allowed. |
| `UnknownComputedRelation` | Valid tupleset has no target type defining the computed relation. At least one target must define it, **not every target**. Suppress if any target type is unresolved. |
| `InvalidParameterType` | Manually constructed parameter type is outside §4. |
| `EmptyDirectAssignment` | Manually constructed direct-target vector is empty. |

Other manually constructed ASTs get the same reference checks, but are not re-lexed and do not get textual operator-placement checks. Missing spans are allowed. No unused-condition warnings, CEL checks, argument/runtime checks, or cycle/entrypoint analysis. Include a cyclic model that passes these bounded checks to make the boundary executable.

## 6. Manifest contract

Define `ModelManifest { pub schema: String, pub contents: Vec<PathBuf> }` without file handles or modules.

Use `serde_yaml` with a custom visitor detecting duplicate keys and checking scalar types without string coercion. Require exactly one YAML document whose root is a mapping. Required keys are `schema` and `contents`; reject unknown keys. Schema is a YAML string matching ASCII `[0-9]+\.[0-9]+`: quoted `'1.2'` succeeds; numeric `1.2` fails. Well-formed unsupported versions parse and fail modular validation. Contents is a nonempty sequence of nonempty strings.

Path policy is crate-specific: accept relative slash-separated paths, `.` and internal `..`; normalize lexically before storage. Reject above-root traversal, absolute paths, backslashes, drive prefixes, NUL, and paths normalizing to empty. Preserve spaces in components; do not trim. No `.fga` suffix requirement. Reject duplicate normalized paths; preserve entry order. YAML comments and anchors/aliases supported by `serde_yaml` are allowed; validate the resolved values identically to literal values. Recursive/unresolvable aliases fail with `InvalidYaml`. Reject explicit YAML tags as `UnsupportedYamlFeature`; merge key `<<` is an unknown field, not a merge operation.

Define `ManifestError { pub code: ManifestErrorCode, pub field: Option<String>, pub message: String }`. Field is `schema`, `contents`, `contents[N]` (zero-based), offending key, or `None` for document-level errors. YAML spans are not part of this API.

`ManifestErrorCode` variants: `InvalidYaml`, `InvalidRoot`, `MissingField`, `UnknownField`, `DuplicateField`, `WrongType`, `InvalidSchemaVersion`, `EmptyContents`, `InvalidPath`, `DuplicatePath`, `UnsupportedYamlFeature`. Implement `code()` as in §3. Error precedence: YAML syntax/multiple documents; explicit tags; root shape; unknown/duplicate keys in source order; missing schema then contents; schema value; contents entries in order. A non-string root key is `WrongType` with `field = None` at the key-checking stage. Return one error.

## 7. Modular composition contract

Public types in `modular.rs`:

```rust
pub struct ModuleSource {
    pub path: PathBuf, // normalized manifest-relative identity
    pub schema: Schema,
}
pub struct ModularModel {
    pub manifest: ModelManifest,
    pub modules: Vec<ModuleSource>, // original declarations retained
    pub schema: Schema,            // assembled model
    pub type_origins: Vec<SourceLocation>,
    pub relation_origins: Vec<Vec<SourceLocation>>,
    pub condition_origins: Vec<SourceLocation>,
}
```

Origins are index-aligned with assembled types, each type's relations, and conditions. Copy original spans; origins distinguish documents. Assembled header uses the manifest version and `header_span = None`. Assembled types have `is_extended = false`.

### Assembly algorithm

1. Pure `assemble_modular_model` performs no I/O. Modules must match manifest entries exactly in count, order, and normalized path, otherwise `InputMismatch` at the first differing/missing/extra index.
2. Every document must have a module header, otherwise `NonModuleDocument`. Repeated module names in different files are valid.
3. Collect all base types first; extensions may precede their bases. Base type order and condition order are manifest/declaration order.
4. Keep base relation order; append extension relations in manifest/declaration order after all base relations, even when an extension file precedes the base.
5. Collect structural issues before producing a model. Return `Composition { errors }` on conflicts; never overwrite, silently discard, or return a partial successful model.
6. Do not check versions, ordinary references, CEL, duplicate conditions/parameters, or empty models during assembly. These remain explicit validation work.

Structural issues reuse `DuplicateType`/`DuplicateRelation` and add `UnknownExtensionType` (no base anywhere) and `DuplicateExtension` (same type extended twice in one file). Check duplicate relations within bases/extensions as well as across contributions. Collision locations follow composition order; relate the first declaration. Duplicate-extension scope is file, not module name. Empty extensions and same-module extensions are allowed; ownership discussion adds no fourth constraint to the three documented rules. For missing/ambiguous bases suppress dependent extension-merging errors.

`validate_modular_model` recomposes cloned manifest/modules to verify public-model invariants. If recomposition fails or assembled schema/origins differ, return `InvalidComposition` first, followed by any structural issues from recomposition, sorted as §3 specifies. Its location has no file/module/span; its message identifies the failed invariant. Otherwise apply §5 to the assembled model with original origins and exact modular version `1.2`. Do not validate module documents separately. Manifest-level locations have no file/module/span because the pure manifest type has no source identity.

Pure assembly also checks manually constructed manifest values against §6 before matching inputs. Add `ModularModelError::InvalidManifest { source: ManifestError }` for this path-free failure; reuse the manifest value-validation helper rather than serialize/reparse YAML. Non-normalized manifest entries fail `InvalidPath` rather than being silently changed. Filesystem manifest parse failures retain the path-bearing `Manifest` variant below.

### Loading and errors

`load_modular_model` reads the UTF-8 manifest, parses it, then reads/parses each listed file once in manifest order. Relative manifest paths use process working directory; content paths join the manifest parent (empty parent means `.`). Follow normal symlinks; this is not a sandbox. Distinct normalized entries aliasing the same physical file remain separate. Do not canonicalize diagnostic identities.

Fail fast on I/O, manifest, module parse, or non-module errors. Collect structural errors only after all valid files are parsed. Never run static validation automatically.

```rust
pub enum ModularModelError {
    Io { path: PathBuf, entry: Option<usize>, source: std::io::Error },
    Manifest { path: PathBuf, source: ManifestError },
    InvalidManifest { source: ManifestError },
    Parse { path: PathBuf, entry: usize, source: ParseError },
    InputMismatch { entry: usize, message: String },
    NonModuleDocument { path: PathBuf, entry: usize },
    Composition { errors: Vec<ValidationError> },
}
```

Manifest I/O uses `entry = None`, modules use `Some(index)`. Invalid UTF-8 is `Io`. I/O paths are joined filesystem paths; module parse/header errors use normalized manifest-relative identities. Implement `Error::source` for wrappers. This I/O-bearing enum need not implement `Clone`/`Eq`.

## 8. Fixtures and upstream evidence

Use `tests/fixtures/openfga/{valid,invalid,semantic,manifest,modular}/` and a README. Valid/invalid classify syntax only; semantic errors do not belong in syntax-invalid fixtures.

Each syntax fixture has `.fga` and same-stem `.json` metadata: `id`, `owner_task`, `source_url`, `production`, `expected_parse` (`accept`/`reject`), `evidence` (`grammar-derived`/`upstream-executed`), `notes`. Rejected cases also have `error_code`, `span_start`, `span_end` for crate diagnostics. Reject unknown JSON fields. `tests/conformance.rs` enumerates sorted paths, verifies pairing/unique IDs, and includes fixture paths in failures. No runtime download or CLI dependency.

Vendor the exact pinned `.g4` files and upstream license in `tests/fixtures/openfga/upstream/`; record revision and SHA-256 checksums in its README. Derived fixtures identify their production and mutation. Label them grammar-derived until actually run upstream; do not fabricate execution evidence.

Add a Java ANTLR runner in `tools/conformance/`, using **ANTLR 4.13.2** and **Java 17**. Generate lexer/parser from vendored grammars in a clean output directory, passing generated token vocabulary to parser generation. Attach lexer/parser error listeners; invoke `main`; print sorted JSON Lines containing fixture ID, acceptance, diagnostic count. Record exact generator/compiler/runner commands and jar SHA-256 in the tooling README. This is maintainer tooling, not a Cargo build/test dependency.

In Task 10 run every syntax fixture through the runner and retain `upstream-results.jsonl`. Change evidence only for executed fixtures. Compare acceptance, not ANTLR prose/AST serialization. Disagreement blocks completion, not permission to change expectations. Future upstream refreshes require a separately reviewed pin update, regenerated evidence, and review of every acceptance delta.

## 9. Ordered implementation tasks

### Task 1 — Baseline and pinned fixture infrastructure [DONE]

**Depends on:** none.

**Files:** Cargo manifests, `tests/conformance.rs`, fixtures, `tools/conformance/`.

**Deliver:** Record existing test baseline. Vendor references/license/checksums; implement metadata loader and upstream runner. Add currently passing canonical multiline header, direct assignment, computed userset, tuple-to-userset, union, intersection, difference, simple condition, unknown-character, and missing-header fixtures. Keep existing focused tests.

**Gate:** `cargo fmt --check`, `cargo test --all-targets`; fixture pairing/unique IDs and paths in failures; runner generation/compilation succeeds. No ignored tests.

**Completion evidence:**

- Baseline before changes: `cargo test --all-targets` passed (7 parser tests).
- Changed files: `Cargo.toml`, `Cargo.lock`, `tests/conformance.rs`, syntax fixtures and metadata under `tests/fixtures/openfga/{valid,invalid}/`, pinned grammars/license and checksum READMEs under `tests/fixtures/openfga/upstream/`, `tests/fixtures/openfga/upstream-results.jsonl`, `tests/fixtures/openfga/README.md`, `tools/conformance/{ConformanceRunner.java,run.sh,README.md}`, and this plan.
- `cargo fmt --check` passed.
- `cargo test --all-targets --locked` passed: 1 conformance test and all 7 existing parser tests.
- ANTLR 4.13.2 runner generation and Java 17 compilation succeeded. It executed all 10 fixtures: 8 accepted with zero diagnostics and 2 rejected; output is retained in `tests/fixtures/openfga/upstream-results.jsonl`.
- `git diff --check` passed. Vendored upstream file checksums were verified and are recorded in `tests/fixtures/openfga/upstream/README.md`; the ANTLR jar checksum is recorded in `tools/conformance/README.md`.

### Task 2 — Lexer and typed parser diagnostics [TODO]

**Depends on:** Task 1.

**Files:** `src/diagnostics.rs`, `src/ast.rs`, `src/lib.rs`, parser modules including new `lexer.rs`, `tests/parser.rs`, `examples/demo.rs`.

**Deliver:** §3 diagnostics/spans and §4 lexer; convert private parsers to `nom` token slices. Remove `trim_start` and unrestricted `spnl`. Consume comments/whitespace only through matching productions. Migrate callers. Replace same-line headers and `module team/access` in positive tests with canonical multiline headers and `module team-access`; add old forms as negatives. Update demo syntax.

**Tests:** Longest match/keyword priority; ASCII names; `#` versus userset syntax; hidden comments at EOF; condition lexer mode; newline encodings; offsets after leading whitespace and multibyte comment text; EOF; parsed/present versus manual/absent spans. Retain exact expression assertions independently from spans.

**Gate:** Existing feature coverage retained, original-input spans present, formatting and all-target tests pass.

**Completion evidence:** pending.

### Task 3 — Headers, declarations, and rewrites [TODO]

**Depends on:** Task 2.

**Files:** `src/parser/{schema,relation,common}.rs`, parser tests, fixtures.

**Deliver:** Exact header/declaration/rewrite productions; distinct direct-allowed and no-direct recursion paths. Capture full version tokens; enforce nonempty restrictions, one ungrouped difference, homogeneous chains, and declaration order. No hard-coded `1.1` parser policy.

**Tests:** All non-condition §4 rows; AST association/grouping; keyword names; trailing input; header-only files; extensions; correctly attached comments; nested RHS grouping that previously admitted direct assignments.

**Gate:** Each affected production has a positive fixture and every prohibition a negative fixture; formatting and all-target tests pass.

**Completion evidence:** pending.

### Task 4 — Conditional relationship AST [TODO]

**Depends on:** Task 3.

**Files:** `src/ast.rs`, `src/parser/relation.rs`, exports, parser tests, fixtures.

**Deliver:** `RelationCondition` and §4 restriction alternatives; migrate string assertions/examples.

**Tests:** Named/inline forms on plain, wildcard, and userset targets; mixed conditioned/unconditioned lists; missing condition; invalid dollar names/suffixes; exact AST variants.

**Gate:** No old condition-string field/assertions; formatting and all-target tests pass.

**Completion evidence:** pending.

### Task 5 — Parameters and token-delimited CEL [TODO]

**Depends on:** Task 4.

**Files:** `src/parser/{condition,cel,mod}.rs`, parser tests, fixtures.

**Deliver:** Exact parameters, token-based boundaries, body-byte preservation. Replace trimmed-expression assertions, e.g. expect `" ids.size() > 0 "`.

**Tests:** All 8 simple/16 container combinations; every rejected type form; zero/trailing-comma/newline parameters; ordinary/raw/byte/triple strings; escapes; braces in strings/comments; empty/multiline/multiple bodies; missing brace/unterminated string; nested-map rejection; accepted invalid CEL semantics. Assert exact body substrings.

**Gate:** Complete type/body matrix; formatting and all-target tests pass.

**Completion evidence:** pending.

### Task 6 — Bounded standalone validation [DONE]

**Depends on:** Task 5.

**Files:** `src/validation.rs`, diagnostics/exports, `tests/validation.rs`, semantic fixtures.

**Deliver:** §5 rules, symbol tables, typed and deterministic diagnostics, separate from parsing.

**Tests:** Success/failure per rule; forward references; related duplicate spans; exact multi-error order; cascade suppression; unsupported version preservation; standalone extensions; module-only error; manually invalid parameter/empty restriction; cycle boundary. Tuple-to-userset tests cover absent/rewrite-based tuplesets, wildcard/userset targets, conditioned plain targets, none/some/all targets defining computed relations, unresolved target types.

**Gate:** Every issue has code/location assertions; formatting and all-target tests pass.

**Completion evidence:**

- Added `src/validation.rs` with standalone schema/version checks, first-declaration symbol tables, duplicate diagnostics with related locations, ordered reference validation, tuple-to-userset constraints, parameter-type checks, and manually constructed empty-assignment checks. Module documents return only `ModuleRequiresComposition`; extension declarations are excluded from standalone symbols and dependent checks.
- Added `SourceLocation` and `ValidationError` with stable issue codes, `Display`, and `Error`; exported the validation module, `ValidationIssue`, `validate_schema`, and new diagnostic types from the crate root.
- Added `tests/validation.rs` and semantic fixtures for forward references, cyclic relations within the bounded validation boundary, deterministic multi-error ordering, cascade suppression, all tuple-to-userset cases, duplicate related spans, unsupported versions, standalone extensions, and manual AST invariants.
- `cargo fmt --all -- --check` passed.
- `cargo test --all-targets --locked` passed: 1 conformance test, all 21 parser tests, all 8 validation tests, and the demo target.
- `git diff --check` passed.

### Task 7 — Deterministic manifest parsing [DONE]

**Depends on:** Task 6.

**Files:** Cargo manifests, `src/manifest.rs`, exports, `tests/manifest.rs`, fixtures.

**Deliver:** All §6 YAML/path/API/error-precedence rules without I/O.

**Tests:** Ordered valid manifest; each error code/field; numeric versus quoted version; unsupported valid version accepted; missing/null/wrong types; unknown/duplicate/non-string keys; multiple documents; resolved and recursive aliases; explicit tags and merge keys; normalized duplicates; dot/internal-parent paths; above-root/absolute/drive/backslash/NUL/empty paths; spaces and non-`.fga` suffixes.

**Gate:** Exact normalized order and first-error expectations; formatting and all-target tests pass.

**Completion evidence:**

- Added runtime `serde` and `serde_yaml = "0.9.34"`, exported the manifest API, and implemented ordered custom YAML deserialization that preserves duplicate keys and scalar types. The parser enforces document/tag/root/key/version/content/path rules without filesystem access.
- Added `tests/manifest.rs` with code, field, and precedence assertions, plus ordered, alias, and normalized-path examples under `tests/fixtures/openfga/manifest/`.
- `cargo fmt --all -- --check` passed.
- `cargo test --all-targets --locked` passed: 1 conformance test, 10 manifest tests, 21 parser tests, 8 validation tests, and the demo target.
- `git diff --check` passed.

### Task 8 — Pure assembly and filesystem loading [TODO]

**Depends on:** Task 7.

**Files:** Cargo manifests, `src/modular.rs`, validation/exports, `tests/modular.rs`, fixtures.

**Deliver:** §7 types, assembler, structural checks, origins, loader. Share structural helpers with validation. Use a private injectable read closure for read-count/error tests; do not change public APIs.

**Tests:** Same module name across files; extension before base; type/relation/condition ordering and origins; each structural error; empty/same-module extensions; manually invalid manifest values; wrong input count/order/path; missing/unreadable/invalid-UTF-8 module; parse error; non-module; one read per entry; no automatic reference/version validation. Use `tempfile` and injected I/O errors, not permission-bit tests dependent on user privileges.

**Gate:** No partial success on conflicts; both source identities in structural errors; formatting and all-target tests pass.

**Completion evidence:**

- Added `src/modular.rs` with path-free manifest validation, exact module-input matching, module-header checks, deterministic structural diagnostics, base-first assembly, extension relation merging, source origins, and synchronous manifest-relative loading. The loader uses a private injected reader for deterministic read-order and I/O-error coverage; no semantic validation runs automatically.
- Added `UnknownExtensionType` and `DuplicateExtension` issue codes, and shared duplicate-relation diagnostic construction with standalone validation. Exported the modular API from the crate root and added `tempfile` for loader tests.
- Added `tests/modular.rs` and modular fixtures covering extension-before-base assembly, repeated module names, declaration/origin order, duplicate base/relation/extension errors, missing and ambiguous bases, empty extensions, invalid manual manifests, input mismatches, non-module documents, missing/invalid-UTF-8/parse-failing files, read-once behavior, and validation boundaries.
- `cargo fmt --all -- --check` passed.
- `cargo test --all-targets --locked` passed: 2 modular loader unit tests, 12 modular integration tests, 10 manifest tests, 21 parser tests, 8 validation tests, 1 conformance test, and the demo target.
- `git diff --check` passed.

### Task 9 — Cross-file validation and provenance [DONE]

**Depends on:** Task 8.

**Files:** validation/modular modules, validation/modular tests, fixtures.

**Deliver:** `validate_modular_model`, public invariant checking, exact 1.2 policy, source-aware §5 reuse. Synthetic `InvalidComposition` precedes sorted structural errors.

**Tests:** Cross-file type/relation/condition resolution; tuple-to-userset through extended relation; duplicate conditions/parameters; unresolved references in extensions; repeated module names; standalone 1.1 valid/modular 1.1 invalid; mutated public schema/origins; exact multi-file error order.

**Gate:** Valid composed fixtures pass; invalid cases fail named rules at correct origins; formatting and all-target tests pass.

**Completion evidence:**

- Added `validate_modular_model` with recomposition checks for the public assembled schema and all origin vectors; synthetic `InvalidComposition` diagnostics precede structural recomposition errors. Reused §5 semantic checks with manifest-indexed file/module/span provenance and exact modular schema `1.2` policy.
- Updated `src/validation.rs`, `src/modular.rs`, and `src/lib.rs`; added `tests/modular_validation.rs` and semantic fixtures under `tests/fixtures/openfga/modular/validation/`.
- Added eight integration tests covering cross-file type/relation/condition resolution, extension-provided tuple-to-userset relations, duplicate conditions/parameters, extension reference errors, repeated module names, standalone/modular version boundaries, public schema/provenance mutation, and deterministic multi-file ordering.
- `cargo fmt --all -- --check` passed.
- `cargo test --all-targets --locked` passed: 2 modular unit tests, 1 conformance test, 10 manifest tests, 12 modular tests, 8 modular validation tests, 21 parser tests, 8 standalone validation tests, and the demo target.
- `git diff --check` passed.

### Task 10 — Differential audit and published boundary [DONE]

**Depends on:** Task 9.

**Files:** conformance tests/metadata/results/README, tooling README, crate/public-module docs, demo.

**Deliver:** Production-to-fixture matrix for every pinned parser production and lexer token family used by DSL, including modes/hidden comments. Execute §8 runner and retain results. Document parser/validator/loader responsibilities, breaking changes, spans, crate manifest policies, bounded validation, parameter-newline mismatch, first-`RBRACE` behavior, and inline-condition server limits.

**Documentation examples:** Parse then validate; parse manifest without I/O; assemble pre-parsed modules; load then explicitly validate. Compile examples; `no_run` only for filesystem examples, never `ignore`.

**Final gates:**

```text
cargo fmt --check
cargo test --all-targets --locked
cargo test --doc --locked
cargo clippy --all-targets --locked -- -D warnings
```

After dependencies are cached, run `cargo test --all-targets --locked --offline` to prove ordinary tests need no network or external parser installation. Every syntax fixture needs executed upstream evidence and matching acceptance. Tasks 1–9 need completion evidence; no ignored tests, unpaired fixtures, unresolved contracts, or full-server-compliance claims. If the upstream runner cannot execute, this task is blocked, not DONE.

**Completion evidence:**

- Added parser-production and lexer-token-family matrices to `tests/fixtures/openfga/README.md`, covering every pinned parser rule, condition lexer mode, and hidden CEL comment family. Documented the parameter-newline mismatch, first-`RBRACE` body boundary, and inline-condition server limitation.
- Added the accepted `cel-token-families` syntax fixture. Executed the pinned ANTLR 4.13.2 runner with Java 17 for all 64 syntax fixtures and retained sorted results in `tests/fixtures/openfga/upstream-results.jsonl`: 26 accepted, 38 rejected, no missing/extra results, and no acceptance mismatches. Marked all 64 paired metadata records `upstream-executed` only after this run. The jar checksum matched the value recorded in `tools/conformance/README.md`.
- Expanded crate and public-module documentation for parser/validator/loader responsibilities, intentional pre-1.0 API changes, UTF-8 byte spans, manifest YAML/path rules, bounded validation, and the documented syntax/server boundary. Added compiling parse-then-validate, manifest-only, pure-assembly, and filesystem `no_run` load-then-validate examples. Updated `examples/demo.rs` to parse and then validate.
- Made behavior-preserving clippy cleanups in the tuple-to-userset checker, lexer literal helper, and modular test assertions/path comparisons.
- `cargo fmt --check` passed.
- `cargo test --all-targets --locked` passed: 2 unit tests, 60 integration/conformance tests, and the demo target.
- `cargo test --doc --locked` passed: all 4 rustdoc examples compiled; only the filesystem loader example is `no_run`.
- `cargo clippy --all-targets --locked -- -D warnings` passed.
- `cargo test --all-targets --locked --offline` passed with the same suite and no network or parser installation.
- `git diff --check` passed.
