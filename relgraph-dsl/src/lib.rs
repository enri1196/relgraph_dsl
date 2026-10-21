//! Parse OpenFGA DSL documents, run bounded static checks, and compose modular models.
//!
//! Parsing is a syntax operation. [`parse_fga_schema`] accepts the pinned grammar's
//! syntax, preserves condition-expression bytes, and returns typed [`ParseError`]
//! diagnostics with spans into the original input. It does not run semantic
//! validation.
//!
//! `#` comments follow the OpenFGA tooling rather than the bare grammar. The
//! tooling (`parseDSL` in `openfga/language`) blanks every line whose first
//! non-blank character is `#` and cuts every other line at its first ` #` (a
//! space, then `#`) before parsing. The parser accepts the same documents
//! without rewriting the input: such comments are skipped as hidden tokens, so
//! a comment may follow the `model`, `schema`, `module`, `type` or `relations`
//! line, a relation definition, a restriction-list line or a condition's
//! closing brace, and a comment line may stand wherever the grammar allows a
//! line break outside a condition, including between `model` and `schema` and
//! after the last declaration. The bare grammar rejects most of
//! these positions. A `#` with no space before it (`group#member`), or after a
//! tab, is not a comment. Inside a condition body no comment is recognized: the
//! body keeps its exact bytes, where the tooling would also cut ` #` tails.
//! The comment lines directly above a type, relation or condition are kept in
//! its `comments_before`. The parser accepts numeric `major.minor` version tokens; standalone
//! validation supports exactly `1.1` and `1.2`, while modular validation supports
//! exactly `1.2`.
//!
//! Parsed declaration spans are half-open UTF-8 byte offsets into the unmodified
//! source. They exclude comments and surrounding whitespace. Parsed nodes carry
//! spans; manually constructed AST nodes may use `None`. This is a pre-1.0
//! breaking API: parser errors changed from `String` to [`ParseError`], AST nodes
//! gained span fields, and relationship conditions use [`RelationCondition`].
//!
//! Static validation implements the explicit crate rules for versions, names,
//! duplicate declarations, references, tuple-to-userset structure, repeated
//! restrictions and operands, unused conditions, and relation entry points. It
//! does not compile, evaluate, or type-check CEL; decide which cycles the
//! authorization runtime can evaluate; enforce server resource limits; or claim
//! complete OpenFGA server validation. Inline `$expression` conditions
//! ([`RelationCondition::InlineExpression`]) are accepted by syntax and bounded
//! validation, though a server may reject them in a particular context. The
//! name `$expression` is reserved for them, as the pinned lexer makes it a token
//! of its own: a manually constructed condition declaration or
//! `RelationCondition::Named` reference with that name is
//! `ReservedConditionName`.
//!
//! The following [`ValidationIssue`] rules follow the pinned `openfga/language`
//! validator. They reject models that earlier releases of this crate accepted:
//!
//! - `ReservedTypeName` / `ReservedRelationName`: a type or relation named
//!   `self` or `this`.
//! - `InvalidName`: a type name outside 1 to 254 characters or a relation name
//!   outside 1 to 50 characters, or one containing `:`, `#`, `@`, `*` or
//!   whitespace. Characters are counted as Unicode scalar values.
//! - `DuplicateTypeRestriction`: the same restriction twice in one direct
//!   assignment (`[user, user]`); a different condition makes it distinct.
//! - `DuplicateOperand`: the same computed userset or tuple-to-userset twice
//!   among the operands of a relation's top-level union, intersection or
//!   difference (`viewer or viewer`). A left-nested chain of one operator is
//!   one operator, so `(a or b) or a` also repeats `a`; operands inside a
//!   nested group of another operator are not compared.
//! - `UnusedCondition`: a condition no type restriction names.
//! - `NoEntryPoint`: a relation no relationship tuple can satisfy, such as
//!   `define a: b` with `define b: a`. A union needs one operand with an entry
//!   point; an intersection and, as in OpenFGA, a difference need all of them.
//!   This check only runs when every other rule passed.
//!
//! Each diagnostic's span covers the owning type, relation or condition
//! declaration.
//!
//! Condition-expression bodies preserve their source bytes and end at the first
//! visible `RBRACE` token. Braces are not balanced: an unclosed `{` in a body can
//! parse, while a nested map's first unquoted `}` closes the condition. The pinned
//! grammar also has a parameter-newline mismatch: its condition lexer mode does
//! not emit `NEWLINE`, so a line break before a parameter is rejected even though
//! the parser production marks that token optional.
//!
//! Manifest parsing applies the crate's YAML and lexical path policies without
//! file access; like OpenFGA's `fga.mod` transformer it accepts only schema
//! `1.2` and `.fga` module paths, and rejects `..` components and
//! percent-encoded paths. Assembly is pure and checks the manifest value and
//! module structure, not semantic references. Loading is synchronous and reads only the paths listed
//! in the manifest. Neither assembly nor loading validates the composed model
//! automatically; call [`validate_modular_model`] explicitly.
//!
//! # Parse and validate
//!
//! ```
//! use relgraph_dsl::{parse_fga_schema, validate_schema};
//!
//! let schema = parse_fga_schema("model\nschema 1.2\n\ntype user\n")
//!     .expect("the source should match the DSL syntax");
//! validate_schema(&schema).expect("the schema should pass bounded checks");
//! ```

/// Public syntax tree types for parsed OpenFGA documents.
///
/// Parsed declaration spans refer to half-open UTF-8 byte offsets in the
/// original source; manually created declarations may have no span.
pub mod ast;
/// Typed syntax and static-validation diagnostics.
///
/// [`SourceSpan`] uses half-open UTF-8 byte offsets into the unmodified source,
/// not character indices or offsets into normalized text.
pub mod diagnostics;
/// Parse crate-policy model manifests without filesystem access.
///
/// This API requires one YAML mapping with a `schema` string equal to `1.2` and
/// a nonempty `contents` list of `.fga` paths. It lexically normalizes relative
/// slash-separated paths and rejects absolute paths, backslashes, `..`
/// components, and `%`.
///
/// ```
/// use relgraph_dsl::parse_model_manifest;
///
/// let manifest = parse_model_manifest(
///     "schema: '1.2'\ncontents:\n  - modules/base.fga\n",
/// )
/// .expect("manifest is valid");
/// assert_eq!(manifest.schema, "1.2");
/// assert_eq!(manifest.contents[0], std::path::PathBuf::from("modules/base.fga"));
/// ```
pub mod manifest;
/// Apply bounded static validation to standalone schemas.
///
/// This module does not compile or evaluate CEL and does not claim complete
/// server-side validation. Module documents require modular composition first.
pub mod validation;

/// Compose pre-parsed modules or synchronously load a manifest and its listed files.
///
/// Assembly and loading do not run static semantic validation; call
/// [`validate_modular_model`] explicitly on the result.
pub mod modular;
pub use modular::validate_modular_model;

pub use manifest::{ManifestError, ManifestErrorCode, ModelManifest, parse_model_manifest};
pub use modular::{
    ModularModel, ModularModelError, ModuleSource, assemble_modular_model, load_modular_model,
};

pub use diagnostics::{SourceLocation, ValidationError};
pub use validation::{ValidationIssue, validate_schema};
mod parser;

pub use ast::*;
pub use diagnostics::{ParseError, ParseErrorCode, SourceSpan};
pub use parser::parse_fga_schema;
