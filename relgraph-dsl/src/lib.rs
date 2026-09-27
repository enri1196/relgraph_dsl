//! Parse OpenFGA DSL documents, run bounded static checks, and compose modular models.
//!
//! Parsing is a syntax operation. [`parse_fga_schema`] accepts the pinned grammar's
//! syntax, preserves condition-expression bytes, and returns typed [`ParseError`]
//! diagnostics with spans into the original input. It does not run semantic
//! validation. The parser accepts numeric `major.minor` version tokens; standalone
//! validation supports exactly `1.1` and `1.2`, while modular validation supports
//! exactly `1.2`.
//!
//! Parsed declaration spans are half-open UTF-8 byte offsets into the unmodified
//! source. They exclude comments and surrounding whitespace. Parsed nodes carry
//! spans; manually constructed AST nodes may use `None`. This is a pre-1.0
//! breaking API: parser errors changed from `String` to [`ParseError`], AST nodes
//! gained span fields, and relationship conditions use [`RelationCondition`].
//!
//! Static validation implements the explicit crate rules for versions, duplicate
//! declarations, references, and tuple-to-userset structure. It does not compile,
//! evaluate, or type-check CEL; analyze cycles or entrypoints; enforce server
//! resource limits; or claim complete OpenFGA server validation. Inline
//! `$expression` conditions are accepted by syntax and bounded validation, though
//! a server may reject them in a particular context.
//!
//! Condition-expression bodies preserve their source bytes and end at the first
//! visible `RBRACE` token. Braces are not balanced: an unclosed `{` in a body can
//! parse, while a nested map's first unquoted `}` closes the condition. The pinned
//! grammar also has a parameter-newline mismatch: its condition lexer mode does
//! not emit `NEWLINE`, so a line break before a parameter is rejected even though
//! the parser production marks that token optional.
//!
//! Manifest parsing applies the crate's YAML and lexical path policies without
//! file access. Assembly is pure and checks module structure, not semantic
//! references or versions. Loading is synchronous and reads only the paths listed
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
/// This API requires one YAML mapping with string `schema` and nonempty string
/// `contents` fields. It lexically normalizes relative slash-separated paths and
/// rejects absolute paths, backslashes, and above-root traversal.
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
