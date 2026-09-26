//! A parser for OpenFGA schema DSL documents.

pub mod ast;
pub mod diagnostics;
pub mod manifest;
pub mod validation;

pub use manifest::{ManifestError, ManifestErrorCode, ModelManifest, parse_model_manifest};

pub use diagnostics::{SourceLocation, ValidationError};
pub use validation::{ValidationIssue, validate_schema};
mod parser;

pub use ast::*;
pub use diagnostics::{ParseError, ParseErrorCode, SourceSpan};
pub use parser::parse_fga_schema;
