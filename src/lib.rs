//! A parser for OpenFGA schema DSL documents.

pub mod ast;
pub mod diagnostics;
mod parser;

pub use ast::*;
pub use diagnostics::{ParseError, ParseErrorCode, SourceSpan};
pub use parser::parse_fga_schema;
