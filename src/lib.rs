//! A parser for OpenFGA schema DSL documents.

pub mod ast;
mod parser;

pub use ast::*;
pub use parser::parse_fga_schema;
