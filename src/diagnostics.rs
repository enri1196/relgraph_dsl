//! Source locations and syntax diagnostics returned by the parser.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub code: ParseErrorCode,
    pub span: SourceSpan,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorCode {
    InvalidToken,
    UnexpectedToken,
    UnexpectedEof,
}

impl ParseErrorCode {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidToken => "InvalidToken",
            Self::UnexpectedToken => "UnexpectedToken",
            Self::UnexpectedEof => "UnexpectedEof",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at bytes {}..{}: {}",
            self.code.code(),
            self.span.start,
            self.span.end,
            self.message
        )
    }
}

impl std::error::Error for ParseError {}

/// Identifies a source document, optional module, and declaration span.
///
/// Standalone validation leaves `file` and `module` unset. Modular validation
/// fills them with the normalized manifest path and declared module name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    /// Normalized manifest-relative path for modular source, if available.
    pub file: Option<PathBuf>,
    /// Declared module name for modular source, if available.
    pub module: Option<String>,
    /// Byte span of the owning declaration, when the AST has one.
    pub span: Option<SourceSpan>,
}

/// A typed static-validation diagnostic with optional related declarations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Machine-readable validation rule that failed.
    pub issue: crate::validation::ValidationIssue,
    /// Location of the declaration that owns the issue.
    pub location: SourceLocation,
    /// Other source locations that help explain the issue, such as the first
    /// declaration involved in a duplicate.
    pub related: Vec<SourceLocation>,
    /// Human-readable explanation. Message wording is not a stable API.
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.issue.code(), self.message)
    }
}

impl std::error::Error for ValidationError {}
