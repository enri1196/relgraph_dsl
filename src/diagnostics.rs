//! Source locations and syntax diagnostics returned by the parser.

use std::fmt;

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
