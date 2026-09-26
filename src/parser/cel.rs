use nom::{error::Error, error::ErrorKind};

use super::common::{Res, TokenInput};
use super::lexer::{Token, TokenKind};
use crate::diagnostics::SourceSpan;

/// Captures the exact CEL source bytes up to the first visible closing brace.
pub(super) fn capture_expression<'a>(
    input: TokenInput<'a>,
    source: &str,
    open_brace: &Token,
) -> Res<'a, (String, SourceSpan)> {
    let Some(close_index) = input
        .iter()
        .position(|token| token.kind == TokenKind::RBrace)
    else {
        return Err(nom::Err::Error(Error::new(
            input.take_from(input.len()),
            ErrorKind::Eof,
        )));
    };

    let close_brace = input
        .get(close_index)
        .expect("position returned an in-range index");
    let body_start = open_brace.span.end;
    let body_end = close_brace.span.start;
    let expression = source
        .get(body_start..body_end)
        .unwrap_or_default()
        .to_string();

    Ok((
        input.take_from(close_index + 1),
        (expression, close_brace.span.clone()),
    ))
}
