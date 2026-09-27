use nom::{error::Error, error::ErrorKind};

use super::cel::capture_expression;
use super::common::{Res, TokenInput, expect_kind, skip_layout, span_from_consumed};
use super::lexer::TokenKind;
use crate::ast::{ConditionDefinition, ConditionParameter, ParameterType};
use crate::diagnostics::SourceSpan;

fn parse_parameter_type(input: TokenInput<'_>) -> Res<'_, ParameterType> {
    if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::ConditionType)
    {
        let (input, simple) = expect_kind(input, TokenKind::ConditionType)?;
        return Ok((
            input,
            ParameterType::Simple(input.text(&simple).to_string()),
        ));
    }

    let (input, container) = expect_kind(input, TokenKind::ConditionContainer)?;
    let (input, _) = expect_kind(input, TokenKind::Less)?;
    let (input, inner) = expect_kind(input, TokenKind::ConditionType)?;
    let (input, _) = expect_kind(input, TokenKind::Greater)?;
    Ok((
        input,
        ParameterType::Generic {
            container: input.text(&container).to_string(),
            inner: input.text(&inner).to_string(),
        },
    ))
}

fn parse_parameter(input: TokenInput<'_>) -> Res<'_, ConditionParameter> {
    let start = input;
    let name_token = input
        .first()
        .filter(|token| token.kind == TokenKind::Identifier)
        .cloned()
        .ok_or_else(|| nom::Err::Error(Error::new(input, ErrorKind::Tag)))?;
    let (input, _) = expect_kind(input, TokenKind::Identifier)?;
    let (input, _) = skip_layout(input)?;
    let (input, _) = expect_kind(input, TokenKind::Colon)?;
    let (input, _) = skip_layout(input)?;
    let (input, param_type) = parse_parameter_type(input)?;
    let span = span_from_consumed(start, input).unwrap_or(SourceSpan {
        start: name_token.span.start,
        end: name_token.span.end,
    });
    Ok((
        input,
        ConditionParameter {
            name: start.text(&name_token).to_string(),
            param_type,
            span: Some(span),
        },
    ))
}

pub(super) fn parse_condition_definition<'a>(
    input: TokenInput<'a>,
    comments_before: Vec<String>,
    source: &str,
) -> Res<'a, ConditionDefinition> {
    let (input, condition_token) = expect_kind(input, TokenKind::Condition)?;
    let (input, _) = expect_kind(input, TokenKind::Whitespace)?;
    let (input, name_token) = expect_kind(input, TokenKind::Identifier)?;
    let (mut input, _) = expect_kind(input, TokenKind::LParen)?;

    let mut parameters = Vec::new();
    loop {
        let (rest, _) = skip_layout(input)?;
        let (rest, parameter) = parse_parameter(rest)?;
        parameters.push(parameter);
        let (rest, _) = skip_layout(rest)?;
        if rest
            .first()
            .is_some_and(|token| token.kind == TokenKind::Comma)
        {
            input = rest.tail();
            continue;
        }
        input = rest;
        break;
    }
    let (input, _) = expect_kind(input, TokenKind::RParen)?;
    let (input, _) = skip_layout(input)?;
    let (input, open_brace) = expect_kind(input, TokenKind::LBrace)?;

    let (input_after_close, (expression, close_brace_span)) =
        capture_expression(input, source, &open_brace)?;

    let span = SourceSpan {
        start: condition_token.span.start,
        end: close_brace_span.end,
    };
    Ok((
        input_after_close,
        ConditionDefinition {
            name: input.text(&name_token).to_string(),
            parameters,
            expression,
            comments_before,
            span: Some(span),
        },
    ))
}
