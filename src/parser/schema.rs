use nom::{IResult, Parser, error::Error};

use super::common::{
    Res, TokenInput, expect_kind, parse_extended_identifier, parse_identifier, skip_layout,
};
use super::condition::parse_condition_definition;
use super::lexer::{Token, TokenKind, lex};
use super::relation::parse_relations_block;
use crate::ast::{Schema, SchemaHeader, TypeDefinition};
use crate::diagnostics::{ParseError, ParseErrorCode, SourceSpan};

fn parse_header(input: TokenInput<'_>) -> Res<'_, (SchemaHeader, SourceSpan)> {
    match input.first().map(|token| token.kind) {
        Some(TokenKind::Model) => {
            let (input, model) = expect_kind(input, TokenKind::Model)?;
            let (input, _) = expect_kind(input, TokenKind::Newline)?;
            let (input, _) = expect_kind(input, TokenKind::Schema)?;
            let (input, _) = expect_kind(input, TokenKind::Whitespace)?;
            let (input, version) = expect_kind(input, TokenKind::SchemaVersion)?;
            let header = SchemaHeader::ModelSchema {
                version: input.text(&version).to_string(),
            };
            Ok((
                input,
                (
                    header,
                    SourceSpan {
                        start: model.span.start,
                        end: version.span.end,
                    },
                ),
            ))
        }
        Some(TokenKind::Module) => {
            let (input, module) = expect_kind(input, TokenKind::Module)?;
            let (input, _) = expect_kind(input, TokenKind::Whitespace)?;
            let name_end = input
                .first()
                .map_or(module.span.end, |token| token.span.end);
            let (input, name) = parse_identifier(input)?;
            Ok((
                input,
                (
                    SchemaHeader::Module { name },
                    SourceSpan {
                        start: module.span.start,
                        end: name_end,
                    },
                ),
            ))
        }
        _ => Err(nom::Err::Error(Error::new(
            input,
            nom::error::ErrorKind::Alt,
        ))),
    }
}

fn parse_type_definition(
    input: TokenInput<'_>,
    comments_before: Vec<String>,
) -> Res<'_, TypeDefinition> {
    let start = input;
    let (input, is_extended) = if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Extend)
    {
        let (input, _) = expect_kind(input, TokenKind::Extend)?;
        let (input, _) = expect_kind(input, TokenKind::Whitespace)?;
        (input, true)
    } else {
        (input, false)
    };
    let (input, _) = expect_kind(input, TokenKind::Type)?;
    let (input, _) = expect_kind(input, TokenKind::Whitespace)?;
    let name_end = input.first().map_or(0, |token| token.span.end);
    let (input, name) = parse_extended_identifier(input)?;

    let (after_layout, relation_comments) = skip_layout(input)?;
    let (rest, relations) = if after_layout
        .first()
        .is_some_and(|token| token.kind == TokenKind::Relations)
    {
        parse_relations_block(after_layout, relation_comments)?
    } else {
        (input, Vec::new())
    };

    let span = Some(SourceSpan {
        start: start.first().map_or(0, |first| first.span.start),
        end: relations
            .last()
            .and_then(|relation| relation.span.as_ref())
            .map_or(name_end, |relation_span| relation_span.end),
    });
    Ok((
        rest,
        TypeDefinition {
            is_extended,
            name,
            relations,
            comments_before,
            span,
        },
    ))
}

fn parse_schema_internal<'a>(input: TokenInput<'a>, source: &str) -> Res<'a, Schema> {
    let (input, _) = skip_layout(input)?;
    let (input, (header, header_span)) = parse_header(input)?;
    let (mut input, mut pending_comments) = skip_layout(input)?;

    let mut type_definitions = Vec::new();
    loop {
        if !input
            .first()
            .is_some_and(|token| matches!(token.kind, TokenKind::Type | TokenKind::Extend))
        {
            break;
        }
        let (rest, type_definition) = parse_type_definition(input, pending_comments)?;
        type_definitions.push(type_definition);
        let (next, comments) = skip_layout(rest)?;
        input = next;
        pending_comments = comments;
    }

    let mut condition_definitions = Vec::new();
    while input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Condition)
    {
        let (rest, condition) = parse_condition_definition(input, pending_comments, source)?;
        condition_definitions.push(condition);
        let (next, comments) = skip_layout(rest)?;
        input = next;
        pending_comments = comments;
    }

    if input.is_empty() {
        Ok((
            input,
            Schema {
                header,
                header_span: Some(header_span),
                type_definitions,
                condition_definitions,
            },
        ))
    } else {
        Err(nom::Err::Error(Error::new(
            input,
            nom::error::ErrorKind::Eof,
        )))
    }
}

/// Parses one OpenFGA DSL document into its syntax tree.
pub fn parse_fga_schema(input: &str) -> Result<Schema, ParseError> {
    let tokens = lex(input)?;
    let visible_tokens: Vec<Token> = tokens
        .iter()
        .filter(|token| !token.hidden)
        .cloned()
        .collect();
    let mut parser = nom::combinator::all_consuming(|tokens| parse_schema_internal(tokens, input));
    let parse_result: IResult<_, _, Error<_>> =
        parser.parse(TokenInput::new(&visible_tokens, input));
    match parse_result {
        Ok((_, schema)) => Ok(schema),
        Err(nom::Err::Error(error)) | Err(nom::Err::Failure(error)) => {
            let token = error.input.first();
            let is_eof = token.is_none();
            let span = token.map_or(
                SourceSpan {
                    start: input.len(),
                    end: input.len(),
                },
                |token| token.span.clone(),
            );
            let code = if is_eof {
                ParseErrorCode::UnexpectedEof
            } else {
                ParseErrorCode::UnexpectedToken
            };
            let message = token.map_or_else(
                || "unexpected end of input".to_string(),
                |token| format!("unexpected token {:?}", error.input.text(token)),
            );
            Err(ParseError {
                code,
                span,
                message,
            })
        }
        Err(nom::Err::Incomplete(_)) => Err(ParseError {
            code: ParseErrorCode::UnexpectedEof,
            span: SourceSpan {
                start: input.len(),
                end: input.len(),
            },
            message: "unexpected end of input".to_string(),
        }),
    }
}
