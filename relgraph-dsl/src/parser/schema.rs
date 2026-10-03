use nom::{IResult, Parser, error::Error};

use super::common::{Res, TokenInput, expect_kind, parse_extended_identifier, parse_identifier};
use super::condition::parse_condition_definition;
use super::lexer::{Token, TokenKind, lex};
use super::relation::parse_relations_block;
use crate::ast::{Schema, SchemaHeader, TypeDefinition};
use crate::diagnostics::{ParseError, ParseErrorCode, SourceSpan};

fn parse_header(input: TokenInput<'_>) -> Res<'_, (SchemaHeader, SourceSpan)> {
    let (input, _) = skip_header_comments(input)?;
    match input.first().map(|token| token.kind) {
        Some(TokenKind::Model) => {
            let (input, model) = expect_kind(input, TokenKind::Model)?;
            let (input, _) = expect_kind(input, TokenKind::Newline)?;
            let (input, _) = expect_kind(input, TokenKind::Schema)?;
            let (input, _) = expect_kind(input, TokenKind::Whitespace)?;
            let (input, version) = expect_kind(input, TokenKind::SchemaVersion)?;
            let input = take_optional_whitespace(input);
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
            let input = take_optional_whitespace(input);
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

fn skip_header_comments(mut input: TokenInput<'_>) -> Res<'_, ()> {
    while input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Hash)
    {
        input = input.tail();
        while input
            .first()
            .is_some_and(|token| token.kind != TokenKind::Newline)
        {
            input = input.tail();
        }
        let (rest, _) = expect_kind(input, TokenKind::Newline)?;
        input = rest;
    }
    Ok((input, ()))
}

fn take_optional_whitespace(input: TokenInput<'_>) -> TokenInput<'_> {
    if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Whitespace)
    {
        input.tail()
    } else {
        input
    }
}

/// Maximum parenthesis nesting supported in one relation expression.
pub(super) const MAX_RELATION_EXPRESSION_DEPTH: usize = 128;
/// Maximum expression and target nodes constructed for one relation.
pub(super) const MAX_RELATION_EXPRESSION_NODES: usize = 512;
/// Maximum type, relation, condition, and condition-parameter declarations in one model.
const MAX_SCHEMA_DECLARATIONS: usize = 4096;

pub(super) fn consume_declaration<'a>(input: TokenInput<'a>, count: &mut usize) -> Res<'a, ()> {
    if *count >= MAX_SCHEMA_DECLARATIONS {
        return Err(construction_limit_error(input));
    }
    *count += 1;
    Ok((input, ()))
}

fn construction_limit_error<'a>(input: TokenInput<'a>) -> nom::Err<Error<TokenInput<'a>>> {
    nom::Err::Failure(Error::new(input, nom::error::ErrorKind::TooLarge))
}

fn parse_type_definition<'a>(
    input: TokenInput<'a>,
    comments_before: Vec<String>,
    declaration_count: &mut usize,
) -> Res<'a, TypeDefinition> {
    let (input, _) = consume_declaration(input, declaration_count)?;
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

    let (rest, relations) = if input.first().is_some_and(|token| {
        token.kind == TokenKind::Newline
            && input
                .tail()
                .first()
                .is_some_and(|next| next.kind == TokenKind::Relations)
    }) {
        parse_relations_block(input.tail(), Vec::new(), declaration_count)?
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
    let input = if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Whitespace)
    {
        input.tail()
    } else {
        input
    };
    let input = if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Newline)
    {
        input.tail()
    } else {
        input
    };
    let (mut input, (header, header_span)) = parse_header(input)?;

    let mut declaration_count = 0;
    let mut type_definitions = Vec::new();
    loop {
        let Some((declaration, comments)) = super::common::declaration_prefix(input) else {
            break;
        };
        if !declaration
            .first()
            .is_some_and(|token| matches!(token.kind, TokenKind::Type | TokenKind::Extend))
        {
            break;
        }
        let (rest, type_definition) =
            parse_type_definition(declaration, comments, &mut declaration_count)?;
        type_definitions.push(type_definition);
        input = rest;
    }

    let mut condition_definitions = Vec::new();
    loop {
        let Some((declaration, comments)) = super::common::declaration_prefix(input) else {
            break;
        };
        if !declaration
            .first()
            .is_some_and(|token| token.kind == TokenKind::Condition)
        {
            break;
        }
        let (declaration, _) = consume_declaration(declaration, &mut declaration_count)?;
        let (rest, condition) = parse_condition_definition(declaration, comments, source)?;
        if declaration_count.saturating_add(condition.parameters.len()) > MAX_SCHEMA_DECLARATIONS {
            return Err(construction_limit_error(declaration));
        }
        declaration_count += condition.parameters.len();
        condition_definitions.push(condition);
        input = rest;
    }

    if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Newline)
    {
        input = input.tail();
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

/// Parses one OpenFGA DSL document into its syntax tree without static validation.
///
/// Numeric `major.minor` versions are preserved as written and checked later by
/// [`crate::validate_schema`] or [`crate::validate_modular_model`]. Condition
/// bodies preserve their bytes and stop at the first visible `}` token. Errors
/// use typed codes and spans into the original input; callers migrating from the
/// pre-1.0 `String` error should inspect [`ParseError::code`] and `ParseError::span`.
/// Parses an FGA schema while bounding recursive relation-expression construction.
///
/// Relation expressions are limited to 128 nested parentheses and 512 expression
/// or target nodes per relation. A model may contain at most 4,096 type,
/// relation, condition, and condition-parameter declarations. Exceeding a limit
/// returns [`ParseErrorCode::ConstructionLimitExceeded`] with the source span of
/// the token where parsing reached the limit.
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
            let is_construction_limit = error.code == nom::error::ErrorKind::TooLarge;
            let span = token.map_or(
                SourceSpan {
                    start: input.len(),
                    end: input.len(),
                },
                |token| token.span.clone(),
            );
            let code = if is_construction_limit {
                ParseErrorCode::ConstructionLimitExceeded
            } else if is_eof {
                ParseErrorCode::UnexpectedEof
            } else {
                ParseErrorCode::UnexpectedToken
            };
            let message = if is_construction_limit {
                format!(
                    "schema exceeds parser construction limits: relation expressions allow at most {} nested parentheses and {} expression or target nodes, and models allow at most {} declarations",
                    MAX_RELATION_EXPRESSION_DEPTH,
                    MAX_RELATION_EXPRESSION_NODES,
                    MAX_SCHEMA_DECLARATIONS,
                )
            } else {
                token.map_or_else(
                    || "unexpected end of input".to_string(),
                    |token| format!("unexpected token {:?}", error.input.text(token)),
                )
            };
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
