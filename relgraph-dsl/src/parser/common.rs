use nom::{IResult, error::Error};

use super::lexer::{Token, TokenKind};

#[derive(Debug, Clone, Copy)]
pub(super) struct TokenInput<'a> {
    tokens: &'a [Token],
    source: &'a str,
}

impl<'a> TokenInput<'a> {
    pub(super) fn new(tokens: &'a [Token], source: &'a str) -> Self {
        Self { tokens, source }
    }

    pub(super) fn first(self) -> Option<&'a Token> {
        self.tokens.first()
    }

    pub(super) fn is_empty(self) -> bool {
        self.tokens.is_empty()
    }

    pub(super) fn len(self) -> usize {
        self.tokens.len()
    }

    pub(super) fn tail(self) -> Self {
        Self {
            tokens: &self.tokens[1..],
            source: self.source,
        }
    }

    pub(super) fn take_from(self, index: usize) -> Self {
        Self {
            tokens: &self.tokens[index..],
            source: self.source,
        }
    }

    pub(super) fn take(self, count: usize) -> Self {
        Self {
            tokens: &self.tokens[..count],
            source: self.source,
        }
    }

    pub(super) fn get(self, index: usize) -> Option<&'a Token> {
        self.tokens.get(index)
    }

    pub(super) fn iter(self) -> std::slice::Iter<'a, Token> {
        self.tokens.iter()
    }

    pub(super) fn text(self, token: &Token) -> &'a str {
        &self.source[token.span.start..token.span.end]
    }
}

impl<'a> nom::Input for TokenInput<'a> {
    type Item = Token;
    type Iter = std::iter::Cloned<std::slice::Iter<'a, Token>>;
    type IterIndices = std::iter::Enumerate<Self::Iter>;

    fn input_len(&self) -> usize {
        self.tokens.len()
    }

    fn take(&self, index: usize) -> Self {
        Self {
            tokens: &self.tokens[..index],
            source: self.source,
        }
    }

    fn take_from(&self, index: usize) -> Self {
        Self {
            tokens: &self.tokens[index..],
            source: self.source,
        }
    }

    fn take_split(&self, index: usize) -> (Self, Self) {
        let (prefix, suffix) = self.tokens.split_at(index);
        (
            Self {
                tokens: suffix,
                source: self.source,
            },
            Self {
                tokens: prefix,
                source: self.source,
            },
        )
    }

    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.tokens.iter().cloned().position(predicate)
    }

    fn iter_elements(&self) -> Self::Iter {
        self.tokens.iter().cloned()
    }

    fn iter_indices(&self) -> Self::IterIndices {
        self.iter_elements().enumerate()
    }

    fn slice_index(&self, count: usize) -> Result<usize, nom::Needed> {
        if count <= self.tokens.len() {
            Ok(count)
        } else {
            Err(nom::Needed::new(count))
        }
    }
}

pub(super) type Res<'a, T> = IResult<TokenInput<'a>, T, Error<TokenInput<'a>>>;

pub(super) fn expect_kind<'a>(input: TokenInput<'a>, kind: TokenKind) -> Res<'a, Token> {
    match input.first() {
        Some(token) if token.kind == kind => Ok((input.tail(), token.clone())),
        _ => Err(nom::Err::Error(Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

pub(super) fn skip_layout<'a>(mut input: TokenInput<'a>) -> Res<'a, Vec<String>> {
    let mut comments = Vec::new();
    loop {
        match input.first().map(|token| token.kind) {
            Some(TokenKind::Whitespace | TokenKind::Newline) => input = input.tail(),
            Some(TokenKind::Hash) => {
                input = input.tail();
                let mut text = String::new();
                while let Some(token) = input.first() {
                    if token.kind == TokenKind::Newline {
                        input = input.tail();
                        break;
                    }
                    text.push_str(input.text(token));
                    input = input.tail();
                }
                comments.push(text.trim().to_string());
            }
            _ => break,
        }
    }
    Ok((input, comments))
}

/// Recognizes a declaration prefix: the `Newline` token before a type,
/// relation or condition, returning the `#` comment lines it spans.
///
/// Comment lines are hidden tokens, and the line breaks around them are joined
/// into this one token (see `visible_tokens`), so its source text holds the
/// comments written directly above the declaration, separated by blank lines
/// or not. Trailing ` #` comments of the previous line end before the token.
pub(super) fn declaration_prefix<'a>(
    input: TokenInput<'a>,
) -> Option<(TokenInput<'a>, Vec<String>)> {
    let newline = input.first()?;
    if newline.kind != TokenKind::Newline {
        return None;
    }
    let comments = input
        .text(newline)
        .split(['\n', '\r'])
        .filter_map(|line| line.trim_start().strip_prefix('#'))
        .map(|comment| comment.trim().to_string())
        .collect();
    Some((input.tail(), comments))
}

pub(super) fn skip_horizontal_whitespace<'a>(mut input: TokenInput<'a>) -> TokenInput<'a> {
    while input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Whitespace)
    {
        input = input.tail();
    }
    input
}

pub(super) fn is_identifier_kind(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Identifier
            | TokenKind::Module
            | TokenKind::Model
            | TokenKind::Schema
            | TokenKind::Type
            | TokenKind::Relation
            | TokenKind::Extend
    )
}

pub(super) fn is_extended_identifier_kind(kind: TokenKind) -> bool {
    kind == TokenKind::ExtendedIdentifier || is_identifier_kind(kind)
}

pub(super) fn parse_identifier<'a>(input: TokenInput<'a>) -> Res<'a, String> {
    match input.first() {
        Some(token) if is_identifier_kind(token.kind) => {
            Ok((input.tail(), input.text(token).to_string()))
        }
        _ => Err(nom::Err::Error(Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

pub(super) fn parse_extended_identifier<'a>(input: TokenInput<'a>) -> Res<'a, String> {
    match input.first() {
        Some(token) if is_extended_identifier_kind(token.kind) => {
            Ok((input.tail(), input.text(token).to_string()))
        }
        _ => Err(nom::Err::Error(Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

pub(super) fn span_from_consumed(
    start: TokenInput<'_>,
    rest: TokenInput<'_>,
) -> Option<crate::diagnostics::SourceSpan> {
    let consumed = start.len().checked_sub(rest.len())?;
    let consumed_tokens = start.take(consumed);
    let first = consumed_tokens.iter().find(|token| {
        !matches!(
            token.kind,
            TokenKind::Whitespace | TokenKind::Newline | TokenKind::Hash
        )
    })?;
    let last = consumed_tokens.iter().rev().find(|token| {
        !matches!(
            token.kind,
            TokenKind::Whitespace | TokenKind::Newline | TokenKind::Hash
        )
    })?;
    Some(crate::diagnostics::SourceSpan {
        start: first.span.start,
        end: last.span.end,
    })
}
