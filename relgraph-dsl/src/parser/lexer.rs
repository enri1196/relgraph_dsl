use crate::diagnostics::{ParseError, ParseErrorCode, SourceSpan};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TokenKind {
    Hash,
    Colon,
    Comma,
    And,
    Or,
    ButNot,
    From,
    Module,
    Model,
    Schema,
    SchemaVersion,
    Extend,
    Type,
    Condition,
    Relations,
    Relation,
    Define,
    With,
    Equals,
    NotEquals,
    In,
    Less,
    LessEquals,
    GreaterEquals,
    Greater,
    LogicalAnd,
    LogicalOr,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    LParen,
    RParen,
    Dot,
    Minus,
    Exclam,
    QuestionMark,
    Plus,
    Star,
    Slash,
    Percent,
    CelTrue,
    CelFalse,
    Null,
    Whitespace,
    Newline,
    CelComment,
    /// A hidden `#` comment that the OpenFGA tooling strips before parsing:
    /// a line whose first non-blank character is `#`, or a ` #` tail with its
    /// preceding horizontal whitespace. Never produced inside a condition body.
    Comment,
    NumberFloat,
    NumberInt,
    NumberUint,
    String,
    Bytes,
    DollarExpression,
    Identifier,
    ExtendedIdentifier,
    ConditionContainer,
    ConditionType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Token {
    pub kind: TokenKind,
    pub span: SourceSpan,
    pub hidden: bool,
}

impl Token {
    fn new(kind: TokenKind, start: usize, end: usize, hidden: bool) -> Self {
        Self {
            kind,
            span: SourceSpan { start, end },
            hidden,
        }
    }
}

/// Where the lexer is relative to a condition declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConditionState {
    /// Outside any condition, or after a condition body's closing brace.
    Outside,
    /// Inside the parameter list (the pinned grammar's `CONDITION_DEF` mode).
    Parameters,
    /// After the parameter list, before the body's opening brace.
    BeforeBody,
    /// Inside the body, up to the first visible closing brace.
    Body,
}

/// Tokenizes the complete original document before the parser sees any input.
///
/// `#` comments follow the OpenFGA tooling (`parseDSL` in `openfga/language`),
/// which blanks every line whose first non-blank character is `#` and cuts
/// every other line at its first ` #` before running the grammar. Relgraph
/// does not rewrite the input: such comments become hidden [`TokenKind::Comment`]
/// tokens with their original spans. Inside a condition body no comment is
/// recognized, so CEL bytes are preserved exactly; elsewhere a `#` that is not
/// a comment (for example in `group#member`) stays a visible `Hash` token.
pub(super) fn lex(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let mut offset = 0;
    let mut condition = ConditionState::Outside;
    // True while only horizontal whitespace precedes `offset` on its line.
    let mut at_line_start = true;

    while offset < input.len() {
        let remaining = &input[offset..];
        let candidate = if condition == ConditionState::Parameters {
            lex_condition_token(remaining)
        } else if condition != ConditionState::Body
            && let Some(length) = hash_comment_length(remaining, at_line_start)
        {
            Some((length, TokenKind::Comment, true))
        } else {
            lex_default_token(remaining)
        };

        let Some((length, kind, hidden)) = candidate else {
            let scalar_length = remaining.chars().next().map(char::len_utf8).unwrap_or(0);
            let (code, message) = if matches!(remaining.chars().next(), Some('\'' | '"')) {
                (
                    ParseErrorCode::InvalidToken,
                    "unterminated or invalid string token".to_string(),
                )
            } else {
                (
                    ParseErrorCode::InvalidToken,
                    format!("invalid input character {:?}", remaining.chars().next()),
                )
            };
            return Err(ParseError {
                code,
                span: SourceSpan {
                    start: offset,
                    end: offset + scalar_length,
                },
                message,
            });
        };

        let end = offset + length;
        let token = Token::new(kind, offset, end, hidden);
        condition = match (condition, kind) {
            (ConditionState::Parameters, TokenKind::RParen) => ConditionState::BeforeBody,
            (ConditionState::Parameters, _) => ConditionState::Parameters,
            (ConditionState::BeforeBody, TokenKind::LBrace) => ConditionState::Body,
            (ConditionState::Body, TokenKind::RBrace) => ConditionState::Outside,
            (ConditionState::Body, _) => ConditionState::Body,
            (_, TokenKind::Condition) => ConditionState::Parameters,
            (
                ConditionState::BeforeBody,
                TokenKind::Whitespace
                | TokenKind::Newline
                | TokenKind::CelComment
                | TokenKind::Comment,
            ) => ConditionState::BeforeBody,
            _ => ConditionState::Outside,
        };
        at_line_start = match kind {
            TokenKind::Newline => true,
            TokenKind::Whitespace => at_line_start,
            _ => false,
        };
        tokens.push(token);
        offset = end;
    }

    Ok(tokens)
}

/// Length of a hidden `#` comment starting at `input`, if one starts here.
///
/// At the start of a line (only horizontal whitespace before it), a `#`
/// begins a comment line. Elsewhere, a horizontal whitespace run whose last
/// character is a space and that is followed by `#` begins a trailing
/// comment, which includes that whitespace (the tooling trims it). Both run
/// to the end of the line, excluding the line break.
fn hash_comment_length(input: &str, at_line_start: bool) -> Option<usize> {
    let bytes = input.as_bytes();
    let whitespace = bytes
        .iter()
        .take_while(|byte| is_horizontal_space(**byte))
        .count();
    if bytes.get(whitespace) != Some(&b'#') {
        return None;
    }
    if !at_line_start && (whitespace == 0 || bytes[whitespace - 1] != b' ') {
        return None;
    }
    Some(
        bytes
            .iter()
            .position(|byte| matches!(byte, b'\n' | b'\r'))
            .unwrap_or(bytes.len()),
    )
}

fn lex_condition_token(input: &str) -> Option<(usize, TokenKind, bool)> {
    let bytes = input.as_bytes();
    let first = *bytes.first()?;

    if is_horizontal_space(first) {
        let length = bytes
            .iter()
            .take_while(|byte| is_horizontal_space(**byte))
            .count();
        return Some((length, TokenKind::Whitespace, false));
    }
    if first == b')' {
        return Some((1, TokenKind::RParen, false));
    }
    if first == b'(' {
        return Some((1, TokenKind::LParen, false));
    }
    if first == b':' {
        return Some((1, TokenKind::Colon, false));
    }
    if first == b',' {
        return Some((1, TokenKind::Comma, false));
    }
    if first == b'<' {
        return Some((1, TokenKind::Less, false));
    }
    if first == b'>' {
        return Some((1, TokenKind::Greater, false));
    }
    if is_identifier_start(first) {
        let length = ascii_identifier_length(bytes);
        let word = &input[..length];
        let kind = match word {
            "map" | "list" => TokenKind::ConditionContainer,
            "bool" | "string" | "int" | "uint" | "double" | "duration" | "timestamp"
            | "ipaddress" => TokenKind::ConditionType,
            _ => TokenKind::Identifier,
        };
        return Some((length, kind, false));
    }
    None
}

fn lex_default_token(input: &str) -> Option<(usize, TokenKind, bool)> {
    let bytes = input.as_bytes();
    let mut best: Option<(usize, usize, TokenKind, bool)> = None;
    let mut priority = 0usize;

    macro_rules! candidate {
        ($length:expr, $kind:expr, $hidden:expr) => {{
            let length = $length;
            if length > 0
                && best
                    .as_ref()
                    .is_none_or(|(best_length, best_priority, _, _)| {
                        length > *best_length
                            || (length == *best_length && priority < *best_priority)
                    })
            {
                best = Some((length, priority, $kind, $hidden));
            }
            priority += 1;
        }};
    }

    macro_rules! literal {
        ($text:literal, $kind:expr) => {
            candidate!(literal_prefix_length(input, $text), $kind, false)
        };
    }

    literal!("#", TokenKind::Hash);
    literal!(":", TokenKind::Colon);
    literal!(",", TokenKind::Comma);
    literal!("and", TokenKind::And);
    literal!("or", TokenKind::Or);
    literal!("but not", TokenKind::ButNot);
    literal!("from", TokenKind::From);
    literal!("module", TokenKind::Module);
    literal!("model", TokenKind::Model);
    literal!("schema", TokenKind::Schema);
    candidate!(
        schema_version_length(bytes),
        TokenKind::SchemaVersion,
        false
    );
    literal!("extend", TokenKind::Extend);
    literal!("type", TokenKind::Type);
    literal!("condition", TokenKind::Condition);
    literal!("relations", TokenKind::Relations);
    literal!("relation", TokenKind::Relation);
    literal!("define", TokenKind::Define);
    literal!("with", TokenKind::With);

    literal!("==", TokenKind::Equals);
    literal!("!=", TokenKind::NotEquals);
    literal!("in", TokenKind::In);
    literal!("<=", TokenKind::LessEquals);
    literal!("<", TokenKind::Less);
    literal!(">=", TokenKind::GreaterEquals);
    literal!(">", TokenKind::Greater);
    literal!("&&", TokenKind::LogicalAnd);
    literal!("||", TokenKind::LogicalOr);
    literal!("[", TokenKind::LBracket);
    literal!("]", TokenKind::RBracket);
    literal!("{", TokenKind::LBrace);
    literal!("}", TokenKind::RBrace);
    literal!("(", TokenKind::LParen);
    literal!(")", TokenKind::RParen);
    literal!(".", TokenKind::Dot);
    literal!("-", TokenKind::Minus);
    literal!("!", TokenKind::Exclam);
    literal!("?", TokenKind::QuestionMark);
    literal!("+", TokenKind::Plus);
    literal!("*", TokenKind::Star);
    literal!("/", TokenKind::Slash);
    literal!("%", TokenKind::Percent);
    literal!("true", TokenKind::CelTrue);
    literal!("false", TokenKind::CelFalse);
    literal!("null", TokenKind::Null);

    let whitespace_length = bytes
        .iter()
        .take_while(|byte| is_horizontal_space(**byte))
        .count();
    candidate!(whitespace_length, TokenKind::Whitespace, false);

    if input.starts_with("//") {
        let end = input.find('\n').unwrap_or(input.len());
        candidate!(end, TokenKind::CelComment, true);
    } else {
        candidate!(0, TokenKind::CelComment, true);
    }

    candidate!(float_length(bytes), TokenKind::NumberFloat, false);
    candidate!(unsigned_length(bytes), TokenKind::NumberUint, false);
    candidate!(integer_length(bytes), TokenKind::NumberInt, false);
    candidate!(string_length(input), TokenKind::String, false);
    candidate!(bytes_string_length(input), TokenKind::Bytes, false);
    literal!("$expression", TokenKind::DollarExpression);

    let identifier_length = ascii_identifier_length(bytes);
    candidate!(identifier_length, TokenKind::Identifier, false);
    candidate!(
        extended_identifier_length(bytes),
        TokenKind::ExtendedIdentifier,
        false
    );
    candidate!(newline_length(bytes), TokenKind::Newline, false);

    let _final_priority = priority;
    best.map(|(length, _, kind, hidden)| (length, kind, hidden))
}

fn literal_prefix_length(input: &str, literal: &str) -> usize {
    if input.starts_with(literal) {
        literal.len()
    } else {
        0
    }
}

fn is_horizontal_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | 0x0c)
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn ascii_identifier_length(bytes: &[u8]) -> usize {
    if !bytes.first().is_some_and(|byte| is_identifier_start(*byte)) {
        return 0;
    }
    bytes
        .iter()
        .take_while(|byte| is_identifier_continue(**byte))
        .count()
}

fn extended_identifier_length(bytes: &[u8]) -> usize {
    if !bytes.first().is_some_and(|byte| is_identifier_start(*byte)) {
        return 0;
    }
    let mut index = 1;
    while index < bytes.len() {
        let segment_start = index;
        let mut cursor = index;
        if matches!(bytes[cursor], b'/' | b'.' | b'-') {
            cursor += 1;
        }
        let word_start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        if cursor == word_start {
            break;
        }
        index = cursor;
        if index == segment_start {
            break;
        }
    }
    index
}

fn schema_version_length(bytes: &[u8]) -> usize {
    let major = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if major == 0 || bytes.get(major) != Some(&b'.') {
        return 0;
    }
    let minor = bytes[major + 1..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if minor == 0 { 0 } else { major + 1 + minor }
}

fn newline_length(bytes: &[u8]) -> usize {
    let mut cursor = 0;
    while cursor < bytes.len() && is_horizontal_space(bytes[cursor]) {
        cursor += 1;
    }
    let mut newline_seen = false;
    loop {
        if cursor >= bytes.len() {
            break;
        }
        match bytes[cursor] {
            b'\r' => {
                cursor += 1;
                if bytes.get(cursor) == Some(&b'\n') {
                    cursor += 1;
                }
                newline_seen = true;
            }
            b'\n' | 0x0c => {
                cursor += 1;
                newline_seen = true;
            }
            _ => break,
        }
        while cursor < bytes.len() && is_horizontal_space(bytes[cursor]) {
            cursor += 1;
        }
        let next = cursor;
        if !matches!(bytes.get(next), Some(b'\r' | b'\n' | 0x0c)) {
            break;
        }
    }
    if newline_seen { cursor } else { 0 }
}

fn float_length(bytes: &[u8]) -> usize {
    if bytes.first() == Some(&b'.') {
        let digits = take_digits(bytes, 1);
        if digits == 1 {
            return 0;
        }
        return exponent_end(bytes, digits);
    }

    let before = take_digits(bytes, 0);
    if before == 0 {
        return 0;
    }
    let mut cursor = before;
    let mut has_decimal = false;
    if bytes.get(cursor) == Some(&b'.') {
        let after = take_digits(bytes, cursor + 1);
        if after > cursor + 1 {
            cursor = after;
            has_decimal = true;
        }
    }
    let exp = exponent_end(bytes, cursor);
    if has_decimal || exp > cursor { exp } else { 0 }
}

fn exponent_end(bytes: &[u8], start: usize) -> usize {
    if !matches!(bytes.get(start), Some(b'e' | b'E')) {
        return start;
    }
    let mut cursor = start + 1;
    if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
        cursor += 1;
    }
    let end = take_digits(bytes, cursor);
    if end == cursor { start } else { end }
}

fn integer_length(bytes: &[u8]) -> usize {
    if bytes.starts_with(b"0x") {
        let end = bytes[2..]
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        if end > 0 { end + 2 } else { 0 }
    } else {
        take_digits(bytes, 0)
    }
}

fn unsigned_length(bytes: &[u8]) -> usize {
    let end = integer_length(bytes);
    if end == 0 {
        return 0;
    }
    if matches!(bytes.get(end), Some(b'u' | b'U')) {
        end + 1
    } else {
        0
    }
}

fn take_digits(bytes: &[u8], start: usize) -> usize {
    start
        + bytes[start..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count()
}

fn bytes_string_length(input: &str) -> usize {
    let bytes = input.as_bytes();
    if !matches!(bytes.first(), Some(b'b' | b'B')) {
        return 0;
    }
    let content_length = string_length(&input[1..]);
    if content_length == 0 {
        0
    } else {
        content_length + 1
    }
}

fn string_length(input: &str) -> usize {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let raw =
        matches!(bytes.first(), Some(b'r' | b'R')) && matches!(bytes.get(1), Some(b'\'' | b'"'));
    let start = usize::from(raw);
    let Some(&quote) = bytes.get(start) else {
        return 0;
    };
    if !matches!(quote, b'\'' | b'"') {
        return 0;
    }
    let triple = bytes.get(start..start + 3) == Some(&[quote, quote, quote]);
    let content_start = start + if triple { 3 } else { 1 };

    if raw {
        if triple {
            return find_bytes(&bytes[content_start..], &[quote, quote, quote])
                .map(|closing| content_start + closing + 3)
                .unwrap_or(0);
        }
        let mut cursor = content_start;
        while cursor < bytes.len() {
            if bytes[cursor] == quote {
                return cursor + 1;
            }
            if matches!(bytes[cursor], b'\n' | b'\r') {
                return 0;
            }
            cursor += 1;
        }
        return 0;
    }

    let mut cursor = content_start;
    while cursor < bytes.len() {
        if triple {
            if bytes.get(cursor..cursor + 3) == Some(&[quote, quote, quote]) {
                return cursor + 3;
            }
        } else if bytes[cursor] == quote {
            return cursor + 1;
        }

        if bytes[cursor] == b'\\' {
            let Some(end) = escape_end(bytes, cursor) else {
                return 0;
            };
            cursor = end;
            continue;
        }
        if !triple && matches!(bytes[cursor], b'\n' | b'\r') {
            return 0;
        }
        // Triple-quoted STRING permits newlines but not an unescaped backslash (handled above).
        let width = input[cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(1);
        cursor += width;
    }
    0
}

fn escape_end(bytes: &[u8], start: usize) -> Option<usize> {
    let escaped = *bytes.get(start + 1)?;
    if matches!(
        escaped,
        b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v' | b'"' | b'\'' | b'\\' | b'?' | b'`'
    ) {
        return Some(start + 2);
    }
    if (b'0'..=b'3').contains(&escaped)
        && bytes.get(start + 2..start + 4).is_some_and(|digits| {
            digits.len() == 2 && digits.iter().all(|digit| (b'0'..=b'7').contains(digit))
        })
    {
        return Some(start + 4);
    }
    if matches!(escaped, b'x' | b'X')
        && bytes
            .get(start + 2..start + 4)
            .is_some_and(|digits| digits.len() == 2 && digits.iter().all(u8::is_ascii_hexdigit))
    {
        return Some(start + 4);
    }
    if escaped == b'u'
        && bytes
            .get(start + 2..start + 6)
            .is_some_and(|digits| digits.len() == 4 && digits.iter().all(u8::is_ascii_hexdigit))
    {
        return Some(start + 6);
    }
    if escaped == b'U'
        && bytes
            .get(start + 2..start + 10)
            .is_some_and(|digits| digits.len() == 8 && digits.iter().all(u8::is_ascii_hexdigit))
    {
        return Some(start + 10);
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
