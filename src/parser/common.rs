use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_till, take_while1},
    character::complete::{alpha1, alphanumeric1, multispace1, one_of},
    combinator::{map, opt, recognize},
    error::{Error, context},
    multi::many0,
    sequence::{pair, preceded, terminated},
};

pub(super) type Res<T, U> = IResult<T, U, Error<T>>;

// Consumes at least one EOL (CRLF, LF, CR, FF)
fn eol_any<'a>(input: &'a str) -> Res<&'a str, &'a str> {
    alt((tag("\r\n"), tag("\n"), tag("\r"), tag("\u{000C}"))).parse(input)
}

// `spnl` (space and newlines): consumes inline whitespace, comments (and their newlines), and any other newlines.
// Returns collected comments.
pub(super) fn spnl<'a>(input: &'a str) -> Res<&'a str, Vec<String>> {
    map(
        many0(alt((
            map(multispace1, |_| None), // Consume any whitespace including newlines
            map(
                preceded(
                    tag("#"),
                    terminated(take_till(|c| c == '\n' || c == '\r'), eol_any),
                ),
                |s: &str| Some(s.trim().to_string()),
            ), // # comment
            map(
                preceded(
                    tag("//"),
                    terminated(take_till(|c| c == '\n' || c == '\r'), eol_any),
                ),
                |s: &str| Some(s.trim().to_string()),
            ), // // comment (for CEL, but good to have)
        ))),
        |v| v.into_iter().flatten().collect(),
    )
    .parse(input)
}

// Parses an FGA identifier: (LETTER | '_') (LETTER | DIGIT | '_' | MINUS)*
pub(super) fn fga_identifier<'a>(input: &'a str) -> Res<&'a str, String> {
    context(
        "fga_identifier",
        map(
            recognize(pair(
                alt((alpha1, tag("_"))),
                many0(alt((alphanumeric1, tag("_"), tag("-")))),
            )),
            |s: &str| s.to_string(),
        ),
    )
    .parse(input)
}

// Parses an FGA extended_identifier: (LETTER | '_')((SLASH | DOT | MINUS)?(LETTER | DIGIT | '_')+)*
pub(super) fn fga_extended_identifier<'a>(input: &'a str) -> Res<&'a str, String> {
    context(
        "fga_extended_identifier",
        map(
            recognize(pair(
                alt((alpha1, tag("_"))), // Starts with letter or underscore
                many0(pair(
                    // Zero or more segments
                    opt(one_of("/.-")), // Optional separator
                    take_while1(|c: char| c.is_alphanumeric() || c == '_'), // Followed by alphanumeric or underscore
                )),
            )),
            |s: &str| s.to_string(),
        ),
    )
    .parse(input)
}

// Parses "model schema 1.1" line
