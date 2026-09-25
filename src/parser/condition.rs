use nom::{
    Parser,
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::{char, multispace1},
    combinator::map,
    error::context,
    multi::separated_list0,
    sequence::{delimited, preceded, separated_pair},
};

use super::common::{Res, fga_identifier, spnl};
use crate::ast::{ConditionDefinition, ConditionParameter, ParameterType};

// Condition Parsing (Refined)

fn parse_parameter_type<'a>(input: &'a str) -> Res<&'a str, ParameterType> {
    // ANTLR: parameterType: CONDITION_PARAM_TYPE | (CONDITION_PARAM_CONTAINER LESS CONDITION_PARAM_TYPE GREATER);
    // CONDITION_PARAM_TYPE: 'bool' | 'string' | 'int' | 'uint' | 'double' | 'duration' | 'timestamp' | 'ipaddress';
    // CONDITION_PARAM_CONTAINER: 'map' | 'list';
    let simple_type_parser = || {
        alt((
            tag("bool"),
            tag("string"),
            tag("int"),
            tag("uint"),
            tag("double"),
            tag("duration"),
            tag("timestamp"),
            tag("ipaddress"),
        ))
    };

    alt((
        map(
            (
                alt((tag("list"), tag("map"))),
                preceded(spnl, char('<')),
                preceded(spnl, simple_type_parser()),
                preceded(spnl, char('>')),
            ),
            |(container, _, inner, _)| ParameterType::Generic {
                container: container.to_string(),
                inner: inner.to_string(),
            },
        ),
        map(simple_type_parser(), |s: &str| {
            ParameterType::Simple(s.to_string())
        }),
    ))
    .parse(input)
}

fn parse_condition_parameter<'a>(input: &'a str) -> Res<&'a str, ConditionParameter> {
    context(
        "condition_parameter",
        map(
            separated_pair(
                preceded(spnl, fga_identifier), // parameterName
                (spnl, char(':'), spnl),
                parse_parameter_type, // parameterType
            ),
            |(name, param_type)| ConditionParameter { name, param_type },
        ),
    )
    .parse(input)
}

fn parse_condition_parameters<'a>(input: &'a str) -> Res<&'a str, Vec<ConditionParameter>> {
    context(
        "condition_parameters",
        delimited(
            preceded(spnl, char('(')),
            separated_list0((spnl, char(','), spnl), parse_condition_parameter),
            preceded(spnl, char(')')),
        ),
    )
    .parse(input)
}

// Parses the CEL expression part: { <CEL string> }
fn parse_cel_expression_block<'a>(input: &'a str) -> Res<&'a str, String> {
    context(
        "cel_expression_block",
        delimited(
            preceded(spnl, char('{')),
            map(
                // Take everything until the balancing '}'
                // This is a simplified way; a robust CEL parser would handle nested braces.
                // For now, we find the *last* '}' on the assumption that CEL itself is well-formed.
                // A better approach for nom would be to count braces or use a more context-aware take.
                // For simplicity here, we'll take until the first '}' and assume no '}' in CEL strings.
                // This is a known simplification.
                take_till(|c| c == '}'),
                |s: &str| s.trim().to_string(),
            ),
            preceded(spnl, char('}')),
        ),
    )
    .parse(input)
}

pub(super) fn parse_condition_definition<'a>(input: &'a str) -> Res<&'a str, ConditionDefinition> {
    let (i, comments_before) = spnl(input)?; // Consume comments/newlines before 'condition'
    let (i, _) = tag("condition")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, name) = fga_identifier(i)?; // conditionName
    let (i, params) = parse_condition_parameters(i)?;
    // spnl before '{' is handled by parse_cel_expression_block
    let (i, expr) = parse_cel_expression_block(i)?;

    Ok((
        i,
        ConditionDefinition {
            name,
            parameters: params,
            expression: expr,
            comments_before,
        },
    ))
}
