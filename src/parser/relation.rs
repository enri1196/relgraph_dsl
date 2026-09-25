use nom::{
    Parser,
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, multispace1},
    combinator::{cut, map, opt, peek},
    error::context,
    multi::{many1, separated_list0, separated_list1},
    sequence::{delimited, preceded},
};

use super::common::{Res, fga_extended_identifier, fga_identifier, spnl};
use crate::ast::{Relation, RelationDefinitionBody, RelationExpression, RelationTarget};

// Relation Target Parsing (Refined for 'with' clause)
fn parse_relation_target<'a>(input: &'a str) -> Res<&'a str, RelationTarget> {
    context(
        "relation_target", // ANTLR: relationDefTypeRestriction
        map(
            (
                fga_extended_identifier, // relationDefTypeRestrictionType
                opt(alt((
                    map(preceded(char(':'), char('*')), |_| "*".to_string()), // :* (wildcard)
                    preceded(char('#'), fga_extended_identifier), // #relation (extended_identifier)
                ))),
                opt(preceded(
                    (multispace1, tag("with"), multispace1),
                    fga_identifier,
                )), // with conditionName (simple identifier)
            ),
            |(target_type, opt_rel_wild, condition)| RelationTarget {
                target_type,
                relation_or_wildcard: opt_rel_wild,
                condition,
            },
        ),
    )
    .parse(input)
}

fn parse_relation_target_list<'a>(input: &'a str) -> Res<&'a str, Vec<RelationTarget>> {
    context(
        "relation_target_list", // ANTLR: relationDefDirectAssignment
        delimited(
            preceded(spnl, char('[')),
            separated_list0(
                (spnl, char(','), spnl), // Allow newlines and comments around comma
                parse_relation_target,
            ),
            preceded(spnl, char(']')),
        ),
    )
    .parse(input)
}

// Relation Expression Parsing (Refined for operator non-mixing)

// Base for expressions: direct assignment, computed userset, TTU, or parenthesized expression
// ANTLR: relationDefDirectAssignment | relationDefGrouping | relationRecurse
fn parse_base_expression<'a>(input: &'a str) -> Res<&'a str, RelationExpression> {
    preceded(
        spnl, // Consume leading whitespace/comments
        alt((
            map(
                parse_relation_target_list,
                RelationExpression::DirectAssignment,
            ),
            map(
                (
                    fga_extended_identifier, // rewriteComputedusersetName
                    opt(preceded(
                        (multispace1, tag("from"), multispace1),
                        fga_extended_identifier,
                    )), // rewriteTuplesetName
                ),
                |(name, opt_from)| {
                    if let Some(from_rel) = opt_from {
                        RelationExpression::TupleToUserset {
                            computed_userset: name,
                            tupleset_relation: from_rel,
                        }
                    } else {
                        RelationExpression::ComputedUserset(name)
                    }
                },
            ),
            delimited(
                char('('),
                parse_relation_expression, // ANTLR: relationDef | relationRecurseNoDirect
                preceded(spnl, char(')')),
            ),
        )),
    )
    .parse(input)
}

// Term for right-hand side of operators (cannot be direct assignment)
// ANTLR: relationDefGrouping | relationRecurseNoDirect
fn parse_term_for_partials<'a>(input: &'a str) -> Res<&'a str, RelationExpression> {
    preceded(
        spnl,
        alt((
            map(
                (
                    fga_extended_identifier,
                    opt(preceded(
                        (multispace1, tag("from"), multispace1),
                        fga_extended_identifier,
                    )),
                ),
                |(name, opt_from)| {
                    if let Some(from_rel) = opt_from {
                        RelationExpression::TupleToUserset {
                            computed_userset: name,
                            tupleset_relation: from_rel,
                        }
                    } else {
                        RelationExpression::ComputedUserset(name)
                    }
                },
            ),
            delimited(
                char('('),
                parse_relation_expression, // ANTLR: relationDefNoDirect | relationRecurseNoDirect
                // parse_relation_expression itself handles the structure correctly
                preceded(spnl, char(')')),
            ),
        )),
    )
    .parse(input)
}

fn parse_relation_expression<'a>(input: &'a str) -> Res<&'a str, RelationExpression> {
    // This function now implements the ANTLR logic: base (partials)?
    // where partials is ONE OF (OR sequence | AND sequence | BUT_NOT sequence)

    let (i, base) = parse_base_expression(input)?;

    // Try OR sequence
    // Peek to see if "or" is next, to avoid consuming input if it's not an OR sequence
    if peek(opt(preceded(
        (multispace1, tag("or"), multispace1),
        parse_term_for_partials,
    )))
    .parse(i)?
    .1
    .is_some()
    {
        if let Ok((i_or, or_terms)) = many1(preceded(
            (multispace1, tag("or"), multispace1),
            parse_term_for_partials,
        ))
        .parse(i)
        {
            let final_expr = or_terms.into_iter().fold(base, |acc, val| {
                RelationExpression::Union(Box::new(acc), Box::new(val))
            });
            return Ok((i_or, final_expr));
        }
    }

    // Try AND sequence
    if peek(opt(preceded(
        (multispace1, tag("and"), multispace1),
        parse_term_for_partials,
    )))
    .parse(i)?
    .1
    .is_some()
    {
        if let Ok((i_and, and_terms)) = many1(preceded(
            (multispace1, tag("and"), multispace1),
            parse_term_for_partials,
        ))
        .parse(i)
        {
            let final_expr = and_terms.into_iter().fold(base, |acc, val| {
                RelationExpression::Intersection(Box::new(acc), Box::new(val))
            });
            return Ok((i_and, final_expr));
        }
    }

    // Try BUT NOT sequence
    if peek(opt(preceded(
        (multispace1, tag("but not"), multispace1),
        parse_term_for_partials,
    )))
    .parse(i)?
    .1
    .is_some()
    {
        if let Ok((i_bn, bn_terms)) = many1(preceded(
            (multispace1, tag("but not"), multispace1),
            parse_term_for_partials,
        ))
        .parse(i)
        {
            let final_expr = bn_terms.into_iter().fold(base, |acc, val| {
                RelationExpression::Difference(Box::new(acc), Box::new(val))
            });
            return Ok((i_bn, final_expr));
        }
    }

    // If no sequence matched, return the base expression itself
    Ok((i, base))
}

fn parse_relation<'a>(input: &'a str) -> Res<&'a str, Relation> {
    let (i, comments_before) = spnl(input)?; // Consume comments/newlines before 'define'
    let (i, _) = tag("define")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, name) = fga_extended_identifier(i)?; // relationName
    let (i, _) = spnl(i)?; // Whitespace/comments
    let (i, _) = char(':')(i)?;
    // spnl before expression is handled by parse_relation_expression itself
    let (i, expr) = parse_relation_expression(i)?;

    Ok((
        i,
        Relation {
            name,
            definition: RelationDefinitionBody { expression: expr },
            comments_before,
        },
    ))
}

pub(super) fn parse_relations_block<'a>(input: &'a str) -> Res<&'a str, Vec<Relation>> {
    context(
        "relations_block",
        preceded(
            (tag("relations"), spnl), // ANTLR: NEWLINE RELATIONS
            // ANTLR: relationDeclaration+ (must have at least one)
            cut(separated_list1(spnl, parse_relation)), // Use separated_list1 for '+'
        ),
    )
    .parse(input)
}
