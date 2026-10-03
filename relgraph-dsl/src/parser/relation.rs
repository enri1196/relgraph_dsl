use nom::{error::Error, error::ErrorKind};

use super::common::{Res, TokenInput, expect_kind, parse_extended_identifier, span_from_consumed};
use super::lexer::TokenKind;
use crate::ast::{
    Relation, RelationCondition, RelationDefinitionBody, RelationExpression, RelationTarget,
};

fn take_whitespace(input: TokenInput<'_>) -> (TokenInput<'_>, bool) {
    if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Whitespace)
    {
        (input.tail(), true)
    } else {
        (input, false)
    }
}

fn parse_relation_target(input: TokenInput<'_>) -> Res<'_, RelationTarget> {
    let (mut input, target_type) = parse_extended_identifier(input)?;
    let relation_or_wildcard = match input.first().map(|token| token.kind) {
        Some(TokenKind::Colon) => {
            let (rest, _) = expect_kind(input, TokenKind::Colon)?;
            let (rest, _) = expect_kind(rest, TokenKind::Star)?;
            input = rest;
            Some("*".to_string())
        }
        Some(TokenKind::Hash) => {
            let (rest, _) = expect_kind(input, TokenKind::Hash)?;
            let (rest, relation) = parse_extended_identifier(rest)?;
            input = rest;
            Some(relation)
        }
        _ => None,
    };

    let (after_space, had_space) = take_whitespace(input);
    let condition = if had_space
        && after_space
            .first()
            .is_some_and(|token| token.kind == TokenKind::With)
    {
        let (rest, _) = expect_kind(after_space, TokenKind::With)?;
        let (rest, _) = expect_kind(rest, TokenKind::Whitespace)?;
        let (rest, condition) = if rest
            .first()
            .is_some_and(|token| token.kind == TokenKind::DollarExpression)
        {
            let (rest, _) = expect_kind(rest, TokenKind::DollarExpression)?;
            (rest, RelationCondition::InlineExpression)
        } else {
            let (rest, name) = super::common::parse_identifier(rest)?;
            (rest, RelationCondition::Named(name))
        };
        input = rest;
        Some(condition)
    } else {
        None
    };

    Ok((
        input,
        RelationTarget {
            target_type,
            relation_or_wildcard,
            condition,
        },
    ))
}

fn parse_relation_target_list<'a>(
    input: TokenInput<'a>,
    budget: &mut ExpressionBudget,
) -> Res<'a, Vec<RelationTarget>> {
    let (input, _) = expect_kind(input, TokenKind::LBracket)?;
    let mut input = super::common::skip_horizontal_whitespace(input);
    let mut targets = Vec::new();

    loop {
        let (next_input, _) = budget.consume(input)?;
        input = next_input;
        let (rest, target) = parse_relation_restriction(input)?;
        targets.push(target);
        let rest = super::common::skip_horizontal_whitespace(rest);
        if rest
            .first()
            .is_some_and(|token| token.kind == TokenKind::Comma)
        {
            let (rest, _) = expect_kind(rest, TokenKind::Comma)?;
            input = super::common::skip_horizontal_whitespace(rest);
            continue;
        }
        let (rest, _) = expect_kind(rest, TokenKind::RBracket)?;
        return Ok((rest, targets));
    }
}

fn parse_relation_restriction(input: TokenInput<'_>) -> Res<'_, RelationTarget> {
    let input = if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Newline)
    {
        input.tail()
    } else {
        input
    };
    let (input, target) = parse_relation_target(input)?;
    let input = if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::Newline)
    {
        input.tail()
    } else {
        input
    };
    Ok((input, target))
}

fn parse_rewrite(input: TokenInput<'_>) -> Res<'_, RelationExpression> {
    let (input, name) = parse_extended_identifier(input)?;
    let (after_space, had_space) = take_whitespace(input);
    if !had_space
        || !after_space
            .first()
            .is_some_and(|token| token.kind == TokenKind::From)
    {
        return Ok((input, RelationExpression::ComputedUserset(name)));
    }
    let (input, _) = expect_kind(after_space, TokenKind::From)?;
    let (input, _) = expect_kind(input, TokenKind::Whitespace)?;
    let (input, tupleset_relation) = parse_extended_identifier(input)?;
    Ok((
        input,
        RelationExpression::TupleToUserset {
            computed_userset: name,
            tupleset_relation,
        },
    ))
}

fn parse_right_term<'a>(
    input: TokenInput<'a>,
    budget: &mut ExpressionBudget,
    depth: usize,
) -> Res<'a, RelationExpression> {
    if input
        .first()
        .is_some_and(|token| token.kind == TokenKind::LParen)
    {
        if depth >= super::schema::MAX_RELATION_EXPRESSION_DEPTH {
            return Err(construction_limit_error(input));
        }
        let (input, _) = expect_kind(input, TokenKind::LParen)?;
        let input = super::common::skip_horizontal_whitespace(input);
        let (input, expression) = parse_no_direct_expression(input, budget, depth + 1)?;
        let input = super::common::skip_horizontal_whitespace(input);
        let (input, _) = expect_kind(input, TokenKind::RParen)?;
        Ok((input, expression))
    } else {
        let (input, _) = budget.consume(input)?;
        parse_rewrite(input)
    }
}

fn operator_kind(input: TokenInput<'_>) -> Option<TokenKind> {
    match input.first()?.kind {
        TokenKind::Or | TokenKind::And | TokenKind::ButNot => input.first().map(|token| token.kind),
        _ => None,
    }
}

fn parse_relation_expression(input: TokenInput<'_>) -> Res<'_, RelationExpression> {
    let mut budget = ExpressionBudget::default();
    parse_expression(input, true, &mut budget, 0)
}

fn parse_no_direct_expression<'a>(
    input: TokenInput<'a>,
    budget: &mut ExpressionBudget,
    depth: usize,
) -> Res<'a, RelationExpression> {
    parse_expression(input, false, budget, depth)
}

fn parse_expression<'a>(
    input: TokenInput<'a>,
    direct_assignment_allowed: bool,
    budget: &mut ExpressionBudget,
    depth: usize,
) -> Res<'a, RelationExpression> {
    if depth > super::schema::MAX_RELATION_EXPRESSION_DEPTH {
        return Err(construction_limit_error(input));
    }
    let (input, base) = parse_expression_primary(input, direct_assignment_allowed, budget, depth)?;
    let (after_space, had_space) = take_whitespace(input);
    if !had_space {
        return Ok((input, base));
    }
    let Some(operator) = operator_kind(after_space) else {
        return Ok((input, base));
    };
    let (after_space, _) = budget.consume(after_space)?;
    let (mut rest, _) = expect_kind(after_space, operator)?;
    let (next, had_space) = take_whitespace(rest);
    if !had_space {
        return Err(nom::Err::Error(Error::new(next, ErrorKind::Tag)));
    }
    rest = next;
    let (next, first_term) = parse_right_term(rest, budget, depth)?;
    let mut terms = vec![first_term];
    rest = next;

    if operator != TokenKind::ButNot {
        loop {
            let (after_space, had_space) = take_whitespace(rest);
            if !had_space
                || !after_space
                    .first()
                    .is_some_and(|token| token.kind == operator)
            {
                break;
            }
            let (after_space, _) = budget.consume(after_space)?;
            let (after_operator, _) = expect_kind(after_space, operator)?;
            let (after_required_space, had_space) = take_whitespace(after_operator);
            if !had_space {
                return Err(nom::Err::Error(Error::new(
                    after_required_space,
                    ErrorKind::Tag,
                )));
            }
            let (next, term) = parse_right_term(after_required_space, budget, depth)?;
            terms.push(term);
            rest = next;
        }
    }

    let expression = terms.into_iter().fold(base, |left, right| match operator {
        TokenKind::Or => RelationExpression::Union(Box::new(left), Box::new(right)),
        TokenKind::And => RelationExpression::Intersection(Box::new(left), Box::new(right)),
        TokenKind::ButNot => RelationExpression::Difference(Box::new(left), Box::new(right)),
        _ => unreachable!("only rewrite operators are accepted"),
    });
    Ok((rest, expression))
}

fn parse_expression_primary<'a>(
    input: TokenInput<'a>,
    direct_assignment_allowed: bool,
    budget: &mut ExpressionBudget,
    depth: usize,
) -> Res<'a, RelationExpression> {
    match input.first().map(|token| token.kind) {
        Some(TokenKind::LBracket) if direct_assignment_allowed => {
            let (input, _) = budget.consume(input)?;
            let (input, targets) = parse_relation_target_list(input, budget)?;
            Ok((input, RelationExpression::DirectAssignment(targets)))
        }
        Some(TokenKind::LParen) => {
            if depth >= super::schema::MAX_RELATION_EXPRESSION_DEPTH {
                return Err(construction_limit_error(input));
            }
            let (input, _) = expect_kind(input, TokenKind::LParen)?;
            let input = super::common::skip_horizontal_whitespace(input);
            let (input, expression) =
                parse_expression(input, direct_assignment_allowed, budget, depth + 1)?;
            let input = super::common::skip_horizontal_whitespace(input);
            let (input, _) = expect_kind(input, TokenKind::RParen)?;
            Ok((input, expression))
        }
        _ => {
            let (input, _) = budget.consume(input)?;
            parse_rewrite(input)
        }
    }
}

#[derive(Default)]
struct ExpressionBudget {
    nodes: usize,
}

impl ExpressionBudget {
    fn consume<'a>(&mut self, input: TokenInput<'a>) -> Res<'a, ()> {
        if self.nodes >= super::schema::MAX_RELATION_EXPRESSION_NODES {
            return Err(construction_limit_error(input));
        }
        self.nodes += 1;
        Ok((input, ()))
    }
}

fn construction_limit_error<'a>(input: TokenInput<'a>) -> nom::Err<Error<TokenInput<'a>>> {
    nom::Err::Failure(Error::new(input, nom::error::ErrorKind::TooLarge))
}

fn parse_relation(input: TokenInput<'_>, comments_before: Vec<String>) -> Res<'_, Relation> {
    let start = input;
    let (input, _) = expect_kind(input, TokenKind::Define)?;
    let (input, _) = expect_kind(input, TokenKind::Whitespace)?;
    let (input, name) = parse_extended_identifier(input)?;
    let (input, _) = take_whitespace(input);
    let (input, _) = expect_kind(input, TokenKind::Colon)?;
    let (input, _) = take_whitespace(input);
    let (input, expression) = parse_relation_expression(input)?;
    let span = span_from_consumed(start, input);
    Ok((
        input,
        Relation {
            name,
            definition: RelationDefinitionBody { expression },
            comments_before,
            span,
        },
    ))
}

pub(super) fn parse_relations_block<'a>(
    input: TokenInput<'a>,
    _block_comments: Vec<String>,
    declaration_count: &mut usize,
) -> Res<'a, Vec<Relation>> {
    let (input, _) = expect_kind(input, TokenKind::Relations)?;
    let Some((declaration, comments)) = super::common::declaration_prefix(input) else {
        return Err(nom::Err::Error(Error::new(input, ErrorKind::Tag)));
    };
    if !declaration
        .first()
        .is_some_and(|token| token.kind == TokenKind::Define)
    {
        return Err(nom::Err::Error(Error::new(declaration, ErrorKind::Tag)));
    }
    let (declaration, _) = super::schema::consume_declaration(declaration, declaration_count)?;
    let mut relations = Vec::new();

    let (mut input, relation) = parse_relation(declaration, comments)?;
    relations.push(relation);
    loop {
        let Some((declaration, comments)) = super::common::declaration_prefix(input) else {
            return Ok((input, relations));
        };
        if !declaration
            .first()
            .is_some_and(|token| token.kind == TokenKind::Define)
        {
            return Ok((input, relations));
        }
        let (declaration, _) = super::schema::consume_declaration(declaration, declaration_count)?;
        let (rest, relation) = parse_relation(declaration, comments)?;
        relations.push(relation);
        input = rest;
    }
}
