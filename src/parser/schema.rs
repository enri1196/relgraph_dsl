use nom::{
    Parser,
    branch::alt,
    bytes::complete::tag,
    character::complete::multispace1,
    combinator::{all_consuming, eof, map, opt},
    error::context,
    multi::many0,
    sequence::{preceded, terminated},
};

use super::common::{Res, fga_extended_identifier, spnl};
use super::condition::parse_condition_definition;
use super::relation::parse_relations_block;
use crate::ast::{Schema, SchemaHeader, TypeDefinition};

fn parse_model_schema_header<'a>(input: &'a str) -> Res<&'a str, SchemaHeader> {
    context(
        "model_schema_header",
        map(
            (
                tag("model"),
                multispace1, // ANTLR: NEWLINE (but can be space then newline)
                tag("schema"),
                multispace1,
                tag("1.1"), // Specific to schema 1.1 as per original request
            ),
            |_| SchemaHeader::ModelSchema {
                version: "1.1".to_string(),
            },
        ),
    )
    .parse(input)
}

// Parses "module <name>" line
fn parse_module_header<'a>(input: &'a str) -> Res<&'a str, SchemaHeader> {
    context(
        "module_header",
        map(
            (tag("module"), multispace1, fga_extended_identifier), // Use extended_identifier for moduleName
            |(_, _, name)| SchemaHeader::Module { name },
        ),
    )
    .parse(input)
}

fn parse_schema_header<'a>(input: &'a str) -> Res<&'a str, SchemaHeader> {
    alt((parse_model_schema_header, parse_module_header)).parse(input)
}

fn parse_type_definition<'a>(input: &'a str) -> Res<&'a str, TypeDefinition> {
    let (i, comments_before) = spnl(input)?; // Consume comments/newlines before 'type' or 'extend'
    let (i, is_extended_opt) = opt(terminated(tag("extend"), multispace1)).parse(i)?;
    let (i, _) = tag("type")(i)?;
    let (i, _) = multispace1(i)?;
    let (i, name) = fga_extended_identifier(i)?; // typeName
    let (i, relations_opt) = opt(preceded(spnl, parse_relations_block)).parse(i)?;

    Ok((
        i,
        TypeDefinition {
            is_extended: is_extended_opt.is_some(),
            name,
            relations: relations_opt.unwrap_or_default(),
            comments_before,
        },
    ))
}

// Top-level parser for the entire schema
fn parse_schema_internal<'a>(input: &'a str) -> Res<&'a str, Schema> {
    let (i, _initial_comments_and_newlines) = spnl(input)?; // Consume any leading comments/newlines

    // ANTLR: (modelHeader | moduleHeader) NEWLINE? typeDefs NEWLINE? conditions NEWLINE? EOF;
    // One of modelHeader or moduleHeader is required.
    let (i, header) = parse_schema_header(i)?;
    let (i, _) = spnl(i)?; // Newlines and comments after header

    let (i, types) = many0(terminated(parse_type_definition, opt(spnl))).parse(i)?;
    let (i, _) = spnl(i)?; // Newlines and comments after typeDefs

    let (i, conditions) = many0(terminated(parse_condition_definition, opt(spnl))).parse(i)?;
    let (i, _) = spnl(i)?; // Trailing whitespace/comments before eof

    let (i, _) = eof(i)?; // Ensure all input is consumed

    Ok((
        i,
        Schema {
            header,
            type_definitions: types,
            condition_definitions: conditions,
        },
    ))
}

/// Parses an OpenFGA v1.1 DSL string into a Schema struct.
pub fn parse_fga_schema(input: &str) -> Result<Schema, String> {
    match all_consuming(parse_schema_internal).parse(input.trim_start()) {
        // Trim start for initial whitespace before first significant token
        Ok((_, schema)) => Ok(schema),
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(e.to_string()),
        Err(nom::Err::Incomplete(_)) => {
            Err("Parsing incomplete: more input was expected.".to_string())
        }
    }
}
