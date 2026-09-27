use relgraph_dsl::{parse_fga_schema, validate_schema};

fn main() {
    let source =
        "model\nschema 1.2\n\ntype user\n\ntype document\n  relations\n    define viewer: [user]\n";
    let schema = parse_fga_schema(source).expect("example source should parse");
    validate_schema(&schema).expect("example schema should pass bounded validation");

    println!(
        "Validated {} type definitions",
        schema.type_definitions.len()
    );
}
