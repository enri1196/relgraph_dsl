#[path = "support/construction_models.rs"]
mod construction_models;

use construction_models::construction_cases;
use relgraph_authz::{ConstructionError, FgaAuthz};
use relgraph_dsl::{ParseErrorCode, parse_fga_schema, validate_schema};
use std::process::Command;

const CHILD_CASE_ENV: &str = "RELGRAPH_CONSTRUCTION_DEPTH_CHILD";
const ALLOWED_CASE_ENV: &str = "RELGRAPH_ALLOWED_CONSTRUCTION_CASE";

#[test]
fn flat_expression_below_construction_limit_validates() {
    let model = flat_expression_model(200);
    let schema = parse_fga_schema(&model).expect("a bounded flat expression parses");

    validate_schema(&schema).expect("the bounded expression validates iteratively");
}

#[test]
fn declaration_limit_is_enforced_at_the_boundary() {
    let declarations_at_limit = std::iter::repeat_n("type user", 4_096)
        .collect::<Vec<_>>()
        .join("\n");
    let accepted = format!("model\nschema 1.1\n{declarations_at_limit}\n");
    parse_fga_schema(&accepted).expect("the maximum declaration count is accepted");

    let declarations_over_limit = std::iter::repeat_n("type user", 4_097)
        .collect::<Vec<_>>()
        .join("\n");
    let rejected = format!("model\nschema 1.1\n{declarations_over_limit}\n");
    let expected_start = rejected.match_indices("type user").nth(4_096).unwrap().0;
    let error = parse_fga_schema(&rejected).expect_err("one extra declaration is rejected");

    assert_eq!(error.code, ParseErrorCode::ConstructionLimitExceeded);
    assert_eq!(error.span.start, expected_start);
    assert_eq!(error.span.end, expected_start + "type".len());
}

#[test]
fn allowed_construction_cases_compile_in_child_processes() {
    if let Ok(case_name) = std::env::var(ALLOWED_CASE_ENV) {
        let case = construction_cases()
            .into_iter()
            .find(|case| case.name == case_name)
            .unwrap_or_else(|| panic!("unknown allowed construction case: {case_name}"));
        compile_allowed_case(&case);
        return;
    }

    for case in construction_cases() {
        let output = Command::new(std::env::current_exe().expect("test executable path"))
            .arg("--exact")
            .arg("allowed_construction_cases_compile_in_child_processes")
            .arg("--nocapture")
            .env(ALLOWED_CASE_ENV, case.name)
            .output()
            .expect("allowed construction child starts");

        assert!(
            output.status.success(),
            "allowed construction case '{}' failed with {:?}\nstdout:\n{}\nstderr:\n{}",
            case.name,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn construction_unit_boundaries_are_exact() {
    drop(
        FgaAuthz::new(&construction_models::union_model(256, true))
            .expect("a 512-unit union compiles"),
    );
    drop(
        FgaAuthz::new(&construction_models::target_fanout_model(511))
            .expect("a 512-unit target fanout compiles"),
    );

    assert!(matches!(
        FgaAuthz::new(&construction_models::union_model(257, false)),
        Err(ConstructionError::Parse(error))
            if error.code == ParseErrorCode::ConstructionLimitExceeded
    ));
    assert!(matches!(
        FgaAuthz::new(&construction_models::target_fanout_model(512)),
        Err(ConstructionError::Parse(error))
            if error.code == ParseErrorCode::ConstructionLimitExceeded
    ));

    drop(
        FgaAuthz::new(&construction_models::nested_model(128))
            .expect("128 nested parentheses compile"),
    );
    assert!(matches!(
        FgaAuthz::new(&construction_models::nested_model(129)),
        Err(ConstructionError::Parse(error))
            if error.code == ParseErrorCode::ConstructionLimitExceeded
    ));

    drop(
        FgaAuthz::new(&construction_models::wide_index_model(2047))
            .expect("4,095 declarations compile"),
    );
    assert!(matches!(
        FgaAuthz::new(&construction_models::wide_index_model(2048)),
        Err(ConstructionError::Parse(error))
            if error.code == ParseErrorCode::ConstructionLimitExceeded
    ));
}

/// Parses, validates, compiles, and drops one allowed construction case.
fn compile_allowed_case(case: &construction_models::ConstructionCase) {
    let schema = parse_fga_schema(&case.source)
        .unwrap_or_else(|error| panic!("case '{}' did not parse: {error}", case.name));
    let declarations = schema.type_definitions.len()
        + schema
            .type_definitions
            .iter()
            .map(|type_definition| type_definition.relations.len())
            .sum::<usize>();
    assert!(schema.condition_definitions.is_empty());
    assert_eq!(case.declarations, declarations, "case '{}'", case.name);
    assert!(
        case.maximum_relation_units <= 512,
        "case '{}' exceeds the declared relation-unit limit",
        case.name
    );
    validate_schema(&schema)
        .unwrap_or_else(|errors| panic!("case '{}' did not validate: {errors:?}", case.name));
    let authorizer = FgaAuthz::new(&case.source)
        .unwrap_or_else(|error| panic!("case '{}' did not compile: {error}", case.name));
    drop(authorizer);
}

#[test]
fn depth_limits_return_errors_without_terminating_parent() {
    if let Ok(case) = std::env::var(CHILD_CASE_ENV) {
        run_child_case(&case);
        return;
    }

    for case in ["nested", "flat", "dependencies"] {
        let output = Command::new(std::env::current_exe().expect("test executable path"))
            .arg("--exact")
            .arg("depth_limits_return_errors_without_terminating_parent")
            .arg("--nocapture")
            .env(CHILD_CASE_ENV, case)
            .output()
            .expect("depth regression child starts");

        assert!(
            output.status.success(),
            "child case '{case}' failed with {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

fn run_child_case(case: &str) {
    match case {
        "nested" => {
            let depth = 1_024;
            let model = format!(
                "model\nschema 1.1\n# source offsets stay tied to the original bytes\ntype user\ntype document\n relations\n  define viewer: {}[user]{}\n",
                "(".repeat(depth),
                ")".repeat(depth),
            );
            let expected_start = model.match_indices('(').nth(128).unwrap().0;
            let error = parse_fga_schema(&model).expect_err("excessive nesting is rejected");

            assert_eq!(
                error.code,
                ParseErrorCode::ConstructionLimitExceeded,
                "{error:?}"
            );
            assert_eq!(error.span.start, expected_start);
            assert_eq!(error.span.end, expected_start + 1);
        }
        "flat" => {
            let model = flat_expression_model(1_024);
            let error = parse_fga_schema(&model).expect_err("an oversized flat AST is rejected");

            assert_eq!(error.code, ParseErrorCode::ConstructionLimitExceeded);
        }
        "dependencies" => {
            let model = acyclic_dependency_model(3_000);
            let _compiled =
                FgaAuthz::new(model.as_str()).expect("a long acyclic dependency chain compiles");
        }
        _ => panic!("unknown construction-depth child case: {case}"),
    }
}

fn flat_expression_model(terms: usize) -> String {
    let names: Vec<String> = (0..terms).map(|term| format!("base{term:04}")).collect();
    let bases: String = names
        .iter()
        .map(|name| format!("  define {name}: [user]\n"))
        .collect();
    let expression = names.join(" or ");
    format!(
        "model\nschema 1.1\ntype user\ntype document\n relations\n{bases}  define viewer: {expression}\n"
    )
}

fn acyclic_dependency_model(depth: usize) -> String {
    let mut model = String::from("model\nschema 1.1\ntype user\ntype document\n relations\n");
    for index in 0..depth {
        if index + 1 == depth {
            model.push_str(&format!("  define r{index:04}: [user]\n"));
        } else {
            model.push_str(&format!("  define r{index:04}: r{:04}\n", index + 1));
        }
    }
    model
}
