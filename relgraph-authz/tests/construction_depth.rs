use relgraph_authz::FgaAuthz;
use relgraph_dsl::{ParseErrorCode, parse_fga_schema, validate_schema};
use std::process::Command;

const CHILD_CASE_ENV: &str = "RELGRAPH_CONSTRUCTION_DEPTH_CHILD";

#[test]
fn flat_expression_below_construction_limit_validates() {
    let model = flat_expression_model(200);
    let schema = parse_fga_schema(&model).expect("a bounded flat expression parses");

    validate_schema(&schema).expect("the bounded expression validates iteratively");
}

#[test]
fn declaration_limit_is_enforced_at_the_boundary() {
    let declarations_at_limit = std::iter::repeat("type user")
        .take(4_096)
        .collect::<Vec<_>>()
        .join("\n");
    let accepted = format!("model\nschema 1.1\n{declarations_at_limit}\n");
    parse_fga_schema(&accepted).expect("the maximum declaration count is accepted");

    let declarations_over_limit = std::iter::repeat("type user")
        .take(4_097)
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
    let expression = std::iter::repeat("base")
        .take(terms)
        .collect::<Vec<_>>()
        .join(" or ");
    format!(
        "model\nschema 1.1\ntype user\ntype document\n relations\n  define base: [user]\n  define viewer: {expression}\n"
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
