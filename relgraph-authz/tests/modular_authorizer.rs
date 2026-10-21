use std::collections::BTreeMap;
use std::path::PathBuf;

use relgraph_authz::{
    AuthorizationDecision, CheckRequest, ConditionContext, ConstructionError, EvaluationLimits,
    FgaAuthz, InMemoryRelationshipStore, ObjectRef, RelationName, RelationshipTuple, Subject,
    TenantId,
};
use relgraph_dsl::{
    ModularModel, ModuleSource, assemble_modular_model, parse_fga_schema, parse_model_manifest,
};
use serde_json::json;

fn modular_model(sources: &[(&str, &str)]) -> ModularModel {
    let contents = sources
        .iter()
        .map(|(path, _)| format!("  - '{path}'\n"))
        .collect::<String>();
    let manifest = parse_model_manifest(&format!("schema: '1.2'\ncontents:\n{contents}"))
        .expect("manifest should parse");
    let modules = sources
        .iter()
        .map(|(path, source)| ModuleSource {
            path: PathBuf::from(path),
            schema: parse_fga_schema(source)
                .unwrap_or_else(|error| panic!("failed to parse {path}: {error}")),
        })
        .collect();

    assemble_modular_model(manifest, modules).expect("module structure should assemble")
}

#[tokio::test]
async fn composed_modular_model_constructs_authorizer_and_allows_check() {
    let model = modular_model(&[
        (
            "base.fga",
            "module base\ntype user\ntype document\n  relations\n    define viewer: [user]\n",
        ),
        (
            "extension.fga",
            "module extension\nextend type document\n  relations\n    define editor: [user]\n",
        ),
    ]);

    let store = InMemoryRelationshipStore::new();
    store
        .insert(RelationshipTuple::new(
            TenantId::new("tenant-a").unwrap(),
            ObjectRef::new("document", "doc-1").unwrap(),
            RelationName::new("viewer").unwrap(),
            Subject::new("user", "anne").unwrap(),
        ))
        .unwrap();

    let authorizer = FgaAuthz::from_modular_model(model)
        .expect("modular model should compile")
        .with_store(store, EvaluationLimits::default());
    let decision = authorizer
        .check(CheckRequest::new(
            TenantId::new("tenant-a").unwrap(),
            Subject::new("user", "anne").unwrap(),
            ObjectRef::new("document", "doc-1").unwrap(),
            RelationName::new("viewer").unwrap(),
        ))
        .await
        .expect("check should succeed");

    assert_eq!(decision, AuthorizationDecision::Allow);
}

#[test]
fn modular_semantic_errors_keep_their_module_and_file_origin() {
    let model = modular_model(&[
        (
            "base.fga",
            "module base\ntype user\ntype document\n  relations\n    define viewer: [user]\n",
        ),
        (
            "extension.fga",
            "module extension\nextend type document\n  relations\n    define reviewer: [ghost]\n",
        ),
    ]);

    let Err(ConstructionError::Validation(errors)) = FgaAuthz::from_modular_model(model) else {
        panic!("expected a modular semantic validation error");
    };
    assert!(errors.iter().any(|error| {
        error.location.file.as_deref() == Some(std::path::Path::new("extension.fga"))
            && error.location.module.as_deref() == Some("extension")
    }));
}

#[tokio::test]
async fn modular_constructor_accepts_inline_conditions() {
    let model = modular_model(&[(
        "inline.fga",
        "module inline\ntype user\ntype document\n  relations\n    define viewer: [user with $expression]\n",
    )]);
    let tenant = TenantId::new("tenant-a").unwrap();
    let authorizer = FgaAuthz::from_modular_model(model)
        .expect("inline conditions are in the runtime profile")
        .with_store(
            InMemoryRelationshipStore::new(),
            EvaluationLimits::default(),
        );
    let context = ConditionContext::new(
        "$expression",
        BTreeMap::from([("expression".to_owned(), json!("env == 'prod'"))]),
    )
    .unwrap();
    authorizer
        .write_tuple(
            &tenant,
            &RelationshipTuple::new(
                tenant.clone(),
                ObjectRef::new("document", "doc-1").unwrap(),
                RelationName::new("viewer").unwrap(),
                Subject::new("user", "anne").unwrap(),
            )
            .with_condition(context),
        )
        .await
        .expect("a compiling inline condition is a valid tuple");

    let decision = authorizer
        .check(
            CheckRequest::new(
                tenant,
                Subject::new("user", "anne").unwrap(),
                ObjectRef::new("document", "doc-1").unwrap(),
                RelationName::new("viewer").unwrap(),
            )
            .with_context(BTreeMap::from([("env".to_owned(), json!("prod"))])),
        )
        .await
        .expect("check should succeed");
    assert_eq!(decision, AuthorizationDecision::Allow);
}

#[test]
fn modular_constructor_compiles_cel_conditions_with_the_runtime_profile() {
    let model = modular_model(&[(
        "condition.fga",
        "module checks\ntype user\ntype document\n  relations\n    define viewer: [user with allowed]\ncondition allowed(roles: list<string>) { roles.exists(role, role == \"admin\") }\n",
    )]);

    assert!(matches!(
        FgaAuthz::from_modular_model(model),
        Err(ConstructionError::ConditionCompilation { .. })
    ));
}
