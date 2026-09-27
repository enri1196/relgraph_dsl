use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use http::{HeaderValue, Request, request::Parts};
use relgraph_authz::{
    AsyncContextResolver, AuthorizationDecision, CheckRequest, ContextBinding,
    ContextResolverFuture, ContextValue, ContextValueProvider, ContextValueType, EvaluationLimits,
    FgaAuthz, InMemoryRelationshipStore, ObjectIdSource, ObjectRef, PathParameters, PolicyError,
    PolicyInputError, PrincipalIdentity, PrincipalSource, RelationKey, RelationName,
    RelationshipTuple, RequirementExpression, RoutePolicy, Subject, TenantId, TenantIdentity,
    TenantSource,
};
use serde_json::{Value, json};

const POLICY_MODEL: &str = "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user with by_id]\ntype folder\n  relations\n    define viewer: [user with by_name]\ntype document\n  relations\n    define parent: [folder]\n    define viewer: [group#member] or viewer from parent\ncondition by_id(value: int) { value > 0 }\ncondition by_name(value: string) { value.startsWith(\"a\") }\n";

fn object_id_source() -> ObjectIdSource {
    ObjectIdSource::from_request_parts("test object id", |_: &Parts| {
        relgraph_authz::EntityId::new("42")
            .map_err(|error| PolicyInputError::InvalidObjectId(error.to_string()))
    })
}

fn base_policy() -> RoutePolicy {
    RoutePolicy::new("document", "viewer")
        .principal(PrincipalSource::extension::<ExtensionPrincipal>())
        .tenant(TenantSource::extension::<ExtensionPrincipal>())
        .object_id(object_id_source())
}

fn provider(value_type: ContextValueType, value: Value) -> ContextValueProvider {
    ContextValueProvider::from_request_parts(value_type.clone(), move |_: &Parts| {
        ContextValue::new(value_type.clone(), value.clone())
    })
}

#[test]
fn requirements_preserve_branches_and_resolve_group_and_inherited_relations() {
    let model = FgaAuthz::new(POLICY_MODEL).unwrap();
    let requirements = model.requirements("document", "viewer").unwrap();

    assert_eq!(requirements.root(), &RelationKey::new("document", "viewer"));
    assert!(matches!(
        requirements
            .relations()
            .get(&RelationKey::new("document", "viewer"))
            .unwrap()
            .expression(),
        RequirementExpression::Union(_, _)
    ));
    assert!(
        requirements
            .relations()
            .contains_key(&RelationKey::new("group", "member"))
    );
    assert!(
        requirements
            .relations()
            .contains_key(&RelationKey::new("document", "parent"))
    );
    assert!(
        requirements
            .relations()
            .contains_key(&RelationKey::new("folder", "viewer"))
    );
    assert_eq!(
        requirements.candidate_subject_types(),
        BTreeSet::from(["folder".to_owned(), "group".to_owned(), "user".to_owned(),])
    );

    let group_member = requirements
        .relations()
        .get(&RelationKey::new("group", "member"))
        .unwrap();
    let RequirementExpression::DirectAssignment(targets) = group_member.expression() else {
        panic!("group#member is direct assignment");
    };
    let group_condition = targets[0].condition().unwrap();
    assert_eq!(group_condition.name(), "by_id");
    assert_eq!(group_condition.parameters()[0].name(), "value");
    assert_eq!(
        group_condition.parameters()[0].value_type(),
        &ContextValueType::Int
    );

    let folder_viewer = requirements
        .relations()
        .get(&RelationKey::new("folder", "viewer"))
        .unwrap();
    let RequirementExpression::DirectAssignment(targets) = folder_viewer.expression() else {
        panic!("folder#viewer is direct assignment");
    };
    let folder_condition = targets[0].condition().unwrap();
    assert_eq!(folder_condition.name(), "by_name");
    assert_eq!(
        folder_condition.parameters()[0].value_type(),
        &ContextValueType::String
    );
}

#[test]
fn registration_rejects_unknown_relations_and_invalid_context_bindings() {
    let model = FgaAuthz::new(POLICY_MODEL).unwrap();
    assert_eq!(
        model.requirements("missing", "viewer"),
        Err(PolicyError::UnknownObjectType("missing".into()))
    );
    assert_eq!(
        model.requirements("document", "missing"),
        Err(PolicyError::UnknownRelation {
            object_type: "document".into(),
            relation: "missing".into(),
        })
    );

    let undeclared_condition = model
        .validate_policy(base_policy().bind_context(ContextBinding::new(
            "missing",
            "value",
            provider(ContextValueType::Int, json!(1)),
        )))
        .err()
        .expect("undeclared condition must fail registration");
    assert_eq!(
        undeclared_condition,
        PolicyError::UndeclaredCondition("missing".into())
    );

    let undeclared_parameter = model
        .validate_policy(base_policy().bind_context(ContextBinding::new(
            "by_id",
            "missing",
            provider(ContextValueType::Int, json!(1)),
        )))
        .err()
        .expect("undeclared parameter must fail registration");
    assert_eq!(
        undeclared_parameter,
        PolicyError::UndeclaredParameter {
            condition: "by_id".into(),
            parameter: "missing".into(),
        }
    );

    let missing_tenant = model
        .validate_policy(
            RoutePolicy::new("document", "viewer")
                .principal(PrincipalSource::extension::<ExtensionPrincipal>())
                .object_id(object_id_source()),
        )
        .err()
        .expect("missing tenant source must fail registration");
    assert_eq!(missing_tenant, PolicyError::MissingTenantSource);

    let unknown_type = model
        .validate_policy(
            RoutePolicy::new("missing", "viewer")
                .principal(PrincipalSource::extension::<ExtensionPrincipal>())
                .tenant(TenantSource::extension::<ExtensionPrincipal>())
                .object_id(object_id_source()),
        )
        .err()
        .expect("unknown object type must fail registration");
    assert_eq!(
        unknown_type,
        PolicyError::UnknownObjectType("missing".into())
    );

    let unknown_relation = model
        .validate_policy(
            RoutePolicy::new("document", "missing")
                .principal(PrincipalSource::extension::<ExtensionPrincipal>())
                .tenant(TenantSource::extension::<ExtensionPrincipal>())
                .object_id(object_id_source()),
        )
        .err()
        .expect("unknown relation must fail registration");
    assert_eq!(
        unknown_relation,
        PolicyError::UnknownRelation {
            object_type: "document".into(),
            relation: "missing".into(),
        }
    );

    let type_mismatch = model
        .validate_policy(base_policy().bind_context(ContextBinding::new(
            "by_id",
            "value",
            provider(ContextValueType::String, json!("one")),
        )))
        .err()
        .expect("provider type mismatch must fail registration");
    assert_eq!(
        type_mismatch,
        PolicyError::ProviderTypeMismatch {
            condition: "by_id".into(),
            parameter: "value".into(),
            expected: ContextValueType::Int,
            actual: ContextValueType::String,
        }
    );
}

#[test]
fn same_parameter_name_with_different_condition_types_requires_scoped_bindings() {
    let model = FgaAuthz::new(POLICY_MODEL).unwrap();

    // Bindings always identify both condition and parameter; same-named inputs
    // therefore cannot be treated as one global value with incompatible types.
    let validated = model
        .validate_policy(
            base_policy()
                .bind_context(ContextBinding::new(
                    "by_id",
                    "value",
                    provider(ContextValueType::Int, json!(3)),
                ))
                .bind_context(ContextBinding::new(
                    "by_name",
                    "value",
                    provider(ContextValueType::String, json!("anna")),
                )),
        )
        .unwrap();
    assert_eq!(validated.relation(), "viewer");
    assert_eq!(validated.object_type(), "document");

    // Request providers are optional because a tuple may already hold context,
    // or a different branch may authorize without evaluating this condition.
    assert!(model.validate_policy(base_policy()).is_ok());
}

#[test]
fn typed_double_context_rejects_lossy_integer_conversions() {
    assert!(ContextValue::new(ContextValueType::Double, json!(9_007_199_254_740_992_u64),).is_ok());
    assert!(
        ContextValue::new(ContextValueType::Double, json!(9_007_199_254_740_993_u64),).is_err()
    );
    assert!(ContextValue::new(ContextValueType::Double, json!(1.25)).is_ok());
}

#[derive(Clone)]
struct ExtensionPrincipal(Subject, TenantId);

impl PrincipalIdentity for ExtensionPrincipal {
    fn subject(&self) -> &Subject {
        &self.0
    }
}

impl TenantIdentity for ExtensionPrincipal {
    fn tenant_id(&self) -> &TenantId {
        &self.1
    }
}

struct CapturedAsyncValue(ContextValue);

impl AsyncContextResolver for CapturedAsyncValue {
    fn resolve<'a>(&'a self, _parts: &'a Parts) -> ContextResolverFuture<'a> {
        let value = self.0.clone();
        Box::pin(async move { Ok(value) })
    }
}

#[test]
fn request_parts_and_async_resolvers_produce_scoped_values_without_body_access() {
    let model = FgaAuthz::new(POLICY_MODEL).unwrap();
    let int_provider =
        ContextValueProvider::from_request_parts(ContextValueType::Int, |parts: &Parts| {
            let value = parts
                .headers
                .get("x-count")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<i64>().ok())
                .ok_or_else(|| PolicyInputError::ResolverFailure("missing x-count".into()))?;
            ContextValue::new(ContextValueType::Int, json!(value))
        });
    let async_provider = ContextValueProvider::from_async(
        ContextValueType::String,
        CapturedAsyncValue(ContextValue::new(ContextValueType::String, json!("anna")).unwrap()),
    );
    let validated = model
        .validate_policy(
            RoutePolicy::new("document", "viewer")
                .principal(PrincipalSource::extension::<ExtensionPrincipal>())
                .tenant(TenantSource::extension::<ExtensionPrincipal>())
                .object_id(ObjectIdSource::path("document_id"))
                .bind_context(ContextBinding::new("by_id", "value", int_provider))
                .bind_context(ContextBinding::new("by_name", "value", async_provider)),
        )
        .unwrap();

    let (mut parts, body) = Request::new("body stays available").into_parts();
    parts
        .headers
        .insert("x-count", HeaderValue::from_static("7"));
    parts.extensions.insert(ExtensionPrincipal(
        Subject::new("user", "anne").unwrap(),
        TenantId::new("tenant-a").unwrap(),
    ));
    parts
        .extensions
        .insert(PathParameters::new(BTreeMap::from([(
            "document_id".into(),
            "42".into(),
        )])));

    assert_eq!(
        validated.resolve_principal(&parts).unwrap(),
        Subject::new("user", "anne").unwrap()
    );
    assert_eq!(
        validated.resolve_tenant(&parts).unwrap(),
        TenantId::new("tenant-a").unwrap()
    );
    assert_eq!(validated.resolve_object_id(&parts).unwrap().as_str(), "42");
    assert!(validated.requires_path_params());
    let context = block_on(validated.resolve_context(&parts)).unwrap();
    assert_eq!(context["by_id"]["value"], json!(7));
    assert_eq!(context["by_name"]["value"], json!("anna"));
    assert_eq!(body, "body stays available");
}

#[test]
fn condition_scoped_context_values_do_not_collide_with_global_values() {
    let definition = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define int_viewer: [user with by_id]\n    define string_viewer: [user with by_name]\ncondition by_id(value: int) { value > 0 }\ncondition by_name(value: string) { value.startsWith(\"a\") }\n";
    let store = InMemoryRelationshipStore::new();
    let subject = Subject::new("user", "anne").unwrap();
    for (relation, condition) in [("int_viewer", "by_id"), ("string_viewer", "by_name")] {
        store
            .insert(
                RelationshipTuple::new(
                    TenantId::new("tenant-a").unwrap(),
                    ObjectRef::new("document", "42").unwrap(),
                    RelationName::new(relation).unwrap(),
                    subject.clone(),
                )
                .with_condition(
                    relgraph_authz::ConditionContext::new(condition, BTreeMap::new()).unwrap(),
                ),
            )
            .unwrap();
    }
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());
    let request = |relation: &str, condition: &str, scoped_value: Value, global_value: Value| {
        CheckRequest::new(
            TenantId::new("tenant-a").unwrap(),
            Subject::new("user", "anne").unwrap(),
            ObjectRef::new("document", "42").unwrap(),
            RelationName::new(relation).unwrap(),
        )
        .with_context(BTreeMap::from([("value".into(), global_value)]))
        .with_condition_context(condition, BTreeMap::from([("value".into(), scoped_value)]))
    };

    assert_eq!(
        block_on(authz.check(request(
            "int_viewer",
            "by_id",
            json!(4),
            json!("wrong type")
        )))
        .unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        block_on(authz.check(request("string_viewer", "by_name", json!("anna"), json!(4),)))
            .unwrap(),
        AuthorizationDecision::Allow
    );
}

#[test]
fn stored_tuple_context_cannot_be_overridden_by_condition_scoped_request_values() {
    let definition = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user with enabled]\ncondition enabled(value: int) { value > 0 }\n";
    let store = InMemoryRelationshipStore::new();
    store
        .insert(
            RelationshipTuple::new(
                TenantId::new("tenant-a").unwrap(),
                ObjectRef::new("document", "42").unwrap(),
                RelationName::new("viewer").unwrap(),
                Subject::new("user", "anne").unwrap(),
            )
            .with_condition(
                relgraph_authz::ConditionContext::new(
                    "enabled",
                    BTreeMap::from([("value".into(), json!(0))]),
                )
                .unwrap(),
            ),
        )
        .unwrap();
    let authz = FgaAuthz::new(definition)
        .unwrap()
        .with_store(store, EvaluationLimits::default());
    let request = CheckRequest::new(
        TenantId::new("tenant-a").unwrap(),
        Subject::new("user", "anne").unwrap(),
        ObjectRef::new("document", "42").unwrap(),
        RelationName::new("viewer").unwrap(),
    )
    .with_condition_context("enabled", BTreeMap::from([("value".into(), json!(1))]));

    assert_eq!(
        block_on(authz.check(request)).unwrap(),
        AuthorizationDecision::Deny
    );
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::as_mut(&mut future).poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
