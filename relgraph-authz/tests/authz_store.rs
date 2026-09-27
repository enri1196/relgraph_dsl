#[allow(dead_code)]
mod common;

use common::{block_on, object, relation, subject, tenant};
use relgraph_authz::{
    ConditionContext, InMemoryRelationshipStore, RelationshipReadSession, RelationshipStore,
    RelationshipTuple,
};

#[test]
fn in_memory_store_is_explicitly_empty_and_tenant_scoped() {
    let store = InMemoryRelationshipStore::new();
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    let object = object("document", "42");
    let relation = relation("viewer");
    let tuple = RelationshipTuple::new(
        tenant_a.clone(),
        object.clone(),
        relation.clone(),
        subject("user", "anne"),
    );

    let empty = block_on(store.begin_read(&tenant_a)).unwrap();
    assert!(
        block_on(empty.tuples(&object, &relation, 10))
            .unwrap()
            .is_empty()
    );

    store.insert(tuple.clone()).unwrap();
    let session_a = block_on(store.begin_read(&tenant_a)).unwrap();
    let session_b = block_on(store.begin_read(&tenant_b)).unwrap();
    assert_eq!(
        block_on(session_a.tuples(&object, &relation, 10)).unwrap(),
        vec![tuple.clone()]
    );
    assert!(
        block_on(session_b.tuples(&object, &relation, 10))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn read_session_keeps_an_immutable_snapshot() {
    let store = InMemoryRelationshipStore::new();
    let tenant = tenant("tenant-a");
    let object = object("document", "42");
    let relation = relation("viewer");
    let session = block_on(store.begin_read(&tenant)).unwrap();

    store
        .insert(RelationshipTuple::new(
            tenant,
            object.clone(),
            relation.clone(),
            subject("user", "anne"),
        ))
        .unwrap();

    assert!(
        block_on(session.tuples(&object, &relation, 10))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn in_memory_store_reports_tuple_limit_exhaustion() {
    let store = InMemoryRelationshipStore::new();
    let tenant = tenant("tenant-a");
    let object = object("document", "42");
    let relation = relation("viewer");
    for id in ["anne", "bea"] {
        store
            .insert(RelationshipTuple::new(
                tenant.clone(),
                object.clone(),
                relation.clone(),
                subject("user", id),
            ))
            .unwrap();
    }

    let session = block_on(store.begin_read(&tenant)).unwrap();
    let error = block_on(session.tuples(&object, &relation, 1)).unwrap_err();
    assert_eq!(
        error.kind(),
        relgraph_authz::StoreErrorKind::TupleLimitExceeded
    );
}

#[test]
fn store_preserves_named_condition_context_for_later_evaluation() {
    let store = InMemoryRelationshipStore::new();
    let tenant = tenant("tenant-a");
    let object = object("document", "42");
    let relation = relation("viewer");
    let context = ConditionContext::new(
        "paid_plan",
        std::collections::BTreeMap::from([("plan".to_owned(), serde_json::json!("pro"))]),
    )
    .unwrap();
    let tuple = RelationshipTuple::new(
        tenant.clone(),
        object.clone(),
        relation.clone(),
        subject("user", "anne"),
    )
    .with_condition(context);
    store.insert(tuple.clone()).unwrap();

    let session = block_on(store.begin_read(&tenant)).unwrap();
    let stored = block_on(session.tuples(&object, &relation, 10)).unwrap();
    assert_eq!(stored, vec![tuple]);
    assert_eq!(
        stored[0].condition().unwrap().values().get("plan"),
        Some(&serde_json::json!("pro"))
    );
}
