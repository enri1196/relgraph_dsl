#[allow(dead_code)]
mod common;

#[path = "support/store_contract.rs"]
mod store_contract;

use common::{block_on, object, relation, subject, tenant};
use relgraph_authz::{
    ConditionContext, InMemoryRelationshipStore, RelationshipReadSession, RelationshipStore,
    RelationshipTuple, RelationshipWriteStore, StoreError, StoreErrorKind, StoreFuture,
};
use std::collections::BTreeMap;

#[test]
fn in_memory_cursors_are_session_and_query_bound() {
    let store = InMemoryRelationshipStore::new();
    let tenant = tenant("tenant-a");
    let document = object("document", "42");
    let viewer_relation = relation("viewer");
    for id in ["anne", "bob", "carlos"] {
        store
            .insert(RelationshipTuple::new(
                tenant.clone(),
                document.clone(),
                viewer_relation.clone(),
                subject("user", id),
            ))
            .unwrap();
    }

    let first_session = block_on(store.begin_read(&tenant)).unwrap();
    let first_page =
        block_on(first_session.tuples_page(&document, &viewer_relation, None, 1)).unwrap();
    assert_eq!(first_page.tuples.len(), 1);
    let cursor = first_page.next_cursor.expect("more tuples remain");
    assert!(!cursor.as_bytes().is_empty());

    let second_page =
        block_on(first_session.tuples_page(&document, &viewer_relation, Some(cursor.clone()), 1))
            .unwrap();
    assert_eq!(second_page.tuples.len(), 1);
    let next_cursor = second_page.next_cursor.expect("one tuple remains");
    let last_page =
        block_on(first_session.tuples_page(&document, &viewer_relation, Some(next_cursor), 1))
            .unwrap();
    assert_eq!(last_page.tuples.len(), 1);
    assert!(last_page.next_cursor.is_none());

    let other_session = block_on(store.begin_read(&tenant)).unwrap();
    assert_eq!(
        block_on(other_session.tuples_page(&document, &viewer_relation, Some(cursor.clone()), 1,))
            .unwrap_err()
            .kind(),
        StoreErrorKind::IncompleteRead
    );

    let other_tenant = relgraph_authz::TenantId::new("tenant-b").unwrap();
    let other_tenant_session = block_on(store.begin_read(&other_tenant)).unwrap();
    assert_eq!(
        block_on(other_tenant_session.tuples_page(
            &document,
            &viewer_relation,
            Some(cursor.clone()),
            1,
        ))
        .unwrap_err()
        .kind(),
        StoreErrorKind::IncompleteRead
    );

    let other_object = object("folder", "42");
    assert_eq!(
        block_on(first_session.tuples_page(
            &other_object,
            &viewer_relation,
            Some(cursor.clone()),
            1,
        ))
        .unwrap_err()
        .kind(),
        StoreErrorKind::IncompleteRead
    );

    let other_relation = relation("editor");
    assert_eq!(
        block_on(first_session.tuples_page(&document, &other_relation, Some(cursor), 1))
            .unwrap_err()
            .kind(),
        StoreErrorKind::IncompleteRead
    );

    assert_eq!(
        block_on(first_session.tuples_page(&document, &viewer_relation, None, 0))
            .unwrap_err()
            .kind(),
        StoreErrorKind::IncompleteRead
    );
}

struct CompleteReadSession;

impl RelationshipReadSession for CompleteReadSession {
    fn tuples<'a>(
        &'a self,
        _object: &'a relgraph_authz::ObjectRef,
        _relation: &'a relgraph_authz::RelationName,
        _maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

#[test]
fn default_page_adapter_rejects_zero_maximum() {
    let session = CompleteReadSession;
    let document = object("document", "42");
    let relation = relation("viewer");
    assert_eq!(
        block_on(session.tuples_page(&document, &relation, None, 0))
            .unwrap_err()
            .kind(),
        StoreErrorKind::IncompleteRead
    );
}

#[test]
fn in_memory_write_trait_validates_tenant_and_preserves_exact_tuple_identity() {
    let store = InMemoryRelationshipStore::new();
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    let document = object("document", "42");
    let relation = relation("viewer");
    let condition_a = ConditionContext::new(
        "grant",
        BTreeMap::from([("enabled".to_owned(), serde_json::json!(true))]),
    )
    .unwrap();
    let condition_b = ConditionContext::new(
        "grant",
        BTreeMap::from([("enabled".to_owned(), serde_json::json!(false))]),
    )
    .unwrap();
    let tuple_a = RelationshipTuple::new(
        tenant_a.clone(),
        document.clone(),
        relation.clone(),
        subject("user", "anne"),
    )
    .with_condition(condition_a);
    let tuple_b = RelationshipTuple::new(
        tenant_a.clone(),
        document.clone(),
        relation.clone(),
        subject("user", "anne"),
    )
    .with_condition(condition_b);

    assert_eq!(
        block_on(store.insert_tuple(&tenant_b, &tuple_a))
            .unwrap_err()
            .kind(),
        StoreErrorKind::CorruptData
    );
    assert_eq!(
        block_on(store.remove_tuple(&tenant_b, &tuple_a))
            .unwrap_err()
            .kind(),
        StoreErrorKind::CorruptData
    );

    block_on(store.insert_tuple(&tenant_a, &tuple_a)).unwrap();
    assert_eq!(
        block_on(store.insert_tuple(&tenant_a, &tuple_a))
            .unwrap_err()
            .kind(),
        StoreErrorKind::CorruptData
    );
    block_on(store.insert_tuple(&tenant_a, &tuple_b)).unwrap();

    let condition_variant_not_stored = RelationshipTuple::new(
        tenant_a.clone(),
        document.clone(),
        relation.clone(),
        subject("user", "anne"),
    )
    .with_condition(
        ConditionContext::new(
            "grant",
            BTreeMap::from([("enabled".to_owned(), serde_json::json!(null))]),
        )
        .unwrap(),
    );
    assert!(!block_on(store.remove_tuple(&tenant_a, &condition_variant_not_stored)).unwrap());
    assert!(block_on(store.remove_tuple(&tenant_a, &tuple_b)).unwrap());
    assert!(!block_on(store.remove_tuple(&tenant_a, &tuple_b)).unwrap());

    let session = block_on(store.begin_read(&tenant_a)).unwrap();
    let remaining = block_on(session.tuples(&document, &relation, 10)).unwrap();
    assert_eq!(remaining, vec![tuple_a]);

    let different_tenant_session = block_on(store.begin_read(&tenant_b)).unwrap();
    assert!(
        block_on(different_tenant_session.tuples(&document, &relation, 10))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn shared_relationship_store_contracts_pass_for_the_in_memory_backend() {
    block_on(store_contract::run_store_contracts(
        InMemoryRelationshipStore::new(),
    ));
}
