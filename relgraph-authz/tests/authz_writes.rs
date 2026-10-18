#[allow(dead_code)]
mod common;

use common::{block_on, object, relation, subject, tenant};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, Bound, CheckRequest, EvaluationLimits, FgaAuthz,
    InMemoryRelationshipStore, RelationshipReadSession, RelationshipStore, RelationshipTuple,
    StoreErrorKind, WriteError,
};

const MODEL: &str = "model\nschema 1.1\ntype user\ntype document\n  relations\n    define owner: [user]\n    define viewer: [user] or owner\n";

fn authorizer() -> (
    InMemoryRelationshipStore,
    FgaAuthz<Bound<InMemoryRelationshipStore>>,
) {
    let store = InMemoryRelationshipStore::new();
    let authz = FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(store.clone(), EvaluationLimits::default());
    (store, authz)
}

fn document_tuple(relation_name: &str, subject_type: &str, id: &str) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation(relation_name),
        subject(subject_type, id),
    )
}

fn stored(store: &InMemoryRelationshipStore, relation_name: &str) -> Vec<RelationshipTuple> {
    let session = block_on(store.begin_read(&tenant("tenant-a"))).unwrap();
    block_on(session.tuples(&object("document", "42"), &relation(relation_name), 10)).unwrap()
}

fn check(authz: &FgaAuthz<Bound<InMemoryRelationshipStore>>, id: &str) -> AuthorizationDecision {
    block_on(authz.check(CheckRequest::new(
        tenant("tenant-a"),
        subject("user", id),
        object("document", "42"),
        relation("viewer"),
    )))
    .unwrap()
}

#[test]
fn validating_writes_insert_and_delete_model_tuples() {
    let (store, authz) = authorizer();
    let owner = document_tuple("owner", "user", "anne");

    block_on(authz.write_tuple(&tenant("tenant-a"), &owner)).unwrap();
    assert_eq!(stored(&store, "owner"), std::slice::from_ref(&owner));
    assert_eq!(check(&authz, "anne"), AuthorizationDecision::Allow);

    assert!(block_on(authz.delete_tuple(&tenant("tenant-a"), &owner)).unwrap());
    assert!(!block_on(authz.delete_tuple(&tenant("tenant-a"), &owner)).unwrap());
    assert!(stored(&store, "owner").is_empty());
    assert_eq!(check(&authz, "anne"), AuthorizationDecision::Deny);
}

#[test]
fn tuples_outside_the_model_never_reach_the_store() {
    let (store, authz) = authorizer();
    let wrong_subject = document_tuple("owner", "document", "7");
    let unknown_relation = RelationshipTuple::new(
        tenant("tenant-a"),
        object("document", "42"),
        relation("missing"),
        subject("user", "anne"),
    );

    for invalid in [&wrong_subject, &unknown_relation] {
        assert!(matches!(
            block_on(authz.write_tuple(&tenant("tenant-a"), invalid)),
            Err(WriteError::Validation(_))
        ));
        assert!(matches!(
            block_on(authz.delete_tuple(&tenant("tenant-a"), invalid)),
            Err(WriteError::Validation(_))
        ));
    }
    assert!(matches!(
        block_on(authz.write_tuple(&tenant("tenant-a"), &unknown_relation)),
        Err(WriteError::Validation(
            AuthorizationError::UnknownRelation { .. }
        ))
    ));
    assert!(stored(&store, "owner").is_empty());
}

#[test]
fn tenant_mismatch_and_duplicates_are_store_errors() {
    let (_store, authz) = authorizer();
    let owner = document_tuple("owner", "user", "anne");

    for result in [
        block_on(authz.write_tuple(&tenant("tenant-b"), &owner)),
        block_on(authz.delete_tuple(&tenant("tenant-b"), &owner)).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(WriteError::Store(error)) if error.kind() == StoreErrorKind::InvalidInput
        ));
    }

    block_on(authz.write_tuple(&tenant("tenant-a"), &owner)).unwrap();
    assert!(matches!(
        block_on(authz.write_tuple(&tenant("tenant-a"), &owner)),
        Err(WriteError::Store(error)) if error.kind() == StoreErrorKind::Conflict
    ));
}
