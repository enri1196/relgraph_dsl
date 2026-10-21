//! Userset and typed-wildcard check subjects through the public API, following
//! OpenFGA's Check semantics for non-concrete request users.

#[allow(dead_code)]
mod common;

use common::{object, relation, subject, tenant};
use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, Bound, CheckRequest,
    EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, RelationshipTuple, TupleSubject,
    TypeName,
};

const MODEL: &str = "\
model
  schema 1.1
type user
type group
  relations
    define member: [user, user:*, group#member]
    define owner: member
type folder
  relations
    define viewer: [user, user:*, group#member]
type document
  relations
    define parent: [folder]
    define viewer: [user, user:*, group#member] or viewer from parent
    define blocked: [user, group#member]
    define reader: viewer but not blocked
";

use AuthorizationDecision::{Allow, Deny};

fn members(id: &str) -> TupleSubject {
    TupleSubject::Userset {
        object: object("group", id),
        relation: relation("member"),
    }
}

fn user(id: &str) -> TupleSubject {
    subject("user", id).into()
}

fn everyone() -> TupleSubject {
    TupleSubject::TypedWildcard(TypeName::new("user").unwrap())
}

fn tuple(
    object_type: &str,
    object_id: &str,
    name: &str,
    subject: TupleSubject,
) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant("acme"),
        object(object_type, object_id),
        relation(name),
        subject,
    )
}

fn authz(
    stored: impl IntoIterator<Item = RelationshipTuple>,
) -> FgaAuthz<Bound<InMemoryRelationshipStore>> {
    let store = InMemoryRelationshipStore::new();
    for tuple in stored {
        store.insert(tuple).unwrap();
    }
    FgaAuthz::new(MODEL)
        .unwrap()
        .with_store(store, EvaluationLimits::default())
}

async fn decide(
    authz: &FgaAuthz<Bound<InMemoryRelationshipStore>>,
    checked: TupleSubject,
    object_type: &str,
    object_id: &str,
    name: &str,
) -> Result<AuthorizationDecision, AuthorizationError> {
    authz
        .check(CheckRequest::new(
            tenant("acme"),
            checked,
            object(object_type, object_id),
            relation(name),
        ))
        .await
}

#[tokio::test]
async fn a_userset_subject_is_granted_by_its_own_tuple_and_nested_usersets() {
    let authz = authz([
        tuple("document", "direct", "viewer", members("eng")),
        // group:eng#member is a member of group:staff, which views "nested".
        tuple("group", "staff", "member", members("eng")),
        tuple("document", "nested", "viewer", members("staff")),
        // Through a tuple-to-userset parent.
        tuple("folder", "shared", "viewer", members("eng")),
        tuple(
            "document",
            "child",
            "parent",
            subject("folder", "shared").into(),
        ),
        tuple("document", "other", "viewer", members("ops")),
        tuple("document", "people", "viewer", user("anne")),
    ]);

    let request = CheckRequest::new(
        tenant("acme"),
        members("eng"),
        object("document", "direct"),
        relation("viewer"),
    );
    assert_eq!(request.subject(), &members("eng"));
    assert_eq!(authz.check(request).await.unwrap(), Allow);
    for (object_id, expected) in [
        ("nested", Allow),
        ("child", Allow),
        ("other", Deny),
        // A concrete user tuple never grants a userset subject.
        ("people", Deny),
    ] {
        assert_eq!(
            decide(&authz, members("eng"), "document", object_id, "viewer")
                .await
                .unwrap(),
            expected,
            "document:{object_id}"
        );
    }
}

#[tokio::test]
async fn a_userset_subject_grants_itself_as_openfga_does() {
    // OpenFGA's Check allows `group:eng#member` on `group:eng#member` without
    // any tuple (`IsSelfDefining`), including through a computed userset.
    let authz = authz([]);
    assert_eq!(
        decide(&authz, members("eng"), "group", "eng", "member")
            .await
            .unwrap(),
        Allow
    );
    assert_eq!(
        decide(&authz, members("eng"), "group", "eng", "owner")
            .await
            .unwrap(),
        Allow
    );
    assert_eq!(
        decide(&authz, members("eng"), "group", "ops", "member")
            .await
            .unwrap(),
        Deny
    );
}

#[tokio::test]
async fn wildcard_tuples_never_grant_a_userset_subject() {
    let authz = authz([tuple("document", "public", "viewer", everyone())]);
    assert_eq!(
        decide(&authz, members("eng"), "document", "public", "viewer")
            .await
            .unwrap(),
        Deny
    );
    assert_eq!(
        decide(&authz, user("anne"), "document", "public", "viewer")
            .await
            .unwrap(),
        Allow
    );
}

#[tokio::test]
async fn a_wildcard_subject_is_granted_only_by_wildcard_tuples() {
    let authz = authz([
        tuple("document", "public", "viewer", everyone()),
        tuple("document", "private", "viewer", user("anne")),
        // Every user is a member of group:all, which views "via-group".
        tuple("group", "all", "member", everyone()),
        tuple("document", "via-group", "viewer", members("all")),
    ]);
    for (object_id, expected) in [("public", Allow), ("private", Deny), ("via-group", Allow)] {
        assert_eq!(
            decide(&authz, everyone(), "document", object_id, "viewer")
                .await
                .unwrap(),
            expected,
            "document:{object_id}"
        );
    }
}

#[tokio::test]
async fn usersets_and_wildcards_combine_with_difference() {
    let authz = authz([
        tuple("document", "1", "viewer", members("eng")),
        tuple("document", "2", "viewer", members("eng")),
        tuple("document", "2", "blocked", members("eng")),
    ]);
    assert_eq!(
        decide(&authz, members("eng"), "document", "1", "reader")
            .await
            .unwrap(),
        Allow
    );
    assert_eq!(
        decide(&authz, members("eng"), "document", "2", "reader")
            .await
            .unwrap(),
        Deny
    );
}

#[tokio::test]
async fn unknown_subject_types_and_relations_are_errors() {
    let authz = authz([]);
    let unknown_type = TupleSubject::Userset {
        object: object("folder_set", "x"),
        relation: relation("member"),
    };
    assert!(matches!(
        decide(&authz, unknown_type, "document", "1", "viewer").await,
        Err(AuthorizationError::UnknownSubjectType(subject_type)) if subject_type == "folder_set"
    ));
    let unknown_relation = TupleSubject::Userset {
        object: object("document", "x"),
        relation: relation("writer"),
    };
    let error = decide(&authz, unknown_relation, "document", "1", "viewer")
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        AuthorizationError::UnknownSubjectRelation { subject_type, relation }
            if subject_type == "document" && relation == "writer"
    ));
    assert_eq!(
        error.to_string(),
        "subject userset relation 'document#writer' is not in the authorization model"
    );
    let unknown_wildcard = TupleSubject::TypedWildcard(TypeName::new("robot").unwrap());
    assert!(matches!(
        decide(&authz, unknown_wildcard, "document", "1", "viewer").await,
        Err(AuthorizationError::UnknownSubjectType(subject_type)) if subject_type == "robot"
    ));

    let batch = BatchCheckRequest::new(
        tenant("acme"),
        TupleSubject::Userset {
            object: object("group", "eng"),
            relation: relation("admin"),
        },
        [(object("document", "1"), relation("viewer"))],
    );
    assert!(matches!(
        authz.batch_check(&batch).await,
        Err(AuthorizationError::UnknownSubjectRelation { .. })
    ));
}

#[tokio::test]
async fn a_batch_with_a_userset_subject_matches_individual_checks() {
    let authz = authz([
        tuple("group", "staff", "member", members("eng")),
        tuple("document", "a", "viewer", members("staff")),
        tuple("document", "b", "viewer", members("eng")),
        tuple("document", "c", "viewer", user("anne")),
        tuple("document", "d", "viewer", everyone()),
    ]);
    let items = [
        (object("document", "a"), relation("viewer")),
        (object("document", "b"), relation("viewer")),
        (object("document", "c"), relation("viewer")),
        (object("document", "d"), relation("viewer")),
        (object("group", "eng"), relation("member")),
        (object("group", "staff"), relation("owner")),
    ];
    let batch = BatchCheckRequest::new(tenant("acme"), members("eng"), items.clone());
    assert_eq!(batch.subject(), &members("eng"));
    let results = authz.batch_check(&batch).await.unwrap();
    let mut individual = Vec::new();
    for (object, name) in items {
        individual.push(
            authz
                .check(CheckRequest::new(
                    tenant("acme"),
                    members("eng"),
                    object,
                    name,
                ))
                .await
                .unwrap(),
        );
    }
    let batched: Vec<_> = results.into_iter().map(Result::unwrap).collect();
    assert_eq!(batched, individual);
    assert_eq!(batched, [Allow, Allow, Deny, Deny, Allow, Allow]);
}
