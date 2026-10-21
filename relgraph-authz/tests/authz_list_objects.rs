//! ListObjects through the public API: candidate generation, decisions by
//! the check path, limits, contextual tuples and the reverse-lookup store.

use std::collections::BTreeMap;

use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, Bound, CheckRequest, ConditionContext,
    ContextualTupleError, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore,
    ListObjectsRequest, ObjectRef, RelationName, RelationshipReadSession, RelationshipStore,
    RelationshipTuple, ReverseLookupSession, StoreCursor, StoreErrorKind, Subject, TenantId,
    TupleSubject, TypeName,
};

const MODEL: &str = r#"model
  schema 1.1
type user
type group
  relations
    define member: [user, user:*, group#member]
type folder
  relations
    define viewer: [user, group#member]
type document
  relations
    define parent: [folder]
    define owner: [user]
    define editor: [user, group#member] or owner
    define viewer: [user, user:*, group#member] or editor or viewer from parent
    define blocked: [user]
    define reader: viewer but not blocked
    define approver: [user]
    define signer: editor and approver
    define guest: [user with in_office]
condition in_office(office: bool) {
  office
}
"#;

type Authorizer = FgaAuthz<Bound<InMemoryRelationshipStore>>;

fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn user(id: &str) -> TupleSubject {
    Subject::new("user", id).unwrap().into()
}

fn userset(object_type: &str, id: &str, relation: &str) -> TupleSubject {
    TupleSubject::Userset {
        object: ObjectRef::new(object_type, id).unwrap(),
        relation: RelationName::new(relation).unwrap(),
    }
}

fn wildcard(type_name: &str) -> TupleSubject {
    TupleSubject::TypedWildcard(TypeName::new(type_name).unwrap())
}

fn tuple(object: &str, relation: &str, subject: TupleSubject) -> RelationshipTuple {
    let (object_type, id) = object.split_once(':').unwrap();
    RelationshipTuple::new(
        tenant(),
        ObjectRef::new(object_type, id).unwrap(),
        RelationName::new(relation).unwrap(),
        subject,
    )
}

fn documents(ids: &[&str]) -> Vec<ObjectRef> {
    ids.iter()
        .map(|id| ObjectRef::new("document", *id).unwrap())
        .collect()
}

fn authorizer(tuples: impl IntoIterator<Item = RelationshipTuple>) -> Authorizer {
    authorizer_with_limits(tuples, EvaluationLimits::default())
}

fn authorizer_with_limits(
    tuples: impl IntoIterator<Item = RelationshipTuple>,
    limits: EvaluationLimits,
) -> Authorizer {
    let store = InMemoryRelationshipStore::new();
    for tuple in tuples {
        store.insert(tuple).unwrap();
    }
    FgaAuthz::new(MODEL).unwrap().with_store(store, limits)
}

fn request(subject: TupleSubject, object_type: &str, relation: &str) -> ListObjectsRequest {
    ListObjectsRequest::new(
        tenant(),
        subject,
        TypeName::new(object_type).unwrap(),
        RelationName::new(relation).unwrap(),
    )
}

async fn list(
    authz: &Authorizer,
    subject: TupleSubject,
    relation: &str,
) -> Result<Vec<ObjectRef>, AuthorizationError> {
    authz
        .list_objects(&request(subject, "document", relation))
        .await
}

#[tokio::test]
async fn lists_direct_tuples_sorted_and_omits_other_subjects() {
    let authz = authorizer([
        tuple("document:2", "viewer", user("anne")),
        tuple("document:1", "viewer", user("anne")),
        tuple("document:3", "viewer", user("bob")),
    ]);

    assert_eq!(
        list(&authz, user("anne"), "viewer").await.unwrap(),
        documents(&["1", "2"])
    );
    assert_eq!(
        list(&authz, user("carl"), "viewer").await.unwrap(),
        documents(&[])
    );
}

#[tokio::test]
async fn follows_computed_usersets_on_the_same_object() {
    let authz = authorizer([
        tuple("document:1", "owner", user("anne")),
        tuple("document:2", "editor", user("anne")),
    ]);

    assert_eq!(
        list(&authz, user("anne"), "editor").await.unwrap(),
        documents(&["1", "2"])
    );
    assert_eq!(
        list(&authz, user("anne"), "viewer").await.unwrap(),
        documents(&["1", "2"])
    );
    assert_eq!(
        list(&authz, user("anne"), "owner").await.unwrap(),
        documents(&["1"])
    );
}

#[tokio::test]
async fn follows_tuple_to_userset_from_the_parent() {
    let authz = authorizer([
        tuple("folder:f1", "viewer", user("anne")),
        tuple("folder:f2", "viewer", userset("group", "eng", "member")),
        tuple("group:eng", "member", user("bob")),
        tuple(
            "document:1",
            "parent",
            Subject::new("folder", "f1").unwrap().into(),
        ),
        tuple(
            "document:2",
            "parent",
            Subject::new("folder", "f2").unwrap().into(),
        ),
    ]);

    assert_eq!(
        list(&authz, user("anne"), "viewer").await.unwrap(),
        documents(&["1"])
    );
    assert_eq!(
        list(&authz, user("bob"), "viewer").await.unwrap(),
        documents(&["2"])
    );
}

#[tokio::test]
async fn wildcard_tuples_grant_concrete_and_wildcard_subjects_only() {
    let authz = authorizer([
        tuple("document:1", "viewer", wildcard("user")),
        tuple("document:2", "viewer", user("anne")),
        tuple("group:all", "member", wildcard("user")),
        tuple("document:3", "viewer", userset("group", "all", "member")),
    ]);

    // A typed wildcard subject matches only wildcard tuples, also through a
    // userset.
    assert_eq!(
        list(&authz, wildcard("user"), "viewer").await.unwrap(),
        documents(&["1", "3"])
    );
    assert_eq!(
        list(&authz, user("carl"), "viewer").await.unwrap(),
        documents(&["1", "3"])
    );
    assert_eq!(
        list(&authz, user("anne"), "viewer").await.unwrap(),
        documents(&["1", "2", "3"])
    );
}

#[tokio::test]
async fn userset_subjects_match_their_tuples_and_their_own_key() {
    let authz = authorizer([
        tuple("document:1", "viewer", userset("group", "eng", "member")),
        tuple("document:2", "editor", userset("group", "ops", "member")),
        tuple("group:ops", "member", userset("group", "eng", "member")),
        tuple("group:eng", "member", user("anne")),
    ]);

    assert_eq!(
        list(&authz, userset("group", "eng", "member"), "viewer")
            .await
            .unwrap(),
        documents(&["1", "2"])
    );
    assert_eq!(
        list(&authz, user("anne"), "viewer").await.unwrap(),
        documents(&["1", "2"])
    );
    // A userset subject holds its own relation on its own object.
    let groups = authz
        .list_objects(&request(
            userset("group", "eng", "member"),
            "group",
            "member",
        ))
        .await
        .unwrap();
    assert_eq!(
        groups,
        [
            ObjectRef::new("group", "eng").unwrap(),
            ObjectRef::new("group", "ops").unwrap()
        ]
    );
}

#[tokio::test]
async fn intersection_and_difference_are_decided_by_check() {
    let authz = authorizer([
        tuple("document:1", "viewer", user("anne")),
        tuple("document:2", "viewer", user("anne")),
        tuple("document:2", "blocked", user("anne")),
        tuple("document:3", "editor", user("anne")),
        tuple("document:3", "approver", user("anne")),
        tuple("document:4", "editor", user("anne")),
        tuple("document:5", "approver", user("anne")),
    ]);

    assert_eq!(
        list(&authz, user("anne"), "reader").await.unwrap(),
        documents(&["1", "3", "4"])
    );
    assert_eq!(
        list(&authz, user("anne"), "signer").await.unwrap(),
        documents(&["3"])
    );
}

#[tokio::test]
async fn unknown_types_relations_and_subjects_are_errors() {
    let authz = authorizer([tuple("document:1", "viewer", user("anne"))]);

    assert!(matches!(
        authz
            .list_objects(&request(user("anne"), "spreadsheet", "viewer"))
            .await,
        Err(AuthorizationError::UnknownObjectType(object_type)) if object_type == "spreadsheet"
    ));
    assert!(matches!(
        list(&authz, user("anne"), "commenter").await,
        Err(AuthorizationError::UnknownRelation { relation, .. }) if relation == "commenter"
    ));
    assert!(matches!(
        list(&authz, Subject::new("robot", "r1").unwrap().into(), "viewer").await,
        Err(AuthorizationError::UnknownSubjectType(subject_type)) if subject_type == "robot"
    ));
    assert!(matches!(
        list(&authz, userset("group", "eng", "owner"), "viewer").await,
        Err(AuthorizationError::UnknownSubjectRelation { relation, .. }) if relation == "owner"
    ));
}

#[tokio::test]
async fn exceeding_the_candidate_limit_is_an_error_not_a_partial_list() {
    let tuples =
        || ["1", "2", "3"].map(|id| tuple(&format!("document:{id}"), "viewer", user("anne")));
    let limited = authorizer_with_limits(
        tuples(),
        EvaluationLimits::default()
            .with_max_list_candidates(2)
            .unwrap(),
    );
    assert!(matches!(
        list(&limited, user("anne"), "viewer").await,
        Err(AuthorizationError::ListCandidateLimitExceeded {
            maximum_candidates: 2
        })
    ));

    let exact = authorizer_with_limits(
        tuples(),
        EvaluationLimits::default()
            .with_max_list_candidates(3)
            .unwrap(),
    );
    assert_eq!(
        list(&exact, user("anne"), "viewer").await.unwrap(),
        documents(&["1", "2", "3"])
    );

    assert_eq!(
        EvaluationLimits::default().max_list_candidates(),
        EvaluationLimits::DEFAULT_MAX_LIST_CANDIDATES
    );
    assert!(
        EvaluationLimits::default()
            .with_max_list_candidates(0)
            .is_err()
    );
    assert!(
        EvaluationLimits::default()
            .with_max_list_candidates(EvaluationLimits::MAX_LIST_CANDIDATES + 1)
            .is_err()
    );
}

#[tokio::test]
async fn budget_hits_are_errors_not_partial_lists() {
    let tuples =
        || ["1", "2", "3"].map(|id| tuple(&format!("document:{id}"), "viewer", user("anne")));

    let tuple_limited = authorizer_with_limits(tuples(), EvaluationLimits::new(2).unwrap());
    assert!(matches!(
        list(&tuple_limited, user("anne"), "viewer").await,
        Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples: 2 })
    ));

    let work_limited = authorizer_with_limits(
        tuples(),
        EvaluationLimits::default().with_max_work_units(3).unwrap(),
    );
    assert!(matches!(
        list(&work_limited, user("anne"), "viewer").await,
        Err(AuthorizationError::WorkLimitExceeded {
            maximum_work_units: 3
        })
    ));

    let call_limited = authorizer_with_limits(
        tuples(),
        EvaluationLimits::default().with_max_store_calls(1).unwrap(),
    );
    assert!(matches!(
        list(&call_limited, user("anne"), "viewer").await,
        Err(AuthorizationError::StoreCallLimitExceeded { maximum_calls: 1 })
    ));
}

#[tokio::test]
async fn each_candidate_decision_gets_its_own_budgets() {
    // The traversal reads 1,000 tuples; each decision reads a handful. A
    // shared budget of 1,500 tuples would run out.
    let ids: Vec<String> = (0..1_000).map(|id| format!("{id:04}")).collect();
    let limited = authorizer_with_limits(
        ids.iter()
            .map(|id| tuple(&format!("document:{id}"), "viewer", user("anne"))),
        EvaluationLimits::new(1_500).unwrap(),
    );
    let listed = list(&limited, user("anne"), "viewer").await.unwrap();
    assert_eq!(listed.len(), 1_000);
    assert_eq!(listed[0], ObjectRef::new("document", "0000").unwrap());
}

#[tokio::test]
async fn conditions_never_prune_and_candidate_errors_fail_the_list() {
    let conditioned = tuple("document:1", "guest", user("anne"))
        .with_condition(ConditionContext::new("in_office", BTreeMap::new()).unwrap());
    let authz = authorizer([conditioned]);
    let guest = |office: Option<bool>| {
        let request = request(user("anne"), "document", "guest");
        match office {
            Some(office) => {
                request.with_context(BTreeMap::from([("office".to_owned(), office.into())]))
            }
            None => request,
        }
    };

    assert_eq!(
        authz.list_objects(&guest(Some(true))).await.unwrap(),
        documents(&["1"])
    );
    assert_eq!(
        authz.list_objects(&guest(Some(false))).await.unwrap(),
        documents(&[])
    );
    assert!(matches!(
        authz.list_objects(&guest(None)).await,
        Err(AuthorizationError::MissingConditionContext { parameter, .. }) if parameter == "office"
    ));
}

#[tokio::test]
async fn stored_tuples_that_drifted_from_the_model_fail_the_list() {
    // The traversal validates a tuple before following it.
    let drifted = tuple("document:1", "viewer", user("anne"))
        .with_condition(ConditionContext::new("in_office", BTreeMap::new()).unwrap());
    let authz = authorizer([drifted]);
    assert!(matches!(
        list(&authz, user("anne"), "viewer").await,
        Err(AuthorizationError::InvalidTuple(_))
    ));

    // A candidate's decision reads the drifted wildcard approver tuple.
    let authz = authorizer([
        tuple("document:1", "editor", user("anne")),
        tuple("document:1", "approver", wildcard("user")),
    ]);
    assert!(matches!(
        list(&authz, user("anne"), "signer").await,
        Err(AuthorizationError::InvalidTuple(_))
    ));
}

#[tokio::test]
async fn contextual_tuples_are_followed_as_edges() {
    let authz = authorizer([
        tuple("document:2", "viewer", userset("group", "eng", "member")),
        tuple(
            "document:3",
            "parent",
            Subject::new("folder", "f1").unwrap().into(),
        ),
    ]);
    let listed = authz
        .list_objects(
            &request(user("anne"), "document", "viewer").with_contextual_tuples([
                tuple("document:1", "viewer", user("anne")),
                tuple("group:eng", "member", user("anne")),
                tuple("folder:f1", "viewer", user("anne")),
            ]),
        )
        .await
        .unwrap();
    assert_eq!(listed, documents(&["1", "2", "3"]));

    // Without them, nothing is granted.
    assert_eq!(
        list(&authz, user("anne"), "viewer").await.unwrap(),
        documents(&[])
    );
}

#[tokio::test]
async fn lists_drop_duplicate_contextual_tuples_while_checks_reject_them() {
    let authz = authorizer([]);
    let grant = tuple("document:1", "viewer", user("anne"));

    let listed = authz
        .list_objects(
            &request(user("anne"), "document", "viewer")
                .with_contextual_tuples([grant.clone(), grant.clone()]),
        )
        .await
        .unwrap();
    assert_eq!(listed, documents(&["1"]));

    let check = CheckRequest::new(
        tenant(),
        user("anne"),
        ObjectRef::new("document", "1").unwrap(),
        RelationName::new("viewer").unwrap(),
    )
    .with_contextual_tuples([grant.clone(), grant]);
    assert!(matches!(
        authz.check(check).await,
        Err(AuthorizationError::InvalidContextualTuple {
            index: 1,
            reason: ContextualTupleError::Duplicate { first_index: 0 }
        })
    ));

    // Other contextual tuple checks still apply to lists.
    let foreign = RelationshipTuple::new(
        TenantId::new("other").unwrap(),
        ObjectRef::new("document", "1").unwrap(),
        RelationName::new("viewer").unwrap(),
        Subject::new("user", "anne").unwrap(),
    );
    assert!(matches!(
        authz
            .list_objects(
                &request(user("anne"), "document", "viewer").with_contextual_tuples([foreign])
            )
            .await,
        Err(AuthorizationError::InvalidContextualTuple {
            index: 0,
            reason: ContextualTupleError::TenantMismatch
        })
    ));
}

/// A small store exercising every edge kind, wildcards, usersets, nested
/// groups, intersection and difference.
fn brute_force_tuples() -> Vec<RelationshipTuple> {
    let folder = |id: &str| -> TupleSubject { Subject::new("folder", id).unwrap().into() };
    vec![
        tuple("group:eng", "member", user("anne")),
        tuple("group:eng", "member", userset("group", "ops", "member")),
        tuple("group:ops", "member", user("bob")),
        tuple("group:all", "member", wildcard("user")),
        tuple("folder:f1", "viewer", user("anne")),
        tuple("folder:f2", "viewer", userset("group", "eng", "member")),
        tuple("document:1", "viewer", user("anne")),
        tuple("document:2", "owner", user("bob")),
        tuple("document:3", "parent", folder("f1")),
        tuple("document:4", "parent", folder("f2")),
        tuple("document:4", "blocked", user("bob")),
        tuple("document:5", "viewer", userset("group", "all", "member")),
        tuple("document:5", "blocked", user("carl")),
        tuple("document:6", "editor", userset("group", "ops", "member")),
        tuple("document:6", "approver", user("bob")),
        tuple("document:6", "approver", user("anne")),
        tuple("document:7", "viewer", wildcard("user")),
        tuple("document:7", "blocked", user("anne")),
        tuple("document:8", "parent", folder("f3")),
        tuple("document:8", "editor", user("carl")),
        tuple("document:8", "approver", user("carl")),
    ]
}

#[tokio::test]
async fn list_objects_matches_brute_force_check() {
    let authz = authorizer(brute_force_tuples());
    let subjects = [
        user("anne"),
        user("bob"),
        user("carl"),
        user("dave"),
        wildcard("user"),
        userset("group", "eng", "member"),
        userset("group", "ops", "member"),
        userset("group", "all", "member"),
        userset("folder", "f2", "viewer"),
        Subject::new("folder", "f1").unwrap().into(),
    ];
    let universe: [(&str, &[&str], &[&str]); 3] = [
        (
            "document",
            &["1", "2", "3", "4", "5", "6", "7", "8", "9"],
            &[
                "parent", "owner", "editor", "viewer", "blocked", "reader", "approver", "signer",
            ],
        ),
        ("folder", &["f1", "f2", "f3"], &["viewer"]),
        ("group", &["eng", "ops", "all"], &["member"]),
    ];

    let mut allowed_pairs = 0;
    for subject in &subjects {
        for (object_type, ids, relations) in universe {
            for relation in relations {
                let listed = authz
                    .list_objects(&request(subject.clone(), object_type, relation))
                    .await
                    .unwrap();
                let mut expected = Vec::new();
                for id in ids {
                    let object = ObjectRef::new(object_type, *id).unwrap();
                    let decision = authz
                        .check(CheckRequest::new(
                            tenant(),
                            subject.clone(),
                            object.clone(),
                            RelationName::new(*relation).unwrap(),
                        ))
                        .await
                        .unwrap();
                    if decision == AuthorizationDecision::Allow {
                        expected.push(object);
                    }
                }
                expected.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
                assert_eq!(
                    listed, expected,
                    "{subject:?} {object_type}#{relation} differs from brute-force check"
                );
                allowed_pairs += expected.len();
            }
        }
    }
    // The comparison is not vacuous.
    assert!(allowed_pairs > 40, "only {allowed_pairs} allowed pairs");
}

#[tokio::test]
async fn in_memory_subject_pages_are_tenant_scoped_snapshots() {
    let store = InMemoryRelationshipStore::new();
    for id in 0..300 {
        store
            .insert(tuple(&format!("document:{id}"), "viewer", user("anne")))
            .unwrap();
    }
    store
        .insert(tuple("document:x", "viewer", wildcard("user")))
        .unwrap();
    store
        .insert(tuple("document:y", "owner", user("anne")))
        .unwrap();
    store
        .insert(RelationshipTuple::new(
            TenantId::new("other").unwrap(),
            ObjectRef::new("document", "z").unwrap(),
            RelationName::new("viewer").unwrap(),
            Subject::new("user", "anne").unwrap(),
        ))
        .unwrap();

    let document = TypeName::new("document").unwrap();
    let viewer = RelationName::new("viewer").unwrap();
    let anne = user("anne");
    let session = store.begin_read(&tenant()).await.unwrap();
    // A later write is not observed by the open session.
    store
        .insert(tuple("document:late", "viewer", user("anne")))
        .unwrap();

    let mut cursor: Option<StoreCursor> = None;
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let page = session
            .tuples_by_subject_page(&document, &viewer, &anne, cursor.take(), 128)
            .await
            .unwrap();
        assert!(page.tuples.len() <= 128);
        pages += 1;
        seen.extend(page.tuples.into_iter().map(|tuple| {
            assert_eq!(tuple.subject(), &anne);
            assert_eq!(tuple.tenant(), &tenant());
            tuple.object().id().as_str().to_owned()
        }));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    seen.sort();
    let mut expected: Vec<String> = (0..300).map(|id| id.to_string()).collect();
    expected.sort();
    assert_eq!(seen, expected);

    let wildcard_page = session
        .tuples_by_subject_page(&document, &viewer, &wildcard("user"), None, 10)
        .await
        .unwrap();
    assert_eq!(
        wildcard_page.tuples,
        [tuple("document:x", "viewer", wildcard("user"))]
    );
    assert_eq!(wildcard_page.next_cursor, None);

    let first = session
        .tuples_by_subject_page(&document, &viewer, &anne, None, 1)
        .await
        .unwrap();
    let foreign_cursor = first.next_cursor.unwrap();
    // A cursor is bound to its session and its query.
    let other_query = session
        .tuples_by_subject_page(
            &document,
            &viewer,
            &user("bob"),
            Some(foreign_cursor.clone()),
            1,
        )
        .await
        .unwrap_err();
    assert_eq!(other_query.kind(), StoreErrorKind::IncompleteRead);
    let other_session = store.begin_read(&tenant()).await.unwrap();
    let other = other_session
        .tuples_by_subject_page(&document, &viewer, &anne, Some(foreign_cursor), 1)
        .await
        .unwrap_err();
    assert_eq!(other.kind(), StoreErrorKind::IncompleteRead);

    // Object queries on the same session are unaffected.
    let object_page = session
        .tuples_page(
            &ObjectRef::new("document", "y").unwrap(),
            &RelationName::new("owner").unwrap(),
            None,
            10,
        )
        .await
        .unwrap();
    assert_eq!(
        object_page.tuples,
        [tuple("document:y", "owner", user("anne"))]
    );

    let empty = session
        .tuples_by_subject_page(&document, &viewer, &anne, None, 0)
        .await
        .unwrap_err();
    assert_eq!(empty.kind(), StoreErrorKind::IncompleteRead);
}
