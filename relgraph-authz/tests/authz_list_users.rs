//! ListUsers through the public API: forward candidate expansion, decisions
//! by the check path, filters, limits and contextual tuples.

use std::collections::BTreeMap;

use relgraph_authz::{
    AuthorizationDecision, AuthorizationError, Bound, CheckRequest, ConditionContext,
    ContextualTupleError, EvaluationLimits, FgaAuthz, InMemoryRelationshipStore, ListUsersRequest,
    ObjectRef, RelationName, RelationshipTuple, Subject, TenantId, TupleSubject, TypeName,
    UserFilter, UserFilterError,
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
    define blocked: [user, user:*]
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

fn folder(id: &str) -> TupleSubject {
    Subject::new("folder", id).unwrap().into()
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

fn object(object: &str) -> ObjectRef {
    let (object_type, id) = object.split_once(':').unwrap();
    ObjectRef::new(object_type, id).unwrap()
}

fn tuple(object_name: &str, relation: &str, subject: TupleSubject) -> RelationshipTuple {
    RelationshipTuple::new(
        tenant(),
        object(object_name),
        RelationName::new(relation).unwrap(),
        subject,
    )
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

fn request(object_name: &str, relation: &str, filter: &str) -> ListUsersRequest {
    ListUsersRequest::new(
        tenant(),
        object(object_name),
        RelationName::new(relation).unwrap(),
        filter.parse().unwrap(),
    )
}

async fn list(
    authz: &Authorizer,
    object_name: &str,
    relation: &str,
    filter: &str,
) -> Result<Vec<TupleSubject>, AuthorizationError> {
    authz
        .list_users(&request(object_name, relation, filter))
        .await
}

#[tokio::test]
async fn lists_direct_subjects_sorted_and_omits_other_objects() {
    let authz = authorizer([
        tuple("document:1", "viewer", user("bob")),
        tuple("document:1", "viewer", user("anne")),
        tuple("document:2", "viewer", user("carl")),
    ]);

    assert_eq!(
        list(&authz, "document:1", "viewer", "user").await.unwrap(),
        [user("anne"), user("bob")]
    );
    assert_eq!(
        list(&authz, "document:3", "viewer", "user").await.unwrap(),
        []
    );
    // A type filter lists the concrete subjects of that type a tuple names.
    let authz = authorizer([tuple("document:1", "parent", folder("f1"))]);
    assert_eq!(
        list(&authz, "document:1", "parent", "folder")
            .await
            .unwrap(),
        [folder("f1")]
    );
    assert_eq!(
        list(&authz, "document:1", "parent", "user").await.unwrap(),
        []
    );
}

#[tokio::test]
async fn follows_computed_usersets_on_the_same_object() {
    let authz = authorizer([
        tuple("document:1", "owner", user("anne")),
        tuple("document:1", "editor", user("bob")),
    ]);

    assert_eq!(
        list(&authz, "document:1", "editor", "user").await.unwrap(),
        [user("anne"), user("bob")]
    );
    assert_eq!(
        list(&authz, "document:1", "viewer", "user").await.unwrap(),
        [user("anne"), user("bob")]
    );
    assert_eq!(
        list(&authz, "document:1", "owner", "user").await.unwrap(),
        [user("anne")]
    );
}

#[tokio::test]
async fn follows_tuple_to_userset_to_the_parent() {
    let authz = authorizer([
        tuple("folder:f1", "viewer", user("anne")),
        tuple("folder:f1", "viewer", userset("group", "eng", "member")),
        tuple("group:eng", "member", user("bob")),
        tuple("document:1", "parent", folder("f1")),
        tuple("document:2", "parent", folder("f2")),
    ]);

    assert_eq!(
        list(&authz, "document:1", "viewer", "user").await.unwrap(),
        [user("anne"), user("bob")]
    );
    assert_eq!(
        list(&authz, "document:2", "viewer", "user").await.unwrap(),
        []
    );
    // The parent's userset holds the relation through the tupleset.
    assert_eq!(
        list(&authz, "document:1", "viewer", "folder#viewer")
            .await
            .unwrap(),
        [userset("folder", "f1", "viewer")]
    );
    // The tupleset subject itself is not a viewer.
    assert_eq!(
        list(&authz, "document:1", "viewer", "folder")
            .await
            .unwrap(),
        []
    );
}

#[tokio::test]
async fn wildcard_tuples_are_listed_as_the_wildcard() {
    let authz = authorizer([
        tuple("document:1", "viewer", wildcard("user")),
        tuple("document:1", "viewer", user("jon")),
        tuple("group:all", "member", wildcard("user")),
        tuple("group:all", "member", user("anne")),
        tuple("document:2", "viewer", userset("group", "all", "member")),
        tuple("document:3", "viewer", wildcard("user")),
        tuple("document:3", "blocked", user("anne")),
        tuple("document:4", "viewer", user("anne")),
        tuple("document:4", "viewer", user("bob")),
        tuple("document:4", "blocked", wildcard("user")),
    ]);

    // Like upstream `wildcard_direct`: the wildcard and the named subject.
    assert_eq!(
        list(&authz, "document:1", "viewer", "user").await.unwrap(),
        [wildcard("user"), user("jon")]
    );
    // Subjects granted through a wildcard are not listed by ID; the wildcard
    // is, also through a userset.
    assert_eq!(
        list(&authz, "document:2", "viewer", "user").await.unwrap(),
        [wildcard("user"), user("anne")]
    );
    // A concrete exclusion does not exclude the wildcard, and a subject only
    // named in the subtracted operand is never a candidate.
    assert_eq!(
        list(&authz, "document:3", "reader", "user").await.unwrap(),
        [wildcard("user")]
    );
    // A wildcard exclusion excludes every subject of the type.
    assert_eq!(
        list(&authz, "document:4", "reader", "user").await.unwrap(),
        []
    );
    // Every listed subject is allowed by check.
    let check = |subject: TupleSubject| {
        authz.check(CheckRequest::new(
            tenant(),
            subject,
            object("document:3"),
            RelationName::new("reader").unwrap(),
        ))
    };
    assert_eq!(
        check(wildcard("user")).await.unwrap(),
        AuthorizationDecision::Allow
    );
    assert_eq!(
        check(user("anne")).await.unwrap(),
        AuthorizationDecision::Deny
    );
}

#[tokio::test]
async fn userset_filters_list_usersets_and_the_objects_own_userset() {
    let authz = authorizer([
        tuple("document:1", "viewer", userset("group", "eng", "member")),
        tuple("group:eng", "member", userset("group", "ops", "member")),
        tuple("group:ops", "member", user("anne")),
        tuple("document:2", "editor", userset("group", "empty", "member")),
    ]);

    // Like upstream `userset_as_user`, with a nested group.
    assert_eq!(
        list(&authz, "document:1", "viewer", "group#member")
            .await
            .unwrap(),
        [
            userset("group", "eng", "member"),
            userset("group", "ops", "member")
        ]
    );
    assert_eq!(
        list(&authz, "document:1", "viewer", "user").await.unwrap(),
        [user("anne")]
    );
    // A userset named by a tuple is listed even when it has no members.
    assert_eq!(
        list(&authz, "document:2", "viewer", "group#member")
            .await
            .unwrap(),
        [userset("group", "empty", "member")]
    );
    // A userset holds its own relation on its own object.
    assert_eq!(
        list(&authz, "group:eng", "member", "group#member")
            .await
            .unwrap(),
        [
            userset("group", "eng", "member"),
            userset("group", "ops", "member")
        ]
    );
    assert_eq!(
        list(&authz, "document:1", "viewer", "document#viewer")
            .await
            .unwrap(),
        [userset("document", "1", "viewer")]
    );
    // A type filter never lists usersets.
    assert_eq!(
        list(&authz, "document:1", "viewer", "group").await.unwrap(),
        []
    );
}

#[tokio::test]
async fn intersection_and_difference_are_decided_by_check() {
    let authz = authorizer([
        tuple("document:1", "viewer", user("anne")),
        tuple("document:1", "viewer", user("bob")),
        tuple("document:1", "blocked", user("bob")),
        tuple("document:1", "editor", user("carl")),
        tuple("document:1", "editor", user("dave")),
        tuple("document:1", "approver", user("carl")),
        tuple("document:1", "approver", user("erin")),
    ]);

    assert_eq!(
        list(&authz, "document:1", "reader", "user").await.unwrap(),
        [user("anne"), user("carl"), user("dave")]
    );
    assert_eq!(
        list(&authz, "document:1", "signer", "user").await.unwrap(),
        [user("carl")]
    );
}

#[tokio::test]
async fn unknown_types_relations_and_filters_are_errors() {
    let authz = authorizer([tuple("document:1", "viewer", user("anne"))]);

    assert!(matches!(
        list(&authz, "spreadsheet:1", "viewer", "user").await,
        Err(AuthorizationError::UnknownObjectType(object_type)) if object_type == "spreadsheet"
    ));
    assert!(matches!(
        list(&authz, "document:1", "commenter", "user").await,
        Err(AuthorizationError::UnknownRelation { relation, .. }) if relation == "commenter"
    ));
    assert!(matches!(
        list(&authz, "document:1", "viewer", "robot").await,
        Err(AuthorizationError::UnknownSubjectType(subject_type)) if subject_type == "robot"
    ));
    assert!(matches!(
        list(&authz, "document:1", "viewer", "robot#member").await,
        Err(AuthorizationError::UnknownSubjectType(subject_type)) if subject_type == "robot"
    ));
    assert!(matches!(
        list(&authz, "document:1", "viewer", "group#owner").await,
        Err(AuthorizationError::UnknownSubjectRelation { relation, .. }) if relation == "owner"
    ));
}

#[test]
fn filters_parse_only_the_type_and_userset_forms() {
    let user_type = TypeName::new("user").unwrap();
    assert_eq!(
        "user".parse::<UserFilter>().unwrap(),
        UserFilter::new(user_type.clone())
    );
    let member = "group#member".parse::<UserFilter>().unwrap();
    assert_eq!(member.type_name().as_str(), "group");
    assert_eq!(member.relation().map(RelationName::as_str), Some("member"));
    assert_eq!(UserFilter::new(user_type).relation(), None);

    for unsupported in ["user:anne", "user:*", "group:eng#member", "group#member#x"] {
        assert_eq!(
            unsupported.parse::<UserFilter>(),
            Err(UserFilterError::UnsupportedForm),
            "{unsupported}"
        );
    }
    for invalid in ["", "#member", "group#", " "] {
        assert!(
            matches!(
                invalid.parse::<UserFilter>(),
                Err(UserFilterError::Identifier(_))
            ),
            "{invalid:?}"
        );
    }
    assert_eq!(
        UserFilterError::UnsupportedForm.to_string(),
        "user filter must have the form `type` or `type#relation`"
    );
}

#[tokio::test]
async fn exceeding_the_candidate_limit_is_an_error_not_a_partial_list() {
    let tuples = || ["anne", "bob", "carl"].map(|id| tuple("document:1", "viewer", user(id)));
    let limited = authorizer_with_limits(
        tuples(),
        EvaluationLimits::default()
            .with_max_list_candidates(2)
            .unwrap(),
    );
    assert!(matches!(
        list(&limited, "document:1", "viewer", "user").await,
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
        list(&exact, "document:1", "viewer", "user").await.unwrap(),
        [user("anne"), user("bob"), user("carl")]
    );

    // Repeated grants of one subject are one candidate; a candidate denied
    // by check still counts.
    let repeated = authorizer_with_limits(
        [
            tuple("document:1", "viewer", user("anne")),
            tuple("document:1", "owner", user("anne")),
            tuple("document:1", "editor", user("bob")),
            tuple("document:1", "approver", user("anne")),
        ],
        EvaluationLimits::default()
            .with_max_list_candidates(2)
            .unwrap(),
    );
    assert_eq!(
        list(&repeated, "document:1", "viewer", "user")
            .await
            .unwrap(),
        [user("anne"), user("bob")]
    );
    assert_eq!(
        list(&repeated, "document:1", "signer", "user")
            .await
            .unwrap(),
        [user("anne")]
    );
}

#[tokio::test]
async fn budget_hits_are_errors_not_partial_lists() {
    let tuples = || ["anne", "bob", "carl"].map(|id| tuple("document:1", "viewer", user(id)));

    let tuple_limited = authorizer_with_limits(tuples(), EvaluationLimits::new(2).unwrap());
    assert!(matches!(
        list(&tuple_limited, "document:1", "viewer", "user").await,
        Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples: 2 })
    ));

    let work_limited = authorizer_with_limits(
        tuples(),
        EvaluationLimits::default().with_max_work_units(3).unwrap(),
    );
    assert!(matches!(
        list(&work_limited, "document:1", "viewer", "user").await,
        Err(AuthorizationError::WorkLimitExceeded {
            maximum_work_units: 3
        })
    ));

    // The expansion reads `viewer`, `editor`, `owner` and `parent`.
    let call_limited = authorizer_with_limits(
        tuples(),
        EvaluationLimits::default().with_max_store_calls(2).unwrap(),
    );
    assert!(matches!(
        list(&call_limited, "document:1", "viewer", "user").await,
        Err(AuthorizationError::StoreCallLimitExceeded { maximum_calls: 2 })
    ));

    // A candidate's check that exceeds the depth limit fails the list, as
    // in upstream `resolution_too_complex_throws_error`.
    let nested: Vec<_> = (0..4)
        .map(|level| {
            tuple(
                &format!("group:g{level}"),
                "member",
                userset("group", &format!("g{}", level + 1), "member"),
            )
        })
        .chain([tuple("group:g4", "member", user("anne"))])
        .collect();
    let depth_limited = authorizer_with_limits(
        nested,
        EvaluationLimits::default()
            .with_max_relation_depth(2)
            .unwrap(),
    );
    assert!(matches!(
        list(&depth_limited, "group:g0", "member", "user").await,
        Err(AuthorizationError::RelationDepthExceeded { maximum_depth: 2 })
    ));
}

#[tokio::test]
async fn each_candidate_decision_gets_its_own_budgets() {
    // The expansion reads 1,000 tuples and so does the last decision. A
    // shared budget of 1,500 tuples would run out.
    let ids: Vec<String> = (0..1_000).map(|id| format!("{id:04}")).collect();
    let limited = authorizer_with_limits(
        ids.iter().map(|id| tuple("document:1", "viewer", user(id))),
        EvaluationLimits::new(1_500).unwrap(),
    );
    let listed = list(&limited, "document:1", "viewer", "user")
        .await
        .unwrap();
    assert_eq!(listed.len(), 1_000);
    assert_eq!(listed[0], user("0000"));
    assert_eq!(listed[999], user("0999"));
}

#[tokio::test]
async fn conditions_never_prune_and_candidate_errors_fail_the_list() {
    let conditioned = tuple("document:1", "guest", user("anne"))
        .with_condition(ConditionContext::new("in_office", BTreeMap::new()).unwrap());
    let authz = authorizer([conditioned]);
    let guest = |office: Option<bool>| {
        let request = request("document:1", "guest", "user");
        match office {
            Some(office) => {
                request.with_context(BTreeMap::from([("office".to_owned(), office.into())]))
            }
            None => request,
        }
    };

    assert_eq!(
        authz.list_users(&guest(Some(true))).await.unwrap(),
        [user("anne")]
    );
    assert_eq!(authz.list_users(&guest(Some(false))).await.unwrap(), []);
    assert!(matches!(
        authz.list_users(&guest(None)).await,
        Err(AuthorizationError::MissingConditionContext { parameter, .. }) if parameter == "office"
    ));
    // Condition-scoped context reaches each candidate's check.
    let scoped = request("document:1", "guest", "user").with_condition_context(
        "in_office",
        BTreeMap::from([("office".to_owned(), true.into())]),
    );
    assert_eq!(authz.list_users(&scoped).await.unwrap(), [user("anne")]);
}

#[tokio::test]
async fn stored_tuples_that_drifted_from_the_model_fail_the_list() {
    // The expansion validates a tuple before following it.
    let drifted = tuple("document:1", "viewer", user("anne"))
        .with_condition(ConditionContext::new("in_office", BTreeMap::new()).unwrap());
    let authz = authorizer([drifted]);
    assert!(matches!(
        list(&authz, "document:1", "viewer", "user").await,
        Err(AuthorizationError::InvalidTuple(_))
    ));

    // The expansion reads both intersection operands, so it meets the
    // drifted wildcard approver tuple.
    let authz = authorizer([
        tuple("document:1", "editor", user("anne")),
        tuple("document:1", "approver", wildcard("user")),
    ]);
    assert!(matches!(
        list(&authz, "document:1", "signer", "user").await,
        Err(AuthorizationError::InvalidTuple(_))
    ));
}

#[tokio::test]
async fn contextual_tuples_are_followed_as_edges() {
    let authz = authorizer([
        tuple("document:1", "viewer", userset("group", "eng", "member")),
        tuple("document:1", "parent", folder("f1")),
    ]);
    let listed = authz
        .list_users(
            &request("document:1", "viewer", "user").with_contextual_tuples([
                tuple("document:1", "viewer", user("anne")),
                tuple("group:eng", "member", user("bob")),
                tuple("folder:f1", "viewer", user("carl")),
            ]),
        )
        .await
        .unwrap();
    assert_eq!(listed, [user("anne"), user("bob"), user("carl")]);

    // Without them, nothing is granted.
    assert_eq!(
        list(&authz, "document:1", "viewer", "user").await.unwrap(),
        []
    );
}

#[tokio::test]
async fn lists_drop_duplicate_contextual_tuples_while_checks_reject_them() {
    let authz = authorizer([]);
    let grant = tuple("document:1", "viewer", user("anne"));

    let listed = authz
        .list_users(
            &request("document:1", "viewer", "user")
                .with_contextual_tuples([grant.clone(), grant.clone()]),
        )
        .await
        .unwrap();
    assert_eq!(listed, [user("anne")]);

    let check = CheckRequest::new(
        tenant(),
        user("anne"),
        object("document:1"),
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
        object("document:1"),
        RelationName::new("viewer").unwrap(),
        Subject::new("user", "anne").unwrap(),
    );
    assert!(matches!(
        authz
            .list_users(&request("document:1", "viewer", "user").with_contextual_tuples([foreign]))
            .await,
        Err(AuthorizationError::InvalidContextualTuple {
            index: 0,
            reason: ContextualTupleError::TenantMismatch
        })
    ));
}

#[tokio::test]
async fn lists_are_tenant_scoped() {
    let authz = authorizer([tuple("document:1", "viewer", user("anne"))]);
    let other = ListUsersRequest::new(
        TenantId::new("other").unwrap(),
        object("document:1"),
        RelationName::new("viewer").unwrap(),
        "user".parse().unwrap(),
    );
    assert_eq!(authz.list_users(&other).await.unwrap(), []);
}

/// A small store exercising every edge kind, wildcards, usersets, nested
/// groups, intersection and difference.
fn brute_force_tuples() -> Vec<RelationshipTuple> {
    vec![
        tuple("group:eng", "member", user("anne")),
        tuple("group:eng", "member", userset("group", "ops", "member")),
        tuple("group:ops", "member", user("bob")),
        tuple("group:all", "member", wildcard("user")),
        tuple("group:all", "member", user("carl")),
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
        tuple("document:9", "viewer", user("dave")),
        tuple("document:9", "blocked", wildcard("user")),
    ]
}

/// Every filter, with every subject of the store it could select.
fn brute_force_filters() -> Vec<(&'static str, Vec<TupleSubject>)> {
    fn each(ids: &[&str], make: impl Fn(&str) -> TupleSubject) -> Vec<TupleSubject> {
        ids.iter().map(|id| make(id)).collect()
    }
    let documents = ["1", "2", "3", "4", "5", "6", "7", "8", "9"];
    let mut users = each(&["anne", "bob", "carl", "dave", "erin"], user);
    users.push(wildcard("user"));
    vec![
        ("user", users),
        (
            "group#member",
            each(&["eng", "ops", "all", "none"], |id| {
                userset("group", id, "member")
            }),
        ),
        ("folder", each(&["f1", "f2", "f3"], folder)),
        (
            "folder#viewer",
            each(&["f1", "f2", "f3"], |id| userset("folder", id, "viewer")),
        ),
        (
            "document#viewer",
            each(&documents, |id| userset("document", id, "viewer")),
        ),
        (
            "document#editor",
            each(&documents, |id| userset("document", id, "editor")),
        ),
    ]
}

/// Compares every list of the store against `check` of every subject the
/// filter could select. A concrete subject that check allows only through a
/// wildcard tuple is not listed by ID, so with `exact` false an allowed
/// concrete subject may be missing when its type's wildcard is listed.
async fn compare_with_brute_force_check(authz: &Authorizer, exact: bool) -> usize {
    let documents = ["1", "2", "3", "4", "5", "6", "7", "8", "9"];
    let universe: [(&str, &[&str], &[&str]); 3] = [
        (
            "document",
            &documents,
            &[
                "parent", "owner", "editor", "viewer", "blocked", "reader", "approver", "signer",
            ],
        ),
        ("folder", &["f1", "f2", "f3"], &["viewer"]),
        ("group", &["eng", "ops", "all"], &["member"]),
    ];

    let mut allowed_pairs = 0;
    for (filter, subjects) in brute_force_filters() {
        for (object_type, ids, relations) in universe {
            for relation in relations {
                for id in ids {
                    let object_name = format!("{object_type}:{id}");
                    let listed = list(authz, &object_name, relation, filter).await.unwrap();
                    let mut allowed = Vec::new();
                    for subject in &subjects {
                        let decision = authz
                            .check(CheckRequest::new(
                                tenant(),
                                subject.clone(),
                                object(&object_name),
                                RelationName::new(*relation).unwrap(),
                            ))
                            .await
                            .unwrap();
                        if decision == AuthorizationDecision::Allow {
                            allowed.push(subject.clone());
                        }
                    }
                    let context = format!("{object_name}#{relation} with filter {filter}");
                    for subject in &listed {
                        assert!(
                            allowed.contains(subject),
                            "{context}: listed {subject:?}, which check denies"
                        );
                    }
                    for subject in &allowed {
                        let hidden_by_wildcard = !exact
                            && matches!(subject, TupleSubject::Direct(direct)
                            if listed.contains(&TupleSubject::TypedWildcard(
                                direct.type_name().clone(),
                            )));
                        assert!(
                            listed.contains(subject) || hidden_by_wildcard,
                            "{context}: check allows {subject:?}, which is not listed"
                        );
                    }
                    allowed_pairs += listed.len();
                }
            }
        }
    }
    allowed_pairs
}

#[tokio::test]
async fn list_users_matches_brute_force_check() {
    let authz = authorizer(brute_force_tuples());
    let allowed_pairs = compare_with_brute_force_check(&authz, false).await;
    // The comparison is not vacuous.
    assert!(allowed_pairs > 60, "only {allowed_pairs} listed pairs");

    // Without wildcard tuples nothing hides a concrete subject, so the lists
    // equal the subjects check allows.
    let authz = authorizer(
        brute_force_tuples()
            .into_iter()
            .filter(|tuple| !matches!(tuple.subject(), TupleSubject::TypedWildcard(_))),
    );
    let allowed_pairs = compare_with_brute_force_check(&authz, true).await;
    assert!(allowed_pairs > 50, "only {allowed_pairs} listed pairs");
}
