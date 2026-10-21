//! Candidate generation for ListObjects and ListUsers (S4, S4e).
//!
//! ListObjects runs a reverse traversal from the checked subject over the
//! model's grant edges to every object that could hold the listed relation.
//! ListUsers expands forward from the listed object over the same edges to
//! every subject the filter selects. Both only generate: they evaluate no
//! condition and decide nothing, so they may over-include, and every
//! candidate is then decided by [`Evaluator::check_item`](super::Evaluator).
//! Completeness is what matters here: each edge the evaluator follows when it
//! grants, the ListObjects traversal follows backward and the ListUsers
//! expansion follows forward.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

use super::{ContextualTuples, EVALUATION_PAGE_SIZE, EvaluationKey, map_store_error};
use crate::authz::model::{
    CompiledExpression, CompiledModel, CompiledTargetRange, CompiledTargetRestriction,
};
use crate::authz::request::{
    AuthorizationError, CheckScope, EvaluationLimits, ObjectRef, RelationName, Subject, TenantId,
    TypeName,
};
use crate::authz::store::{
    RelationshipPage, RelationshipReadSession, RelationshipTuple, ReverseLookupSession,
    StoreCursor, TupleSubject,
};

/// The model's grant edges, reversed and indexed by compiled ID.
///
/// Only operands that can grant are indexed: both operands of a union or an
/// intersection and the base of a difference, never its subtracted operand.
#[derive(Default)]
struct ReverseEdges {
    /// By subject type: relations whose direct assignment accepts a concrete
    /// subject of that type.
    direct: HashMap<usize, Vec<usize>>,
    /// By subject type: relations whose direct assignment accepts its wildcard.
    wildcard: HashMap<usize, Vec<usize>>,
    /// By relation: same-object relations that include it as a computed userset.
    computed: HashMap<usize, Vec<usize>>,
    /// By relation: relations whose direct assignment accepts its userset.
    userset: HashMap<usize, Vec<usize>>,
    /// By computed relation: `(relation, tupleset relation)` pairs whose
    /// tuple-to-userset evaluates it on the tupleset tuple's subject.
    tuple_to_userset: HashMap<usize, Vec<(usize, usize)>>,
}

impl ReverseEdges {
    fn new(compiled: &CompiledModel) -> Self {
        let mut edges = Self::default();
        let mut pending = Vec::new();
        for relation_id in 0..compiled.relation_count() {
            pending.push(compiled.relation_expression_id(relation_id));
            while let Some(expression_id) = pending.pop() {
                match compiled.expression(expression_id) {
                    CompiledExpression::DirectAssignment(targets) => {
                        for target_id in targets.start..targets.start + targets.len {
                            let target = compiled.target(target_id);
                            let index = match target.restriction {
                                CompiledTargetRestriction::Direct => {
                                    edges.direct.entry(target.type_id)
                                }
                                CompiledTargetRestriction::Wildcard => {
                                    edges.wildcard.entry(target.type_id)
                                }
                                CompiledTargetRestriction::Userset(userset_relation_id) => {
                                    edges.userset.entry(userset_relation_id)
                                }
                            };
                            index.or_default().push(relation_id);
                        }
                    }
                    CompiledExpression::ComputedUserset(computed_relation_id) => {
                        edges
                            .computed
                            .entry(computed_relation_id)
                            .or_default()
                            .push(relation_id);
                    }
                    CompiledExpression::TupleToUserset {
                        tupleset_relation_id,
                        edge_range,
                    } => {
                        for edge_id in edge_range.start..edge_range.start + edge_range.len {
                            if let Some(computed_relation_id) =
                                compiled.tuple_to_userset_edge(edge_id).computed_relation_id
                            {
                                edges
                                    .tuple_to_userset
                                    .entry(computed_relation_id)
                                    .or_default()
                                    .push((relation_id, tupleset_relation_id));
                            }
                        }
                    }
                    CompiledExpression::Union { left, right }
                    | CompiledExpression::Intersection { left, right } => {
                        pending.extend([right, left]);
                    }
                    // The subtracted operand never grants.
                    CompiledExpression::Difference { left, .. } => pending.push(left),
                }
            }
        }
        for relations in edges
            .direct
            .values_mut()
            .chain(edges.wildcard.values_mut())
            .chain(edges.computed.values_mut())
            .chain(edges.userset.values_mut())
        {
            relations.sort_unstable();
            relations.dedup();
        }
        for pairs in edges.tuple_to_userset.values_mut() {
            pairs.sort_unstable();
            pairs.dedup();
        }
        edges
    }
}

/// Returns the IDs indexed under `key`, or none.
fn indexed<K: std::hash::Hash + Eq, V>(index: &HashMap<K, Vec<V>>, key: K) -> &[V] {
    index.get(&key).map_or(&[], Vec::as_slice)
}

/// A generator's single set of tuple, store-call and work budgets (S4d).
struct Budget {
    limits: EvaluationLimits,
    tuples_scanned: usize,
    store_calls: usize,
    work_units: usize,
}

impl Budget {
    fn new(limits: EvaluationLimits) -> Self {
        Self {
            limits,
            tuples_scanned: 0,
            store_calls: 0,
            work_units: 0,
        }
    }

    /// Charges one store page call and returns the page size to request.
    fn start_page(&mut self) -> Result<usize, AuthorizationError> {
        if self.store_calls >= self.limits.max_store_calls() {
            return Err(AuthorizationError::StoreCallLimitExceeded {
                maximum_calls: self.limits.max_store_calls(),
            });
        }
        let maximum_tuples = self.limits.max_tuples_scanned();
        let remaining = maximum_tuples.saturating_sub(self.tuples_scanned);
        if remaining == 0 {
            return Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples });
        }
        self.store_calls += 1;
        self.charge_work(1)?;
        Ok(remaining.min(EVALUATION_PAGE_SIZE))
    }

    /// Accounts for a page returned for a request of `requested_maximum`.
    fn finish_page(
        &mut self,
        page: &RelationshipPage,
        requested_maximum: usize,
    ) -> Result<(), AuthorizationError> {
        if page.tuples.len() > requested_maximum {
            return Err(AuthorizationError::EvaluationLimitExceeded {
                maximum_tuples: self.limits.max_tuples_scanned(),
            });
        }
        self.scan(page.tuples.len())
    }

    /// Charges tuples read, stored or contextual, to the tuple and work budgets.
    fn scan(&mut self, count: usize) -> Result<(), AuthorizationError> {
        let maximum_tuples = self.limits.max_tuples_scanned();
        if count > maximum_tuples.saturating_sub(self.tuples_scanned) {
            return Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples });
        }
        self.charge_work(count)?;
        self.tuples_scanned += count;
        Ok(())
    }

    /// Charges a bounded unit of traversal work.
    fn charge_work(&mut self, amount: usize) -> Result<(), AuthorizationError> {
        let next = self.work_units.saturating_add(amount);
        if next > self.limits.max_work_units() {
            return Err(AuthorizationError::WorkLimitExceeded {
                maximum_work_units: self.limits.max_work_units(),
            });
        }
        self.work_units = next;
        Ok(())
    }
}

/// Applies the paging contract to a finished page: returns the cursor to
/// continue with, or `None` once the query is exhausted.
fn continuation(
    page: RelationshipPage,
    seen_cursors: &mut HashSet<StoreCursor>,
) -> Result<Option<StoreCursor>, AuthorizationError> {
    let Some(next_cursor) = page.next_cursor else {
        return Ok(None);
    };
    if page.tuples.is_empty() {
        return Err(AuthorizationError::InvalidTuple(
            "relationship page continued without returning tuples",
        ));
    }
    if !seen_cursors.insert(next_cursor.clone()) {
        return Err(AuthorizationError::InvalidTuple(
            "relationship page cursor repeated",
        ));
    }
    Ok(Some(next_cursor))
}

/// Reverse traversal state with the generator's single set of budgets.
struct CandidateSearch<'a, S> {
    compiled: &'a CompiledModel,
    session: &'a S,
    limits: EvaluationLimits,
    scope: &'a CheckScope,
    contextual: &'a ContextualTuples,
    listed_relation_id: usize,
    visited: HashSet<EvaluationKey>,
    queue: VecDeque<(usize, ObjectRef)>,
    candidates: Vec<ObjectRef>,
    budget: Budget,
}

/// Returns, unsorted, every object of the listed relation's type that the
/// scope's subject reaches through a grant edge.
///
/// Seeds are the keys holding the subject: tuples naming it or (for a
/// concrete subject) its type's wildcard, and a userset subject's own key.
/// From each reached key the traversal follows, to a fixpoint over a visited
/// set, the same-object relations that compute it, the tuples naming its
/// userset, and the tupleset tuples naming its object. Contextual tuples are
/// read as extra edges; stored tuples are followed only after validation, so
/// one that drifted from the model fails the list (S1).
pub(super) async fn object_candidates<S: ReverseLookupSession>(
    compiled: &CompiledModel,
    session: &S,
    limits: EvaluationLimits,
    scope: &CheckScope,
    contextual: &ContextualTuples,
    subject_userset: Option<&EvaluationKey>,
    listed_relation_id: usize,
) -> Result<Vec<ObjectRef>, AuthorizationError> {
    let edges = ReverseEdges::new(compiled);
    let mut search = CandidateSearch {
        compiled,
        session,
        limits,
        scope,
        contextual,
        listed_relation_id,
        visited: HashSet::new(),
        queue: VecDeque::new(),
        candidates: Vec::new(),
        budget: Budget::new(limits),
    };

    match scope.subject() {
        TupleSubject::Direct(subject) => {
            if let Some(type_id) = compiled.type_id(subject.type_name().as_str()) {
                search
                    .seed(indexed(&edges.direct, type_id), scope.subject())
                    .await?;
                let wildcard = TupleSubject::TypedWildcard(subject.type_name().clone());
                search
                    .seed(indexed(&edges.wildcard, type_id), &wildcard)
                    .await?;
            }
        }
        TupleSubject::TypedWildcard(type_name) => {
            if let Some(type_id) = compiled.type_id(type_name.as_str()) {
                search
                    .seed(indexed(&edges.wildcard, type_id), scope.subject())
                    .await?;
            }
        }
        // Tuples naming the userset are found from its own key below.
        TupleSubject::Userset { object, .. } => {
            if let Some(key) = subject_userset {
                search.reach(key.relation_id, object.clone())?;
            }
        }
    }

    while let Some((relation_id, object)) = search.queue.pop_front() {
        search.budget.charge_work(1)?;
        for &parent_id in indexed(&edges.computed, relation_id) {
            search.reach(parent_id, object.clone())?;
        }
        let parents = indexed(&edges.userset, relation_id);
        if let (false, Some(relation)) = (
            parents.is_empty(),
            compiled.checked_relation_name(relation_id),
        ) {
            let userset = TupleSubject::Userset {
                object: object.clone(),
                relation: relation.clone(),
            };
            for &parent_id in parents {
                for reached in search.objects_by_subject(parent_id, &userset).await? {
                    search.reach(parent_id, reached)?;
                }
            }
        }
        let pairs = indexed(&edges.tuple_to_userset, relation_id);
        if !pairs.is_empty() {
            let tupleset_subject = TupleSubject::Direct(Subject::from_object(&object));
            for &(parent_id, tupleset_relation_id) in pairs {
                for reached in search
                    .objects_by_subject(tupleset_relation_id, &tupleset_subject)
                    .await?
                {
                    search.reach(parent_id, reached)?;
                }
            }
        }
    }
    Ok(search.candidates)
}

impl<S: ReverseLookupSession> CandidateSearch<'_, S> {
    /// Reaches the objects whose `relation_ids` tuples name `subject`.
    async fn seed(
        &mut self,
        relation_ids: &[usize],
        subject: &TupleSubject,
    ) -> Result<(), AuthorizationError> {
        for &relation_id in relation_ids {
            for object in self.objects_by_subject(relation_id, subject).await? {
                self.reach(relation_id, object)?;
            }
        }
        Ok(())
    }

    /// Marks a key reached, queues it once, and records a new candidate.
    fn reach(&mut self, relation_id: usize, object: ObjectRef) -> Result<(), AuthorizationError> {
        let key = EvaluationKey {
            relation_id,
            object_id: object.id().clone(),
        };
        if !self.visited.insert(key) {
            return Ok(());
        }
        if relation_id == self.listed_relation_id {
            if self.candidates.len() >= self.limits.max_list_candidates() {
                return Err(AuthorizationError::ListCandidateLimitExceeded {
                    maximum_candidates: self.limits.max_list_candidates(),
                });
            }
            self.candidates.push(object.clone());
        }
        self.queue.push_back((relation_id, object));
        Ok(())
    }

    /// Returns the objects whose `relation_id` tuples name `subject` exactly:
    /// the matching contextual tuples, then every page of stored ones.
    async fn objects_by_subject(
        &mut self,
        relation_id: usize,
        subject: &TupleSubject,
    ) -> Result<Vec<ObjectRef>, AuthorizationError> {
        // A name outside the identifier limits can never match a tuple.
        let Some(relation) = self.compiled.checked_relation_name(relation_id) else {
            return Ok(Vec::new());
        };
        let owner_type_id = self.compiled.relation_owner_type_id(relation_id);
        let Ok(object_type) = TypeName::new(self.compiled.type_name(owner_type_id)) else {
            return Ok(Vec::new());
        };

        self.budget.charge_work(1)?;
        let mut objects = Vec::new();
        for (object, relations) in &self.contextual.by_object {
            if object.type_name() != &object_type {
                continue;
            }
            let matching = relations
                .get(relation)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter(|tuple| tuple.subject() == subject)
                .count();
            if matching > 0 {
                self.budget.scan(matching)?;
                objects.push(object.clone());
            }
        }

        let maximum_tuples = self.limits.max_tuples_scanned();
        let mut cursor: Option<StoreCursor> = None;
        let mut seen_cursors = HashSet::new();
        loop {
            let requested_maximum = self.budget.start_page()?;
            let page = self
                .session
                .tuples_by_subject_page(
                    &object_type,
                    relation,
                    subject,
                    cursor.take(),
                    requested_maximum,
                )
                .await
                .map_err(|error| map_store_error(error, maximum_tuples))?;
            self.budget.finish_page(&page, requested_maximum)?;
            for tuple in &page.tuples {
                self.validate_tuple(tuple, &object_type, relation, subject)?;
                objects.push(tuple.object().clone());
            }
            match continuation(page, &mut seen_cursors)? {
                Some(next_cursor) => cursor = Some(next_cursor),
                None => return Ok(objects),
            }
        }
    }

    /// Applies the store contract and the model's tuple checks to a stored
    /// tuple returned for a subject query.
    fn validate_tuple(
        &self,
        tuple: &RelationshipTuple,
        object_type: &TypeName,
        relation: &RelationName,
        subject: &TupleSubject,
    ) -> Result<(), AuthorizationError> {
        if tuple.tenant() != self.scope.tenant() {
            return Err(AuthorizationError::InvalidTuple(
                "tuple belongs to a different tenant",
            ));
        }
        if tuple.object().type_name() != object_type
            || tuple.relation() != relation
            || tuple.subject() != subject
        {
            return Err(AuthorizationError::InvalidTuple(
                "tuple does not match the requested subject query",
            ));
        }
        self.compiled.validate_tuple(tuple)
    }
}

/// What a ListUsers filter selects, by compiled ID.
#[derive(Clone, Copy)]
pub(super) enum FilterTarget {
    /// Concrete subjects of this type and its typed wildcard.
    Type(usize),
    /// Usersets of this relation; the relation ID implies their type.
    Userset(usize),
}

/// Orders ListUsers results by subject type, then ID (a typed wildcard as
/// `*`), then userset relation.
pub(super) fn subject_order(left: &TupleSubject, right: &TupleSubject) -> Ordering {
    fn key(subject: &TupleSubject) -> (&str, &str, &str) {
        match subject {
            TupleSubject::Direct(subject) => {
                (subject.type_name().as_str(), subject.id().as_str(), "")
            }
            TupleSubject::TypedWildcard(type_name) => (type_name.as_str(), "*", ""),
            TupleSubject::Userset { object, relation } => (
                object.type_name().as_str(),
                object.id().as_str(),
                relation.as_str(),
            ),
        }
    }
    key(left).cmp(&key(right))
}

/// Forward expansion state with the generator's single set of budgets.
struct UserSearch<'a, S> {
    compiled: &'a CompiledModel,
    session: &'a S,
    limits: EvaluationLimits,
    tenant: &'a TenantId,
    contextual: &'a ContextualTuples,
    filter: FilterTarget,
    visited: HashSet<EvaluationKey>,
    queue: VecDeque<(usize, ObjectRef)>,
    candidates: Vec<TupleSubject>,
    candidate_set: HashSet<TupleSubject>,
    budget: Budget,
}

/// Returns, unsorted, every subject selected by `filter` that the listed
/// relation of `object` reaches through a grant edge.
///
/// From the listed key the expansion follows, to a fixpoint over a visited
/// set, the operands that can grant (both operands of a union or an
/// intersection, the base of a difference): computed usersets on the same
/// object, the usersets named by direct-assignment tuples, and the
/// tuple-to-userset targets named by tupleset tuples. A type filter collects
/// the concrete subjects and typed wildcards of its type that
/// direct-assignment tuples name; a userset filter collects every reached
/// key of its relation, the listed key included, since a userset holds its
/// own relation. Contextual tuples are read first; stored tuples are followed
/// only after validation, so one that drifted from the model fails the list
/// (S1).
#[allow(clippy::too_many_arguments)]
pub(super) async fn user_candidates<S: RelationshipReadSession>(
    compiled: &CompiledModel,
    session: &S,
    limits: EvaluationLimits,
    tenant: &TenantId,
    contextual: &ContextualTuples,
    filter: FilterTarget,
    object: &ObjectRef,
    listed_relation_id: usize,
) -> Result<Vec<TupleSubject>, AuthorizationError> {
    let mut search = UserSearch {
        compiled,
        session,
        limits,
        tenant,
        contextual,
        filter,
        visited: HashSet::new(),
        queue: VecDeque::new(),
        candidates: Vec::new(),
        candidate_set: HashSet::new(),
        budget: Budget::new(limits),
    };
    search.reach(listed_relation_id, object.clone())?;

    while let Some((relation_id, object)) = search.queue.pop_front() {
        search.budget.charge_work(1)?;
        let mut pending = vec![compiled.relation_expression_id(relation_id)];
        while let Some(expression_id) = pending.pop() {
            match compiled.expression(expression_id) {
                CompiledExpression::DirectAssignment(_) => {
                    search.expand_assignment(&object, relation_id).await?;
                }
                CompiledExpression::ComputedUserset(computed_relation_id) => {
                    search.reach(computed_relation_id, object.clone())?;
                }
                CompiledExpression::TupleToUserset {
                    tupleset_relation_id,
                    edge_range,
                } => {
                    search
                        .expand_tupleset(&object, tupleset_relation_id, edge_range)
                        .await?;
                }
                CompiledExpression::Union { left, right }
                | CompiledExpression::Intersection { left, right } => {
                    pending.extend([right, left]);
                }
                // The subtracted operand never grants.
                CompiledExpression::Difference { left, .. } => pending.push(left),
            }
        }
    }
    Ok(search.candidates)
}

impl<S: RelationshipReadSession> UserSearch<'_, S> {
    /// Marks a key reached and queues it once; under a userset filter, a key
    /// of the filter's relation is a candidate userset.
    fn reach(&mut self, relation_id: usize, object: ObjectRef) -> Result<(), AuthorizationError> {
        let key = EvaluationKey {
            relation_id,
            object_id: object.id().clone(),
        };
        if !self.visited.insert(key) {
            return Ok(());
        }
        if let FilterTarget::Userset(filter_relation_id) = self.filter
            && filter_relation_id == relation_id
            && let Some(relation) = self.compiled.checked_relation_name(relation_id)
        {
            self.add_candidate(TupleSubject::Userset {
                object: object.clone(),
                relation: relation.clone(),
            })?;
        }
        self.queue.push_back((relation_id, object));
        Ok(())
    }

    /// Records a new distinct candidate within the candidate limit.
    fn add_candidate(&mut self, subject: TupleSubject) -> Result<(), AuthorizationError> {
        if self.candidate_set.contains(&subject) {
            return Ok(());
        }
        if self.candidates.len() >= self.limits.max_list_candidates() {
            return Err(AuthorizationError::ListCandidateLimitExceeded {
                maximum_candidates: self.limits.max_list_candidates(),
            });
        }
        self.candidate_set.insert(subject.clone());
        self.candidates.push(subject);
        Ok(())
    }

    /// Collects the filtered subjects a relation's direct-assignment tuples
    /// name and reaches the usersets they name.
    async fn expand_assignment(
        &mut self,
        object: &ObjectRef,
        relation_id: usize,
    ) -> Result<(), AuthorizationError> {
        for tuple in self.tuples(object, relation_id).await? {
            let subject_type = match tuple.subject() {
                TupleSubject::Direct(subject) => subject.type_name(),
                TupleSubject::TypedWildcard(type_name) => type_name,
                TupleSubject::Userset {
                    object: userset_object,
                    relation,
                } => {
                    let userset_relation_id = self
                        .compiled
                        .type_id(userset_object.type_name().as_str())
                        .and_then(|type_id| self.compiled.relation_id(type_id, relation.as_str()))
                        .ok_or(AuthorizationError::InvalidTuple(
                            "userset subject is absent from the authorization model",
                        ))?;
                    self.reach(userset_relation_id, userset_object.clone())?;
                    continue;
                }
            };
            if let FilterTarget::Type(filter_type_id) = self.filter
                && self.compiled.type_name(filter_type_id) == subject_type.as_str()
            {
                self.add_candidate(tuple.subject().clone())?;
            }
        }
        Ok(())
    }

    /// Reaches the computed relation of every tuple-to-userset target that
    /// the tupleset tuples name.
    async fn expand_tupleset(
        &mut self,
        object: &ObjectRef,
        tupleset_relation_id: usize,
        edge_range: CompiledTargetRange,
    ) -> Result<(), AuthorizationError> {
        for tuple in self.tuples(object, tupleset_relation_id).await? {
            let TupleSubject::Direct(subject) = tuple.subject() else {
                return Err(AuthorizationError::InvalidTuple(
                    "tupleset tuple subject must be a direct object",
                ));
            };
            let subject_type_id = self.compiled.type_id(subject.type_name().as_str());
            // Targets whose type lacks the computed relation cannot grant.
            let computed_relation_id = (edge_range.start..edge_range.start + edge_range.len)
                .map(|edge_id| self.compiled.tuple_to_userset_edge(edge_id))
                .find(|edge| {
                    let target = self.compiled.target(edge.target_id);
                    Some(target.type_id) == subject_type_id
                        && matches!(target.restriction, CompiledTargetRestriction::Direct)
                })
                .and_then(|edge| edge.computed_relation_id);
            let Some(computed_relation_id) = computed_relation_id else {
                continue;
            };
            let target_object = ObjectRef::new(subject.type_name().as_str(), subject.id().as_str())
                .map_err(|_| AuthorizationError::InvalidTuple("invalid tupleset subject"))?;
            self.reach(computed_relation_id, target_object)?;
        }
        Ok(())
    }

    /// Returns one object relation's tuples: its contextual tuples, then
    /// every page of stored ones, each validated before it is followed.
    async fn tuples(
        &mut self,
        object: &ObjectRef,
        relation_id: usize,
    ) -> Result<Vec<RelationshipTuple>, AuthorizationError> {
        // A name outside the identifier limits can never match a tuple.
        let Some(relation) = self.compiled.checked_relation_name(relation_id) else {
            return Ok(Vec::new());
        };
        self.budget.charge_work(1)?;
        let mut tuples = self.contextual.tuples(object, relation).to_vec();
        self.budget.scan(tuples.len())?;

        let maximum_tuples = self.limits.max_tuples_scanned();
        let mut cursor: Option<StoreCursor> = None;
        let mut seen_cursors = HashSet::new();
        loop {
            let requested_maximum = self.budget.start_page()?;
            let page = self
                .session
                .tuples_page(object, relation, cursor.take(), requested_maximum)
                .await
                .map_err(|error| map_store_error(error, maximum_tuples))?;
            self.budget.finish_page(&page, requested_maximum)?;
            for tuple in &page.tuples {
                self.validate_tuple(tuple, object, relation)?;
                tuples.push(tuple.clone());
            }
            match continuation(page, &mut seen_cursors)? {
                Some(next_cursor) => cursor = Some(next_cursor),
                None => return Ok(tuples),
            }
        }
    }

    /// Applies the store contract and the model's tuple checks to a stored
    /// tuple returned for an object query.
    fn validate_tuple(
        &self,
        tuple: &RelationshipTuple,
        object: &ObjectRef,
        relation: &RelationName,
    ) -> Result<(), AuthorizationError> {
        if tuple.tenant() != self.tenant {
            return Err(AuthorizationError::InvalidTuple(
                "tuple belongs to a different tenant",
            ));
        }
        if tuple.object() != object || tuple.relation() != relation {
            return Err(AuthorizationError::InvalidTuple(
                "tuple does not match the requested object and relation",
            ));
        }
        self.compiled.validate_tuple(tuple)
    }
}
