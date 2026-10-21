use super::conditions::{
    INLINE_EXPRESSION_NAME, InlineConditionCache, PreparedConditionContext, RequestValueCache,
};
use super::model::{
    CompiledExpression, CompiledModel, CompiledTargetRange, CompiledTargetRestriction,
};
use super::request::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, CheckRequest, CheckScope,
    ContextualTupleError, EntityId, EvaluationLimits, ListObjectsRequest, ListUsersRequest,
    MAX_CONTEXTUAL_TUPLES, ObjectRef, RelationName, TenantId, UserFilter,
};
use super::store::{
    RelationshipReadSession, RelationshipStore, RelationshipTuple, ReverseLookupStore, StoreCursor,
    StoreError, StoreErrorKind, TupleSubject,
};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;

mod list;

type EvalFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, AuthorizationError>> + Send + 'a>>;

/// Maximum tuple count requested for one relationship page.
const EVALUATION_PAGE_SIZE: usize = 128;

/// Pagination state retained while one relation's tuples are evaluated.
///
/// The relation's contextual tuples form the first page; store pages follow.
#[derive(Default)]
struct TuplePageState {
    contextual_loaded: bool,
    cursor: Option<StoreCursor>,
    seen_cursors: HashSet<StoreCursor>,
    exhausted: bool,
}

/// A scope's validated contextual tuples, indexed by object and relation.
///
/// Built once per check or batch, before the store is read. The evaluator
/// merges a relation's contextual tuples into its tuple loading instead of
/// wrapping the read session, so store cursors keep their session- and
/// query-bound meaning.
#[derive(Default)]
struct ContextualTuples {
    by_object: HashMap<ObjectRef, HashMap<RelationName, Vec<RelationshipTuple>>>,
}

/// What preparing contextual tuples does with an exact repeat.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Repeats {
    /// Checks and batches reject it.
    Reject,
    /// Lists drop it (S4e), as OpenFGA's ListObjects does.
    Drop,
}

impl ContextualTuples {
    /// Rejects an oversized set, a tuple of another tenant, a tuple that does
    /// not fit the model, and an exact repeat, in request order.
    fn prepare(compiled: &CompiledModel, scope: &CheckScope) -> Result<Self, AuthorizationError> {
        Self::prepare_with(
            compiled,
            scope.tenant(),
            scope.contextual_tuples(),
            Repeats::Reject,
        )
    }

    /// Validates a list request's `tuples` like [`Self::prepare`], but keeps
    /// only the first of exact repeats instead of rejecting them.
    fn prepare_for_list(
        compiled: &CompiledModel,
        tenant: &TenantId,
        tuples: &[RelationshipTuple],
    ) -> Result<Self, AuthorizationError> {
        Self::prepare_with(compiled, tenant, tuples, Repeats::Drop)
    }

    fn prepare_with(
        compiled: &CompiledModel,
        tenant: &TenantId,
        tuples: &[RelationshipTuple],
        repeats: Repeats,
    ) -> Result<Self, AuthorizationError> {
        if tuples.len() > MAX_CONTEXTUAL_TUPLES {
            return Err(AuthorizationError::ContextualTupleLimitExceeded {
                maximum_tuples: MAX_CONTEXTUAL_TUPLES,
            });
        }
        let mut prepared = Self::default();
        for (index, tuple) in tuples.iter().enumerate() {
            let invalid = |reason| AuthorizationError::InvalidContextualTuple { index, reason };
            if tuple.tenant() != tenant {
                return Err(invalid(ContextualTupleError::TenantMismatch));
            }
            compiled
                .validate_tuple(tuple)
                .map_err(|error| invalid(ContextualTupleError::Model(Box::new(error))))?;
            if let Some(first_index) = tuples[..index].iter().position(|earlier| earlier == tuple) {
                match repeats {
                    Repeats::Reject => {
                        return Err(invalid(ContextualTupleError::Duplicate { first_index }));
                    }
                    Repeats::Drop => continue,
                }
            }
            prepared
                .by_object
                .entry(tuple.object().clone())
                .or_default()
                .entry(tuple.relation().clone())
                .or_default()
                .push(tuple.clone());
        }
        Ok(prepared)
    }

    /// Returns one object relation's contextual tuples in request order.
    fn tuples(&self, object: &ObjectRef, relation: &RelationName) -> &[RelationshipTuple] {
        self.by_object
            .get(object)
            .and_then(|relations| relations.get(relation))
            .map_or(&[], Vec::as_slice)
    }
}

/// How a validated assignment tuple's subject relates to the checked subject.
enum AssignmentMembership {
    /// A direct subject or typed wildcard, matched against the checked subject.
    Known(bool),
    /// A userset subject whose membership requires evaluating its relation.
    Userset {
        object: ObjectRef,
        relation_id: usize,
    },
}

/// Tuple metadata validated before evaluating an assignment page.
struct PreparedAssignmentTuple {
    condition: Option<PreparedTupleCondition>,
    membership: AssignmentMembership,
}

/// Tuple metadata validated before evaluating a tupleset page.
struct PreparedTuplesetTuple {
    condition: Option<PreparedTupleCondition>,
    target_object: ObjectRef,
    computed_relation_id: Option<usize>,
}

/// A conditioned tuple's validated condition and stored context.
struct PreparedTupleCondition {
    /// The tuple's inline condition in the evaluator's cache, or `None` for a
    /// model condition, which is looked up by name.
    inline_id: Option<usize>,
    /// Stored parameter values; an inline condition stores none.
    context: PreparedConditionContext,
}

/// Evaluates one structured check against one tenant-scoped store snapshot.
pub(crate) async fn check<S: RelationshipStore>(
    compiled: &CompiledModel,
    store: &S,
    limits: EvaluationLimits,
    request: &CheckRequest,
) -> Result<AuthorizationDecision, AuthorizationError> {
    let relation_id = resolve_relation(compiled, request.object(), request.relation())?;
    let subject_userset = resolve_subject(compiled, request.scope())?;
    let contextual = ContextualTuples::prepare(compiled, request.scope())?;

    // The session and evaluator are owned by this future. Dropping a cancelled
    // check drops the in-flight page future and its read snapshot without any
    // detached work or shared mutable decision state.
    let session = store
        .begin_read(request.tenant())
        .await
        .map_err(|error| map_store_error(error, limits.max_tuples_scanned()))?;
    let mut evaluator = Evaluator::new(
        compiled,
        session,
        limits,
        request.scope(),
        contextual,
        subject_userset,
    );
    evaluator
        .check_item(request.object().clone(), relation_id)
        .await
}

/// Evaluates every batch item against one snapshot with a shared memo.
///
/// Per-item failures, including unknown object types and relations, are
/// returned in that item's slot; the outer error covers the item bound, the
/// shared subject and contextual tuples, and opening the read session.
pub(crate) async fn batch_check<S: RelationshipStore>(
    compiled: &CompiledModel,
    store: &S,
    limits: EvaluationLimits,
    request: &BatchCheckRequest,
) -> Result<Vec<Result<AuthorizationDecision, AuthorizationError>>, AuthorizationError> {
    if request.items().len() > limits.max_batch_items() {
        return Err(AuthorizationError::BatchLimitExceeded {
            maximum_items: limits.max_batch_items(),
        });
    }
    let subject_userset = resolve_subject(compiled, request.scope())?;
    let contextual = ContextualTuples::prepare(compiled, request.scope())?;
    if request.items().is_empty() {
        return Ok(Vec::new());
    }

    // Cancellation drops the session and evaluator as it does for `check`.
    let session = store
        .begin_read(request.tenant())
        .await
        .map_err(|error| map_store_error(error, limits.max_tuples_scanned()))?;
    let mut evaluator = Evaluator::new(
        compiled,
        session,
        limits,
        request.scope(),
        contextual,
        subject_userset,
    );
    let mut results = Vec::with_capacity(request.items().len());
    for (object, relation) in request.items() {
        let result = match resolve_relation(compiled, object, relation) {
            Ok(relation_id) => evaluator.check_item(object.clone(), relation_id).await,
            Err(error) => Err(error),
        };
        results.push(result);
    }
    Ok(results)
}

/// Lists the objects of one type on which the scope's subject holds a
/// relation, from one snapshot.
///
/// The reverse traversal in [`list`] finds candidates with its own budgets;
/// each candidate is then decided by [`Evaluator::check_item`], exactly as a
/// batch item is, with a shared memo and fresh per-candidate budgets. Any
/// candidate error, and any budget or candidate-limit hit, fails the list.
pub(crate) async fn list_objects<S: ReverseLookupStore>(
    compiled: &CompiledModel,
    store: &S,
    limits: EvaluationLimits,
    request: &ListObjectsRequest,
) -> Result<Vec<ObjectRef>, AuthorizationError> {
    let object_type = request.object_type().as_str();
    let type_id = compiled
        .type_id(object_type)
        .ok_or_else(|| AuthorizationError::UnknownObjectType(object_type.to_owned()))?;
    let relation_id = compiled
        .relation_id(type_id, request.relation().as_str())
        .ok_or_else(|| AuthorizationError::UnknownRelation {
            object_type: object_type.to_owned(),
            relation: request.relation().as_str().to_owned(),
        })?;
    let subject_userset = resolve_subject(compiled, request.scope())?;
    let contextual = ContextualTuples::prepare_for_list(
        compiled,
        request.tenant(),
        request.contextual_tuples(),
    )?;

    // Cancellation drops the session and evaluator as it does for `check`.
    let session = store
        .begin_read(request.tenant())
        .await
        .map_err(|error| map_store_error(error, limits.max_tuples_scanned()))?;
    let mut candidates = list::object_candidates(
        compiled,
        &session,
        limits,
        request.scope(),
        &contextual,
        subject_userset.as_ref(),
        relation_id,
    )
    .await?;
    candidates.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));

    let mut evaluator = Evaluator::new(
        compiled,
        session,
        limits,
        request.scope(),
        contextual,
        subject_userset,
    );
    let mut allowed = Vec::new();
    for object in candidates {
        if evaluator.check_item(object.clone(), relation_id).await? == AuthorizationDecision::Allow
        {
            allowed.push(object);
        }
    }
    Ok(allowed)
}

/// Lists the subjects selected by a filter that hold a relation on one
/// object, from one snapshot.
///
/// The forward expansion in [`list`] finds candidates with its own budgets.
/// A scope fixes its checked subject, so each candidate is then decided by
/// its own [`Evaluator`] (S4e): a fresh memo and fresh budgets, exactly as a
/// separate `check` with that subject, on the one shared read session. Any
/// candidate error, and any budget or candidate-limit hit, fails the list.
pub(crate) async fn list_users<S: RelationshipStore>(
    compiled: &CompiledModel,
    store: &S,
    limits: EvaluationLimits,
    request: &ListUsersRequest,
) -> Result<Vec<TupleSubject>, AuthorizationError> {
    let relation_id = resolve_relation(compiled, request.object(), request.relation())?;
    let filter = resolve_filter(compiled, request.filter())?;
    let mut contextual = ContextualTuples::prepare_for_list(
        compiled,
        request.tenant(),
        request.contextual_tuples(),
    )?;

    // Cancellation drops the session and evaluator as it does for `check`.
    let mut session = store
        .begin_read(request.tenant())
        .await
        .map_err(|error| map_store_error(error, limits.max_tuples_scanned()))?;
    let mut candidates = list::user_candidates(
        compiled,
        &session,
        limits,
        request.tenant(),
        &contextual,
        filter,
        request.object(),
        relation_id,
    )
    .await?;
    candidates.sort_by(list::subject_order);

    let mut allowed = Vec::new();
    for subject in candidates {
        let scope = request.scope_for(subject.clone());
        let subject_userset = resolve_subject(compiled, &scope)?;
        let mut evaluator = Evaluator::new(
            compiled,
            session,
            limits,
            &scope,
            contextual,
            subject_userset,
        );
        let decision = evaluator
            .check_item(request.object().clone(), relation_id)
            .await?;
        (session, contextual) = evaluator.into_parts();
        if decision == AuthorizationDecision::Allow {
            allowed.push(subject);
        }
    }
    Ok(allowed)
}

/// Resolves a ListUsers filter to the compiled type or userset relation it
/// selects; an unknown type or relation fails like an unknown check subject.
fn resolve_filter(
    compiled: &CompiledModel,
    filter: &UserFilter,
) -> Result<list::FilterTarget, AuthorizationError> {
    let type_name = filter.type_name().as_str();
    let type_id = compiled
        .type_id(type_name)
        .ok_or_else(|| AuthorizationError::UnknownSubjectType(type_name.to_owned()))?;
    let Some(relation) = filter.relation() else {
        return Ok(list::FilterTarget::Type(type_id));
    };
    compiled
        .relation_id(type_id, relation.as_str())
        .map(list::FilterTarget::Userset)
        .ok_or_else(|| AuthorizationError::UnknownSubjectRelation {
            subject_type: type_name.to_owned(),
            relation: relation.as_str().to_owned(),
        })
}

/// Resolves a checked object's relation to its compiled relation ID.
fn resolve_relation(
    compiled: &CompiledModel,
    object: &ObjectRef,
    relation: &RelationName,
) -> Result<usize, AuthorizationError> {
    let object_type_name = object.type_name().as_str();
    let object_type_id = compiled
        .type_id(object_type_name)
        .ok_or_else(|| AuthorizationError::UnknownObjectType(object_type_name.to_owned()))?;
    compiled
        .relation_id(object_type_id, relation.as_str())
        .ok_or_else(|| AuthorizationError::UnknownRelation {
            object_type: object_type_name.to_owned(),
            relation: relation.as_str().to_owned(),
        })
}

/// Rejects a checked subject whose type, or userset relation, is absent from
/// the model, as OpenFGA's Check does.
///
/// For a userset subject, returns the memo key of the userset itself: OpenFGA
/// allows a userset subject on its own object and relation (`IsSelfDefining`).
fn resolve_subject(
    compiled: &CompiledModel,
    scope: &CheckScope,
) -> Result<Option<EvaluationKey>, AuthorizationError> {
    let subject_type_name = match scope.subject() {
        TupleSubject::Direct(subject) => subject.type_name(),
        TupleSubject::Userset { object, .. } => object.type_name(),
        TupleSubject::TypedWildcard(type_name) => type_name,
    }
    .as_str();
    let type_id = compiled
        .type_id(subject_type_name)
        .ok_or_else(|| AuthorizationError::UnknownSubjectType(subject_type_name.to_owned()))?;
    let TupleSubject::Userset { object, relation } = scope.subject() else {
        return Ok(None);
    };
    let relation_id = compiled
        .relation_id(type_id, relation.as_str())
        .ok_or_else(|| AuthorizationError::UnknownSubjectRelation {
            subject_type: subject_type_name.to_owned(),
            relation: relation.as_str().to_owned(),
        })?;
    Ok(Some(EvaluationKey {
        relation_id,
        object_id: object.id().clone(),
    }))
}

/// One memo key; tenant, subject, contexts, and contextual tuples are fixed by
/// the evaluator's scope.
///
/// A relation ID identifies its owner type, so the object type is implied.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct EvaluationKey {
    relation_id: usize,
    object_id: EntityId,
}

/// Per-scope state for bounded graph traversal and decision memoization.
///
/// One evaluator serves every item of a batch: completed decisions and
/// converted request values are shared across items, while the tuple,
/// store-call, and work budgets restart for each item (see `check_item`).
///
/// Recursive models are evaluated as least fixed points with Tarjan-style
/// bookkeeping. Each relation frame gets a DFS index. Reaching a key that is
/// still unresolved (in flight, or finished false inside an open cycle) yields
/// a provisional `false` and lowers the caller's low link to that key's index.
/// Construction admits cycles only through monotone operators, so:
///
/// - `true` is always memoized: it was derived from under-approximations.
/// - A frame whose low link stays at its own index is a cycle root. A `false`
///   root resolves itself and every unresolved key above it as `false`.
/// - A `false` frame whose low link points below it stays unresolved until its
///   root finishes.
/// - Errors are never memoized; an erroring or allowing frame discards the
///   unresolved keys above it, which a later visit evaluates again.
///
/// Repeated evaluation of discarded keys is bounded by the work budget, and
/// the depth limit bounds traversal.
struct Evaluator<'a, S> {
    compiled: &'a CompiledModel,
    session: S,
    limits: EvaluationLimits,
    scope: &'a CheckScope,
    contextual: ContextualTuples,
    /// For a userset subject, the key of that userset, which grants itself.
    subject_userset: Option<EvaluationKey>,
    completed: HashMap<EvaluationKey, bool>,
    /// DFS index of every key that is in flight or awaiting its cycle root.
    unresolved: HashMap<EvaluationKey, usize>,
    /// Unresolved keys in DFS order; a frame owns the suffix it pushed.
    unresolved_stack: Vec<EvaluationKey>,
    /// Lowest DFS index the current frame's provisional results depend on.
    low_link: usize,
    next_index: usize,
    tuples_scanned: usize,
    store_calls: usize,
    work_units: usize,
    request_values: RequestValueCache,
    /// Inline conditions compiled from stored tuples, shared across a batch.
    inline_conditions: InlineConditionCache,
}

impl<'a, S: RelationshipReadSession> Evaluator<'a, S> {
    /// Creates isolated evaluation state for one scope and store snapshot.
    fn new(
        compiled: &'a CompiledModel,
        session: S,
        limits: EvaluationLimits,
        scope: &'a CheckScope,
        contextual: ContextualTuples,
        subject_userset: Option<EvaluationKey>,
    ) -> Self {
        Self {
            compiled,
            session,
            limits,
            scope,
            contextual,
            subject_userset,
            completed: HashMap::new(),
            unresolved: HashMap::new(),
            unresolved_stack: Vec::new(),
            low_link: usize::MAX,
            next_index: 0,
            tuples_scanned: 0,
            store_calls: 0,
            work_units: 0,
            request_values: RequestValueCache::default(),
            inline_conditions: InlineConditionCache::default(),
        }
    }

    /// Ends this scope's evaluation and returns its read session and
    /// contextual tuples, so another scope can decide on the same snapshot.
    fn into_parts(self) -> (S, ContextualTuples) {
        (self.session, self.contextual)
    }

    /// Resolves one top-level item with fresh budgets and the shared memo.
    ///
    /// Every root frame finishes, so no unresolved key survives an item and
    /// later items see only sound memo entries. Reusing a memoized decision
    /// spends no budget, so an item can succeed in a batch where a separate
    /// check would exceed a limit.
    async fn check_item(
        &mut self,
        object: ObjectRef,
        relation_id: usize,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.tuples_scanned = 0;
        self.store_calls = 0;
        self.work_units = 0;
        self.low_link = usize::MAX;
        let allowed = self.evaluate_relation(object, relation_id, 0).await;
        debug_assert!(self.unresolved.is_empty() && self.unresolved_stack.is_empty());
        Ok(if allowed? {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny
        })
    }

    /// Resolves one relation for the checked subject and memoizes its decision.
    fn evaluate_relation(
        &mut self,
        object: ObjectRef,
        relation_id: usize,
        depth: usize,
    ) -> EvalFuture<'_> {
        Box::pin(async move {
            if depth > self.limits.max_relation_depth() {
                return Err(AuthorizationError::RelationDepthExceeded {
                    maximum_depth: self.limits.max_relation_depth(),
                });
            }
            self.charge_work(1)?;
            let key = EvaluationKey {
                relation_id,
                object_id: object.id().clone(),
            };
            if self.subject_userset.as_ref() == Some(&key) {
                return Ok(true);
            }
            if let Some(decision) = self.completed.get(&key) {
                return Ok(*decision);
            }
            if let Some(&index) = self.unresolved.get(&key) {
                self.low_link = self.low_link.min(index);
                return Ok(false);
            }

            let index = self.next_index;
            self.next_index += 1;
            let stack_start = self.unresolved_stack.len();
            self.unresolved.insert(key.clone(), index);
            self.unresolved_stack.push(key);
            let caller_low_link = std::mem::replace(&mut self.low_link, index);

            let expression_id = self.compiled.relation_expression_id(relation_id);
            let result = self
                .evaluate_expression(object, relation_id, expression_id, depth)
                .await;

            let low_link = self.low_link;
            self.low_link = caller_low_link.min(low_link);
            if !matches!(result, Ok(false)) || low_link >= index {
                self.finish_frame(stack_start, result.as_ref().ok().copied());
            }
            result
        })
    }

    /// Pops a finished frame's unresolved suffix and memoizes what is sound.
    ///
    /// A `false` cycle root resolves the whole suffix as `false`; `true` is
    /// memoized for the frame itself only; errors memoize nothing.
    fn finish_frame(&mut self, stack_start: usize, decision: Option<bool>) {
        for (offset, key) in self.unresolved_stack.drain(stack_start..).enumerate() {
            self.unresolved.remove(&key);
            match decision {
                Some(false) => {
                    self.completed.insert(key, false);
                }
                Some(true) if offset == 0 => {
                    self.completed.insert(key, true);
                }
                _ => {}
            }
        }
    }

    /// Evaluates one AST node while preserving the operator's three-valued rules.
    fn evaluate_expression(
        &mut self,
        object: ObjectRef,
        relation_id: usize,
        expression_id: usize,
        depth: usize,
    ) -> EvalFuture<'_> {
        Box::pin(async move {
            self.charge_work(1)?;
            match self.compiled.expression(expression_id) {
                CompiledExpression::DirectAssignment(targets) => {
                    self.evaluate_direct_assignment(object, relation_id, targets, depth)
                        .await
                }
                CompiledExpression::ComputedUserset(target_relation_id) => {
                    self.evaluate_relation(object, target_relation_id, depth + 1)
                        .await
                }
                CompiledExpression::TupleToUserset {
                    tupleset_relation_id,
                    edge_range,
                } => {
                    self.evaluate_tuple_to_userset(object, tupleset_relation_id, edge_range, depth)
                        .await
                }
                CompiledExpression::Union { left, right } => {
                    let left_result = self
                        .evaluate_expression(object.clone(), relation_id, left, depth)
                        .await;
                    if let Ok(true) = &left_result {
                        return Ok(true);
                    }
                    let right_result = self
                        .evaluate_expression(object, relation_id, right, depth)
                        .await;
                    combine_union(left_result, right_result)
                }
                CompiledExpression::Intersection { left, right } => {
                    let left_result = self
                        .evaluate_expression(object.clone(), relation_id, left, depth)
                        .await;
                    if let Ok(false) = &left_result {
                        return Ok(false);
                    }
                    let right_result = self
                        .evaluate_expression(object, relation_id, right, depth)
                        .await;
                    combine_intersection(left_result, right_result)
                }
                CompiledExpression::Difference { left, right } => {
                    let base_result = self
                        .evaluate_expression(object.clone(), relation_id, left, depth)
                        .await;
                    if let Ok(false) = &base_result {
                        return Ok(false);
                    }
                    let subtract_result = self
                        .evaluate_expression(object, relation_id, right, depth)
                        .await;
                    combine_difference(base_result, subtract_result)
                }
            }
        })
    }

    /// Streams direct-assignment pages after validating each whole fetched page.
    fn evaluate_direct_assignment(
        &mut self,
        object: ObjectRef,
        relation_id: usize,
        targets: CompiledTargetRange,
        depth: usize,
    ) -> EvalFuture<'_> {
        Box::pin(async move {
            let mut state = TuplePageState::default();
            let mut first_error = None;
            loop {
                let Some(tuples) = self
                    .load_tuple_page(&object, relation_id, &mut state)
                    .await?
                else {
                    break;
                };
                let prepared_tuples =
                    self.prepare_assignment_page(&tuples, &object, relation_id, &targets)?;
                for (tuple, prepared) in tuples.iter().zip(prepared_tuples) {
                    let membership = match prepared.membership {
                        AssignmentMembership::Known(matches) => Ok(matches),
                        AssignmentMembership::Userset {
                            object,
                            relation_id,
                        } => self.evaluate_relation(object, relation_id, depth + 1).await,
                    };
                    let result = match membership {
                        Ok(true) => self.evaluate_tuple_condition(tuple, prepared.condition),
                        other => other,
                    };
                    match result {
                        Ok(true) => return Ok(true),
                        Ok(false) => {}
                        Err(error) => {
                            if first_error.is_none() {
                                first_error = Some(error);
                            }
                        }
                    }
                }
            }
            if let Some(error) = first_error {
                Err(error)
            } else {
                Ok(false)
            }
        })
    }

    /// Streams a direct tupleset and unions computed relation checks by page.
    fn evaluate_tuple_to_userset(
        &mut self,
        object: ObjectRef,
        tupleset_relation_id: usize,
        edge_range: CompiledTargetRange,
        depth: usize,
    ) -> EvalFuture<'_> {
        Box::pin(async move {
            let mut state = TuplePageState::default();
            let mut first_error = None;
            loop {
                let Some(tuples) = self
                    .load_tuple_page(&object, tupleset_relation_id, &mut state)
                    .await?
                else {
                    break;
                };
                let prepared_tuples =
                    self.prepare_tupleset_page(&tuples, &object, tupleset_relation_id, edge_range)?;
                for (tuple, prepared) in tuples.iter().zip(prepared_tuples) {
                    let PreparedTuplesetTuple {
                        condition,
                        target_object,
                        computed_relation_id,
                    } = prepared;
                    // Validation guarantees that some tupleset target type defines
                    // the computed relation; targets of other types cannot grant.
                    let Some(computed_relation_id) = computed_relation_id else {
                        continue;
                    };
                    let membership = self
                        .evaluate_relation(target_object, computed_relation_id, depth + 1)
                        .await;
                    let result = match membership {
                        Ok(true) => self.evaluate_tuple_condition(tuple, condition),
                        other => other,
                    };
                    match result {
                        Ok(true) => return Ok(true),
                        Ok(false) => {}
                        Err(error) => {
                            if first_error.is_none() {
                                first_error = Some(error);
                            }
                        }
                    }
                }
            }
            if let Some(error) = first_error {
                Err(error)
            } else {
                Ok(false)
            }
        })
    }

    /// Validates and prepares every tuple's context and assignment restriction.
    fn prepare_assignment_page(
        &mut self,
        tuples: &[RelationshipTuple],
        object: &ObjectRef,
        relation_id: usize,
        targets: &CompiledTargetRange,
    ) -> Result<Vec<PreparedAssignmentTuple>, AuthorizationError> {
        let mut prepared_tuples = Vec::with_capacity(tuples.len());
        let checked = self.scope.subject();
        for tuple in tuples {
            let condition = self.validate_tuple(tuple, object, relation_id)?;
            let restriction = self.compiled.validate_assignment_subject(tuple, targets)?;
            // OpenFGA semantics: a wildcard tuple grants a concrete subject of
            // its type and the equal wildcard subject, never a userset subject;
            // a tuple naming the checked userset grants it directly.
            let membership = match (tuple.subject(), checked) {
                (TupleSubject::Direct(subject), TupleSubject::Direct(checked)) => {
                    AssignmentMembership::Known(subject == checked)
                }
                (TupleSubject::Direct(_), _) => AssignmentMembership::Known(false),
                (TupleSubject::TypedWildcard(type_name), TupleSubject::Direct(checked)) => {
                    AssignmentMembership::Known(type_name == checked.type_name())
                }
                (TupleSubject::TypedWildcard(type_name), TupleSubject::TypedWildcard(checked)) => {
                    AssignmentMembership::Known(type_name == checked)
                }
                (TupleSubject::TypedWildcard(_), TupleSubject::Userset { .. }) => {
                    AssignmentMembership::Known(false)
                }
                (subject @ TupleSubject::Userset { .. }, checked) if subject == checked => {
                    AssignmentMembership::Known(true)
                }
                (TupleSubject::Userset { object, .. }, _) => {
                    let CompiledTargetRestriction::Userset(relation_id) = restriction else {
                        unreachable!("a userset subject validates as a userset restriction");
                    };
                    AssignmentMembership::Userset {
                        object: object.clone(),
                        relation_id,
                    }
                }
            };
            prepared_tuples.push(PreparedAssignmentTuple {
                condition,
                membership,
            });
        }
        Ok(prepared_tuples)
    }

    /// Validates and prepares every tuple's context, edge, and target object.
    fn prepare_tupleset_page(
        &mut self,
        tuples: &[RelationshipTuple],
        object: &ObjectRef,
        tupleset_relation_id: usize,
        edge_range: CompiledTargetRange,
    ) -> Result<Vec<PreparedTuplesetTuple>, AuthorizationError> {
        let mut prepared_tuples = Vec::with_capacity(tuples.len());
        for tuple in tuples {
            let condition = self.validate_tuple(tuple, object, tupleset_relation_id)?;
            let TupleSubject::Direct(tuple_subject) = tuple.subject() else {
                return Err(AuthorizationError::InvalidTuple(
                    "tupleset tuple subject must be a direct object",
                ));
            };
            let subject_type = tuple_subject.type_name().as_str();
            let subject_type_id = self.compiled.type_id(subject_type);
            let compatible_edge = (edge_range.start..edge_range.start + edge_range.len)
                .map(|edge_id| self.compiled.tuple_to_userset_edge(edge_id))
                .find(|edge| {
                    let target = self.compiled.target(edge.target_id);
                    Some(target.type_id) == subject_type_id
                        && matches!(target.restriction, CompiledTargetRestriction::Direct)
                        && self.compiled.condition_matches(target.condition, tuple)
                });
            let Some(edge) = compatible_edge else {
                return Err(AuthorizationError::InvalidTuple(
                    "tupleset subject type is incompatible with the relation",
                ));
            };
            let target_object = ObjectRef::new(
                subject_type.to_owned(),
                tuple_subject.id().as_str().to_owned(),
            )
            .map_err(|_| AuthorizationError::InvalidTuple("invalid tupleset subject"))?;
            prepared_tuples.push(PreparedTuplesetTuple {
                condition,
                target_object,
                computed_relation_id: edge.computed_relation_id,
            });
        }
        Ok(prepared_tuples)
    }

    /// Validates tuple ownership and prepares its condition: a model
    /// condition's stored context, or an inline condition compiled (once per
    /// check or batch) from the CEL source the tuple stores.
    fn validate_tuple(
        &mut self,
        tuple: &RelationshipTuple,
        object: &ObjectRef,
        relation_id: usize,
    ) -> Result<Option<PreparedTupleCondition>, AuthorizationError> {
        if tuple.tenant() != self.scope.tenant() {
            return Err(AuthorizationError::InvalidTuple(
                "tuple belongs to a different tenant",
            ));
        }
        if tuple.object() != object
            || tuple.relation().as_str() != self.compiled.relation_name(relation_id)
        {
            return Err(AuthorizationError::InvalidTuple(
                "tuple does not match the requested object and relation",
            ));
        }
        if let Some(context) = tuple.condition() {
            let mut work = 0;
            let prepared = if context.name().as_str() == INLINE_EXPRESSION_NAME {
                self.inline_conditions
                    .resolve(context.values(), &mut work)
                    .map(|inline_id| PreparedTupleCondition {
                        inline_id: Some(inline_id),
                        context: PreparedConditionContext::default(),
                    })
            } else {
                let condition = self.compiled.condition(context.name().as_str()).ok_or(
                    AuthorizationError::InvalidTuple(
                        "tuple condition is absent from the authorization model",
                    ),
                )?;
                condition
                    .validate_stored_context(context.values(), &mut work)
                    .map(|context| PreparedTupleCondition {
                        inline_id: None,
                        context,
                    })
            };
            self.charge_work(work)?;
            return prepared.map(Some);
        }
        Ok(None)
    }

    fn evaluate_tuple_condition(
        &mut self,
        tuple: &RelationshipTuple,
        prepared: Option<PreparedTupleCondition>,
    ) -> Result<bool, AuthorizationError> {
        let Some(context) = tuple.condition() else {
            return Ok(true);
        };
        let compiled = self.compiled;
        let (condition, stored_values) = match prepared {
            Some(PreparedTupleCondition {
                inline_id: Some(inline_id),
                context,
            }) => (self.inline_conditions.get(inline_id), Some(context)),
            prepared => (
                compiled.condition(context.name().as_str()).ok_or(
                    AuthorizationError::InvalidTuple(
                        "tuple condition is absent from the authorization model",
                    ),
                )?,
                prepared.map(|prepared| prepared.context),
            ),
        };
        let mut work = 0;
        let evaluation = condition.evaluate(
            stored_values,
            self.scope.condition_context(context.name().as_str()),
            self.scope.context(),
            &mut self.request_values,
            self.limits.max_condition_cost(),
            &mut work,
        );
        self.charge_work(work)?;
        let evaluation = evaluation?;
        Ok(evaluation.allowed)
    }

    /// Fetches, accounts for, and validates one bounded page for a relation.
    ///
    /// The relation's contextual tuples come first, as one page charged to the
    /// tuple and work budgets like a store page (but not to store calls).
    /// Store pages follow without the stored tuples that equal a contextual
    /// one; those still count as scanned.
    async fn load_tuple_page(
        &mut self,
        object: &ObjectRef,
        relation_id: usize,
        state: &mut TuplePageState,
    ) -> Result<Option<Vec<RelationshipTuple>>, AuthorizationError> {
        let relation = self.compiled.checked_relation_name(relation_id).ok_or(
            AuthorizationError::InvalidTuple("model contains an invalid relation reference"),
        )?;
        let maximum_tuples = self.limits.max_tuples_scanned();
        if !state.contextual_loaded {
            state.contextual_loaded = true;
            let contextual = self.contextual.tuples(object, relation);
            if !contextual.is_empty() {
                let contextual = contextual.to_vec();
                if contextual.len() > maximum_tuples.saturating_sub(self.tuples_scanned) {
                    return Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples });
                }
                self.charge_work(contextual.len())?;
                self.tuples_scanned += contextual.len();
                return Ok(Some(contextual));
            }
        }
        if state.exhausted {
            return Ok(None);
        }
        if self.store_calls >= self.limits.max_store_calls() {
            return Err(AuthorizationError::StoreCallLimitExceeded {
                maximum_calls: self.limits.max_store_calls(),
            });
        }
        let remaining = maximum_tuples.saturating_sub(self.tuples_scanned);
        if remaining == 0 {
            return Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples });
        }
        let requested_maximum = remaining.min(EVALUATION_PAGE_SIZE);
        self.store_calls += 1;
        self.charge_work(1)?;
        let page = self
            .session
            .tuples_page(object, relation, state.cursor.clone(), requested_maximum)
            .await
            .map_err(|error| map_store_error(error, maximum_tuples))?;
        if page.tuples.len() > requested_maximum {
            return Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples });
        }
        self.charge_work(page.tuples.len())?;
        self.tuples_scanned += page.tuples.len();
        match page.next_cursor.clone() {
            None => state.exhausted = true,
            Some(next_cursor) => {
                if page.tuples.is_empty() {
                    return Err(AuthorizationError::InvalidTuple(
                        "relationship page continued without returning tuples",
                    ));
                }
                if !state.seen_cursors.insert(next_cursor.clone()) {
                    return Err(AuthorizationError::InvalidTuple(
                        "relationship page cursor repeated",
                    ));
                }
                state.cursor = Some(next_cursor);
            }
        }
        // Only tuples equal to one of this query's contextual tuples are
        // dropped, so a stored tuple for another object or relation still
        // fails validation.
        let mut tuples = page.tuples;
        let contextual = self.contextual.tuples(object, relation);
        if !contextual.is_empty() {
            tuples.retain(|tuple| !contextual.contains(tuple));
        }
        Ok(Some(tuples))
    }

    /// Charges a bounded unit of evaluator work.
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

/// Combines union branches so any allow dominates branch errors.
fn combine_union(
    left: Result<bool, AuthorizationError>,
    right: Result<bool, AuthorizationError>,
) -> Result<bool, AuthorizationError> {
    match (left, right) {
        (Ok(true), _) | (_, Ok(true)) => Ok(true),
        (Ok(false), Ok(false)) => Ok(false),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

/// Combines intersection branches so any deny dominates branch errors.
fn combine_intersection(
    left: Result<bool, AuthorizationError>,
    right: Result<bool, AuthorizationError>,
) -> Result<bool, AuthorizationError> {
    match (left, right) {
        (Ok(false), _) | (_, Ok(false)) => Ok(false),
        (Ok(true), Ok(true)) => Ok(true),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

/// Evaluates `base AND NOT subtract` without treating a failed subtraction as absence.
fn combine_difference(
    base: Result<bool, AuthorizationError>,
    subtract: Result<bool, AuthorizationError>,
) -> Result<bool, AuthorizationError> {
    match (base, subtract) {
        (_, Ok(true)) | (Ok(false), _) => Ok(false),
        (Ok(true), Ok(false)) => Ok(true),
        (Err(error), Ok(false)) => Err(error),
        (Ok(true), Err(error)) | (Err(error), Err(_)) => Err(error),
    }
}

/// Maps bounded-store failures without turning incomplete reads into denial.
fn map_store_error(error: StoreError, maximum_tuples: usize) -> AuthorizationError {
    if error.kind() == StoreErrorKind::TupleLimitExceeded {
        AuthorizationError::EvaluationLimitExceeded { maximum_tuples }
    } else {
        AuthorizationError::Store(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{ContextualTuples, Evaluator, TuplePageState};
    use crate::authz::model::CompiledModel;
    use crate::authz::request::{
        CheckRequest, EvaluationLimits, ObjectRef, RelationName, Subject, TenantId,
    };
    use crate::authz::store::{InMemoryRelationshipStore, RelationshipStore, RelationshipTuple};

    fn viewer(id: &str) -> RelationshipTuple {
        RelationshipTuple::new(
            TenantId::new("acme").unwrap(),
            ObjectRef::new("document", "1").unwrap(),
            RelationName::new("viewer").unwrap(),
            Subject::new("user", id).unwrap(),
        )
    }

    #[tokio::test]
    async fn contextual_tuples_come_first_and_replace_equal_stored_tuples() {
        let schema = relgraph_dsl::parse_fga_schema(
            "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n",
        )
        .unwrap();
        let compiled = CompiledModel::compile(schema).unwrap();
        let relation_id = compiled
            .relation_id(compiled.type_id("document").unwrap(), "viewer")
            .unwrap();
        let store = InMemoryRelationshipStore::new();
        store.insert(viewer("anne")).unwrap();
        store.insert(viewer("bob")).unwrap();
        let request = CheckRequest::new(
            TenantId::new("acme").unwrap(),
            Subject::new("user", "zoe").unwrap(),
            ObjectRef::new("document", "1").unwrap(),
            RelationName::new("viewer").unwrap(),
        )
        .with_contextual_tuples([viewer("anne"), viewer("carl")]);
        let contextual = ContextualTuples::prepare(&compiled, request.scope()).unwrap();
        let session = store.begin_read(request.tenant()).await.unwrap();
        let mut evaluator = Evaluator::new(
            &compiled,
            session,
            EvaluationLimits::default(),
            request.scope(),
            contextual,
            None,
        );

        let object = request.object().clone();
        let mut state = TuplePageState::default();
        let mut pages = Vec::new();
        while let Some(page) = evaluator
            .load_tuple_page(&object, relation_id, &mut state)
            .await
            .unwrap()
        {
            pages.push(page);
        }

        assert_eq!(
            pages,
            [vec![viewer("anne"), viewer("carl")], vec![viewer("bob")]]
        );
        // The dropped stored duplicate was still read from the store.
        assert_eq!(evaluator.tuples_scanned, 4);
        assert_eq!(evaluator.store_calls, 1);
    }
}
