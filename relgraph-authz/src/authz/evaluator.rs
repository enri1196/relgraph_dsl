use super::model::{
    CompiledExpression, CompiledModel, CompiledTargetRange, CompiledTargetRestriction,
};
use super::request::{
    AuthorizationDecision, AuthorizationError, BatchCheckRequest, CheckRequest, CheckScope,
    EntityId, EvaluationLimits, ObjectRef, RelationName,
};
use super::store::{
    RelationshipPage, RelationshipReadSession, RelationshipStore, RelationshipTuple, StoreCursor,
    StoreError, StoreErrorKind, TupleSubject,
};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;

type EvalFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, AuthorizationError>> + Send + 'a>>;

/// Maximum tuple count requested for one relationship page.
const EVALUATION_PAGE_SIZE: usize = 128;

/// Pagination state retained while one relation's tuples are evaluated.
#[derive(Default)]
struct TuplePageState {
    cursor: Option<StoreCursor>,
    seen_cursors: HashSet<StoreCursor>,
    exhausted: bool,
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
    condition_context: Option<super::conditions::PreparedConditionContext>,
    membership: AssignmentMembership,
}

/// Tuple metadata validated before evaluating a tupleset page.
struct PreparedTuplesetTuple {
    condition_context: Option<super::conditions::PreparedConditionContext>,
    target_object: ObjectRef,
    computed_relation_id: Option<usize>,
}

/// Evaluates one structured check against one tenant-scoped store snapshot.
pub(crate) async fn check<S: RelationshipStore>(
    compiled: &CompiledModel,
    store: &S,
    limits: EvaluationLimits,
    request: &CheckRequest,
) -> Result<AuthorizationDecision, AuthorizationError> {
    let relation_id = resolve_relation(compiled, request.object(), request.relation())?;
    validate_subject_type(compiled, request.scope())?;

    // The session and evaluator are owned by this future. Dropping a cancelled
    // check drops the in-flight page future and its read snapshot without any
    // detached work or shared mutable decision state.
    let session = store
        .begin_read(request.tenant())
        .await
        .map_err(|error| map_store_error(error, limits.max_tuples_scanned()))?;
    let mut evaluator = Evaluator::new(compiled, session, limits, request.scope());
    evaluator
        .check_item(request.object().clone(), relation_id)
        .await
}

/// Evaluates every batch item against one snapshot with a shared memo.
///
/// Per-item failures, including unknown object types and relations, are
/// returned in that item's slot; the outer error covers the item bound, the
/// shared subject, and opening the read session.
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
    validate_subject_type(compiled, request.scope())?;
    if request.items().is_empty() {
        return Ok(Vec::new());
    }

    // Cancellation drops the session and evaluator as it does for `check`.
    let session = store
        .begin_read(request.tenant())
        .await
        .map_err(|error| map_store_error(error, limits.max_tuples_scanned()))?;
    let mut evaluator = Evaluator::new(compiled, session, limits, request.scope());
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

/// Rejects a checked subject whose type is absent from the model.
fn validate_subject_type(
    compiled: &CompiledModel,
    scope: &CheckScope,
) -> Result<(), AuthorizationError> {
    let subject_type_name = scope.subject().type_name().as_str();
    compiled
        .type_id(subject_type_name)
        .map(|_| ())
        .ok_or_else(|| AuthorizationError::UnknownSubjectType(subject_type_name.to_owned()))
}

/// One memo key; tenant, subject, and contexts are fixed by the evaluator's scope.
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
    request_values: super::conditions::RequestValueCache,
}

impl<'a, S: RelationshipReadSession> Evaluator<'a, S> {
    /// Creates isolated evaluation state for one scope and store snapshot.
    fn new(
        compiled: &'a CompiledModel,
        session: S,
        limits: EvaluationLimits,
        scope: &'a CheckScope,
    ) -> Self {
        Self {
            compiled,
            session,
            limits,
            scope,
            completed: HashMap::new(),
            unresolved: HashMap::new(),
            unresolved_stack: Vec::new(),
            low_link: usize::MAX,
            next_index: 0,
            tuples_scanned: 0,
            store_calls: 0,
            work_units: 0,
            request_values: super::conditions::RequestValueCache::default(),
        }
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
                let Some(page) = self
                    .load_tuple_page(&object, relation_id, &mut state)
                    .await?
                else {
                    break;
                };
                let prepared_tuples =
                    self.prepare_assignment_page(&page.tuples, &object, relation_id, &targets)?;
                for (tuple, prepared) in page.tuples.iter().zip(prepared_tuples) {
                    let membership = match prepared.membership {
                        AssignmentMembership::Known(matches) => Ok(matches),
                        AssignmentMembership::Userset {
                            object,
                            relation_id,
                        } => self.evaluate_relation(object, relation_id, depth + 1).await,
                    };
                    let result = match membership {
                        Ok(true) => {
                            self.evaluate_tuple_condition(tuple, prepared.condition_context)
                        }
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
                let Some(page) = self
                    .load_tuple_page(&object, tupleset_relation_id, &mut state)
                    .await?
                else {
                    break;
                };
                let prepared_tuples = self.prepare_tupleset_page(
                    &page.tuples,
                    &object,
                    tupleset_relation_id,
                    edge_range,
                )?;
                for (tuple, prepared) in page.tuples.iter().zip(prepared_tuples) {
                    let PreparedTuplesetTuple {
                        condition_context,
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
                        Ok(true) => self.evaluate_tuple_condition(tuple, condition_context),
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
            let condition_context = self.validate_tuple(tuple, object, relation_id)?;
            let restriction = self.compiled.validate_assignment_subject(tuple, targets)?;
            let membership = match tuple.subject() {
                TupleSubject::Direct(subject) => AssignmentMembership::Known(
                    subject.type_name() == checked.type_name() && subject.id() == checked.id(),
                ),
                TupleSubject::TypedWildcard(type_name) => {
                    AssignmentMembership::Known(type_name == checked.type_name())
                }
                TupleSubject::Userset { object, .. } => {
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
                condition_context,
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
            let condition_context = self.validate_tuple(tuple, object, tupleset_relation_id)?;
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
                        && self.compiled.condition_matches(target.condition_id, tuple)
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
                condition_context,
                target_object,
                computed_relation_id: edge.computed_relation_id,
            });
        }
        Ok(prepared_tuples)
    }

    /// Validates tuple ownership and prepares its stored condition context.
    fn validate_tuple(
        &mut self,
        tuple: &RelationshipTuple,
        object: &ObjectRef,
        relation_id: usize,
    ) -> Result<Option<super::conditions::PreparedConditionContext>, AuthorizationError> {
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
            let condition = self.compiled.condition(context.name().as_str()).ok_or(
                AuthorizationError::InvalidTuple(
                    "tuple condition is absent from the authorization model",
                ),
            )?;
            let mut work = 0;
            let prepared = condition.validate_stored_context(context.values(), &mut work);
            self.charge_work(work)?;
            return prepared.map(Some);
        }
        Ok(None)
    }

    fn evaluate_tuple_condition(
        &mut self,
        tuple: &RelationshipTuple,
        prepared_context: Option<super::conditions::PreparedConditionContext>,
    ) -> Result<bool, AuthorizationError> {
        let Some(context) = tuple.condition() else {
            return Ok(true);
        };
        let condition = self.compiled.condition(context.name().as_str()).ok_or(
            AuthorizationError::InvalidTuple(
                "tuple condition is absent from the authorization model",
            ),
        )?;
        let mut work = 0;
        let evaluation = condition.evaluate(
            prepared_context,
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
    async fn load_tuple_page(
        &mut self,
        object: &ObjectRef,
        relation_id: usize,
        state: &mut TuplePageState,
    ) -> Result<Option<RelationshipPage>, AuthorizationError> {
        if state.exhausted {
            return Ok(None);
        }
        let relation = self.compiled.checked_relation_name(relation_id).ok_or(
            AuthorizationError::InvalidTuple("model contains an invalid relation reference"),
        )?;
        let maximum_tuples = self.limits.max_tuples_scanned();
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
        Ok(Some(page))
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
