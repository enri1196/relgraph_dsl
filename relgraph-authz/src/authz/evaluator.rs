use super::model::{
    CompiledExpression, CompiledModel, CompiledTargetRange, CompiledTargetRestriction,
};
use super::request::{
    AuthorizationDecision, AuthorizationError, CheckRequest, EvaluationLimits, ObjectRef,
    RelationName,
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
    let object_type_name = request.object().type_name().as_str();
    let object_type_id = compiled
        .type_id(object_type_name)
        .ok_or_else(|| AuthorizationError::UnknownObjectType(object_type_name.to_owned()))?;
    let relation_id = compiled
        .relation_id(object_type_id, request.relation().as_str())
        .ok_or_else(|| AuthorizationError::UnknownRelation {
            object_type: object_type_name.to_owned(),
            relation: request.relation().as_str().to_owned(),
        })?;

    let subject_type_name = request.subject().type_name().as_str();
    compiled
        .type_id(subject_type_name)
        .ok_or_else(|| AuthorizationError::UnknownSubjectType(subject_type_name.to_owned()))?;

    // The session and evaluator are owned by this future. Dropping a cancelled
    // check drops the in-flight page future and its read snapshot without any
    // detached work or shared mutable decision state.
    let session = store
        .begin_read(request.tenant())
        .await
        .map_err(|error| map_store_error(error, limits.max_tuples_scanned()))?;
    let mut evaluator = Evaluator::new(compiled, session, limits, request);
    let allowed = evaluator
        .evaluate_relation_by_id(request.object().clone(), relation_id, 0)
        .await?;
    Ok(if allowed {
        AuthorizationDecision::Allow
    } else {
        AuthorizationDecision::Deny
    })
}

/// One memo key; tenant and subject are fixed for this evaluator's single check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct EvaluationKey {
    object_type: String,
    object_id: String,
    relation: String,
}

/// Per-check state for bounded graph traversal and decision memoization.
struct Evaluator<'a, S> {
    compiled: &'a CompiledModel,
    session: S,
    limits: EvaluationLimits,
    request: &'a CheckRequest,
    completed: HashMap<EvaluationKey, bool>,
    in_flight: HashSet<EvaluationKey>,
    tuples_scanned: usize,
    store_calls: usize,
    work_units: usize,
    request_values: super::conditions::RequestValueCache,
}

impl<'a, S: RelationshipReadSession> Evaluator<'a, S> {
    /// Creates isolated evaluation state for a single check and store snapshot.
    fn new(
        compiled: &'a CompiledModel,
        session: S,
        limits: EvaluationLimits,
        request: &'a CheckRequest,
    ) -> Self {
        Self {
            compiled,
            session,
            limits,
            request,
            completed: HashMap::new(),
            in_flight: HashSet::new(),
            tuples_scanned: 0,
            store_calls: 0,
            work_units: 0,
            request_values: super::conditions::RequestValueCache::default(),
        }
    }

    /// Resolves one relation for the checked subject and tracks recursive work.
    fn evaluate_relation(
        &mut self,
        object: ObjectRef,
        relation: RelationName,
        depth: usize,
    ) -> EvalFuture<'_> {
        self.evaluate_relation_resolved(object, Some(relation), None, depth)
    }

    fn evaluate_relation_by_id(
        &mut self,
        object: ObjectRef,
        relation_id: usize,
        depth: usize,
    ) -> EvalFuture<'_> {
        self.evaluate_relation_resolved(object, None, Some(relation_id), depth)
    }

    fn evaluate_relation_resolved(
        &mut self,
        object: ObjectRef,
        relation: Option<RelationName>,
        known_relation_id: Option<usize>,
        depth: usize,
    ) -> EvalFuture<'_> {
        Box::pin(async move {
            let relation_name = match known_relation_id {
                Some(relation_id) => self.compiled.relation_name(relation_id).to_owned(),
                None => relation
                    .as_ref()
                    .expect("unresolved relation names are supplied by callers")
                    .as_str()
                    .to_owned(),
            };
            if depth > self.limits.max_relation_depth() {
                return Err(AuthorizationError::RelationDepthExceeded {
                    maximum_depth: self.limits.max_relation_depth(),
                });
            }
            self.charge_work(1)?;
            let key = EvaluationKey {
                object_type: object.type_name().as_str().to_owned(),
                object_id: object.id().as_str().to_owned(),
                relation: relation_name.clone(),
            };
            if let Some(decision) = self.completed.get(&key) {
                return Ok(*decision);
            }
            if !self.in_flight.insert(key.clone()) {
                return Err(AuthorizationError::TupleGraphCycle {
                    object_type: key.object_type,
                    object_id: key.object_id,
                    relation: key.relation,
                });
            }

            let relation_id = match known_relation_id {
                Some(relation_id) => Ok(relation_id),
                None => self.resolve_relation_id(object.type_name().as_str(), &relation_name),
            };
            let result = match relation_id {
                Ok(relation_id) => {
                    let expression_id = self.compiled.relation_expression_id(relation_id);
                    self.evaluate_expression(object.clone(), relation_id, expression_id, depth)
                        .await
                }
                Err(error) => Err(error),
            };
            self.in_flight.remove(&key);
            if let Ok(decision) = &result {
                self.completed.insert(key, *decision);
            }
            result
        })
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
                    self.evaluate_relation_by_id(object, target_relation_id, depth + 1)
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
                let prepared_contexts =
                    self.prepare_assignment_page(&page.tuples, &object, relation_id, &targets)?;
                for (tuple, prepared_context) in page.tuples.iter().zip(prepared_contexts) {
                    let membership = match tuple.subject() {
                        TupleSubject::Direct(tuple_subject) => Ok(tuple_subject.type_name()
                            == self.request.subject().type_name()
                            && tuple_subject.id() == self.request.subject().id()),
                        TupleSubject::TypedWildcard(type_name) => {
                            Ok(type_name == self.request.subject().type_name())
                        }
                        TupleSubject::Userset { object, relation } => {
                            self.evaluate_relation(object.clone(), relation.clone(), depth + 1)
                                .await
                        }
                    };
                    let result = match membership {
                        Ok(true) => self.evaluate_tuple_condition(tuple, prepared_context),
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
            let tupleset_expression_id = self.compiled.relation_expression_id(tupleset_relation_id);
            let CompiledExpression::DirectAssignment(_) =
                self.compiled.expression(tupleset_expression_id)
            else {
                return Err(AuthorizationError::InvalidTuple(
                    "tupleset relation is not a direct assignment",
                ));
            };

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
                        .evaluate_relation_by_id(target_object, computed_relation_id, depth + 1)
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
    ) -> Result<Vec<Option<super::conditions::PreparedConditionContext>>, AuthorizationError> {
        let mut prepared_contexts = Vec::with_capacity(tuples.len());
        for tuple in tuples {
            let condition_context = self.validate_tuple(tuple, object, relation_id)?;
            self.compiled.validate_assignment_subject(tuple, targets)?;
            prepared_contexts.push(condition_context);
        }
        Ok(prepared_contexts)
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
        if tuple.tenant() != self.request.tenant() {
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
            self.request.condition_context(context.name().as_str()),
            self.request.context(),
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
        let relation = relation_name(self.compiled.relation_name(relation_id))?;
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
            .tuples_page(object, &relation, state.cursor.clone(), requested_maximum)
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

    /// Looks up one validated relation expression from the immutable model.
    fn resolve_relation_id(
        &self,
        object_type: &str,
        relation: &str,
    ) -> Result<usize, AuthorizationError> {
        let type_id = self
            .compiled
            .type_id(object_type)
            .ok_or_else(|| AuthorizationError::UnknownObjectType(object_type.to_owned()))?;
        self.compiled.relation_id(type_id, relation).ok_or_else(|| {
            AuthorizationError::UnknownRelation {
                object_type: object_type.to_owned(),
                relation: relation.to_owned(),
            }
        })
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

/// Converts a model relation name into the checked runtime representation.
fn relation_name(value: &str) -> Result<RelationName, AuthorizationError> {
    RelationName::new(value.to_owned()).map_err(|_| {
        AuthorizationError::InvalidTuple("model contains an invalid relation reference")
    })
}

/// Maps bounded-store failures without turning incomplete reads into denial.
fn map_store_error(error: StoreError, maximum_tuples: usize) -> AuthorizationError {
    if error.kind() == StoreErrorKind::TupleLimitExceeded {
        AuthorizationError::EvaluationLimitExceeded { maximum_tuples }
    } else {
        AuthorizationError::Store(error)
    }
}
