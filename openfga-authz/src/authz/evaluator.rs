use super::model::CompiledModel;
use super::request::{
    AuthorizationDecision, AuthorizationError, CheckRequest, EvaluationLimits, ObjectRef,
    RelationName,
};
use super::store::{
    RelationshipReadSession, RelationshipStore, RelationshipTuple, StoreError, StoreErrorKind,
    TupleSubject,
};
use openfga_dsl::{RelationExpression, RelationTarget};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;

type EvalFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, AuthorizationError>> + Send + 'a>>;

fn condition_matches(target: &RelationTarget, tuple: &RelationshipTuple) -> bool {
    match (&target.condition, tuple.condition()) {
        (None, None) => true,
        (Some(openfga_dsl::RelationCondition::Named(expected)), Some(context)) => {
            expected == context.name().as_str()
        }
        _ => false,
    }
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
    if compiled
        .relation_id(object_type_id, request.relation().as_str())
        .is_none()
    {
        return Err(AuthorizationError::UnknownRelation {
            object_type: object_type_name.to_owned(),
            relation: request.relation().as_str().to_owned(),
        });
    }

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
        .evaluate_relation(request.object().clone(), request.relation().clone(), 0)
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
    condition_cost_used: usize,
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
            condition_cost_used: 0,
        }
    }

    /// Resolves one relation for the checked subject and tracks recursive work.
    fn evaluate_relation(
        &mut self,
        object: ObjectRef,
        relation: RelationName,
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
                object_type: object.type_name().as_str().to_owned(),
                object_id: object.id().as_str().to_owned(),
                relation: relation.as_str().to_owned(),
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

            let result = match self.relation_expression(&object, &relation) {
                Ok(expression) => {
                    self.evaluate_expression(object.clone(), relation.clone(), expression, depth)
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
        relation: RelationName,
        expression: RelationExpression,
        depth: usize,
    ) -> EvalFuture<'_> {
        Box::pin(async move {
            self.charge_work(1)?;
            match expression {
                RelationExpression::DirectAssignment(targets) => {
                    self.evaluate_direct_assignment(object, relation, targets, depth)
                        .await
                }
                RelationExpression::ComputedUserset(target_relation) => {
                    let target_relation = relation_name(&target_relation)?;
                    self.evaluate_relation(object.clone(), target_relation, depth + 1)
                        .await
                }
                RelationExpression::TupleToUserset {
                    computed_userset,
                    tupleset_relation,
                } => {
                    self.evaluate_tuple_to_userset(
                        object,
                        computed_userset,
                        tupleset_relation,
                        depth,
                    )
                    .await
                }
                RelationExpression::Union(left, right) => {
                    let left_result = self
                        .evaluate_expression(object.clone(), relation.clone(), *left, depth)
                        .await;
                    if let Ok(true) = &left_result {
                        return Ok(true);
                    }
                    let right_result = self
                        .evaluate_expression(object, relation, *right, depth)
                        .await;
                    combine_union(left_result, right_result)
                }
                RelationExpression::Intersection(left, right) => {
                    let left_result = self
                        .evaluate_expression(object.clone(), relation.clone(), *left, depth)
                        .await;
                    if let Ok(false) = &left_result {
                        return Ok(false);
                    }
                    let right_result = self
                        .evaluate_expression(object, relation, *right, depth)
                        .await;
                    combine_intersection(left_result, right_result)
                }
                RelationExpression::Difference(base, subtract) => {
                    let base_result = self
                        .evaluate_expression(object.clone(), relation.clone(), *base, depth)
                        .await;
                    if let Ok(false) = &base_result {
                        return Ok(false);
                    }
                    let subtract_result = self
                        .evaluate_expression(object, relation, *subtract, depth)
                        .await;
                    combine_difference(base_result, subtract_result)
                }
            }
        })
    }

    /// Reads and validates every tuple for a direct assignment expression.
    fn evaluate_direct_assignment(
        &mut self,
        object: ObjectRef,
        relation: RelationName,
        targets: Vec<RelationTarget>,
        depth: usize,
    ) -> EvalFuture<'_> {
        Box::pin(async move {
            let tuples = self.load_tuples(object.clone(), relation.clone()).await?;
            let mut allowed = false;
            let mut first_error = None;
            for tuple in &tuples {
                self.validate_tuple(tuple, &object, &relation)?;
                self.validate_assignment_subject(tuple, &targets)?;

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
                    Ok(true) => self.evaluate_tuple_condition(tuple),
                    other => other,
                };
                match result {
                    Ok(true) => allowed = true,
                    Ok(false) => {}
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
            if allowed {
                Ok(true)
            } else if let Some(error) = first_error {
                Err(error)
            } else {
                Ok(false)
            }
        })
    }

    /// Traverses a direct tupleset and unions the computed relation checks.
    fn evaluate_tuple_to_userset(
        &mut self,
        object: ObjectRef,
        computed_userset: String,
        tupleset_relation: String,
        depth: usize,
    ) -> EvalFuture<'_> {
        Box::pin(async move {
            let tupleset_name = relation_name(&tupleset_relation)?;
            let tuples = self
                .load_tuples(object.clone(), tupleset_name.clone())
                .await?;
            let type_id = self
                .compiled
                .type_id(object.type_name().as_str())
                .ok_or_else(|| {
                    AuthorizationError::UnknownObjectType(object.type_name().as_str().to_owned())
                })?;
            let tupleset_expression = self.compiled.schema().type_definitions[type_id]
                .relations
                .iter()
                .find(|candidate| candidate.name == tupleset_relation)
                .map(|candidate| &candidate.definition.expression)
                .ok_or_else(|| AuthorizationError::UnknownRelation {
                    object_type: object.type_name().as_str().to_owned(),
                    relation: tupleset_relation.clone(),
                })?;
            let RelationExpression::DirectAssignment(targets) = tupleset_expression else {
                return Err(AuthorizationError::InvalidTuple(
                    "tupleset relation is not a direct assignment",
                ));
            };

            let computed_relation = relation_name(&computed_userset)?;
            let mut allowed = false;
            let mut first_error = None;
            for tuple in &tuples {
                self.validate_tuple(tuple, &object, &tupleset_name)?;
                let TupleSubject::Direct(tuple_subject) = tuple.subject() else {
                    return Err(AuthorizationError::InvalidTuple(
                        "tupleset tuple subject must be a direct object",
                    ));
                };
                let subject_type = tuple_subject.type_name().as_str();
                let compatible = targets.iter().any(|target| {
                    target.target_type == subject_type
                        && target.relation_or_wildcard.is_none()
                        && condition_matches(target, tuple)
                });
                if !compatible {
                    return Err(AuthorizationError::InvalidTuple(
                        "tupleset subject type is incompatible with the relation",
                    ));
                }
                let target_object = ObjectRef::new(
                    subject_type.to_owned(),
                    tuple_subject.id().as_str().to_owned(),
                )
                .map_err(|_| AuthorizationError::InvalidTuple("invalid tupleset subject"))?;
                let membership = self
                    .evaluate_relation(target_object, computed_relation.clone(), depth + 1)
                    .await;
                let result = match membership {
                    Ok(true) => self.evaluate_tuple_condition(tuple),
                    other => other,
                };
                match result {
                    Ok(true) => allowed = true,
                    Ok(false) => {}
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
            if allowed {
                Ok(true)
            } else if let Some(error) = first_error {
                Err(error)
            } else {
                Ok(false)
            }
        })
    }

    /// Confirms that a tuple subject is one of the model's declared targets.
    fn validate_assignment_subject(
        &self,
        tuple: &RelationshipTuple,
        targets: &[RelationTarget],
    ) -> Result<(), AuthorizationError> {
        let (subject_type, restriction) = match tuple.subject() {
            TupleSubject::Direct(subject) => (subject.type_name().as_str(), None),
            TupleSubject::Userset { object, relation } => {
                (object.type_name().as_str(), Some(relation.as_str()))
            }
            TupleSubject::TypedWildcard(type_name) => (type_name.as_str(), Some("*")),
        };
        let type_id =
            self.compiled
                .type_id(subject_type)
                .ok_or(AuthorizationError::InvalidTuple(
                    "tuple subject type is absent from the authorization model",
                ))?;
        if let Some(relation) = restriction.filter(|relation| *relation != "*") {
            if self.compiled.relation_id(type_id, relation).is_none() {
                return Err(AuthorizationError::InvalidTuple(
                    "tuple userset relation is absent from the authorization model",
                ));
            }
        }
        if targets.iter().any(|target| {
            target.target_type == subject_type
                && target.relation_or_wildcard.as_deref() == restriction
                && condition_matches(target, tuple)
        }) {
            Ok(())
        } else {
            Err(AuthorizationError::InvalidTuple(
                "tuple subject is incompatible with the relation restriction",
            ))
        }
    }

    /// Validates tuple ownership and rejects condition metadata until Task 4.
    fn validate_tuple(
        &self,
        tuple: &RelationshipTuple,
        object: &ObjectRef,
        relation: &RelationName,
    ) -> Result<(), AuthorizationError> {
        if tuple.tenant() != self.request.tenant() {
            return Err(AuthorizationError::InvalidTuple(
                "tuple belongs to a different tenant",
            ));
        }
        if tuple.object() != object || tuple.relation() != relation {
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
            condition.validate_stored_context(context.values())?;
        }
        Ok(())
    }

    fn evaluate_tuple_condition(
        &mut self,
        tuple: &RelationshipTuple,
    ) -> Result<bool, AuthorizationError> {
        let Some(context) = tuple.condition() else {
            return Ok(true);
        };
        let condition = self.compiled.condition(context.name().as_str()).ok_or(
            AuthorizationError::InvalidTuple(
                "tuple condition is absent from the authorization model",
            ),
        )?;
        let remaining_cost = self
            .limits
            .max_condition_cost()
            .saturating_sub(self.condition_cost_used);
        let evaluation = condition.evaluate(
            Some(context.values()),
            self.request.condition_context(context.name().as_str()),
            self.request.context(),
            remaining_cost,
        )?;
        self.condition_cost_used = self.condition_cost_used.saturating_add(evaluation.cost);
        Ok(evaluation.allowed)
    }

    /// Reads every page while enforcing the per-check tuple and call budgets.
    async fn load_tuples(
        &mut self,
        object: ObjectRef,
        relation: RelationName,
    ) -> Result<Vec<RelationshipTuple>, AuthorizationError> {
        let maximum_tuples = self.limits.max_tuples_scanned();
        let mut tuples = Vec::new();
        let mut cursor = None;
        let mut seen_cursors = HashSet::new();
        loop {
            if self.store_calls >= self.limits.max_store_calls() {
                return Err(AuthorizationError::StoreCallLimitExceeded {
                    maximum_calls: self.limits.max_store_calls(),
                });
            }
            let remaining = maximum_tuples.saturating_sub(self.tuples_scanned);
            if remaining == 0 {
                return Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples });
            }
            self.store_calls += 1;
            self.charge_work(1)?;
            let page = self
                .session
                .tuples_page(&object, &relation, cursor.clone(), remaining)
                .await
                .map_err(|error| map_store_error(error, maximum_tuples))?;
            if page.tuples.len() > remaining {
                return Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples });
            }
            let page_is_empty = page.tuples.is_empty();
            self.charge_work(page.tuples.len())?;
            self.tuples_scanned += page.tuples.len();
            tuples.extend(page.tuples);
            match page.next_cursor {
                None => break,
                Some(next_cursor) => {
                    if page_is_empty {
                        return Err(AuthorizationError::InvalidTuple(
                            "relationship page continued without returning tuples",
                        ));
                    }
                    if !seen_cursors.insert(next_cursor.clone()) {
                        return Err(AuthorizationError::InvalidTuple(
                            "relationship page cursor repeated",
                        ));
                    }
                    if self.tuples_scanned >= maximum_tuples {
                        return Err(AuthorizationError::EvaluationLimitExceeded { maximum_tuples });
                    }
                    cursor = Some(next_cursor);
                }
            }
        }
        Ok(tuples)
    }

    /// Looks up one validated relation expression from the immutable model.
    fn relation_expression(
        &self,
        object: &ObjectRef,
        relation: &RelationName,
    ) -> Result<RelationExpression, AuthorizationError> {
        let object_type = object.type_name().as_str();
        let type_id = self
            .compiled
            .type_id(object_type)
            .ok_or_else(|| AuthorizationError::UnknownObjectType(object_type.to_owned()))?;
        let expression = self.compiled.schema().type_definitions[type_id]
            .relations
            .iter()
            .find(|candidate| candidate.name == relation.as_str())
            .map(|candidate| candidate.definition.expression.clone())
            .ok_or_else(|| AuthorizationError::UnknownRelation {
                object_type: object_type.to_owned(),
                relation: relation.as_str().to_owned(),
            })?;
        Ok(expression)
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
