//! Immutable model validation, capability checks, and lookup indexes.

use std::collections::{HashMap, HashSet};

use relgraph_dsl::{
    RelationCondition, RelationExpression, RelationTarget, Schema, validate_schema,
};

use super::conditions::{self, CompiledCondition};
use super::request::{
    AuthorizationError, CapabilityDiagnostic, ConstructionError, RelationLocation, RelationName,
    RuntimeCapability,
};
use super::store::{RelationshipTuple, TupleSubject};

/// The immutable model shared by all lifecycle handles.
#[derive(Debug)]
pub(crate) struct CompiledModel {
    schema: Schema,
    type_index: HashMap<String, usize>,
    relation_index: Vec<HashMap<String, usize>>,
    relations: Vec<CompiledRelation>,
    expressions: Vec<CompiledExpression>,
    targets: Vec<CompiledTarget>,
    tuple_to_userset_edges: Vec<CompiledTupleToUsersetEdge>,
    conditions: HashMap<String, CompiledCondition>,
    condition_index: HashMap<String, usize>,
}

#[cfg(test)]
mod construction_costs;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompiledTargetRange {
    pub(crate) start: usize,
    pub(crate) len: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CompiledTargetRestriction {
    Direct,
    Userset(usize),
    Wildcard,
}

impl CompiledTargetRestriction {
    pub(crate) fn matches(self, other: Self) -> bool {
        match (self, other) {
            (Self::Direct, Self::Direct) | (Self::Wildcard, Self::Wildcard) => true,
            (Self::Userset(left), Self::Userset(right)) => left == right,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompiledTarget {
    pub(crate) type_id: usize,
    pub(crate) restriction: CompiledTargetRestriction,
    pub(crate) condition_id: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompiledTupleToUsersetEdge {
    pub(crate) target_id: usize,
    pub(crate) computed_relation_id: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CompiledExpression {
    DirectAssignment(CompiledTargetRange),
    ComputedUserset(usize),
    TupleToUserset {
        tupleset_relation_id: usize,
        edge_range: CompiledTargetRange,
    },
    Union {
        left: usize,
        right: usize,
    },
    Intersection {
        left: usize,
        right: usize,
    },
    Difference {
        left: usize,
        right: usize,
    },
}

#[derive(Debug)]
struct CompiledRelation {
    owner_type_id: usize,
    definition_index: usize,
    expression_id: usize,
    /// The relation name as a store query identifier, or `None` when the model
    /// name exceeds identifier limits and so can never match a stored tuple.
    checked_name: Option<RelationName>,
}

impl CompiledModel {
    /// Validates and indexes one parsed standalone schema.
    pub(crate) fn compile(schema: Schema) -> Result<Self, ConstructionError> {
        validate_schema(&schema).map_err(ConstructionError::Validation)?;

        Self::compile_validated(schema)
    }

    /// Compiles runtime structures from a schema that already passed semantic
    /// validation at its trust boundary.
    pub(crate) fn compile_validated(schema: Schema) -> Result<Self, ConstructionError> {
        let mut capability_errors = unsupported_capabilities(&schema);
        capability_errors.extend(recursive_dependencies(&schema));
        if !capability_errors.is_empty() {
            return Err(ConstructionError::UnsupportedCapabilities(
                capability_errors,
            ));
        }

        let conditions = conditions::compile_all(&schema)?;
        Ok(Self::compile_indexes(schema, conditions))
    }

    #[cfg(test)]
    fn compile_unchecked_for_test(schema: Schema) -> Self {
        Self::compile_indexes(schema, HashMap::new())
    }

    fn compile_indexes(schema: Schema, conditions: HashMap<String, CompiledCondition>) -> Self {
        let mut type_index = HashMap::with_capacity(schema.type_definitions.len());
        let mut relation_index = Vec::with_capacity(schema.type_definitions.len());
        let mut relations = Vec::new();

        for (type_id, type_definition) in schema.type_definitions.iter().enumerate() {
            type_index.insert(type_definition.name.clone(), type_id);
            let mut type_relations = HashMap::with_capacity(type_definition.relations.len());
            for relation in &type_definition.relations {
                let relation_id = relations.len();
                type_relations.insert(relation.name.clone(), relation_id);
                relations.push(CompiledRelation {
                    owner_type_id: type_id,
                    definition_index: type_relations.len() - 1,
                    expression_id: usize::MAX,
                    checked_name: RelationName::new(relation.name.clone()).ok(),
                });
            }
            relation_index.push(type_relations);
        }

        let condition_index = schema
            .condition_definitions
            .iter()
            .enumerate()
            .map(|(condition_id, definition)| (definition.name.clone(), condition_id))
            .collect::<HashMap<_, _>>();

        let mut targets = Vec::new();
        let mut target_ranges = vec![None; relations.len()];
        for (type_id, type_definition) in schema.type_definitions.iter().enumerate() {
            for relation in &type_definition.relations {
                let relation_id = relation_index[type_id][&relation.name];
                let relgraph_dsl::RelationExpression::DirectAssignment(ast_targets) =
                    &relation.definition.expression
                else {
                    continue;
                };
                let range = compile_targets(
                    ast_targets,
                    &type_index,
                    &relation_index,
                    &condition_index,
                    &mut targets,
                );
                target_ranges[relation_id] = Some(range);
            }
        }

        let mut expressions = Vec::new();
        let mut tuple_to_userset_edges = Vec::new();
        let mut compiler = ExpressionCompiler {
            type_index: &type_index,
            relation_index: &relation_index,
            condition_index: &condition_index,
            target_ranges: &target_ranges,
            targets: &mut targets,
            tuple_to_userset_edges: &mut tuple_to_userset_edges,
            expressions: &mut expressions,
        };
        for (type_id, type_definition) in schema.type_definitions.iter().enumerate() {
            for relation in &type_definition.relations {
                let relation_id = relation_index[type_id][&relation.name];
                let root = RootExpression {
                    expression: &relation.definition.expression,
                    target_range: target_ranges[relation_id],
                    owner_type_id: type_id,
                };
                relations[relation_id].expression_id =
                    compiler.compile(&relation.definition.expression, &root);
            }
        }

        Self {
            schema,
            type_index,
            relation_index,
            relations,
            expressions,
            targets,
            tuple_to_userset_edges,
            conditions,
            condition_index,
        }
    }

    /// Returns the validated syntax tree retained by this compiled model.
    pub(crate) fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Returns the number of declared object types.
    pub(crate) fn type_count(&self) -> usize {
        self.type_index.len()
    }

    /// Returns the number of declared relations.
    pub(crate) fn relation_count(&self) -> usize {
        self.relations.len()
    }

    /// Resolves an object type name to its stable index.
    #[allow(dead_code)]
    pub(crate) fn type_id(&self, object_type: &str) -> Option<usize> {
        self.type_index.get(object_type).copied()
    }

    /// Resolves a relation name within a known type to its stable index.
    pub(crate) fn relation_id(&self, type_id: usize, relation: &str) -> Option<usize> {
        self.relation_index.get(type_id)?.get(relation).copied()
    }

    pub(crate) fn type_name(&self, type_id: usize) -> &str {
        &self.schema.type_definitions[type_id].name
    }

    pub(crate) fn relation_name(&self, relation_id: usize) -> &str {
        let relation = &self.relations[relation_id];
        &self.schema.type_definitions[relation.owner_type_id].relations[relation.definition_index]
            .name
    }

    /// Returns the relation name as a store query identifier, if it is one.
    pub(crate) fn checked_relation_name(&self, relation_id: usize) -> Option<&RelationName> {
        self.relations[relation_id].checked_name.as_ref()
    }

    pub(crate) fn relation_owner_type_id(&self, relation_id: usize) -> usize {
        self.relations[relation_id].owner_type_id
    }

    pub(crate) fn relation_expression_id(&self, relation_id: usize) -> usize {
        self.relations[relation_id].expression_id
    }

    pub(crate) fn expression(&self, expression_id: usize) -> CompiledExpression {
        self.expressions[expression_id]
    }

    pub(crate) fn target(&self, target_id: usize) -> CompiledTarget {
        self.targets[target_id]
    }

    pub(crate) fn tuple_to_userset_edge(&self, edge_id: usize) -> CompiledTupleToUsersetEdge {
        self.tuple_to_userset_edges[edge_id]
    }

    /// Validates a tuple against this model with the checks a read applies.
    ///
    /// The relation must accept directly assigned tuples, the subject and
    /// condition must match one of its declared targets, and any stored
    /// condition context must convert to the declared parameter types.
    pub(crate) fn validate_tuple(
        &self,
        tuple: &RelationshipTuple,
    ) -> Result<(), AuthorizationError> {
        let object_type = tuple.object().type_name().as_str();
        let type_id = self
            .type_id(object_type)
            .ok_or_else(|| AuthorizationError::UnknownObjectType(object_type.to_owned()))?;
        let relation_id = self
            .relation_id(type_id, tuple.relation().as_str())
            .ok_or_else(|| AuthorizationError::UnknownRelation {
                object_type: object_type.to_owned(),
                relation: tuple.relation().as_str().to_owned(),
            })?;

        // A check reads this relation's tuples for each direct assignment in
        // its expression tree; other operands refer to other relations.
        let mut pending = vec![self.relation_expression_id(relation_id)];
        let mut first_error = None;
        let mut matched = false;
        while let Some(expression_id) = pending.pop() {
            match self.expression(expression_id) {
                CompiledExpression::DirectAssignment(targets) => {
                    match self.validate_assignment_subject(tuple, &targets) {
                        Ok(_) => {
                            matched = true;
                            break;
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                CompiledExpression::Union { left, right }
                | CompiledExpression::Intersection { left, right }
                | CompiledExpression::Difference { left, right } => {
                    pending.extend([right, left]);
                }
                CompiledExpression::ComputedUserset(_)
                | CompiledExpression::TupleToUserset { .. } => {}
            }
        }
        if !matched {
            return Err(first_error.unwrap_or(AuthorizationError::InvalidTuple(
                "relation does not accept directly assigned tuples",
            )));
        }

        if let Some(context) = tuple.condition() {
            let condition =
                self.condition(context.name().as_str())
                    .ok_or(AuthorizationError::InvalidTuple(
                        "tuple condition is absent from the authorization model",
                    ))?;
            let mut work = 0;
            condition.validate_stored_context(context.values(), &mut work)?;
        }
        Ok(())
    }

    /// Confirms that a tuple subject is one of the model's declared targets and
    /// returns the subject's restriction, including a userset's relation ID.
    pub(crate) fn validate_assignment_subject(
        &self,
        tuple: &RelationshipTuple,
        targets: &CompiledTargetRange,
    ) -> Result<CompiledTargetRestriction, AuthorizationError> {
        let (subject_type, restriction) = match tuple.subject() {
            TupleSubject::Direct(subject) => (subject.type_name().as_str(), None),
            TupleSubject::Userset { object, relation } => {
                (object.type_name().as_str(), Some(relation.as_str()))
            }
            TupleSubject::TypedWildcard(type_name) => (type_name.as_str(), Some("*")),
        };
        let type_id = self
            .type_id(subject_type)
            .ok_or(AuthorizationError::InvalidTuple(
                "tuple subject type is absent from the authorization model",
            ))?;
        let restriction = match restriction {
            None => CompiledTargetRestriction::Direct,
            Some("*") => CompiledTargetRestriction::Wildcard,
            Some(relation) => CompiledTargetRestriction::Userset(
                self.relation_id(type_id, relation)
                    .ok_or(AuthorizationError::InvalidTuple(
                        "tuple userset relation is absent from the authorization model",
                    ))?,
            ),
        };
        let matches = (targets.start..targets.start + targets.len).any(|target_id| {
            let target = self.target(target_id);
            target.type_id == type_id
                && target.restriction.matches(restriction)
                && self.condition_matches(target.condition_id, tuple)
        });
        if matches {
            Ok(restriction)
        } else {
            Err(AuthorizationError::InvalidTuple(
                "tuple subject is incompatible with the relation restriction",
            ))
        }
    }

    /// Returns whether a tuple carries exactly the condition a target declares.
    pub(crate) fn condition_matches(
        &self,
        condition_id: Option<usize>,
        tuple: &RelationshipTuple,
    ) -> bool {
        match (condition_id, tuple.condition()) {
            (None, None) => true,
            (Some(expected), Some(context)) => {
                self.condition_id(context.name().as_str()) == Some(expected)
            }
            _ => false,
        }
    }

    pub(crate) fn condition_id(&self, name: &str) -> Option<usize> {
        self.condition_index.get(name).copied()
    }

    pub(crate) fn condition_definition(
        &self,
        condition_id: usize,
    ) -> &relgraph_dsl::ConditionDefinition {
        &self.schema.condition_definitions[condition_id]
    }

    /// Resolves a model condition by its declared name.
    pub(crate) fn condition(&self, name: &str) -> Option<&CompiledCondition> {
        self.conditions.get(name)
    }
}

fn compile_targets(
    ast_targets: &[relgraph_dsl::RelationTarget],
    type_index: &HashMap<String, usize>,
    relation_index: &[HashMap<String, usize>],
    condition_index: &HashMap<String, usize>,
    targets: &mut Vec<CompiledTarget>,
) -> CompiledTargetRange {
    let range = CompiledTargetRange {
        start: targets.len(),
        len: ast_targets.len(),
    };
    for target in ast_targets {
        let target_type_id = *type_index
            .get(&target.target_type)
            .expect("validated target type has a compiled index");
        let restriction = match target.relation_or_wildcard.as_deref() {
            None => CompiledTargetRestriction::Direct,
            Some("*") => CompiledTargetRestriction::Wildcard,
            Some(relation_name) => CompiledTargetRestriction::Userset(
                *relation_index[target_type_id]
                    .get(relation_name)
                    .expect("validated target relation has a compiled index"),
            ),
        };
        let condition_id = match &target.condition {
            None => None,
            Some(relgraph_dsl::RelationCondition::Named(name)) => Some(
                *condition_index
                    .get(name)
                    .expect("validated target condition has a compiled index"),
            ),
            Some(relgraph_dsl::RelationCondition::InlineExpression) => {
                unreachable!("unsupported inline conditions were rejected above")
            }
        };
        targets.push(CompiledTarget {
            type_id: target_type_id,
            restriction,
            condition_id,
        });
    }
    range
}

/// The relation whose expression tree is being compiled.
struct RootExpression<'a> {
    expression: &'a relgraph_dsl::RelationExpression,
    /// Targets of a root direct assignment, compiled before any expression.
    target_range: Option<CompiledTargetRange>,
    owner_type_id: usize,
}

/// Lookup indexes and output tables shared while compiling expression trees.
struct ExpressionCompiler<'a> {
    type_index: &'a HashMap<String, usize>,
    relation_index: &'a [HashMap<String, usize>],
    condition_index: &'a HashMap<String, usize>,
    target_ranges: &'a [Option<CompiledTargetRange>],
    targets: &'a mut Vec<CompiledTarget>,
    tuple_to_userset_edges: &'a mut Vec<CompiledTupleToUsersetEdge>,
    expressions: &'a mut Vec<CompiledExpression>,
}

impl ExpressionCompiler<'_> {
    /// Compiles one validated expression node and returns its expression ID.
    fn compile(
        &mut self,
        expression: &relgraph_dsl::RelationExpression,
        root: &RootExpression<'_>,
    ) -> usize {
        let expression = match expression {
            relgraph_dsl::RelationExpression::DirectAssignment(ast_targets) => {
                let range = if std::ptr::eq(expression, root.expression) {
                    root.target_range
                        .expect("direct-assignment targets are compiled before expressions")
                } else {
                    compile_targets(
                        ast_targets,
                        self.type_index,
                        self.relation_index,
                        self.condition_index,
                        self.targets,
                    )
                };
                CompiledExpression::DirectAssignment(range)
            }
            relgraph_dsl::RelationExpression::ComputedUserset(relation) => {
                let relation_id = *self.relation_index[root.owner_type_id]
                    .get(relation)
                    .expect("validated computed userset has a compiled relation");
                CompiledExpression::ComputedUserset(relation_id)
            }
            relgraph_dsl::RelationExpression::TupleToUserset {
                computed_userset,
                tupleset_relation,
            } => {
                let tupleset_relation_id = *self.relation_index[root.owner_type_id]
                    .get(tupleset_relation)
                    .expect("validated tupleset has a compiled relation");
                let target_range = self.target_ranges[tupleset_relation_id]
                    .expect("validated tupleset relation is a direct assignment");
                let edge_range = CompiledTargetRange {
                    start: self.tuple_to_userset_edges.len(),
                    len: target_range.len,
                };
                let tupleset_targets =
                    &self.targets[target_range.start..target_range.start + target_range.len];
                for (target_id, target) in (target_range.start..).zip(tupleset_targets) {
                    let computed_relation_id = self.relation_index[target.type_id]
                        .get(computed_userset)
                        .copied();
                    self.tuple_to_userset_edges
                        .push(CompiledTupleToUsersetEdge {
                            target_id,
                            computed_relation_id,
                        });
                }
                CompiledExpression::TupleToUserset {
                    tupleset_relation_id,
                    edge_range,
                }
            }
            relgraph_dsl::RelationExpression::Union(left, right) => CompiledExpression::Union {
                left: self.compile(left, root),
                right: self.compile(right, root),
            },
            relgraph_dsl::RelationExpression::Intersection(left, right) => {
                CompiledExpression::Intersection {
                    left: self.compile(left, root),
                    right: self.compile(right, root),
                }
            }
            relgraph_dsl::RelationExpression::Difference(left, right) => {
                CompiledExpression::Difference {
                    left: self.compile(left, root),
                    right: self.compile(right, root),
                }
            }
        };
        let expression_id = self.expressions.len();
        self.expressions.push(expression);
        expression_id
    }
}

/// Collects all model constructs that exceed the initial runtime profile.
fn unsupported_capabilities(schema: &Schema) -> Vec<CapabilityDiagnostic> {
    let mut diagnostics = Vec::new();

    for type_definition in &schema.type_definitions {
        for relation in &type_definition.relations {
            let location = RelationLocation {
                object_type: type_definition.name.clone(),
                relation: relation.name.clone(),
            };
            inspect_expression(
                &relation.definition.expression,
                &location,
                relation.span.clone(),
                &mut diagnostics,
            );
        }
    }

    diagnostics
}

/// Recursively checks one relation expression and all of its operands.
fn inspect_expression(
    expression: &RelationExpression,
    location: &RelationLocation,
    span: Option<relgraph_dsl::SourceSpan>,
    diagnostics: &mut Vec<CapabilityDiagnostic>,
) {
    let mut pending = vec![expression];
    while let Some(expression) = pending.pop() {
        match expression {
            RelationExpression::DirectAssignment(targets) => {
                for target in targets {
                    inspect_target(target, location, span.clone(), diagnostics);
                }
            }
            RelationExpression::ComputedUserset(_) | RelationExpression::TupleToUserset { .. } => {}
            RelationExpression::Union(left, right)
            | RelationExpression::Intersection(left, right)
            | RelationExpression::Difference(left, right) => {
                pending.push(right);
                pending.push(left);
            }
        }
    }
}

/// Checks whether a direct-assignment target requires unsupported semantics.
fn inspect_target(
    target: &RelationTarget,
    location: &RelationLocation,
    span: Option<relgraph_dsl::SourceSpan>,
    diagnostics: &mut Vec<CapabilityDiagnostic>,
) {
    match target.condition {
        Some(RelationCondition::Named(_)) => {}
        Some(RelationCondition::InlineExpression) => diagnostics.push(CapabilityDiagnostic {
            capability: RuntimeCapability::InlineConditionExpression,
            relation: Some(location.clone()),
            span,
            message: "inline condition expressions are not supported yet".into(),
        }),
        None => {}
    }
}

#[derive(Debug, Clone)]
/// A node in the model's relation-dependency graph.
struct RelationNode {
    location: RelationLocation,
    span: Option<relgraph_dsl::SourceSpan>,
}

#[derive(Debug, Clone)]
/// A directed dependency between two declared relations.
struct RelationEdge {
    target: usize,
    span: Option<relgraph_dsl::SourceSpan>,
}

/// Reports relation dependency cycles that require recursive evaluation.
fn recursive_dependencies(schema: &Schema) -> Vec<CapabilityDiagnostic> {
    let mut nodes = Vec::new();
    let mut ids = HashMap::new();

    for type_definition in &schema.type_definitions {
        for relation in &type_definition.relations {
            let id = nodes.len();
            let location = RelationLocation {
                object_type: type_definition.name.clone(),
                relation: relation.name.clone(),
            };
            ids.insert(
                (location.object_type.clone(), location.relation.clone()),
                id,
            );
            nodes.push(RelationNode {
                location,
                span: relation.span.clone(),
            });
        }
    }

    let mut graph = vec![Vec::new(); nodes.len()];
    for type_definition in &schema.type_definitions {
        for relation in &type_definition.relations {
            let source = ids[&(type_definition.name.clone(), relation.name.clone())];
            collect_relation_edges(
                source,
                &relation.definition.expression,
                type_definition,
                &ids,
                &mut graph,
                relation.span.clone(),
            );
        }
    }

    let mut state = vec![0_u8; nodes.len()];
    let mut stack = Vec::new();
    let mut emitted = HashSet::new();
    let mut diagnostics = Vec::new();
    for node in 0..nodes.len() {
        if state[node] == 0 {
            visit_dependencies(
                node,
                &graph,
                &nodes,
                &mut state,
                &mut stack,
                &mut emitted,
                &mut diagnostics,
            );
        }
    }
    diagnostics
}

#[allow(clippy::too_many_arguments)]
/// Adds dependency edges implied by one parsed relation expression.
fn collect_relation_edges(
    source: usize,
    expression: &RelationExpression,
    owner: &relgraph_dsl::TypeDefinition,
    ids: &HashMap<(String, String), usize>,
    graph: &mut [Vec<RelationEdge>],
    span: Option<relgraph_dsl::SourceSpan>,
) {
    let mut pending = vec![expression];
    while let Some(expression) = pending.pop() {
        match expression {
            RelationExpression::DirectAssignment(targets) => {
                for target in targets {
                    if let Some(Some(target_relation)) = target
                        .relation_or_wildcard
                        .as_deref()
                        .map(|relation| (relation != "*").then_some(relation))
                    {
                        add_edge(
                            source,
                            &(target.target_type.clone(), target_relation.to_owned()),
                            ids,
                            graph,
                            span.clone(),
                        );
                    }
                }
            }
            RelationExpression::ComputedUserset(target_relation) => add_edge(
                source,
                &(owner.name.clone(), target_relation.clone()),
                ids,
                graph,
                span.clone(),
            ),
            RelationExpression::TupleToUserset {
                computed_userset,
                tupleset_relation,
            } => {
                add_edge(
                    source,
                    &(owner.name.clone(), tupleset_relation.clone()),
                    ids,
                    graph,
                    span.clone(),
                );

                if let Some(tupleset) = owner
                    .relations
                    .iter()
                    .find(|relation| relation.name == *tupleset_relation)
                    && let RelationExpression::DirectAssignment(targets) =
                        &tupleset.definition.expression
                {
                    for target in targets {
                        add_edge(
                            source,
                            &(target.target_type.clone(), computed_userset.clone()),
                            ids,
                            graph,
                            span.clone(),
                        );
                    }
                }
            }
            RelationExpression::Union(left, right)
            | RelationExpression::Intersection(left, right)
            | RelationExpression::Difference(left, right) => {
                pending.push(right);
                pending.push(left);
            }
        }
    }
}

/// Adds a dependency edge if semantic validation resolved the target relation.
fn add_edge(
    source: usize,
    target: &(String, String),
    ids: &HashMap<(String, String), usize>,
    graph: &mut [Vec<RelationEdge>],
    span: Option<relgraph_dsl::SourceSpan>,
) {
    if let Some(target_id) = ids.get(target) {
        graph[source].push(RelationEdge {
            target: *target_id,
            span,
        });
    }
}

/// Runs depth-first cycle detection from one relation node.
fn visit_dependencies(
    node: usize,
    graph: &[Vec<RelationEdge>],
    nodes: &[RelationNode],
    state: &mut [u8],
    stack: &mut Vec<usize>,
    emitted: &mut HashSet<Vec<usize>>,
    diagnostics: &mut Vec<CapabilityDiagnostic>,
) {
    state[node] = 1;
    stack.push(node);
    let mut frames = vec![(node, 0usize)];

    loop {
        let next = frames.last().and_then(|(current, edge_index)| {
            graph[*current]
                .get(*edge_index)
                .map(|edge| (*current, *edge_index, edge.target))
        });
        let Some((current, edge_index, target)) = next else {
            let (finished, _) = frames.pop().expect("a finished DFS frame exists");
            let popped = stack.pop();
            debug_assert_eq!(popped, Some(finished));
            state[finished] = 2;
            if frames.is_empty() {
                break;
            }
            continue;
        };
        frames.last_mut().expect("the active DFS frame exists").1 += 1;

        match state[target] {
            0 => {
                state[target] = 1;
                stack.push(target);
                frames.push((target, 0));
            }
            1 => {
                let edge = &graph[current][edge_index];
                let start = stack
                    .iter()
                    .position(|candidate| *candidate == target)
                    .unwrap_or(0);
                let mut cycle = stack[start..].to_vec();
                cycle.sort_unstable();
                cycle.dedup();
                if emitted.insert(cycle) {
                    let path = stack[start..]
                        .iter()
                        .chain(std::iter::once(&target))
                        .map(|id| {
                            let relation = &nodes[*id].location;
                            format!("{}#{}", relation.object_type, relation.relation)
                        })
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    diagnostics.push(CapabilityDiagnostic {
                        capability: RuntimeCapability::RecursiveRelationDependency,
                        relation: Some(nodes[current].location.clone()),
                        span: edge.span.clone().or_else(|| nodes[current].span.clone()),
                        message: format!("recursive relation dependency is unsupported: {path}"),
                    });
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CompiledModel;
    use relgraph_dsl::parse_fga_schema;

    #[test]
    fn direct_assignment_model_has_stable_lookup_indexes() {
        let schema = parse_fga_schema(
            "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n",
        )
        .unwrap();
        let model = CompiledModel::compile(schema).unwrap();

        let document = model.type_id("document").unwrap();
        assert!(model.relation_id(document, "viewer").is_some());
        assert!(model.relation_id(document, "missing").is_none());
    }

    #[test]
    fn depth_limit_bounds_a_recursive_model_that_skipped_construction_checks() {
        use crate::authz::evaluator;
        use crate::authz::request::{
            AuthorizationError, CheckRequest, EvaluationLimits, ObjectRef, RelationName, Subject,
            TenantId,
        };
        use crate::authz::store::{InMemoryRelationshipStore, RelationshipTuple, TupleSubject};
        use std::future::Future;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        let schema = parse_fga_schema(
            "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user, group#member]\ntype document\n  relations\n    define viewer: [group#member]\n",
        )
        .unwrap();
        let compiled = CompiledModel::compile_unchecked_for_test(schema);
        let store = InMemoryRelationshipStore::new();
        let tenant = TenantId::new("tenant-a").unwrap();
        store
            .insert(RelationshipTuple::new(
                tenant.clone(),
                ObjectRef::new("document", "42").unwrap(),
                RelationName::new("viewer").unwrap(),
                TupleSubject::Userset {
                    object: ObjectRef::new("group", "8").unwrap(),
                    relation: RelationName::new("member").unwrap(),
                },
            ))
            .unwrap();
        store
            .insert(RelationshipTuple::new(
                tenant.clone(),
                ObjectRef::new("group", "8").unwrap(),
                RelationName::new("member").unwrap(),
                TupleSubject::Userset {
                    object: ObjectRef::new("group", "8").unwrap(),
                    relation: RelationName::new("member").unwrap(),
                },
            ))
            .unwrap();
        let request = CheckRequest::new(
            tenant,
            Subject::new("user", "anne").unwrap(),
            ObjectRef::new("document", "42").unwrap(),
            RelationName::new("viewer").unwrap(),
        );

        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(evaluator::check(
            &compiled,
            &store,
            EvaluationLimits::default(),
            &request,
        ));
        let result = loop {
            if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                break result;
            }
        };
        // Construction rejects this model; without that check the self-referencing
        // tuple recurses until the depth limit rather than looping forever.
        assert!(matches!(
            result,
            Err(AuthorizationError::RelationDepthExceeded { .. })
        ));
    }
}
