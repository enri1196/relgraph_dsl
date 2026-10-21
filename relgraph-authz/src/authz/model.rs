//! Immutable model validation, capability checks, and lookup indexes.

use std::collections::{HashMap, HashSet};

use relgraph_dsl::{RelationCondition, RelationExpression, Schema, validate_schema};

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
    pub(crate) condition: CompiledTargetCondition,
}

/// The condition a direct-assignment target requires its tuples to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledTargetCondition {
    Unconditioned,
    /// A model condition, by its index in the schema's declarations.
    Named(usize),
    /// An inline expression (`$expression`) whose CEL source and parameter
    /// types each tuple stores.
    Inline,
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
        let capability_errors = recursive_dependencies(&schema);
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
            if context.name().as_str() == conditions::INLINE_EXPRESSION_NAME {
                return conditions::validate_inline_condition(context.values());
            }
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
                && self.condition_matches(target.condition, tuple)
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
        condition: CompiledTargetCondition,
        tuple: &RelationshipTuple,
    ) -> bool {
        match (condition, tuple.condition()) {
            (CompiledTargetCondition::Unconditioned, None) => true,
            (CompiledTargetCondition::Named(expected), Some(context)) => {
                self.condition_id(context.name().as_str()) == Some(expected)
            }
            (CompiledTargetCondition::Inline, Some(context)) => {
                context.name().as_str() == conditions::INLINE_EXPRESSION_NAME
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
        let condition = match &target.condition {
            None => CompiledTargetCondition::Unconditioned,
            Some(RelationCondition::Named(name)) => CompiledTargetCondition::Named(
                *condition_index
                    .get(name)
                    .expect("validated target condition has a compiled index"),
            ),
            Some(RelationCondition::InlineExpression) => CompiledTargetCondition::Inline,
        };
        targets.push(CompiledTarget {
            type_id: target_type_id,
            restriction,
            condition,
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

#[derive(Debug, Clone)]
/// A node in the model's relation-dependency graph.
struct RelationNode {
    location: RelationLocation,
    span: Option<relgraph_dsl::SourceSpan>,
}

/// Whether a dependency edge stays on the evaluated object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeKind {
    /// A computed userset or tupleset read on the same object.
    SameObject,
    /// A userset restriction or tuple-to-userset hop to a tuple's object.
    ObjectHop,
}

#[derive(Debug, Clone)]
/// A directed dependency between two declared relations.
struct RelationEdge {
    target: usize,
    kind: EdgeKind,
    /// The edge lies inside the subtracted operand of a difference.
    subtracted: bool,
    span: Option<relgraph_dsl::SourceSpan>,
}

/// Reports relation dependency cycles outside the fixed-point evaluator's profile.
///
/// Cycles through unions, intersections, base operands, userset restrictions,
/// and tuple-to-userset hops are evaluated as least fixed points. Two cyclic
/// shapes are rejected: a cycle through the subtracted operand of `but not`,
/// which has no sound assume-false evaluation, and a cycle that stays on one
/// object through computed usersets only, which OpenFGA also rejects.
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

    let mut diagnostics = Vec::new();
    let all_edges = |_: &RelationEdge| true;
    let components = strongly_connected_components(&graph, all_edges);
    let mut reported = HashSet::new();
    for (source, edges) in graph.iter().enumerate() {
        for edge in edges {
            if edge.subtracted
                && components[source] == components[edge.target]
                && reported.insert((source, edge.target))
            {
                let path = cycle_path(&graph, &nodes, &components, all_edges, source, edge.target);
                diagnostics.push(CapabilityDiagnostic {
                    capability: RuntimeCapability::RecursiveDifference,
                    relation: Some(nodes[source].location.clone()),
                    span: edge.span.clone().or_else(|| nodes[source].span.clone()),
                    message: format!(
                        "relation depends on itself through the subtracted operand of `but not`: {path}"
                    ),
                });
            }
        }
    }

    let same_object = |edge: &RelationEdge| edge.kind == EdgeKind::SameObject;
    let components = strongly_connected_components(&graph, same_object);
    let mut reported = HashSet::new();
    for (source, edges) in graph.iter().enumerate() {
        for edge in edges {
            if same_object(edge)
                && components[source] == components[edge.target]
                && reported.insert(components[source])
            {
                let path = cycle_path(
                    &graph,
                    &nodes,
                    &components,
                    same_object,
                    source,
                    edge.target,
                );
                diagnostics.push(CapabilityDiagnostic {
                    capability: RuntimeCapability::SameObjectRelationCycle,
                    relation: Some(nodes[source].location.clone()),
                    span: edge.span.clone().or_else(|| nodes[source].span.clone()),
                    message: format!(
                        "relations on one object depend on each other only through computed usersets: {path}"
                    ),
                });
            }
        }
    }
    diagnostics
}

/// Adds dependency edges implied by one parsed relation expression.
fn collect_relation_edges(
    source: usize,
    expression: &RelationExpression,
    owner: &relgraph_dsl::TypeDefinition,
    ids: &HashMap<(String, String), usize>,
    graph: &mut [Vec<RelationEdge>],
    span: Option<relgraph_dsl::SourceSpan>,
) {
    let mut add = |target: (String, String), kind, subtracted| {
        if let Some(target_id) = ids.get(&target) {
            graph[source].push(RelationEdge {
                target: *target_id,
                kind,
                subtracted,
                span: span.clone(),
            });
        }
    };
    let mut pending = vec![(expression, false)];
    while let Some((expression, subtracted)) = pending.pop() {
        match expression {
            RelationExpression::DirectAssignment(targets) => {
                for target in targets {
                    if let Some(Some(target_relation)) = target
                        .relation_or_wildcard
                        .as_deref()
                        .map(|relation| (relation != "*").then_some(relation))
                    {
                        add(
                            (target.target_type.clone(), target_relation.to_owned()),
                            EdgeKind::ObjectHop,
                            subtracted,
                        );
                    }
                }
            }
            RelationExpression::ComputedUserset(target_relation) => add(
                (owner.name.clone(), target_relation.clone()),
                EdgeKind::SameObject,
                subtracted,
            ),
            RelationExpression::TupleToUserset {
                computed_userset,
                tupleset_relation,
            } => {
                add(
                    (owner.name.clone(), tupleset_relation.clone()),
                    EdgeKind::SameObject,
                    subtracted,
                );

                if let Some(tupleset) = owner
                    .relations
                    .iter()
                    .find(|relation| relation.name == *tupleset_relation)
                    && let RelationExpression::DirectAssignment(targets) =
                        &tupleset.definition.expression
                {
                    for target in targets {
                        add(
                            (target.target_type.clone(), computed_userset.clone()),
                            EdgeKind::ObjectHop,
                            subtracted,
                        );
                    }
                }
            }
            RelationExpression::Union(left, right)
            | RelationExpression::Intersection(left, right) => {
                pending.push((right, subtracted));
                pending.push((left, subtracted));
            }
            RelationExpression::Difference(left, right) => {
                pending.push((right, true));
                pending.push((left, subtracted));
            }
        }
    }
}

/// Assigns a strongly connected component ID to every relation node.
///
/// Iterative Tarjan over the edges accepted by `include`, so deeply chained
/// models cannot exhaust the native stack.
fn strongly_connected_components(
    graph: &[Vec<RelationEdge>],
    include: impl Fn(&RelationEdge) -> bool,
) -> Vec<usize> {
    const UNVISITED: usize = usize::MAX;
    let mut index = vec![UNVISITED; graph.len()];
    let mut low_link = vec![0; graph.len()];
    let mut on_stack = vec![false; graph.len()];
    let mut component = vec![UNVISITED; graph.len()];
    let mut stack = Vec::new();
    let mut next_index = 0;
    let mut next_component = 0;

    for root in 0..graph.len() {
        if index[root] != UNVISITED {
            continue;
        }
        index[root] = next_index;
        low_link[root] = next_index;
        next_index += 1;
        stack.push(root);
        on_stack[root] = true;
        let mut frames = vec![(root, 0usize)];

        while let Some(frame) = frames.last_mut() {
            let node = frame.0;
            if let Some(edge) = graph[node].get(frame.1) {
                frame.1 += 1;
                if !include(edge) {
                    continue;
                }
                let target = edge.target;
                if index[target] == UNVISITED {
                    index[target] = next_index;
                    low_link[target] = next_index;
                    next_index += 1;
                    stack.push(target);
                    on_stack[target] = true;
                    frames.push((target, 0));
                } else if on_stack[target] {
                    low_link[node] = low_link[node].min(index[target]);
                }
                continue;
            }

            frames.pop();
            if let Some(&(parent, _)) = frames.last() {
                low_link[parent] = low_link[parent].min(low_link[node]);
            }
            if low_link[node] == index[node] {
                loop {
                    let member = stack.pop().expect("a component root is on the stack");
                    on_stack[member] = false;
                    component[member] = next_component;
                    if member == node {
                        break;
                    }
                }
                next_component += 1;
            }
        }
    }
    component
}

/// Formats the cycle closed by `source -> target` within one component.
fn cycle_path(
    graph: &[Vec<RelationEdge>],
    nodes: &[RelationNode],
    components: &[usize],
    include: impl Fn(&RelationEdge) -> bool,
    source: usize,
    target: usize,
) -> String {
    // Breadth-first search from `target` back to `source` inside the component.
    let mut previous = HashMap::from([(target, target)]);
    let mut queue = std::collections::VecDeque::from([target]);
    while let Some(node) = queue.pop_front() {
        if node == source {
            break;
        }
        for edge in &graph[node] {
            if include(edge)
                && components[edge.target] == components[source]
                && !previous.contains_key(&edge.target)
            {
                previous.insert(edge.target, node);
                queue.push_back(edge.target);
            }
        }
    }

    let mut path = vec![source];
    let mut node = source;
    while node != target {
        node = previous[&node];
        path.push(node);
    }
    path.reverse();
    path.insert(0, source);
    path.iter()
        .map(|id| {
            let relation = &nodes[*id].location;
            format!("{}#{}", relation.object_type, relation.relation)
        })
        .collect::<Vec<_>>()
        .join(" -> ")
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
    fn unresolved_keys_terminate_a_cycle_that_skipped_construction_checks() {
        use crate::authz::evaluator;
        use crate::authz::request::{
            AuthorizationDecision, CheckRequest, EvaluationLimits, ObjectRef, RelationName,
            Subject, TenantId,
        };
        use crate::authz::store::{InMemoryRelationshipStore, RelationshipTuple};
        use std::future::Future;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        // Construction rejects this same-object cycle; the evaluator still
        // terminates on it through its unresolved-key tracking.
        let schema = parse_fga_schema(
            "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user] or editor\n    define editor: viewer\n",
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
                Subject::new("user", "anne").unwrap(),
            ))
            .unwrap();

        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        for (subject, expected) in [
            ("anne", AuthorizationDecision::Allow),
            ("zoe", AuthorizationDecision::Deny),
        ] {
            let request = CheckRequest::new(
                tenant.clone(),
                Subject::new("user", subject).unwrap(),
                ObjectRef::new("document", "42").unwrap(),
                RelationName::new("editor").unwrap(),
            );
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
            assert_eq!(result.unwrap(), expected);
        }
    }
}
