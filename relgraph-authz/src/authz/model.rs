//! Immutable model validation, capability checks, and lookup indexes.

use std::collections::{HashMap, HashSet};

use relgraph_dsl::{
    RelationCondition, RelationExpression, RelationTarget, Schema, validate_schema,
};

use super::conditions::{self, CompiledCondition};
use super::request::{
    CapabilityDiagnostic, ConstructionError, RelationLocation, RuntimeCapability,
};

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
    target_range: Option<CompiledTargetRange>,
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
                    target_range: None,
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
                relations[relation_id].target_range = Some(range);
            }
        }

        let mut expressions = Vec::new();
        let mut tuple_to_userset_edges = Vec::new();
        for (type_id, type_definition) in schema.type_definitions.iter().enumerate() {
            for relation in &type_definition.relations {
                let relation_id = relation_index[type_id][&relation.name];
                let expression_id = compile_expression(
                    &relation.definition.expression,
                    &relation.definition.expression,
                    target_ranges[relation_id],
                    type_id,
                    relation_id,
                    &type_index,
                    &relation_index,
                    &condition_index,
                    &target_ranges,
                    &mut targets,
                    &mut tuple_to_userset_edges,
                    &mut expressions,
                );
                relations[relation_id].expression_id = expression_id;
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

    pub(crate) fn tuple_to_userset_computed_name(
        &self,
        edge_range: CompiledTargetRange,
    ) -> Option<&str> {
        (edge_range.start..edge_range.start + edge_range.len).find_map(|edge_id| {
            self.tuple_to_userset_edge(edge_id)
                .computed_relation_id
                .map(|relation_id| self.relation_name(relation_id))
        })
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

fn compile_expression(
    expression: &relgraph_dsl::RelationExpression,
    root_expression: &relgraph_dsl::RelationExpression,
    root_target_range: Option<CompiledTargetRange>,
    owner_type_id: usize,
    owner_relation_id: usize,
    type_index: &HashMap<String, usize>,
    relation_index: &[HashMap<String, usize>],
    condition_index: &HashMap<String, usize>,
    target_ranges: &[Option<CompiledTargetRange>],
    targets: &mut Vec<CompiledTarget>,
    tuple_to_userset_edges: &mut Vec<CompiledTupleToUsersetEdge>,
    expressions: &mut Vec<CompiledExpression>,
) -> usize {
    let expression = match expression {
        relgraph_dsl::RelationExpression::DirectAssignment(ast_targets) => {
            let range = if std::ptr::eq(expression, root_expression) {
                root_target_range
                    .expect("direct-assignment targets are compiled before expressions")
            } else {
                compile_targets(
                    ast_targets,
                    type_index,
                    relation_index,
                    condition_index,
                    targets,
                )
            };
            CompiledExpression::DirectAssignment(range)
        }
        relgraph_dsl::RelationExpression::ComputedUserset(relation) => {
            let relation_id = *relation_index[owner_type_id]
                .get(relation)
                .expect("validated computed userset has a compiled relation");
            CompiledExpression::ComputedUserset(relation_id)
        }
        relgraph_dsl::RelationExpression::TupleToUserset {
            computed_userset,
            tupleset_relation,
        } => {
            let tupleset_relation_id = *relation_index[owner_type_id]
                .get(tupleset_relation)
                .expect("validated tupleset has a compiled relation");
            let target_range = target_ranges[tupleset_relation_id]
                .expect("validated tupleset relation is a direct assignment");
            let edge_range = CompiledTargetRange {
                start: tuple_to_userset_edges.len(),
                len: target_range.len,
            };
            for target_id in target_range.start..target_range.start + target_range.len {
                let target = targets[target_id];
                let computed_relation_id = relation_index[target.type_id]
                    .get(computed_userset)
                    .copied();
                tuple_to_userset_edges.push(CompiledTupleToUsersetEdge {
                    target_id,
                    computed_relation_id,
                });
            }
            CompiledExpression::TupleToUserset {
                tupleset_relation_id,
                edge_range,
            }
        }
        relgraph_dsl::RelationExpression::Union(left, right) => {
            let left = compile_expression(
                left,
                root_expression,
                root_target_range,
                owner_type_id,
                owner_relation_id,
                type_index,
                relation_index,
                condition_index,
                target_ranges,
                targets,
                tuple_to_userset_edges,
                expressions,
            );
            let right = compile_expression(
                right,
                root_expression,
                root_target_range,
                owner_type_id,
                owner_relation_id,
                type_index,
                relation_index,
                condition_index,
                target_ranges,
                targets,
                tuple_to_userset_edges,
                expressions,
            );
            CompiledExpression::Union { left, right }
        }
        relgraph_dsl::RelationExpression::Intersection(left, right) => {
            let left = compile_expression(
                left,
                root_expression,
                root_target_range,
                owner_type_id,
                owner_relation_id,
                type_index,
                relation_index,
                condition_index,
                target_ranges,
                targets,
                tuple_to_userset_edges,
                expressions,
            );
            let right = compile_expression(
                right,
                root_expression,
                root_target_range,
                owner_type_id,
                owner_relation_id,
                type_index,
                relation_index,
                condition_index,
                target_ranges,
                targets,
                tuple_to_userset_edges,
                expressions,
            );
            CompiledExpression::Intersection { left, right }
        }
        relgraph_dsl::RelationExpression::Difference(left, right) => {
            let left = compile_expression(
                left,
                root_expression,
                root_target_range,
                owner_type_id,
                owner_relation_id,
                type_index,
                relation_index,
                condition_index,
                target_ranges,
                targets,
                tuple_to_userset_edges,
                expressions,
            );
            let right = compile_expression(
                right,
                root_expression,
                root_target_range,
                owner_type_id,
                owner_relation_id,
                type_index,
                relation_index,
                condition_index,
                target_ranges,
                targets,
                tuple_to_userset_edges,
                expressions,
            );
            CompiledExpression::Difference { left, right }
        }
    };
    let expression_id = expressions.len();
    expressions.push(expression);
    expression_id
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
                {
                    if let RelationExpression::DirectAssignment(targets) =
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
    fn evaluator_detects_in_flight_tuple_graph_cycles() {
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
        assert!(matches!(
            result,
            Err(AuthorizationError::TupleGraphCycle { .. })
        ));
    }
}
