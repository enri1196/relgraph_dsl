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
    relation_index: HashMap<(usize, String), usize>,
    relation_count: usize,
    conditions: HashMap<String, CompiledCondition>,
}

impl CompiledModel {
    /// Validates and indexes one parsed standalone schema.
    pub(crate) fn compile(schema: Schema) -> Result<Self, ConstructionError> {
        validate_schema(&schema).map_err(ConstructionError::Validation)?;

        let mut capability_errors = unsupported_capabilities(&schema);
        capability_errors.extend(recursive_dependencies(&schema));
        if !capability_errors.is_empty() {
            return Err(ConstructionError::UnsupportedCapabilities(
                capability_errors,
            ));
        }

        let conditions = conditions::compile_all(&schema)?;

        let mut type_index = HashMap::with_capacity(schema.type_definitions.len());
        let mut relation_index = HashMap::new();
        let mut relation_count = 0;

        for (type_id, type_definition) in schema.type_definitions.iter().enumerate() {
            type_index.insert(type_definition.name.clone(), type_id);
            for relation in &type_definition.relations {
                relation_index.insert((type_id, relation.name.clone()), relation_count);
                relation_count += 1;
            }
        }

        Ok(Self {
            schema,
            type_index,
            relation_index,
            relation_count,
            conditions,
        })
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
        self.relation_count
    }

    /// Resolves an object type name to its stable index.
    #[allow(dead_code)]
    pub(crate) fn type_id(&self, object_type: &str) -> Option<usize> {
        self.type_index.get(object_type).copied()
    }

    /// Resolves a relation name within a known type to its stable index.
    #[allow(dead_code)]
    pub(crate) fn relation_id(&self, type_id: usize, relation: &str) -> Option<usize> {
        self.relation_index
            .get(&(type_id, relation.to_owned()))
            .copied()
    }

    /// Resolves a model condition by its declared name.
    pub(crate) fn condition(&self, name: &str) -> Option<&CompiledCondition> {
        self.conditions.get(name)
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
            inspect_expression(left, location, span.clone(), diagnostics);
            inspect_expression(right, location, span, diagnostics);
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
            span,
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
            collect_relation_edges(source, left, owner, ids, graph, span.clone());
            collect_relation_edges(source, right, owner, ids, graph, span);
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

    for edge in &graph[node] {
        match state[edge.target] {
            0 => visit_dependencies(
                edge.target,
                graph,
                nodes,
                state,
                stack,
                emitted,
                diagnostics,
            ),
            1 => {
                let start = stack
                    .iter()
                    .position(|candidate| *candidate == edge.target)
                    .unwrap_or(0);
                let mut cycle = stack[start..].to_vec();
                cycle.sort_unstable();
                cycle.dedup();
                if emitted.insert(cycle) {
                    let path = stack[start..]
                        .iter()
                        .chain(std::iter::once(&edge.target))
                        .map(|id| {
                            let relation = &nodes[*id].location;
                            format!("{}#{}", relation.object_type, relation.relation)
                        })
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    diagnostics.push(CapabilityDiagnostic {
                        capability: RuntimeCapability::RecursiveRelationDependency,
                        relation: Some(nodes[node].location.clone()),
                        span: edge.span.clone().or_else(|| nodes[node].span.clone()),
                        message: format!("recursive relation dependency is unsupported: {path}"),
                    });
                }
            }
            _ => {}
        }
    }

    stack.pop();
    state[node] = 2;
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
        use std::collections::HashMap;
        use std::future::Future;
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        let schema = parse_fga_schema(
            "model\nschema 1.1\ntype user\ntype group\n  relations\n    define member: [user, group#member]\ntype document\n  relations\n    define viewer: [group#member]\n",
        )
        .unwrap();
        let mut type_index = HashMap::new();
        let mut relation_index = HashMap::new();
        let mut relation_count = 0;
        for (type_id, type_definition) in schema.type_definitions.iter().enumerate() {
            type_index.insert(type_definition.name.clone(), type_id);
            for relation in &type_definition.relations {
                relation_index.insert((type_id, relation.name.clone()), relation_count);
                relation_count += 1;
            }
        }
        let compiled = CompiledModel {
            schema,
            type_index,
            relation_index,
            relation_count,
            conditions: HashMap::new(),
        };
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
