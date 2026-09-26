//! Immutable model validation, capability checks, and lookup indexes.

use std::collections::{HashMap, HashSet};

use openfga_dsl::{RelationCondition, RelationExpression, RelationTarget, Schema, validate_schema};

use super::request::{
    CapabilityDiagnostic, ConstructionError, RelationExpressionKind, RelationLocation,
    RuntimeCapability,
};

/// The immutable model shared by all lifecycle handles.
#[derive(Debug)]
pub(crate) struct CompiledModel {
    schema: Schema,
    type_index: HashMap<String, usize>,
    relation_index: HashMap<(usize, String), usize>,
    relation_count: usize,
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
}

/// Collects all model constructs that exceed the initial runtime profile.
fn unsupported_capabilities(schema: &Schema) -> Vec<CapabilityDiagnostic> {
    let mut diagnostics = Vec::new();

    for condition in &schema.condition_definitions {
        diagnostics.push(CapabilityDiagnostic {
            capability: RuntimeCapability::ConditionDefinitions,
            relation: None,
            span: condition.span.clone(),
            message: format!(
                "condition '{}' is declared, but condition programs are not yet compiled",
                condition.name
            ),
        });
    }

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
    span: Option<openfga_dsl::SourceSpan>,
    diagnostics: &mut Vec<CapabilityDiagnostic>,
) {
    match expression {
        RelationExpression::DirectAssignment(targets) => {
            for target in targets {
                inspect_target(target, location, span.clone(), diagnostics);
            }
        }
        RelationExpression::ComputedUserset(_) => push_expression_error(
            RuntimeCapability::RelationExpression(RelationExpressionKind::ComputedUserset),
            location,
            span,
            diagnostics,
        ),
        RelationExpression::TupleToUserset { .. } => push_expression_error(
            RuntimeCapability::RelationExpression(RelationExpressionKind::TupleToUserset),
            location,
            span,
            diagnostics,
        ),
        RelationExpression::Union(left, right) => {
            push_expression_error(
                RuntimeCapability::RelationExpression(RelationExpressionKind::Union),
                location,
                span.clone(),
                diagnostics,
            );
            inspect_expression(left, location, span.clone(), diagnostics);
            inspect_expression(right, location, span, diagnostics);
        }
        RelationExpression::Intersection(left, right) => {
            push_expression_error(
                RuntimeCapability::RelationExpression(RelationExpressionKind::Intersection),
                location,
                span.clone(),
                diagnostics,
            );
            inspect_expression(left, location, span.clone(), diagnostics);
            inspect_expression(right, location, span, diagnostics);
        }
        RelationExpression::Difference(left, right) => {
            push_expression_error(
                RuntimeCapability::RelationExpression(RelationExpressionKind::Difference),
                location,
                span.clone(),
                diagnostics,
            );
            inspect_expression(left, location, span.clone(), diagnostics);
            inspect_expression(right, location, span, diagnostics);
        }
    }
}

/// Checks whether a direct-assignment target requires unsupported semantics.
fn inspect_target(
    target: &RelationTarget,
    location: &RelationLocation,
    span: Option<openfga_dsl::SourceSpan>,
    diagnostics: &mut Vec<CapabilityDiagnostic>,
) {
    match target.relation_or_wildcard.as_deref() {
        Some("*") => diagnostics.push(CapabilityDiagnostic {
            capability: RuntimeCapability::WildcardRestriction,
            relation: Some(location.clone()),
            span: span.clone(),
            message: format!(
                "typed wildcard subject '{}:*' is not supported yet",
                target.target_type
            ),
        }),
        Some(_) => diagnostics.push(CapabilityDiagnostic {
            capability: RuntimeCapability::UsersetRestriction,
            relation: Some(location.clone()),
            span: span.clone(),
            message: format!(
                "userset subject restriction on type '{}' is not supported yet",
                target.target_type
            ),
        }),
        None => {}
    }

    match target.condition {
        Some(RelationCondition::Named(_)) => diagnostics.push(CapabilityDiagnostic {
            capability: RuntimeCapability::ConditionalRelationship,
            relation: Some(location.clone()),
            span: span.clone(),
            message: "conditioned relationship restrictions are not supported yet".into(),
        }),
        Some(RelationCondition::InlineExpression) => diagnostics.push(CapabilityDiagnostic {
            capability: RuntimeCapability::InlineConditionExpression,
            relation: Some(location.clone()),
            span,
            message: "inline condition expressions are not supported yet".into(),
        }),
        None => {}
    }
}

/// Records a relation expression that the current evaluator cannot execute.
fn push_expression_error(
    capability: RuntimeCapability,
    location: &RelationLocation,
    span: Option<openfga_dsl::SourceSpan>,
    diagnostics: &mut Vec<CapabilityDiagnostic>,
) {
    diagnostics.push(CapabilityDiagnostic {
        capability,
        relation: Some(location.clone()),
        span,
        message: "only unconditional direct-assignment relations are supported yet".into(),
    });
}

#[derive(Debug, Clone)]
/// A node in the model's relation-dependency graph.
struct RelationNode {
    location: RelationLocation,
    span: Option<openfga_dsl::SourceSpan>,
}

#[derive(Debug, Clone)]
/// A directed dependency between two declared relations.
struct RelationEdge {
    target: usize,
    span: Option<openfga_dsl::SourceSpan>,
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
    owner: &openfga_dsl::TypeDefinition,
    ids: &HashMap<(String, String), usize>,
    graph: &mut [Vec<RelationEdge>],
    span: Option<openfga_dsl::SourceSpan>,
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
    span: Option<openfga_dsl::SourceSpan>,
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
    use openfga_dsl::parse_fga_schema;

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
}
