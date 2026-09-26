//! Bounded static validation for standalone OpenFGA DSL schemas.
//!
//! This module checks declaration uniqueness and local references. It does
//! not compile CEL, validate runtime tuples, or analyze cycles and
//! authorization entrypoints.

use std::collections::HashMap;

use crate::ast::{
    ConditionDefinition, ParameterType, Relation, RelationCondition, RelationExpression, Schema,
    SchemaHeader, TypeDefinition,
};
use crate::diagnostics::{SourceLocation, SourceSpan, ValidationError};

/// The bounded static-validation rule represented by a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationIssue {
    /// The schema version is outside the supported standalone versions.
    UnsupportedSchemaVersion,
    /// A module document must be composed before standalone validation.
    ModuleRequiresComposition,
    /// An extension declaration appeared in a standalone model.
    ExtensionOutsideModule,
    /// The standalone model contains no base type declarations.
    EmptyModel,
    /// A base type name was declared more than once.
    DuplicateType,
    /// A relation name was repeated within a type across its declarations.
    DuplicateRelation,
    /// A condition name was declared more than once.
    DuplicateCondition,
    /// A parameter name was repeated within a condition.
    DuplicateParameter,
    /// A relation restriction refers to a type that is not declared.
    UnknownType,
    /// A relation reference does not resolve on its owning or target type.
    UnknownRelation,
    /// A named relation condition is not declared.
    UnknownCondition,
    /// A tuple-to-userset refers to a missing tupleset relation.
    UnknownTuplesetRelation,
    /// A tupleset relation is not a direct assignment of plain types.
    InvalidTuplesetRelation,
    /// No tupleset target type declares the requested computed relation.
    UnknownComputedRelation,
    /// A manually constructed condition parameter has an unsupported type.
    InvalidParameterType,
    /// A manually constructed direct assignment has no targets.
    EmptyDirectAssignment,
}

impl ValidationIssue {
    /// Returns the stable PascalCase code for this validation rule.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "UnsupportedSchemaVersion",
            Self::ModuleRequiresComposition => "ModuleRequiresComposition",
            Self::ExtensionOutsideModule => "ExtensionOutsideModule",
            Self::EmptyModel => "EmptyModel",
            Self::DuplicateType => "DuplicateType",
            Self::DuplicateRelation => "DuplicateRelation",
            Self::DuplicateCondition => "DuplicateCondition",
            Self::DuplicateParameter => "DuplicateParameter",
            Self::UnknownType => "UnknownType",
            Self::UnknownRelation => "UnknownRelation",
            Self::UnknownCondition => "UnknownCondition",
            Self::UnknownTuplesetRelation => "UnknownTuplesetRelation",
            Self::InvalidTuplesetRelation => "InvalidTuplesetRelation",
            Self::UnknownComputedRelation => "UnknownComputedRelation",
            Self::InvalidParameterType => "InvalidParameterType",
            Self::EmptyDirectAssignment => "EmptyDirectAssignment",
        }
    }
}

/// Validates a parsed standalone schema without parsing or mutating it.
///
/// A module header returns only [`ValidationIssue::ModuleRequiresComposition`].
/// Standalone model versions `1.1` and `1.2` are supported; other parsed
/// versions are preserved and reported here. Errors are sorted by source
/// position, issue code, and message so callers receive deterministic output.
pub fn validate_schema(schema: &Schema) -> Result<(), Vec<ValidationError>> {
    if let SchemaHeader::Module { name } = &schema.header {
        return Err(vec![ValidationError {
            issue: ValidationIssue::ModuleRequiresComposition,
            location: location(schema.header_span.as_ref()),
            related: Vec::new(),
            message: format!("module '{name}' must be composed before validation"),
        }]);
    }

    let mut validator = Validator::default();
    if let SchemaHeader::ModelSchema { version } = &schema.header {
        if version != "1.1" && version != "1.2" {
            validator.push(
                ValidationIssue::UnsupportedSchemaVersion,
                location(schema.header_span.as_ref()),
                Vec::new(),
                format!("standalone schema version '{version}' is unsupported"),
            );
        }
    }

    let mut type_symbols: HashMap<String, &TypeDefinition> = HashMap::new();
    let mut base_type_count = 0usize;
    let mut relation_declarations: HashMap<(String, String), SourceLocation> = HashMap::new();

    for type_definition in &schema.type_definitions {
        if type_definition.is_extended {
            validator.push(
                ValidationIssue::ExtensionOutsideModule,
                location(type_definition.span.as_ref()),
                Vec::new(),
                format!(
                    "type '{}' is extended outside a module document",
                    type_definition.name
                ),
            );
        } else {
            base_type_count += 1;
            if let Some(first) = type_symbols.get(&type_definition.name) {
                validator.push(
                    ValidationIssue::DuplicateType,
                    location(type_definition.span.as_ref()),
                    vec![location(first.span.as_ref())],
                    format!("type '{}' is declared more than once", type_definition.name),
                );
            } else {
                type_symbols.insert(type_definition.name.clone(), type_definition);
            }
        }

        // Relation uniqueness is local structural validation, so it also
        // reports repeated names across base and extension declarations.
        for relation in &type_definition.relations {
            let key = (type_definition.name.clone(), relation.name.clone());
            if let Some(first) = relation_declarations.get(&key) {
                validator.push(
                    ValidationIssue::DuplicateRelation,
                    location(relation.span.as_ref()),
                    vec![first.clone()],
                    format!(
                        "type '{}' declares relation '{}' more than once",
                        type_definition.name, relation.name
                    ),
                );
            } else {
                relation_declarations.insert(key, location(relation.span.as_ref()));
            }
        }
    }

    if base_type_count == 0 {
        validator.push(
            ValidationIssue::EmptyModel,
            location(schema.header_span.as_ref()),
            Vec::new(),
            "standalone model has no base type declarations".to_string(),
        );
    }

    let relation_symbols = type_symbols
        .iter()
        .map(|(type_name, definition)| {
            let mut relations = HashMap::new();
            for relation in &definition.relations {
                relations.entry(relation.name.as_str()).or_insert(relation);
            }
            (type_name.as_str(), relations)
        })
        .collect::<HashMap<_, _>>();

    let mut condition_symbols: HashMap<String, &ConditionDefinition> = HashMap::new();
    for condition in &schema.condition_definitions {
        if let Some(first) = condition_symbols.get(&condition.name) {
            validator.push(
                ValidationIssue::DuplicateCondition,
                location(condition.span.as_ref()),
                vec![location(first.span.as_ref())],
                format!("condition '{}' is declared more than once", condition.name),
            );
        } else {
            condition_symbols.insert(condition.name.clone(), condition);
        }

        let mut parameter_symbols: HashMap<&str, &crate::ast::ConditionParameter> = HashMap::new();
        for parameter in &condition.parameters {
            if let Some(first) = parameter_symbols.get(parameter.name.as_str()) {
                validator.push(
                    ValidationIssue::DuplicateParameter,
                    location(parameter.span.as_ref()),
                    vec![location(first.span.as_ref())],
                    format!(
                        "condition '{}' repeats parameter '{}'",
                        condition.name, parameter.name
                    ),
                );
            } else {
                parameter_symbols.insert(parameter.name.as_str(), parameter);
            }

            if !is_supported_parameter_type(&parameter.param_type) {
                validator.push(
                    ValidationIssue::InvalidParameterType,
                    location(parameter.span.as_ref()),
                    Vec::new(),
                    format!(
                        "condition '{}' parameter '{}' has unsupported type '{}'",
                        condition.name,
                        parameter.name,
                        parameter_type_name(&parameter.param_type)
                    ),
                );
            }
        }
    }

    // Empty direct assignments are an AST invariant check. It applies even to
    // manually constructed trees and does not depend on symbol resolution.
    for type_definition in &schema.type_definitions {
        for relation in &type_definition.relations {
            validator.check_empty_assignments(&relation.definition.expression, relation);
        }
    }

    // Extensions have already been diagnosed and are deliberately omitted
    // from standalone symbols and dependent reference checks.
    for type_definition in schema
        .type_definitions
        .iter()
        .filter(|definition| !definition.is_extended)
    {
        for relation in &type_definition.relations {
            validator.check_expression(
                &relation.definition.expression,
                type_definition.name.as_str(),
                relation,
                &type_symbols,
                &relation_symbols,
                &condition_symbols,
            );
        }
    }

    validator.finish()
}

#[derive(Default)]
struct Validator {
    errors: Vec<ValidationError>,
}

impl Validator {
    fn push(
        &mut self,
        issue: ValidationIssue,
        location: SourceLocation,
        related: Vec<SourceLocation>,
        message: String,
    ) {
        self.errors.push(ValidationError {
            issue,
            location,
            related,
            message,
        });
    }

    fn check_empty_assignments(&mut self, expression: &RelationExpression, relation: &Relation) {
        match expression {
            RelationExpression::DirectAssignment(targets) if targets.is_empty() => self.push(
                ValidationIssue::EmptyDirectAssignment,
                location(relation.span.as_ref()),
                Vec::new(),
                format!(
                    "relation '{}' has an empty direct assignment",
                    relation.name
                ),
            ),
            RelationExpression::DirectAssignment(_) | RelationExpression::ComputedUserset(_) => {}
            RelationExpression::TupleToUserset { .. } => {}
            RelationExpression::Union(left, right)
            | RelationExpression::Intersection(left, right)
            | RelationExpression::Difference(left, right) => {
                self.check_empty_assignments(left, relation);
                self.check_empty_assignments(right, relation);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_expression(
        &mut self,
        expression: &RelationExpression,
        owner_type: &str,
        owner_relation: &Relation,
        type_symbols: &HashMap<String, &TypeDefinition>,
        relation_symbols: &HashMap<&str, HashMap<&str, &Relation>>,
        condition_symbols: &HashMap<String, &ConditionDefinition>,
    ) {
        match expression {
            RelationExpression::DirectAssignment(targets) => {
                for target in targets {
                    if !type_symbols.contains_key(&target.target_type) {
                        self.push(
                            ValidationIssue::UnknownType,
                            location(owner_relation.span.as_ref()),
                            Vec::new(),
                            format!(
                                "relation '{}' refers to unknown type '{}'",
                                owner_relation.name, target.target_type
                            ),
                        );
                    } else if let Some(target_relation) = target
                        .relation_or_wildcard
                        .as_deref()
                        .filter(|name| *name != "*")
                    {
                        let relation_exists = relation_symbols
                            .get(target.target_type.as_str())
                            .is_some_and(|relations| relations.contains_key(target_relation));
                        if !relation_exists {
                            self.push(
                                ValidationIssue::UnknownRelation,
                                location(owner_relation.span.as_ref()),
                                Vec::new(),
                                format!(
                                    "relation '{}' refers to missing relation '{}' on type '{}'",
                                    owner_relation.name, target_relation, target.target_type
                                ),
                            );
                        }
                    }

                    if let Some(RelationCondition::Named(condition)) = &target.condition
                        && !condition_symbols.contains_key(condition)
                    {
                        self.push(
                            ValidationIssue::UnknownCondition,
                            location(owner_relation.span.as_ref()),
                            Vec::new(),
                            format!(
                                "relation '{}' refers to unknown condition '{}'",
                                owner_relation.name, condition
                            ),
                        );
                    }
                }
            }
            RelationExpression::ComputedUserset(name) => {
                let exists = relation_symbols
                    .get(owner_type)
                    .is_some_and(|relations| relations.contains_key(name.as_str()));
                if !exists {
                    self.push(
                        ValidationIssue::UnknownRelation,
                        location(owner_relation.span.as_ref()),
                        Vec::new(),
                        format!("type '{}' has no computed relation '{}'", owner_type, name),
                    );
                }
            }
            RelationExpression::TupleToUserset {
                computed_userset,
                tupleset_relation,
            } => self.check_tuple_to_userset(
                owner_type,
                owner_relation,
                computed_userset,
                tupleset_relation,
                type_symbols,
                relation_symbols,
            ),
            RelationExpression::Union(left, right)
            | RelationExpression::Intersection(left, right)
            | RelationExpression::Difference(left, right) => {
                self.check_expression(
                    left,
                    owner_type,
                    owner_relation,
                    type_symbols,
                    relation_symbols,
                    condition_symbols,
                );
                self.check_expression(
                    right,
                    owner_type,
                    owner_relation,
                    type_symbols,
                    relation_symbols,
                    condition_symbols,
                );
            }
        }
    }

    fn check_tuple_to_userset(
        &mut self,
        owner_type: &str,
        owner_relation: &Relation,
        computed_userset: &str,
        tupleset_relation: &str,
        type_symbols: &HashMap<String, &TypeDefinition>,
        relation_symbols: &HashMap<&str, HashMap<&str, &Relation>>,
    ) {
        let Some(tupleset) = relation_symbols
            .get(owner_type)
            .and_then(|relations| relations.get(tupleset_relation))
        else {
            self.push(
                ValidationIssue::UnknownTuplesetRelation,
                location(owner_relation.span.as_ref()),
                Vec::new(),
                format!(
                    "relation '{}' refers to missing tupleset relation '{}'",
                    owner_relation.name, tupleset_relation
                ),
            );
            return;
        };

        let RelationExpression::DirectAssignment(targets) = &tupleset.definition.expression else {
            self.invalid_tupleset(owner_relation, tupleset_relation);
            return;
        };
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| target.relation_or_wildcard.is_some())
        {
            self.invalid_tupleset(owner_relation, tupleset_relation);
            return;
        }

        let mut unresolved_target = false;
        let mut target_defines_computed_relation = false;
        for target in targets {
            if !type_symbols.contains_key(&target.target_type) {
                unresolved_target = true;
                continue;
            }
            if relation_symbols
                .get(target.target_type.as_str())
                .is_some_and(|relations| relations.contains_key(computed_userset))
            {
                target_defines_computed_relation = true;
            }
        }

        if !unresolved_target && !target_defines_computed_relation {
            self.push(
                ValidationIssue::UnknownComputedRelation,
                location(owner_relation.span.as_ref()),
                Vec::new(),
                format!(
                    "no target type of tupleset relation '{}' defines computed relation '{}'",
                    tupleset_relation, computed_userset
                ),
            );
        }
    }

    fn invalid_tupleset(&mut self, relation: &Relation, tupleset_relation: &str) {
        self.push(
            ValidationIssue::InvalidTuplesetRelation,
            location(relation.span.as_ref()),
            Vec::new(),
            format!(
                "tupleset relation '{}' must be a nonempty direct assignment of plain types",
                tupleset_relation
            ),
        );
    }

    fn finish(mut self) -> Result<(), Vec<ValidationError>> {
        if self.errors.is_empty() {
            return Ok(());
        }
        self.errors.sort_by(|left, right| {
            span_start(&left.location)
                .cmp(&span_start(&right.location))
                .then_with(|| left.issue.code().cmp(right.issue.code()))
                .then_with(|| left.message.cmp(&right.message))
        });
        self.errors.dedup_by(|right, left| {
            right.issue == left.issue
                && right.location == left.location
                && right.message == left.message
        });
        Err(self.errors)
    }
}

fn location(span: Option<&SourceSpan>) -> SourceLocation {
    SourceLocation {
        file: None,
        module: None,
        span: span.cloned(),
    }
}

fn span_start(location: &SourceLocation) -> usize {
    location.span.as_ref().map_or(usize::MAX, |span| span.start)
}

fn is_supported_parameter_type(parameter_type: &ParameterType) -> bool {
    const SIMPLE_TYPES: &[&str] = &[
        "bool",
        "string",
        "int",
        "uint",
        "double",
        "duration",
        "timestamp",
        "ipaddress",
    ];
    match parameter_type {
        ParameterType::Simple(name) => SIMPLE_TYPES.contains(&name.as_str()),
        ParameterType::Generic { container, inner } => {
            matches!(container.as_str(), "list" | "map") && SIMPLE_TYPES.contains(&inner.as_str())
        }
    }
}

fn parameter_type_name(parameter_type: &ParameterType) -> String {
    match parameter_type {
        ParameterType::Simple(name) => name.clone(),
        ParameterType::Generic { container, inner } => format!("{container}<{inner}>"),
    }
}
