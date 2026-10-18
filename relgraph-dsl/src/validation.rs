//! Bounded static validation for standalone OpenFGA DSL schemas.
//!
//! This module checks names, declaration uniqueness, local references, repeated
//! restrictions and operands, relation entry points, and condition use. It does
//! not compile CEL, validate runtime tuples, or decide which cycles the
//! authorization runtime can evaluate.

use std::collections::{HashMap, HashSet};

use crate::ast::{
    ConditionDefinition, ParameterType, Relation, RelationCondition, RelationExpression,
    RelationTarget, Schema, SchemaHeader, TypeDefinition,
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
    InvalidComposition,
    /// An extension declaration has no base type to extend in the model.
    UnknownExtensionType,
    /// A module extends the same type more than once.
    DuplicateExtension,
    /// A type is named `self` or `this`.
    ReservedTypeName,
    /// A relation is named `self` or `this`.
    ReservedRelationName,
    /// A type or relation name breaks the OpenFGA naming rule: 1 to 254
    /// (type) or 1 to 50 (relation) characters, none of them `:`, `#`, `@`,
    /// `*` or whitespace.
    InvalidName,
    /// A direct assignment lists the same type restriction more than once.
    DuplicateTypeRestriction,
    /// A relation's top-level union, intersection or difference repeats an
    /// operand (`viewer or viewer`, `x from parent but not x from parent`).
    DuplicateOperand,
    /// No relationship tuple can ever satisfy the relation: every path
    /// through its definition needs the relation itself or another relation
    /// without an entry point. Only checked when no other rule failed.
    NoEntryPoint,
    /// A declared condition is not referenced by any type restriction.
    UnusedCondition,
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
            Self::InvalidComposition => "InvalidComposition",
            Self::UnknownExtensionType => "UnknownExtensionType",
            Self::DuplicateExtension => "DuplicateExtension",
            Self::ReservedTypeName => "ReservedTypeName",
            Self::ReservedRelationName => "ReservedRelationName",
            Self::InvalidName => "InvalidName",
            Self::DuplicateTypeRestriction => "DuplicateTypeRestriction",
            Self::DuplicateOperand => "DuplicateOperand",
            Self::NoEntryPoint => "NoEntryPoint",
            Self::UnusedCondition => "UnusedCondition",
        }
    }
}

/// Validates a parsed standalone schema without parsing or mutating it.
///
/// A module header returns only [`ValidationIssue::ModuleRequiresComposition`].
/// Applies the crate's bounded static checks to a standalone schema.
///
/// Supports exact schema versions `1.1` and `1.2`. Checks reserved and
/// malformed type and relation names, declaration uniqueness, supported
/// parameter types, references, tuple-to-userset structure, repeated type
/// restrictions and top-level operands, and unused conditions, with
/// deterministic diagnostic ordering. When all of those pass, it also checks
/// that every relation has an entry point
/// ([`ValidationIssue::NoEntryPoint`]), as OpenFGA does; the check is skipped
/// otherwise because unresolved references would make it report follow-on
/// errors. A module document returns `ModuleRequiresComposition` and must be
/// checked with [`crate::validate_modular_model`].
///
/// A cycle that has an entry point (`define viewer: [user] or editor` with
/// `define editor: viewer`) passes; the authorization runtime decides
/// separately which cycles it can evaluate.
///
/// This function does not compile, evaluate, or type-check CEL; enforce server
/// resource limits; or guarantee that a server will accept every syntactically
/// valid construct, including `$expression`.
pub fn validate_schema(schema: &Schema) -> Result<(), Vec<ValidationError>> {
    validate_schema_with_context(schema, false, None, &[])
}

/// Provenance aligned with the assembled schema's declarations.
#[derive(Clone, Copy)]
pub(crate) struct ValidationOrigins<'a> {
    pub type_origins: &'a [SourceLocation],
    pub relation_origins: &'a [Vec<SourceLocation>],
    pub condition_origins: &'a [SourceLocation],
}

pub(crate) fn validate_schema_with_origins(
    schema: &Schema,
    origins: ValidationOrigins<'_>,
    manifest_paths: &[std::path::PathBuf],
) -> Result<(), Vec<ValidationError>> {
    validate_schema_with_context(schema, true, Some(origins), manifest_paths)
}

fn validate_schema_with_context(
    schema: &Schema,
    modular: bool,
    origins: Option<ValidationOrigins<'_>>,
    manifest_paths: &[std::path::PathBuf],
) -> Result<(), Vec<ValidationError>> {
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
        let supported = if modular {
            version == "1.2"
        } else {
            version == "1.1" || version == "1.2"
        };
        if !supported {
            validator.push(
                ValidationIssue::UnsupportedSchemaVersion,
                location(schema.header_span.as_ref()),
                Vec::new(),
                format!(
                    "{} schema version '{version}' is unsupported",
                    if modular { "modular" } else { "standalone" }
                ),
            );
        }
    }

    let mut type_symbols: HashMap<String, &TypeDefinition> = HashMap::new();
    let mut type_locations: HashMap<String, SourceLocation> = HashMap::new();
    let mut base_type_count = 0usize;
    let mut relation_declarations: HashMap<(String, String), SourceLocation> = HashMap::new();

    for (type_index, type_definition) in schema.type_definitions.iter().enumerate() {
        let type_location = origin_location(
            origins.and_then(|origins| origins.type_origins.get(type_index)),
            type_definition.span.as_ref(),
        );
        if type_definition.is_extended {
            validator.push(
                ValidationIssue::ExtensionOutsideModule,
                type_location.clone(),
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
                    type_location,
                    vec![
                        type_locations
                            .get(&type_definition.name)
                            .cloned()
                            .unwrap_or_else(|| location(first.span.as_ref())),
                    ],
                    format!("type '{}' is declared more than once", type_definition.name),
                );
            } else {
                type_symbols.insert(type_definition.name.clone(), type_definition);
                type_locations.insert(type_definition.name.clone(), type_location);
            }
        }

        // Relation uniqueness is local structural validation, so it also
        // reports repeated names across base and extension declarations.
        for (relation_index, relation) in type_definition.relations.iter().enumerate() {
            let relation_location = origin_location(
                origins
                    .and_then(|origins| origins.relation_origins.get(type_index))
                    .and_then(|relations| relations.get(relation_index)),
                relation.span.as_ref(),
            );
            let key = (type_definition.name.clone(), relation.name.clone());
            if let Some(first) = relation_declarations.get(&key) {
                validator.errors.push(duplicate_relation_error(
                    &type_definition.name,
                    &relation.name,
                    relation_location,
                    first.clone(),
                ));
            } else {
                relation_declarations.insert(key, relation_location);
            }
        }
    }

    if base_type_count == 0 {
        validator.push(
            ValidationIssue::EmptyModel,
            location(schema.header_span.as_ref()),
            Vec::new(),
            format!(
                "{} model has no base type declarations",
                if modular { "composed" } else { "standalone" }
            ),
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
    let mut condition_locations: HashMap<String, SourceLocation> = HashMap::new();
    for (condition_index, condition) in schema.condition_definitions.iter().enumerate() {
        let condition_location = origin_location(
            origins.and_then(|origins| origins.condition_origins.get(condition_index)),
            condition.span.as_ref(),
        );
        if let Some(first) = condition_symbols.get(&condition.name) {
            validator.push(
                ValidationIssue::DuplicateCondition,
                condition_location,
                vec![
                    condition_locations
                        .get(&condition.name)
                        .cloned()
                        .unwrap_or_else(|| location(first.span.as_ref())),
                ],
                format!("condition '{}' is declared more than once", condition.name),
            );
        } else {
            condition_symbols.insert(condition.name.clone(), condition);
            condition_locations.insert(condition.name.clone(), condition_location.clone());
        }

        let mut parameter_symbols: HashMap<&str, &crate::ast::ConditionParameter> = HashMap::new();
        for parameter in &condition.parameters {
            let parameter_location = origin_location(
                origins.and_then(|origins| origins.condition_origins.get(condition_index)),
                parameter.span.as_ref(),
            );
            if let Some(first) = parameter_symbols.get(parameter.name.as_str()) {
                validator.push(
                    ValidationIssue::DuplicateParameter,
                    parameter_location.clone(),
                    vec![origin_location(
                        origins.and_then(|origins| origins.condition_origins.get(condition_index)),
                        first.span.as_ref(),
                    )],
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
                    parameter_location,
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
    for (type_index, type_definition) in schema.type_definitions.iter().enumerate() {
        for (relation_index, relation) in type_definition.relations.iter().enumerate() {
            let relation_location = origin_location(
                origins
                    .and_then(|origins| origins.relation_origins.get(type_index))
                    .and_then(|relations| relations.get(relation_index)),
                relation.span.as_ref(),
            );
            validator.check_empty_assignments(
                &relation.definition.expression,
                relation,
                &relation_location,
            );
        }
    }

    // Extensions have already been diagnosed and are deliberately omitted
    // from standalone symbols and dependent reference checks.
    for (type_index, type_definition) in schema
        .type_definitions
        .iter()
        .enumerate()
        .filter(|(_, definition)| !definition.is_extended)
    {
        for (relation_index, relation) in type_definition.relations.iter().enumerate() {
            let relation_location = origin_location(
                origins
                    .and_then(|origins| origins.relation_origins.get(type_index))
                    .and_then(|relations| relations.get(relation_index)),
                relation.span.as_ref(),
            );
            validator.check_expression(
                &relation.definition.expression,
                type_definition.name.as_str(),
                relation,
                &relation_location,
                &type_symbols,
                &relation_symbols,
                &condition_symbols,
            );
        }
    }

    validator.check_names(schema, origins);
    validator.check_repetitions(schema, origins);
    // Like OpenFGA, judge entry points only on an otherwise valid model:
    // unresolved references would make every dependent relation look
    // impossible.
    if validator.errors.is_empty() {
        validator.check_entry_points(schema, origins, &relation_symbols);
    }
    validator.check_unused_conditions(schema, &condition_locations);

    let result = validator.finish();
    if !modular {
        return result;
    }

    result.map_err(|mut errors| {
        errors.sort_by(|left, right| {
            manifest_index(&left.location, manifest_paths)
                .cmp(&manifest_index(&right.location, manifest_paths))
                .then_with(|| span_start(&left.location).cmp(&span_start(&right.location)))
                .then_with(|| left.issue.code().cmp(right.issue.code()))
                .then_with(|| left.message.cmp(&right.message))
        });
        errors
    })
}

struct TupleToUsersetNames<'a> {
    computed_userset: &'a str,
    tupleset_relation: &'a str,
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

    fn check_empty_assignments(
        &mut self,
        expression: &RelationExpression,
        relation: &Relation,
        relation_location: &SourceLocation,
    ) {
        let mut pending = vec![expression];
        while let Some(expression) = pending.pop() {
            match expression {
                RelationExpression::DirectAssignment(targets) if targets.is_empty() => self.push(
                    ValidationIssue::EmptyDirectAssignment,
                    relation_location.clone(),
                    Vec::new(),
                    format!(
                        "relation '{}' has an empty direct assignment",
                        relation.name
                    ),
                ),
                RelationExpression::DirectAssignment(_)
                | RelationExpression::ComputedUserset(_)
                | RelationExpression::TupleToUserset { .. } => {}
                RelationExpression::Union(left, right)
                | RelationExpression::Intersection(left, right)
                | RelationExpression::Difference(left, right) => {
                    pending.push(right);
                    pending.push(left);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_expression(
        &mut self,
        expression: &RelationExpression,
        owner_type: &str,
        owner_relation: &Relation,
        owner_location: &SourceLocation,
        type_symbols: &HashMap<String, &TypeDefinition>,
        relation_symbols: &HashMap<&str, HashMap<&str, &Relation>>,
        condition_symbols: &HashMap<String, &ConditionDefinition>,
    ) {
        let mut pending = vec![expression];
        while let Some(expression) = pending.pop() {
            match expression {
                RelationExpression::DirectAssignment(targets) => {
                    for target in targets {
                        if !type_symbols.contains_key(&target.target_type) {
                            self.push(
                                ValidationIssue::UnknownType,
                                owner_location.clone(),
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
                                owner_location.clone(),
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
                                owner_location.clone(),
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
                            owner_location.clone(),
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
                    TupleToUsersetNames {
                        computed_userset,
                        tupleset_relation,
                    },
                    type_symbols,
                    relation_symbols,
                    owner_location,
                ),
                RelationExpression::Union(left, right)
                | RelationExpression::Intersection(left, right)
                | RelationExpression::Difference(left, right) => {
                    pending.push(right);
                    pending.push(left);
                }
            }
        }
    }

    fn check_tuple_to_userset(
        &mut self,
        owner_type: &str,
        owner_relation: &Relation,
        names: TupleToUsersetNames<'_>,
        type_symbols: &HashMap<String, &TypeDefinition>,
        relation_symbols: &HashMap<&str, HashMap<&str, &Relation>>,
        owner_location: &SourceLocation,
    ) {
        let TupleToUsersetNames {
            computed_userset,
            tupleset_relation,
        } = names;
        let Some(tupleset) = relation_symbols
            .get(owner_type)
            .and_then(|relations| relations.get(tupleset_relation))
        else {
            self.push(
                ValidationIssue::UnknownTuplesetRelation,
                owner_location.clone(),
                Vec::new(),
                format!(
                    "relation '{}' refers to missing tupleset relation '{}'",
                    owner_relation.name, tupleset_relation
                ),
            );
            return;
        };

        let RelationExpression::DirectAssignment(targets) = &tupleset.definition.expression else {
            self.invalid_tupleset(tupleset_relation, owner_location);
            return;
        };
        if targets.is_empty()
            || targets
                .iter()
                .any(|target| target.relation_or_wildcard.is_some())
        {
            self.invalid_tupleset(tupleset_relation, owner_location);
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
                owner_location.clone(),
                Vec::new(),
                format!(
                    "no target type of tupleset relation '{}' defines computed relation '{}'",
                    tupleset_relation, computed_userset
                ),
            );
        }
    }

    fn invalid_tupleset(&mut self, tupleset_relation: &str, owner_location: &SourceLocation) {
        self.push(
            ValidationIssue::InvalidTuplesetRelation,
            owner_location.clone(),
            Vec::new(),
            format!(
                "tupleset relation '{}' must be a nonempty direct assignment of plain types",
                tupleset_relation
            ),
        );
    }

    /// Reserved (`self`, `this`) and malformed type and relation names.
    fn check_names(&mut self, schema: &Schema, origins: Option<ValidationOrigins<'_>>) {
        for (type_index, type_definition) in schema.type_definitions.iter().enumerate() {
            let type_location = declared_type_location(origins, type_index, type_definition);
            let name = type_definition.name.as_str();
            if RESERVED_NAMES.contains(&name) {
                self.push(
                    ValidationIssue::ReservedTypeName,
                    type_location.clone(),
                    Vec::new(),
                    format!("type name '{name}' is reserved"),
                );
            }
            if !is_valid_name(name, MAX_TYPE_NAME_CHARS) {
                self.push(
                    ValidationIssue::InvalidName,
                    type_location,
                    Vec::new(),
                    format!(
                        "type name '{name}' must have 1 to {MAX_TYPE_NAME_CHARS} characters \
                         and none of ':', '#', '@', '*' or whitespace"
                    ),
                );
            }

            for (relation_index, relation) in type_definition.relations.iter().enumerate() {
                let relation_location =
                    declared_relation_location(origins, type_index, relation_index, relation);
                let relation_name = relation.name.as_str();
                if RESERVED_NAMES.contains(&relation_name) {
                    self.push(
                        ValidationIssue::ReservedRelationName,
                        relation_location.clone(),
                        Vec::new(),
                        format!("relation name '{relation_name}' of type '{name}' is reserved"),
                    );
                }
                if !is_valid_name(relation_name, MAX_RELATION_NAME_CHARS) {
                    self.push(
                        ValidationIssue::InvalidName,
                        relation_location,
                        Vec::new(),
                        format!(
                            "relation name '{relation_name}' of type '{name}' must have 1 to \
                             {MAX_RELATION_NAME_CHARS} characters and none of ':', '#', '@', \
                             '*' or whitespace"
                        ),
                    );
                }
            }
        }
    }

    /// Repeated type restrictions within one direct assignment, and repeated
    /// operands of a relation's top-level operator.
    fn check_repetitions(&mut self, schema: &Schema, origins: Option<ValidationOrigins<'_>>) {
        for (type_index, type_definition) in schema.type_definitions.iter().enumerate() {
            for (relation_index, relation) in type_definition.relations.iter().enumerate() {
                let relation_location =
                    declared_relation_location(origins, type_index, relation_index, relation);
                let expression = &relation.definition.expression;

                for_each_direct_assignment(expression, |targets| {
                    for (index, target) in targets.iter().enumerate() {
                        if targets[..index].contains(target) {
                            self.push(
                                ValidationIssue::DuplicateTypeRestriction,
                                relation_location.clone(),
                                Vec::new(),
                                format!(
                                    "relation '{}' of type '{}' repeats type restriction '{}'",
                                    relation.name,
                                    type_definition.name,
                                    restriction_text(target)
                                ),
                            );
                        }
                    }
                });

                let operands = top_level_operands(expression);
                let mut seen = HashSet::new();
                for name in operands.iter().filter_map(|operand| operand_name(operand)) {
                    if !seen.insert(name.clone()) {
                        self.push(
                            ValidationIssue::DuplicateOperand,
                            relation_location.clone(),
                            Vec::new(),
                            format!(
                                "relation '{}' of type '{}' repeats operand '{name}'",
                                relation.name, type_definition.name
                            ),
                        );
                    }
                }
            }
        }
    }

    /// Relations that no relationship tuple can ever satisfy.
    ///
    /// A relation has an entry point when its definition can be satisfied
    /// from stored tuples alone: a direct assignment with a plain type or
    /// wildcard restriction, a userset restriction or computed userset naming
    /// a relation with an entry point, or a tuple-to-userset whose computed
    /// relation has one on some tupleset target type. A union needs one
    /// operand with an entry point; an intersection, and (as in OpenFGA) a
    /// difference, need all of them. The set of relations with entry points
    /// is the least fixed point of those rules, so a relation that can only
    /// be reached through itself has none. Callers run this only on a model
    /// whose references resolve.
    fn check_entry_points(
        &mut self,
        schema: &Schema,
        origins: Option<ValidationOrigins<'_>>,
        relation_symbols: &HashMap<&str, HashMap<&str, &Relation>>,
    ) {
        let declared: Vec<(usize, usize, &str, &Relation)> =
            schema
                .type_definitions
                .iter()
                .enumerate()
                .filter(|(_, definition)| !definition.is_extended)
                .flat_map(|(type_index, definition)| {
                    definition.relations.iter().enumerate().map(
                        move |(relation_index, relation)| {
                            (
                                type_index,
                                relation_index,
                                definition.name.as_str(),
                                relation,
                            )
                        },
                    )
                })
                .collect();

        let mut reachable: HashSet<(&str, &str)> = HashSet::new();
        loop {
            let mut changed = false;
            for &(_, _, owner_type, relation) in &declared {
                let key = (owner_type, relation.name.as_str());
                if !reachable.contains(&key)
                    && has_entry_point(
                        &relation.definition.expression,
                        owner_type,
                        relation_symbols,
                        &reachable,
                    )
                {
                    reachable.insert(key);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        for (type_index, relation_index, owner_type, relation) in declared {
            if reachable.contains(&(owner_type, relation.name.as_str())) {
                continue;
            }
            self.push(
                ValidationIssue::NoEntryPoint,
                declared_relation_location(origins, type_index, relation_index, relation),
                Vec::new(),
                format!(
                    "relation '{}' of type '{owner_type}' has no entry point: no relationship \
                     tuple can satisfy it",
                    relation.name
                ),
            );
        }
    }

    /// Conditions that no type restriction names. Each name is reported once,
    /// at its first declaration.
    fn check_unused_conditions(
        &mut self,
        schema: &Schema,
        condition_locations: &HashMap<String, SourceLocation>,
    ) {
        let mut used = HashSet::new();
        for type_definition in &schema.type_definitions {
            for relation in &type_definition.relations {
                for_each_direct_assignment(&relation.definition.expression, |targets| {
                    for target in targets {
                        if let Some(RelationCondition::Named(name)) = &target.condition {
                            used.insert(name.as_str());
                        }
                    }
                });
            }
        }

        let mut reported = HashSet::new();
        for condition in &schema.condition_definitions {
            let name = condition.name.as_str();
            if used.contains(name) || !reported.insert(name) {
                continue;
            }
            self.push(
                ValidationIssue::UnusedCondition,
                condition_locations
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| location(condition.span.as_ref())),
                Vec::new(),
                format!("condition '{name}' is not used by any type restriction"),
            );
        }
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

fn origin_location(origin: Option<&SourceLocation>, span: Option<&SourceSpan>) -> SourceLocation {
    match origin {
        Some(origin) => SourceLocation {
            file: origin.file.clone(),
            module: origin.module.clone(),
            span: span.cloned(),
        },
        None => location(span),
    }
}

/// Names OpenFGA reserves for types and relations.
const RESERVED_NAMES: &[&str] = &["self", "this"];
/// OpenFGA's type name rule is `^[^:#@\*\s]{1,254}$`.
const MAX_TYPE_NAME_CHARS: usize = 254;
/// OpenFGA's relation name rule is `^[^:#@\*\s]{1,50}$`.
const MAX_RELATION_NAME_CHARS: usize = 50;

/// Applies OpenFGA's type/relation naming rule, counting Unicode scalar values.
fn is_valid_name(name: &str, max_chars: usize) -> bool {
    let mut count = 0usize;
    for character in name.chars() {
        if matches!(character, ':' | '#' | '@' | '*') || character.is_whitespace() {
            return false;
        }
        count += 1;
    }
    (1..=max_chars).contains(&count)
}

/// Whether `expression`, owned by `owner_type`, can be satisfied given the
/// relations already known to have entry points. Evaluated with an explicit
/// stack so manually built deep expressions cannot overflow the call stack.
fn has_entry_point(
    expression: &RelationExpression,
    owner_type: &str,
    relation_symbols: &HashMap<&str, HashMap<&str, &Relation>>,
    reachable: &HashSet<(&str, &str)>,
) -> bool {
    enum Step<'a> {
        Visit(&'a RelationExpression),
        Combine(&'a RelationExpression),
    }

    let leaf = |expression: &RelationExpression| -> bool {
        match expression {
            RelationExpression::DirectAssignment(targets) => {
                targets
                    .iter()
                    .any(|target| match target.relation_or_wildcard.as_deref() {
                        None | Some("*") => true,
                        Some(relation) => {
                            reachable.contains(&(target.target_type.as_str(), relation))
                        }
                    })
            }
            RelationExpression::ComputedUserset(relation) => {
                reachable.contains(&(owner_type, relation.as_str()))
            }
            RelationExpression::TupleToUserset {
                computed_userset,
                tupleset_relation,
            } => {
                let Some(RelationExpression::DirectAssignment(targets)) = relation_symbols
                    .get(owner_type)
                    .and_then(|relations| relations.get(tupleset_relation.as_str()))
                    .map(|tupleset| &tupleset.definition.expression)
                else {
                    return false;
                };
                targets.iter().any(|target| {
                    reachable.contains(&(target.target_type.as_str(), computed_userset.as_str()))
                })
            }
            RelationExpression::Union(..)
            | RelationExpression::Intersection(..)
            | RelationExpression::Difference(..) => {
                unreachable!("operators are combined, not evaluated as leaves")
            }
        }
    };

    let mut steps = vec![Step::Visit(expression)];
    let mut values = Vec::new();
    while let Some(step) = steps.pop() {
        match step {
            Step::Visit(
                node @ (RelationExpression::Union(left, right)
                | RelationExpression::Intersection(left, right)
                | RelationExpression::Difference(left, right)),
            ) => {
                steps.push(Step::Combine(node));
                steps.push(Step::Visit(right));
                steps.push(Step::Visit(left));
            }
            Step::Visit(node) => values.push(leaf(node)),
            Step::Combine(node) => {
                let right = values.pop().expect("an operator has a right value");
                let left = values.pop().expect("an operator has a left value");
                values.push(match node {
                    RelationExpression::Union(..) => left || right,
                    _ => left && right,
                });
            }
        }
    }
    values.pop().expect("an expression has one value")
}

/// Calls `visit` with the targets of every direct assignment in `expression`.
fn for_each_direct_assignment<'a>(
    expression: &'a RelationExpression,
    mut visit: impl FnMut(&'a [RelationTarget]),
) {
    let mut pending = vec![expression];
    while let Some(expression) = pending.pop() {
        match expression {
            RelationExpression::DirectAssignment(targets) => visit(targets),
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

/// The operands of a relation's top-level operator, in source order.
///
/// The parser folds `a or b or c` to the left, so a left-nested chain of the
/// same union or intersection operator is one operator with several operands,
/// matching OpenFGA's flat `union` / `intersection` children. A difference has
/// its base and subtracted operand. Any other expression has no operands.
fn top_level_operands(expression: &RelationExpression) -> Vec<&RelationExpression> {
    match expression {
        RelationExpression::Difference(base, subtract) => vec![base, subtract],
        RelationExpression::Union(..) | RelationExpression::Intersection(..) => {
            let same_operator = |candidate: &RelationExpression| {
                std::mem::discriminant(candidate) == std::mem::discriminant(expression)
            };
            let mut operands = Vec::new();
            let mut current = expression;
            loop {
                match current {
                    RelationExpression::Union(left, right)
                    | RelationExpression::Intersection(left, right)
                        if same_operator(current) =>
                    {
                        operands.push(right.as_ref());
                        current = left;
                    }
                    _ => {
                        operands.push(current);
                        break;
                    }
                }
            }
            operands.reverse();
            operands
        }
        _ => Vec::new(),
    }
}

/// OpenFGA's name for a rewrite operand: `relation` or `relation from
/// tupleset`. Direct assignments and nested operators have none.
fn operand_name(operand: &RelationExpression) -> Option<String> {
    match operand {
        RelationExpression::ComputedUserset(name) => Some(name.clone()),
        RelationExpression::TupleToUserset {
            computed_userset,
            tupleset_relation,
        } => Some(format!("{computed_userset} from {tupleset_relation}")),
        _ => None,
    }
}

fn restriction_text(target: &RelationTarget) -> String {
    let mut text = target.target_type.clone();
    match target.relation_or_wildcard.as_deref() {
        Some("*") => text.push_str(":*"),
        Some(relation) => {
            text.push('#');
            text.push_str(relation);
        }
        None => {}
    }
    match &target.condition {
        Some(RelationCondition::Named(name)) => {
            text.push_str(" with ");
            text.push_str(name);
        }
        Some(RelationCondition::InlineExpression) => text.push_str(" with $expression"),
        None => {}
    }
    text
}

fn declared_type_location(
    origins: Option<ValidationOrigins<'_>>,
    type_index: usize,
    type_definition: &TypeDefinition,
) -> SourceLocation {
    origin_location(
        origins.and_then(|origins| origins.type_origins.get(type_index)),
        type_definition.span.as_ref(),
    )
}

fn declared_relation_location(
    origins: Option<ValidationOrigins<'_>>,
    type_index: usize,
    relation_index: usize,
    relation: &Relation,
) -> SourceLocation {
    origin_location(
        origins
            .and_then(|origins| origins.relation_origins.get(type_index))
            .and_then(|relations| relations.get(relation_index)),
        relation.span.as_ref(),
    )
}

fn manifest_index(location: &SourceLocation, manifest_paths: &[std::path::PathBuf]) -> usize {
    location
        .file
        .as_ref()
        .and_then(|file| manifest_paths.iter().position(|path| path == file))
        .unwrap_or(0)
}

/// Builds the shared duplicate-relation diagnostic used by standalone validation and modular composition.
pub(crate) fn duplicate_relation_error(
    type_name: &str,
    relation_name: &str,
    location: SourceLocation,
    first: SourceLocation,
) -> ValidationError {
    ValidationError {
        issue: ValidationIssue::DuplicateRelation,
        location,
        related: vec![first],
        message: format!("type '{type_name}' declares relation '{relation_name}' more than once"),
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
