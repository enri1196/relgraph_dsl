//! Public syntax tree types for parsed OpenFGA schemas.

#[derive(Debug, PartialEq, Clone)]
pub struct Schema {
    pub header: SchemaHeader,
    pub type_definitions: Vec<TypeDefinition>,
    pub condition_definitions: Vec<ConditionDefinition>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum SchemaHeader {
    ModelSchema { version: String }, // e.g., "model schema 1.1"
    Module { name: String },         // e.g., "module my_module"
}

#[derive(Debug, PartialEq, Clone)]
pub struct TypeDefinition {
    pub is_extended: bool, // true if 'extend type'
    pub name: String,      // Extended identifier
    pub relations: Vec<Relation>,
    pub comments_before: Vec<String>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Relation {
    pub name: String, // Extended identifier
    pub definition: RelationDefinitionBody,
    pub comments_before: Vec<String>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RelationDefinitionBody {
    pub expression: RelationExpression,
    // 'with' clause is now part of RelationTarget, not here.
}

#[derive(Debug, PartialEq, Clone)]
pub enum RelationExpression {
    DirectAssignment(Vec<RelationTarget>),
    ComputedUserset(String), // e.g., `writer` (extended_identifier)
    TupleToUserset {
        // e.g., `editor from parent`
        computed_userset: String,  // (extended_identifier)
        tupleset_relation: String, // (extended_identifier)
    },
    Union(Box<RelationExpression>, Box<RelationExpression>),
    Intersection(Box<RelationExpression>, Box<RelationExpression>),
    Difference(Box<RelationExpression>, Box<RelationExpression>),
}

#[derive(Debug, PartialEq, Clone)]
pub struct RelationTarget {
    pub target_type: String, // e.g., "user", "group", "document" (extended_identifier)
    pub relation_or_wildcard: Option<String>, // None for 'type', Some("relation") for 'type#relation', Some("*") for 'type:*'
    // relation here is an extended_identifier
    pub condition: Option<String>, // Name of the condition for this specific target
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConditionDefinition {
    pub name: String, // Identifier
    pub parameters: Vec<ConditionParameter>,
    pub expression: String, // CEL expression string
    pub comments_before: Vec<String>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConditionParameter {
    pub name: String, // Identifier
    pub param_type: ParameterType,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ParameterType {
    Simple(String), // e.g., "string", "int", "bool"
    Generic {
        container: String, // "list" or "map"
        inner: String,     // inner type, e.g., "string"
    },
}
