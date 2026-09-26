//! Public construction diagnostics and stable model-reference descriptions.

use std::error::Error;
use std::fmt;

use openfga_dsl::{ParseError, SourceSpan, ValidationError};

/// A relation's owning object type and declared relation name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelationLocation {
    /// The OpenFGA object type that owns the relation.
    pub object_type: String,
    /// The relation name on that object type.
    pub relation: String,
}

/// Relation expression forms recognized by the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationExpressionKind {
    /// A relation that delegates to another relation on the same object.
    ComputedUserset,
    /// A relation that traverses an object relation before checking another one.
    TupleToUserset,
    /// An additive set expression.
    Union,
    /// A conjunctive set expression.
    Intersection,
    /// A subtractive set expression.
    Difference,
}

impl fmt::Display for RelationExpressionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ComputedUserset => "computed userset",
            Self::TupleToUserset => "tuple-to-userset",
            Self::Union => "union",
            Self::Intersection => "intersection",
            Self::Difference => "difference",
        };
        f.write_str(name)
    }
}

/// A runtime feature that the initial direct-assignment evaluator cannot execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeCapability {
    /// A relation expression other than direct assignment.
    RelationExpression(RelationExpressionKind),
    /// A type restriction names another relation, such as `group#member`.
    UsersetRestriction,
    /// A type restriction grants a typed wildcard subject, such as `user:*`.
    WildcardRestriction,
    /// A tuple restriction has a named condition attached.
    ConditionalRelationship,
    /// A tuple restriction uses an inline condition expression.
    InlineConditionExpression,
    /// The model declares conditions, which are not compiled in this runtime slice.
    ConditionDefinitions,
    /// The relation dependency graph contains a cycle.
    RecursiveRelationDependency,
}

/// One source-located runtime capability diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDiagnostic {
    /// The unsupported capability or model property.
    pub capability: RuntimeCapability,
    /// The relation associated with the unsupported construct, when applicable.
    pub relation: Option<RelationLocation>,
    /// The source span of the construct, when the parser recorded one.
    pub span: Option<SourceSpan>,
    /// A human-readable explanation; wording is not a stable API.
    pub message: String,
}

impl fmt::Display for CapabilityDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(relation) = &self.relation {
            write!(f, "{}#{}: ", relation.object_type, relation.relation)?;
        }
        f.write_str(&self.message)
    }
}

/// A failure while parsing, validating, or compiling an authorization model.
#[derive(Debug)]
pub enum ConstructionError {
    /// The definition could not be parsed; the parser diagnostic is preserved.
    Parse(ParseError),
    /// The parsed definition failed semantic validation; all diagnostics are preserved.
    Validation(Vec<ValidationError>),
    /// The definition contains runtime constructs outside the initial profile.
    UnsupportedCapabilities(Vec<CapabilityDiagnostic>),
}

impl fmt::Display for ConstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "could not parse authorization model: {error}"),
            Self::Validation(errors) => {
                write!(f, "authorization model failed validation")?;
                for error in errors {
                    write!(f, ": {error}")?;
                }
                Ok(())
            }
            Self::UnsupportedCapabilities(errors) => {
                write!(
                    f,
                    "authorization model uses unsupported runtime capabilities"
                )?;
                for error in errors {
                    write!(f, ": {error}")?;
                }
                Ok(())
            }
        }
    }
}

impl Error for ConstructionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Validation(_) | Self::UnsupportedCapabilities(_) => None,
        }
    }
}
