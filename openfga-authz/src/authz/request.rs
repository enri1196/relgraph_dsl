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

/// A validated tenant or namespace identifier used to isolate relationship data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        validate_identifier("tenant", value.into(), 128).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A schema type name used by a subject or object reference.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TypeName(String);

impl TypeName {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        validate_identifier("type", value.into(), 128).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An opaque entity identifier. It is kept separate from its type so callers
/// never need to concatenate untrusted values into an OpenFGA `type:id` string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EntityId(String);

impl EntityId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        validate_identifier("entity id", value.into(), 256).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A relation name selected by the application, not by a check request string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelationName(String);

impl RelationName {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        validate_identifier("relation", value.into(), 128).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A condition name carried with a relationship tuple for runtime profiles that
/// support conditional relationships.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConditionName(String);

impl ConditionName {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        validate_identifier("condition", value.into(), 128).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentifierError {
    field: &'static str,
    reason: IdentifierErrorReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum IdentifierErrorReason {
    Empty,
    TooLong { maximum: usize },
    ControlCharacter,
}

impl std::fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            IdentifierErrorReason::Empty => write!(f, "{} must not be empty", self.field),
            IdentifierErrorReason::TooLong { maximum } => {
                write!(f, "{} exceeds the {maximum}-byte limit", self.field)
            }
            IdentifierErrorReason::ControlCharacter => {
                write!(f, "{} must not contain control characters", self.field)
            }
        }
    }
}

impl std::error::Error for IdentifierError {}

fn validate_identifier(
    field: &'static str,
    value: String,
    maximum: usize,
) -> Result<String, IdentifierError> {
    let reason = if value.trim().is_empty() {
        Some(IdentifierErrorReason::Empty)
    } else if value.len() > maximum {
        Some(IdentifierErrorReason::TooLong { maximum })
    } else if value.chars().any(char::is_control) {
        Some(IdentifierErrorReason::ControlCharacter)
    } else {
        None
    };

    match reason {
        Some(reason) => Err(IdentifierError { field, reason }),
        None => Ok(value),
    }
}

/// A concrete subject being checked.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Subject {
    type_name: TypeName,
    id: EntityId,
}

impl Subject {
    pub fn new(
        type_name: impl Into<String>,
        id: impl Into<String>,
    ) -> Result<Self, IdentifierError> {
        Ok(Self {
            type_name: TypeName::new(type_name)?,
            id: EntityId::new(id)?,
        })
    }

    pub fn type_name(&self) -> &TypeName {
        &self.type_name
    }

    pub fn id(&self) -> &EntityId {
        &self.id
    }
}

/// A concrete object whose relation is being checked.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObjectRef {
    type_name: TypeName,
    id: EntityId,
}

impl ObjectRef {
    pub fn new(
        type_name: impl Into<String>,
        id: impl Into<String>,
    ) -> Result<Self, IdentifierError> {
        Ok(Self {
            type_name: TypeName::new(type_name)?,
            id: EntityId::new(id)?,
        })
    }

    pub fn type_name(&self) -> &TypeName {
        &self.type_name
    }

    pub fn id(&self) -> &EntityId {
        &self.id
    }
}

/// Typed inputs to one authorization check.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckRequest {
    tenant: TenantId,
    subject: Subject,
    object: ObjectRef,
    relation: RelationName,
    context: std::collections::BTreeMap<String, serde_json::Value>,
}

impl CheckRequest {
    pub fn new(
        tenant: TenantId,
        subject: Subject,
        object: ObjectRef,
        relation: RelationName,
    ) -> Self {
        Self {
            tenant,
            subject,
            object,
            relation,
            context: std::collections::BTreeMap::new(),
        }
    }

    pub fn with_context(
        mut self,
        context: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Self {
        self.context = context;
        self
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    pub fn object(&self) -> &ObjectRef {
        &self.object
    }

    pub fn relation(&self) -> &RelationName {
        &self.relation
    }

    pub fn context(&self) -> &std::collections::BTreeMap<String, serde_json::Value> {
        &self.context
    }
}

/// The result of an authorization check. Operational errors are represented by
/// [`AuthorizationError`] and never collapse into a denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    Deny,
}

/// Work limits for the currently supported direct-membership check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvaluationLimits {
    max_tuples_scanned: usize,
}

impl EvaluationLimits {
    pub const DEFAULT_MAX_TUPLES_SCANNED: usize = 10_000;
    pub const MAX_TUPLES_SCANNED: usize = 100_000;

    pub fn new(max_tuples_scanned: usize) -> Result<Self, EvaluationLimitsError> {
        if max_tuples_scanned == 0 {
            return Err(EvaluationLimitsError::ZeroTupleLimit);
        }
        if max_tuples_scanned > Self::MAX_TUPLES_SCANNED {
            return Err(EvaluationLimitsError::TupleLimitTooLarge {
                maximum: Self::MAX_TUPLES_SCANNED,
            });
        }
        Ok(Self { max_tuples_scanned })
    }

    pub const fn max_tuples_scanned(self) -> usize {
        self.max_tuples_scanned
    }
}

impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            max_tuples_scanned: Self::DEFAULT_MAX_TUPLES_SCANNED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationLimitsError {
    ZeroTupleLimit,
    TupleLimitTooLarge { maximum: usize },
}

impl std::fmt::Display for EvaluationLimitsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroTupleLimit => write!(f, "tuple scan limit must be greater than zero"),
            Self::TupleLimitTooLarge { maximum } => {
                write!(f, "tuple scan limit must not exceed {maximum}")
            }
        }
    }
}

impl std::error::Error for EvaluationLimitsError {}

/// Errors raised while executing an authorization check.
#[derive(Debug)]
pub enum AuthorizationError {
    UnknownObjectType(String),
    UnknownSubjectType(String),
    UnknownRelation {
        object_type: String,
        relation: String,
    },
    InvalidTuple(&'static str),
    EvaluationLimitExceeded {
        maximum_tuples: usize,
    },
    Store(super::store::StoreError),
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownObjectType(object_type) => {
                write!(
                    f,
                    "object type '{object_type}' is not in the authorization model"
                )
            }
            Self::UnknownSubjectType(subject_type) => {
                write!(
                    f,
                    "subject type '{subject_type}' is not in the authorization model"
                )
            }
            Self::UnknownRelation {
                object_type,
                relation,
            } => write!(
                f,
                "relation '{relation}' is not defined on object type '{object_type}'"
            ),
            Self::InvalidTuple(reason) => {
                write!(f, "relationship store returned an invalid tuple: {reason}")
            }
            Self::EvaluationLimitExceeded { maximum_tuples } => write!(
                f,
                "authorization check exceeded its limit of {maximum_tuples} relationship tuples"
            ),
            Self::Store(error) => write!(f, "relationship store failed: {error}"),
        }
    }
}

impl std::error::Error for AuthorizationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}
