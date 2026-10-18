//! Public construction diagnostics and stable model-reference descriptions.

use std::error::Error;
use std::fmt;

use relgraph_dsl::{ParseError, SourceSpan, ValidationError};

use super::store::RelationshipTuple;

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
    /// A relation dependency cycle passes through the subtracted operand of
    /// `but not`, which has no sound least-fixed-point evaluation.
    RecursiveDifference,
    /// Relations on one object depend on each other only through computed
    /// usersets; OpenFGA rejects this cycle shape as well.
    SameObjectRelationCycle,
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
    /// A condition failed CEL parsing, static type checking, or profile validation.
    ConditionCompilation {
        condition: String,
        span: Option<SourceSpan>,
        message: String,
    },
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
            Self::ConditionCompilation {
                condition, message, ..
            } => write!(
                f,
                "condition '{condition}' could not be compiled: {message}"
            ),
        }
    }
}

impl Error for ConstructionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Validation(_)
            | Self::UnsupportedCapabilities(_)
            | Self::ConditionCompilation { .. } => None,
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

/// Maximum number of contextual tuples one check or batch may carry.
///
/// This is OpenFGA's limit at `v1.21.0` (`ContextualTupleKeys.tuple_keys`
/// has `max_items: 100` in `openfga/api`). A larger set fails the whole check
/// or batch with [`AuthorizationError::ContextualTupleLimitExceeded`].
pub const MAX_CONTEXTUAL_TUPLES: usize = 100;

/// Inputs fixed for every relation an evaluator resolves: one tenant, one
/// subject, one set of request contexts, and one set of contextual tuples.
/// Memoized decisions stay valid only while these are unchanged.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CheckScope {
    tenant: TenantId,
    subject: Subject,
    context: std::collections::BTreeMap<String, serde_json::Value>,
    condition_context:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, serde_json::Value>>,
    contextual_tuples: Vec<RelationshipTuple>,
}

impl CheckScope {
    fn new(tenant: TenantId, subject: Subject) -> Self {
        Self {
            tenant,
            subject,
            context: std::collections::BTreeMap::new(),
            condition_context: std::collections::BTreeMap::new(),
            contextual_tuples: Vec::new(),
        }
    }

    pub(crate) fn contextual_tuples(&self) -> &[RelationshipTuple] {
        &self.contextual_tuples
    }

    pub(crate) fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub(crate) fn subject(&self) -> &Subject {
        &self.subject
    }

    pub(crate) fn context(&self) -> &std::collections::BTreeMap<String, serde_json::Value> {
        &self.context
    }

    pub(crate) fn condition_context(
        &self,
        condition: &str,
    ) -> Option<&std::collections::BTreeMap<String, serde_json::Value>> {
        self.condition_context.get(condition)
    }
}

/// Typed inputs to one authorization check.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckRequest {
    scope: CheckScope,
    object: ObjectRef,
    relation: RelationName,
}

/// Identifies which authorization context supplied a condition parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionContextSource {
    /// A value persisted with the relationship tuple.
    StoredTuple,
    /// A value supplied for this individual check.
    Request,
}

impl fmt::Display for ConditionContextSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StoredTuple => "stored tuple",
            Self::Request => "request",
        })
    }
}

impl CheckRequest {
    pub fn new(
        tenant: TenantId,
        subject: Subject,
        object: ObjectRef,
        relation: RelationName,
    ) -> Self {
        Self {
            scope: CheckScope::new(tenant, subject),
            object,
            relation,
        }
    }

    pub fn with_context(
        mut self,
        context: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Self {
        self.scope.context = context;
        self
    }

    /// Adds request context scoped to one named condition.
    ///
    /// Condition-scoped values take precedence over global request context for
    /// that condition. Stored tuple context still takes precedence over both.
    pub fn with_condition_context(
        mut self,
        condition: impl Into<String>,
        context: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Self {
        self.scope
            .condition_context
            .insert(condition.into(), context);
        self
    }

    /// Sets the contextual tuples evaluated with the stored ones for this check,
    /// replacing any set earlier.
    ///
    /// Contextual tuples are **trusted input**: they are relationship facts the
    /// caller asserts for this check only, read as if they were stored in the
    /// request's tenant snapshot. Build them from application state you trust,
    /// never from unauthenticated request data; a caller who controls them
    /// controls the decision.
    ///
    /// Before reading the store, the check rejects a set larger than
    /// [`MAX_CONTEXTUAL_TUPLES`], a tuple of another tenant, a tuple that
    /// fails [`FgaAuthz::validate_tuple`](crate::FgaAuthz::validate_tuple), and
    /// an exact repeat within the set
    /// ([`AuthorizationError::InvalidContextualTuple`]). A contextual tuple
    /// equal to a stored tuple is read once. Its condition context is tuple
    /// context, so it keeps precedence over request context, and contextual
    /// tuples count toward the tuple-scan and work budgets like stored ones.
    pub fn with_contextual_tuples(
        mut self,
        tuples: impl IntoIterator<Item = RelationshipTuple>,
    ) -> Self {
        self.scope.contextual_tuples = tuples.into_iter().collect();
        self
    }

    pub fn tenant(&self) -> &TenantId {
        self.scope.tenant()
    }

    pub fn subject(&self) -> &Subject {
        self.scope.subject()
    }

    /// Returns the contextual tuples in the order they were supplied.
    pub fn contextual_tuples(&self) -> &[RelationshipTuple] {
        self.scope.contextual_tuples()
    }

    pub fn object(&self) -> &ObjectRef {
        &self.object
    }

    pub fn relation(&self) -> &RelationName {
        &self.relation
    }

    pub fn context(&self) -> &std::collections::BTreeMap<String, serde_json::Value> {
        self.scope.context()
    }

    /// Returns request context explicitly bound to one condition.
    pub fn condition_context(
        &self,
        condition: &str,
    ) -> Option<&std::collections::BTreeMap<String, serde_json::Value>> {
        self.scope.condition_context(condition)
    }

    pub(crate) fn scope(&self) -> &CheckScope {
        &self.scope
    }
}

/// Typed inputs to many checks that share one subject, request context, and
/// set of contextual tuples.
///
/// Every item is evaluated against the same tenant snapshot, and decisions
/// memoized while resolving one item are reused by later items. Contexts and
/// contextual tuples apply to every item, exactly as they would to an
/// individual [`CheckRequest`].
#[derive(Clone, Debug, PartialEq)]
pub struct BatchCheckRequest {
    scope: CheckScope,
    items: Vec<(ObjectRef, RelationName)>,
}

impl BatchCheckRequest {
    /// Creates a batch whose results are returned in `items` order.
    pub fn new(
        tenant: TenantId,
        subject: Subject,
        items: impl IntoIterator<Item = (ObjectRef, RelationName)>,
    ) -> Self {
        Self {
            scope: CheckScope::new(tenant, subject),
            items: items.into_iter().collect(),
        }
    }

    /// Sets global request context for every item.
    pub fn with_context(
        mut self,
        context: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Self {
        self.scope.context = context;
        self
    }

    /// Adds request context scoped to one named condition for every item.
    ///
    /// Precedence is the same as [`CheckRequest::with_condition_context`].
    pub fn with_condition_context(
        mut self,
        condition: impl Into<String>,
        context: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Self {
        self.scope
            .condition_context
            .insert(condition.into(), context);
        self
    }

    /// Sets contextual tuples for every item, replacing any set earlier.
    ///
    /// They are trusted input and are validated once for the whole batch, as
    /// described for [`CheckRequest::with_contextual_tuples`]; an invalid set
    /// fails the batch with an outer error.
    pub fn with_contextual_tuples(
        mut self,
        tuples: impl IntoIterator<Item = RelationshipTuple>,
    ) -> Self {
        self.scope.contextual_tuples = tuples.into_iter().collect();
        self
    }

    pub fn tenant(&self) -> &TenantId {
        self.scope.tenant()
    }

    pub fn subject(&self) -> &Subject {
        self.scope.subject()
    }

    /// Returns the contextual tuples in the order they were supplied.
    pub fn contextual_tuples(&self) -> &[RelationshipTuple] {
        self.scope.contextual_tuples()
    }

    /// Returns the checked `(object, relation)` pairs in request order.
    pub fn items(&self) -> &[(ObjectRef, RelationName)] {
        &self.items
    }

    pub fn context(&self) -> &std::collections::BTreeMap<String, serde_json::Value> {
        self.scope.context()
    }

    /// Returns request context explicitly bound to one condition.
    pub fn condition_context(
        &self,
        condition: &str,
    ) -> Option<&std::collections::BTreeMap<String, serde_json::Value>> {
        self.scope.condition_context(condition)
    }

    pub(crate) fn scope(&self) -> &CheckScope {
        &self.scope
    }
}

/// The result of an authorization check. Operational errors are represented by
/// [`AuthorizationError`] and never collapse into a denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    Deny,
}

/// Candidates split by a batch check; see `FgaAuthz::filter_objects`.
#[derive(Debug, Default)]
pub struct FilteredObjects {
    /// Candidates the subject holds the relation on, in candidate order.
    pub allowed: Vec<ObjectRef>,
    /// Candidates whose check failed, in candidate order. An error is neither
    /// an allow nor a deny.
    pub errors: Vec<(ObjectRef, AuthorizationError)>,
}

/// Work limits for one authorization check, and the item bound for a batch.
///
/// In a batch, tuple, store-call, and work budgets apply to each item
/// separately; `max_batch_items` bounds the number of items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvaluationLimits {
    max_tuples_scanned: usize,
    max_relation_depth: usize,
    max_store_calls: usize,
    max_work_units: usize,
    max_condition_cost: usize,
    max_batch_items: usize,
}

impl EvaluationLimits {
    /// Default maximum number of tuples scanned by one check.
    pub const DEFAULT_MAX_TUPLES_SCANNED: usize = 10_000;
    /// Largest tuple scan limit accepted by the runtime.
    pub const MAX_TUPLES_SCANNED: usize = 100_000;
    /// Default number of relation-to-relation traversal steps, matching
    /// OpenFGA's default resolve depth.
    pub const DEFAULT_MAX_RELATION_DEPTH: usize = 25;
    /// Largest relation depth accepted by the runtime.
    pub const MAX_RELATION_DEPTH: usize = 256;
    /// Default maximum number of relationship-store page reads.
    pub const DEFAULT_MAX_STORE_CALLS: usize = 1_024;
    /// Largest store-call limit accepted by the runtime.
    pub const MAX_STORE_CALLS: usize = 10_000;
    /// Default maximum number of expression and tuple work units.
    pub const DEFAULT_MAX_WORK_UNITS: usize = 100_000;
    /// Largest work-unit limit accepted by the runtime.
    pub const MAX_WORK_UNITS: usize = 1_000_000;
    /// Default CEL cost limit for one condition evaluation.
    pub const DEFAULT_MAX_CONDITION_COST: usize = 100;
    /// Largest per-evaluation CEL cost limit accepted by the runtime.
    pub const MAX_CONDITION_COST: usize = 100_000;
    /// Default maximum number of items in one batch check.
    pub const DEFAULT_MAX_BATCH_ITEMS: usize = 100;
    /// Largest batch item limit accepted by the runtime.
    pub const MAX_BATCH_ITEMS: usize = 1_000;

    /// Creates limits with the supplied tuple budget and defaults for other bounds.
    pub fn new(max_tuples_scanned: usize) -> Result<Self, EvaluationLimitsError> {
        if max_tuples_scanned == 0 {
            return Err(EvaluationLimitsError::ZeroTupleLimit);
        }
        if max_tuples_scanned > Self::MAX_TUPLES_SCANNED {
            return Err(EvaluationLimitsError::TupleLimitTooLarge {
                maximum: Self::MAX_TUPLES_SCANNED,
            });
        }
        Ok(Self {
            max_tuples_scanned,
            max_relation_depth: Self::DEFAULT_MAX_RELATION_DEPTH,
            max_store_calls: Self::DEFAULT_MAX_STORE_CALLS,
            max_work_units: Self::DEFAULT_MAX_WORK_UNITS,
            max_condition_cost: Self::DEFAULT_MAX_CONDITION_COST,
            max_batch_items: Self::DEFAULT_MAX_BATCH_ITEMS,
        })
    }

    /// Returns the tuple scan budget.
    pub const fn max_tuples_scanned(self) -> usize {
        self.max_tuples_scanned
    }

    /// Sets the maximum number of relation-to-relation traversal steps.
    pub fn with_max_relation_depth(
        mut self,
        maximum: usize,
    ) -> Result<Self, EvaluationLimitsError> {
        if maximum == 0 {
            return Err(EvaluationLimitsError::ZeroRelationDepth);
        }
        if maximum > Self::MAX_RELATION_DEPTH {
            return Err(EvaluationLimitsError::RelationDepthTooLarge {
                maximum: Self::MAX_RELATION_DEPTH,
            });
        }
        self.max_relation_depth = maximum;
        Ok(self)
    }

    /// Sets the maximum number of paged relationship-store reads.
    pub fn with_max_store_calls(mut self, maximum: usize) -> Result<Self, EvaluationLimitsError> {
        if maximum == 0 {
            return Err(EvaluationLimitsError::ZeroStoreCallLimit);
        }
        if maximum > Self::MAX_STORE_CALLS {
            return Err(EvaluationLimitsError::StoreCallLimitTooLarge {
                maximum: Self::MAX_STORE_CALLS,
            });
        }
        self.max_store_calls = maximum;
        Ok(self)
    }

    /// Sets the maximum number of expression and tuple evaluation steps.
    pub fn with_max_work_units(mut self, maximum: usize) -> Result<Self, EvaluationLimitsError> {
        if maximum == 0 {
            return Err(EvaluationLimitsError::ZeroWorkLimit);
        }
        if maximum > Self::MAX_WORK_UNITS {
            return Err(EvaluationLimitsError::WorkLimitTooLarge {
                maximum: Self::MAX_WORK_UNITS,
            });
        }
        self.max_work_units = maximum;
        Ok(self)
    }

    /// Sets the estimated CEL cost limit for each condition evaluation.
    ///
    /// The estimate covers the expression, its input values, and regex
    /// matching. Every evaluation, including failed attempts, and all stored
    /// and request context conversion also consume the check's work budget
    /// ([`Self::with_max_work_units`]), which bounds condition work per check.
    pub fn with_max_condition_cost(
        mut self,
        maximum: usize,
    ) -> Result<Self, EvaluationLimitsError> {
        if maximum == 0 {
            return Err(EvaluationLimitsError::ZeroConditionCost);
        }
        if maximum > Self::MAX_CONDITION_COST {
            return Err(EvaluationLimitsError::ConditionCostTooLarge {
                maximum: Self::MAX_CONDITION_COST,
            });
        }
        self.max_condition_cost = maximum;
        Ok(self)
    }

    /// Sets the maximum number of items in one batch check.
    pub fn with_max_batch_items(mut self, maximum: usize) -> Result<Self, EvaluationLimitsError> {
        if maximum == 0 {
            return Err(EvaluationLimitsError::ZeroBatchItemLimit);
        }
        if maximum > Self::MAX_BATCH_ITEMS {
            return Err(EvaluationLimitsError::BatchItemLimitTooLarge {
                maximum: Self::MAX_BATCH_ITEMS,
            });
        }
        self.max_batch_items = maximum;
        Ok(self)
    }

    /// Returns the relation traversal depth budget.
    pub const fn max_relation_depth(self) -> usize {
        self.max_relation_depth
    }

    /// Returns the relationship-store page read budget.
    pub const fn max_store_calls(self) -> usize {
        self.max_store_calls
    }

    /// Returns the expression and tuple work budget.
    pub const fn max_work_units(self) -> usize {
        self.max_work_units
    }

    /// Returns the estimated CEL cost limit for one condition evaluation.
    pub const fn max_condition_cost(self) -> usize {
        self.max_condition_cost
    }

    /// Returns the maximum number of items in one batch check.
    pub const fn max_batch_items(self) -> usize {
        self.max_batch_items
    }
}

impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            max_tuples_scanned: Self::DEFAULT_MAX_TUPLES_SCANNED,
            max_relation_depth: Self::DEFAULT_MAX_RELATION_DEPTH,
            max_store_calls: Self::DEFAULT_MAX_STORE_CALLS,
            max_work_units: Self::DEFAULT_MAX_WORK_UNITS,
            max_condition_cost: Self::DEFAULT_MAX_CONDITION_COST,
            max_batch_items: Self::DEFAULT_MAX_BATCH_ITEMS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationLimitsError {
    /// The tuple scan limit must be nonzero.
    ZeroTupleLimit,
    /// The tuple scan limit exceeds the runtime maximum.
    TupleLimitTooLarge { maximum: usize },
    /// The relation depth limit must be nonzero.
    ZeroRelationDepth,
    /// The relation depth limit exceeds the runtime maximum.
    RelationDepthTooLarge { maximum: usize },
    /// The store call limit must be nonzero.
    ZeroStoreCallLimit,
    /// The store call limit exceeds the runtime maximum.
    StoreCallLimitTooLarge { maximum: usize },
    /// The work-unit limit must be nonzero.
    ZeroWorkLimit,
    /// The work-unit limit exceeds the runtime maximum.
    WorkLimitTooLarge { maximum: usize },
    /// The CEL condition cost budget must be nonzero.
    ZeroConditionCost,
    /// The CEL condition cost budget exceeds the runtime maximum.
    ConditionCostTooLarge { maximum: usize },
    /// The batch item limit must be nonzero.
    ZeroBatchItemLimit,
    /// The batch item limit exceeds the runtime maximum.
    BatchItemLimitTooLarge { maximum: usize },
}

impl std::fmt::Display for EvaluationLimitsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroTupleLimit => write!(f, "tuple scan limit must be greater than zero"),
            Self::TupleLimitTooLarge { maximum } => {
                write!(f, "tuple scan limit must not exceed {maximum}")
            }
            Self::ZeroRelationDepth => write!(f, "relation depth limit must be greater than zero"),
            Self::RelationDepthTooLarge { maximum } => {
                write!(f, "relation depth limit must not exceed {maximum}")
            }
            Self::ZeroStoreCallLimit => write!(f, "store call limit must be greater than zero"),
            Self::StoreCallLimitTooLarge { maximum } => {
                write!(f, "store call limit must not exceed {maximum}")
            }
            Self::ZeroWorkLimit => write!(f, "work limit must be greater than zero"),
            Self::WorkLimitTooLarge { maximum } => {
                write!(f, "work limit must not exceed {maximum}")
            }
            Self::ZeroConditionCost => write!(f, "condition cost limit must be greater than zero"),
            Self::ConditionCostTooLarge { maximum } => {
                write!(f, "condition cost limit must not exceed {maximum}")
            }
            Self::ZeroBatchItemLimit => write!(f, "batch item limit must be greater than zero"),
            Self::BatchItemLimitTooLarge { maximum } => {
                write!(f, "batch item limit must not exceed {maximum}")
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
    /// A tuple does not fit the authorization model or the store contract.
    InvalidTuple(&'static str),
    EvaluationLimitExceeded {
        maximum_tuples: usize,
    },
    /// Relation traversal exceeded the configured depth bound.
    RelationDepthExceeded {
        maximum_depth: usize,
    },
    /// Relationship-store pagination exceeded the configured call bound.
    StoreCallLimitExceeded {
        maximum_calls: usize,
    },
    /// Expression or tuple processing exceeded the configured work bound.
    WorkLimitExceeded {
        maximum_work_units: usize,
    },
    Store(super::store::StoreError),
    /// A required parameter was absent from both the tuple and check contexts.
    MissingConditionContext {
        condition: String,
        parameter: String,
    },
    /// A supplied context value did not match the declared condition type.
    InvalidConditionContext {
        condition: String,
        parameter: String,
        expected: String,
        source: ConditionContextSource,
    },
    /// Persisted or request context supplied a parameter not declared in CEL.
    UndeclaredConditionContext {
        condition: String,
        parameter: String,
        source: ConditionContextSource,
    },
    /// CEL evaluation failed or produced a value other than bool.
    ConditionEvaluationFailed {
        condition: String,
        message: String,
    },
    /// One condition evaluation's estimated CEL cost exceeded its configured limit.
    ConditionCostLimitExceeded {
        maximum_cost: usize,
        estimated_cost: usize,
    },
    /// A batch check named more items than its configured bound.
    BatchLimitExceeded {
        maximum_items: usize,
    },
    /// A request carried more than [`MAX_CONTEXTUAL_TUPLES`] contextual tuples.
    ContextualTupleLimitExceeded {
        maximum_tuples: usize,
    },
    /// The contextual tuple at `index` (in request order) was rejected before
    /// the store was read. This is caller input, never stored data.
    InvalidContextualTuple {
        index: usize,
        reason: ContextualTupleError,
    },
}

/// Why a contextual tuple was rejected.
#[derive(Debug)]
pub enum ContextualTupleError {
    /// The tuple names a tenant other than the request's.
    TenantMismatch,
    /// The tuple repeats the contextual tuple at `first_index` exactly.
    Duplicate { first_index: usize },
    /// The tuple does not fit the authorization model; the error is the one
    /// [`FgaAuthz::validate_tuple`](crate::FgaAuthz::validate_tuple) returns.
    Model(Box<AuthorizationError>),
}

impl std::fmt::Display for ContextualTupleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TenantMismatch => f.write_str("tuple tenant does not match the request tenant"),
            Self::Duplicate { first_index } => {
                write!(f, "tuple repeats contextual tuple {first_index}")
            }
            Self::Model(error) => error.fmt(f),
        }
    }
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
                write!(f, "invalid relationship tuple: {reason}")
            }
            Self::EvaluationLimitExceeded { maximum_tuples } => write!(
                f,
                "authorization check exceeded its limit of {maximum_tuples} relationship tuples"
            ),
            Self::RelationDepthExceeded { maximum_depth } => write!(
                f,
                "authorization check exceeded its relation depth limit of {maximum_depth}"
            ),
            Self::StoreCallLimitExceeded { maximum_calls } => write!(
                f,
                "authorization check exceeded its store call limit of {maximum_calls}"
            ),
            Self::WorkLimitExceeded { maximum_work_units } => write!(
                f,
                "authorization check exceeded its work limit of {maximum_work_units} units"
            ),
            Self::Store(error) => write!(f, "relationship store failed: {error}"),
            Self::MissingConditionContext {
                condition,
                parameter,
            } => write!(
                f,
                "condition '{condition}' requires context parameter '{parameter}'"
            ),
            Self::InvalidConditionContext {
                condition,
                parameter,
                expected,
                source,
            } => write!(
                f,
                "{source} context parameter '{parameter}' for condition '{condition}' must be {expected}"
            ),
            Self::UndeclaredConditionContext {
                condition,
                parameter,
                source,
            } => write!(
                f,
                "{source} context parameter '{parameter}' is not declared by condition '{condition}'"
            ),
            Self::ConditionEvaluationFailed { condition, message } => {
                write!(
                    f,
                    "condition '{condition}' failed during CEL evaluation: {message}"
                )
            }
            Self::ConditionCostLimitExceeded {
                maximum_cost,
                estimated_cost,
            } => write!(
                f,
                "condition evaluation cost {estimated_cost} exceeds the limit {maximum_cost}"
            ),
            Self::BatchLimitExceeded { maximum_items } => {
                write!(f, "batch check exceeded its limit of {maximum_items} items")
            }
            Self::ContextualTupleLimitExceeded { maximum_tuples } => write!(
                f,
                "request exceeded its limit of {maximum_tuples} contextual tuples"
            ),
            Self::InvalidContextualTuple { index, reason } => {
                write!(f, "invalid contextual tuple {index}: {reason}")
            }
        }
    }
}

impl std::error::Error for AuthorizationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::InvalidContextualTuple {
                reason: ContextualTupleError::Model(error),
                ..
            } => Some(error.as_ref()),
            _ => None,
        }
    }
}
