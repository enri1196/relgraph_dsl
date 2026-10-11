//! Schema-derived authorization requirements and fixed route policies.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::request::Parts;
use relgraph_dsl::{ConditionDefinition, ParameterType};

use super::parameter_profile::{RuntimeParameterType, RuntimeScalarType};
use serde_json::Value;

use super::model::{CompiledExpression, CompiledModel, CompiledTargetRestriction};
use super::{EntityId, FgaAuthz, Subject};

/// A type/relation pair in the validated authorization model.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelationKey {
    object_type: String,
    relation: String,
}

impl RelationKey {
    /// Creates a key from schema names.
    pub fn new(object_type: impl Into<String>, relation: impl Into<String>) -> Self {
        Self {
            object_type: object_type.into(),
            relation: relation.into(),
        }
    }

    /// Returns the object type that owns this relation.
    pub fn object_type(&self) -> &str {
        &self.object_type
    }

    /// Returns the relation name.
    pub fn relation(&self) -> &str {
        &self.relation
    }
}

/// A condition parameter's supported runtime value type.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContextValueType {
    /// CEL boolean value.
    Bool,
    /// Signed 64-bit CEL integer.
    Int,
    /// Unsigned 64-bit CEL integer.
    Uint,
    /// CEL double precision number.
    Double,
    /// CEL string value.
    String,
    /// OpenFGA duration string, converted to CEL duration at evaluation.
    Duration,
    /// RFC3339 timestamp string, converted to CEL timestamp at evaluation.
    Timestamp,
    /// One-level list of scalar values.
    List(Box<Self>),
    /// One-level string-keyed map of scalar values.
    Map(Box<Self>),
}

impl ContextValueType {
    pub(super) fn from_parameter_type(value: &ParameterType) -> Option<Self> {
        let to_context_scalar = |scalar| match scalar {
            RuntimeScalarType::Bool => Self::Bool,
            RuntimeScalarType::Int => Self::Int,
            RuntimeScalarType::Uint => Self::Uint,
            RuntimeScalarType::Double => Self::Double,
            RuntimeScalarType::String => Self::String,
            RuntimeScalarType::Duration => Self::Duration,
            RuntimeScalarType::Timestamp => Self::Timestamp,
        };

        match RuntimeParameterType::from_dsl(value)? {
            RuntimeParameterType::Scalar(scalar) => Some(to_context_scalar(scalar)),
            RuntimeParameterType::List(scalar) => {
                Some(Self::List(Box::new(to_context_scalar(scalar))))
            }
            RuntimeParameterType::Map(scalar) => {
                Some(Self::Map(Box::new(to_context_scalar(scalar))))
            }
        }
    }

    fn accepts(&self, value: &Value) -> bool {
        match self {
            Self::Bool => value.is_boolean(),
            Self::Int => value.as_i64().is_some(),
            Self::Uint => value.as_u64().is_some(),
            Self::Double => value.as_number().is_some_and(|number| {
                const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_992;
                if let Some(value) = number.as_i64() {
                    return value >= -(MAX_EXACT_INTEGER as i64)
                        && value <= MAX_EXACT_INTEGER as i64;
                }
                if let Some(value) = number.as_u64() {
                    return value <= MAX_EXACT_INTEGER;
                }
                number.as_f64().is_some_and(f64::is_finite)
            }),
            Self::String | Self::Duration | Self::Timestamp => value.is_string(),
            Self::List(inner) => value
                .as_array()
                .is_some_and(|values| values.iter().all(|value| inner.accepts(value))),
            Self::Map(inner) => value
                .as_object()
                .is_some_and(|values| values.values().all(|value| inner.accepts(value))),
        }
    }
}

impl fmt::Display for ContextValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool => f.write_str("bool"),
            Self::Int => f.write_str("int"),
            Self::Uint => f.write_str("uint"),
            Self::Double => f.write_str("double"),
            Self::String => f.write_str("string"),
            Self::Duration => f.write_str("duration"),
            Self::Timestamp => f.write_str("timestamp"),
            Self::List(inner) => write!(f, "list<{inner}>"),
            Self::Map(inner) => write!(f, "map<{inner}>"),
        }
    }
}

/// A checked JSON condition value paired with its declared OpenFGA type.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextValue {
    value_type: ContextValueType,
    value: Value,
}

impl ContextValue {
    /// Creates a value after checking its JSON shape against the declared type.
    pub fn new(value_type: ContextValueType, value: Value) -> Result<Self, PolicyInputError> {
        if !value_type.accepts(&value) {
            return Err(PolicyInputError::InvalidContextValue {
                expected: value_type,
            });
        }
        Ok(Self { value_type, value })
    }

    /// Returns the declared value type.
    pub fn value_type(&self) -> &ContextValueType {
        &self.value_type
    }

    /// Returns the JSON value passed to condition evaluation.
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// A possible direct subject restriction on a relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentRequirement {
    subject_type: String,
    subject_relation: Option<String>,
    wildcard: bool,
    condition: Option<ConditionRequirement>,
}

impl AssignmentRequirement {
    /// Returns the allowed tuple subject type.
    pub fn subject_type(&self) -> &str {
        &self.subject_type
    }

    /// Returns the required subject userset relation, if this is a userset.
    pub fn subject_relation(&self) -> Option<&str> {
        self.subject_relation.as_deref()
    }

    /// Reports whether this restriction accepts a typed wildcard.
    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// Returns the condition signature attached to this specific alternative.
    pub fn condition(&self) -> Option<&ConditionRequirement> {
        self.condition.as_ref()
    }
}

/// A condition name and the typed parameters declared by its model definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionRequirement {
    name: String,
    parameters: Vec<ConditionParameterRequirement>,
}

impl ConditionRequirement {
    /// Returns the name used by conditional relationship tuples.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the condition's declared parameter signature.
    pub fn parameters(&self) -> &[ConditionParameterRequirement] {
        &self.parameters
    }
}

/// A declared condition parameter and its exact supported provider type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionParameterRequirement {
    name: String,
    value_type: ContextValueType,
}

impl ConditionParameterRequirement {
    /// Returns the parameter's schema name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the supported runtime value type.
    pub fn value_type(&self) -> &ContextValueType {
        &self.value_type
    }
}

/// A relation expression tree that retains its original boolean alternatives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequirementExpression {
    /// Direct tuple restrictions; entries are independent subject alternatives.
    DirectAssignment(Vec<AssignmentRequirement>),
    /// A relation on the same object type whose permissions are inherited.
    ComputedUserset(RelationKey),
    /// A tupleset relation and the computed relation reached on each target type.
    TupleToUserset {
        /// The relation that contains object references to traverse.
        tupleset: RelationKey,
        /// Computed relations selected by the tupleset's allowed target types.
        computed_usersets: Vec<RelationKey>,
    },
    /// Either child expression may authorize.
    Union(Box<Self>, Box<Self>),
    /// Both child expressions must authorize.
    Intersection(Box<Self>, Box<Self>),
    /// The left expression authorizes unless the right expression also authorizes.
    Difference(Box<Self>, Box<Self>),
}

/// The expression and reachable relation dependencies for one schema relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationRequirements {
    key: RelationKey,
    expression: RequirementExpression,
}

impl RelationRequirements {
    /// Returns the object type and relation described by this node.
    pub fn key(&self) -> &RelationKey {
        &self.key
    }

    /// Returns the branch-preserving relation expression.
    pub fn expression(&self) -> &RequirementExpression {
        &self.expression
    }
}

/// Schema-derived requirements reachable from one fixed object type and relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequirements {
    root: RelationKey,
    relations: BTreeMap<RelationKey, RelationRequirements>,
}

impl AuthorizationRequirements {
    /// Returns the requested root relation.
    pub fn root(&self) -> &RelationKey {
        &self.root
    }

    /// Returns all reachable relation nodes, keyed by type and relation.
    pub fn relations(&self) -> &BTreeMap<RelationKey, RelationRequirements> {
        &self.relations
    }

    /// Returns all possible concrete subject types mentioned by reachable assignments.
    pub fn candidate_subject_types(&self) -> BTreeSet<String> {
        self.relations
            .values()
            .flat_map(|relation| assignment_subject_types(&relation.expression))
            .collect()
    }
}

fn assignment_subject_types(expression: &RequirementExpression) -> Vec<String> {
    match expression {
        RequirementExpression::DirectAssignment(targets) => targets
            .iter()
            .map(|target| target.subject_type.clone())
            .collect(),
        RequirementExpression::Union(left, right)
        | RequirementExpression::Intersection(left, right)
        | RequirementExpression::Difference(left, right) => {
            let mut types = assignment_subject_types(left);
            types.extend(assignment_subject_types(right));
            types
        }
        RequirementExpression::ComputedUserset(_)
        | RequirementExpression::TupleToUserset { .. } => Vec::new(),
    }
}

/// Errors found while deriving requirements or validating a route policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// The fixed object type is absent from the compiled model.
    UnknownObjectType(String),
    /// The fixed relation is absent from the selected object type.
    UnknownRelation {
        object_type: String,
        relation: String,
    },
    /// A route has no trusted principal source.
    MissingPrincipalSource,
    /// A route has no trusted tenant or namespace source.
    MissingTenantSource,
    /// A route has no object identifier source.
    MissingObjectIdSource,
    /// A route contains an empty path parameter name.
    EmptyPathParameter,
    /// A route binding refers to a condition absent from the model.
    UndeclaredCondition(String),
    /// A route binding refers to a parameter absent from its named condition.
    UndeclaredParameter {
        condition: String,
        parameter: String,
    },
    /// A provider's declared type differs from the condition parameter type.
    ProviderTypeMismatch {
        condition: String,
        parameter: String,
        expected: ContextValueType,
        actual: ContextValueType,
    },
    /// More than one provider targets the same condition parameter.
    DuplicateBinding {
        condition: String,
        parameter: String,
    },
    /// A condition parameter is outside the supported runtime type profile.
    UnsupportedConditionParameter {
        condition: String,
        parameter: String,
    },
    /// An inline condition form is not supported by the compiled runtime.
    UnsupportedInlineCondition,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownObjectType(object_type) => {
                write!(f, "unknown authorization object type `{object_type}`")
            }
            Self::UnknownRelation {
                object_type,
                relation,
            } => write!(
                f,
                "unknown authorization relation `{object_type}#{relation}`"
            ),
            Self::MissingPrincipalSource => f.write_str("route policy has no principal source"),
            Self::MissingTenantSource => f.write_str("route policy has no tenant source"),
            Self::MissingObjectIdSource => f.write_str("route policy has no object ID source"),
            Self::EmptyPathParameter => f.write_str("object ID path parameter name is empty"),
            Self::UndeclaredCondition(condition) => {
                write!(f, "condition `{condition}` is not declared by the model")
            }
            Self::UndeclaredParameter {
                condition,
                parameter,
            } => write!(
                f,
                "parameter `{parameter}` is not declared by condition `{condition}`"
            ),
            Self::ProviderTypeMismatch {
                condition,
                parameter,
                expected,
                actual,
            } => write!(
                f,
                "provider for `{condition}.{parameter}` declares `{actual}`, expected `{expected}`"
            ),
            Self::DuplicateBinding {
                condition,
                parameter,
            } => write!(f, "duplicate provider for `{condition}.{parameter}`"),
            Self::UnsupportedConditionParameter {
                condition,
                parameter,
            } => write!(
                f,
                "condition `{condition}` parameter `{parameter}` has an unsupported type"
            ),
            Self::UnsupportedInlineCondition => {
                f.write_str("inline relation conditions are not supported by this runtime")
            }
        }
    }
}

impl Error for PolicyError {}

/// Input resolution failures kept distinct from authorization denial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyInputError {
    /// The configured extension is missing from request parts.
    MissingExtension(String),
    /// The named route parameter is missing from request parts.
    MissingPathParameter(String),
    /// A provider returned a value that does not match its declared schema type.
    InvalidContextValue { expected: ContextValueType },
    /// A resolver returned a value tagged with a different type than declared.
    ContextProviderTypeMismatch {
        expected: ContextValueType,
        actual: ContextValueType,
    },
    /// An object ID failed the standard identifier validation.
    InvalidObjectId(String),
    /// An application resolver failed while constructing an input value.
    ResolverFailure(String),
}

impl fmt::Display for PolicyInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingExtension(name) => write!(f, "request extension `{name}` is missing"),
            Self::MissingPathParameter(name) => write!(f, "path parameter `{name}` is missing"),
            Self::InvalidContextValue { expected } => {
                write!(f, "context value is not a valid `{expected}` value")
            }
            Self::ContextProviderTypeMismatch { expected, actual } => write!(
                f,
                "context resolver returned `{actual}`, expected `{expected}`"
            ),
            Self::InvalidObjectId(message) => write!(f, "invalid object ID: {message}"),
            Self::ResolverFailure(message) => f.write_str(message),
        }
    }
}

impl Error for PolicyInputError {}

/// Authenticated request extension types expose a trusted subject identity.
pub trait PrincipalIdentity: Send + Sync + 'static {
    /// Returns the validated subject attached by the authentication layer.
    fn subject(&self) -> &Subject;
}

/// Trusted request extensions expose a tenant or namespace identifier.
pub trait TenantIdentity: Send + Sync + 'static {
    /// Returns the tenant selected by trusted application or authentication state.
    fn tenant_id(&self) -> &super::TenantId;
}

type PrincipalExtractor = dyn Fn(&Parts) -> Result<Subject, PolicyInputError> + Send + Sync;
type TenantExtractor = dyn Fn(&Parts) -> Result<super::TenantId, PolicyInputError> + Send + Sync;

/// A trusted authenticated principal source for one route.
#[derive(Clone)]
pub struct PrincipalSource {
    name: String,
    extractor: Arc<PrincipalExtractor>,
}

impl PrincipalSource {
    /// Reads a principal from the typed extension installed by authentication.
    ///
    /// The principal identity is never derived from a client-controlled path,
    /// query parameter, or header value.
    pub fn extension<T: PrincipalIdentity>() -> Self {
        Self {
            name: std::any::type_name::<T>().into(),
            extractor: Arc::new(|parts| {
                parts
                    .extensions
                    .get::<T>()
                    .map(|principal| principal.subject().clone())
                    .ok_or_else(|| {
                        PolicyInputError::MissingExtension(std::any::type_name::<T>().into())
                    })
            }),
        }
    }

    /// Returns the name used to describe this source in diagnostics.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Extracts this principal from request parts.
    pub fn resolve(&self, parts: &Parts) -> Result<Subject, PolicyInputError> {
        (self.extractor)(parts)
    }
}

/// Resolves a trusted tenant identifier from one typed request extension.
#[derive(Clone)]
pub struct TenantSource {
    name: String,
    extractor: Arc<TenantExtractor>,
}

impl TenantSource {
    /// Reads the tenant selected by a trusted extension installed by application middleware.
    pub fn extension<T: TenantIdentity>() -> Self {
        Self {
            name: std::any::type_name::<T>().into(),
            extractor: Arc::new(|parts| {
                parts
                    .extensions
                    .get::<T>()
                    .map(|identity| identity.tenant_id().clone())
                    .ok_or_else(|| {
                        PolicyInputError::MissingExtension(std::any::type_name::<T>().into())
                    })
            }),
        }
    }

    /// Returns the extension type used to resolve this tenant.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Extracts the trusted tenant from request parts.
    pub fn resolve(&self, parts: &Parts) -> Result<super::TenantId, PolicyInputError> {
        (self.extractor)(parts)
    }
}

/// Request-matched path values made available to synchronous policy extractors.
#[derive(Clone, Debug, Default)]
pub struct PathParameters(BTreeMap<String, String>);

impl PathParameters {
    /// Creates a path-parameter map from the router's matched captures.
    pub fn new(parameters: BTreeMap<String, String>) -> Self {
        Self(parameters)
    }

    /// Returns a captured value by its route parameter name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

/// A synchronous request-parts extractor for a route input value.
pub trait RequestPartsExtractor<T>: Send + Sync + 'static {
    /// Extracts and validates a value without consuming the request body.
    fn extract(&self, parts: &Parts) -> Result<T, PolicyInputError>;
}

impl<T, F> RequestPartsExtractor<T> for F
where
    F: Fn(&Parts) -> Result<T, PolicyInputError> + Send + Sync + 'static,
{
    fn extract(&self, parts: &Parts) -> Result<T, PolicyInputError> {
        self(parts)
    }
}

type ObjectIdExtractor = dyn RequestPartsExtractor<EntityId>;

/// Resolves a fixed route's object ID from request parts.
#[derive(Clone)]
pub struct ObjectIdSource {
    name: String,
    extractor: Arc<ObjectIdExtractor>,
    requires_path_params: bool,
}

impl ObjectIdSource {
    /// Extracts a named matched path capture from [`PathParameters`].
    pub fn path(name: impl Into<String>) -> Self {
        let name = name.into();
        let capture_name = name.clone();
        Self {
            name,
            extractor: Arc::new(move |parts: &Parts| {
                let value = parts
                    .extensions
                    .get::<PathParameters>()
                    .and_then(|parameters| parameters.get(&capture_name))
                    .ok_or_else(|| PolicyInputError::MissingPathParameter(capture_name.clone()))?;
                EntityId::new(value)
                    .map_err(|error| PolicyInputError::InvalidObjectId(error.to_string()))
            }),
            requires_path_params: true,
        }
    }

    /// Builds an object ID source from synchronous request-parts extraction.
    pub fn from_request_parts(
        name: impl Into<String>,
        extractor: impl RequestPartsExtractor<EntityId>,
    ) -> Self {
        Self {
            name: name.into(),
            extractor: Arc::new(extractor),
            requires_path_params: false,
        }
    }

    /// Returns the source description.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reports whether a router must provide matched path parameters.
    pub fn requires_path_params(&self) -> bool {
        self.requires_path_params
    }

    /// Extracts and validates the object ID from request parts.
    pub fn resolve(&self, parts: &Parts) -> Result<EntityId, PolicyInputError> {
        self.extractor.extract(parts)
    }
}

/// A future returned by an asynchronous condition context resolver.
pub type ContextResolverFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ContextValue, PolicyInputError>> + Send + 'a>>;

/// Application-specific asynchronous resolver for condition context.
pub trait AsyncContextResolver: Send + Sync + 'static {
    /// Resolves a typed context value using request parts and captured app data.
    fn resolve<'a>(&'a self, parts: &'a Parts) -> ContextResolverFuture<'a>;
}

enum ContextProviderResolver {
    Parts(Arc<dyn RequestPartsExtractor<ContextValue>>),
    Async(Arc<dyn AsyncContextResolver>),
}

/// A context provider with an explicit schema-level type declaration.
pub struct ContextValueProvider {
    value_type: ContextValueType,
    resolver: ContextProviderResolver,
}

impl ContextValueProvider {
    /// Creates a synchronous request-parts provider.
    pub fn from_request_parts(
        value_type: ContextValueType,
        extractor: impl RequestPartsExtractor<ContextValue>,
    ) -> Self {
        Self {
            value_type,
            resolver: ContextProviderResolver::Parts(Arc::new(extractor)),
        }
    }

    /// Creates an asynchronous resolver that may capture application data.
    pub fn from_async(value_type: ContextValueType, resolver: impl AsyncContextResolver) -> Self {
        Self {
            value_type,
            resolver: ContextProviderResolver::Async(Arc::new(resolver)),
        }
    }

    /// Returns the type declared by this provider.
    pub fn value_type(&self) -> &ContextValueType {
        &self.value_type
    }

    async fn resolve(&self, parts: &Parts) -> Result<ContextValue, PolicyInputError> {
        let value = match &self.resolver {
            ContextProviderResolver::Parts(extractor) => extractor.extract(parts)?,
            ContextProviderResolver::Async(resolver) => resolver.resolve(parts).await?,
        };
        if value.value_type != self.value_type {
            return Err(PolicyInputError::ContextProviderTypeMismatch {
                expected: self.value_type.clone(),
                actual: value.value_type,
            });
        }
        Ok(value)
    }
}

/// A condition- and parameter-scoped route input binding.
pub struct ContextBinding {
    condition: String,
    parameter: String,
    provider: ContextValueProvider,
}

impl ContextBinding {
    /// Binds one provider to one declared condition parameter.
    pub fn new(
        condition: impl Into<String>,
        parameter: impl Into<String>,
        provider: ContextValueProvider,
    ) -> Self {
        Self {
            condition: condition.into(),
            parameter: parameter.into(),
            provider,
        }
    }

    /// Returns the condition name for this binding.
    pub fn condition(&self) -> &str {
        &self.condition
    }

    /// Returns the parameter name for this binding.
    pub fn parameter(&self) -> &str {
        &self.parameter
    }
}

/// A route's fixed object type, fixed relation, and trusted input providers.
pub struct RoutePolicy {
    object_type: String,
    relation: String,
    principal: Option<PrincipalSource>,
    tenant: Option<TenantSource>,
    object_id: Option<ObjectIdSource>,
    context_bindings: Vec<ContextBinding>,
}

impl RoutePolicy {
    /// Creates a policy whose object type and relation are fixed by the route.
    pub fn new(object_type: impl Into<String>, relation: impl Into<String>) -> Self {
        Self {
            object_type: object_type.into(),
            relation: relation.into(),
            principal: None,
            tenant: None,
            object_id: None,
            context_bindings: Vec::new(),
        }
    }

    /// Sets the trusted authenticated principal source.
    pub fn principal(mut self, source: PrincipalSource) -> Self {
        self.principal = Some(source);
        self
    }

    /// Sets the trusted tenant or namespace source for store isolation.
    pub fn tenant(mut self, source: TenantSource) -> Self {
        self.tenant = Some(source);
        self
    }

    /// Sets the object ID source for this fixed object type.
    pub fn object_id(mut self, source: ObjectIdSource) -> Self {
        self.object_id = Some(source);
        self
    }

    /// Adds an explicitly condition-scoped provider binding.
    pub fn bind_context(mut self, binding: ContextBinding) -> Self {
        self.context_bindings.push(binding);
        self
    }

    /// Returns the fixed object type.
    pub fn object_type(&self) -> &str {
        &self.object_type
    }

    /// Returns the fixed relation.
    pub fn relation(&self) -> &str {
        &self.relation
    }
}

/// A policy validated against a compiled model and ready for request resolution.
pub struct ValidatedRoutePolicy {
    policy: RoutePolicy,
    requirements: AuthorizationRequirements,
}

impl ValidatedRoutePolicy {
    /// Returns the schema-derived requirement graph validated for this route.
    pub fn requirements(&self) -> &AuthorizationRequirements {
        &self.requirements
    }

    /// Returns the fixed object type.
    pub fn object_type(&self) -> &str {
        &self.policy.object_type
    }

    /// Returns the fixed relation.
    pub fn relation(&self) -> &str {
        &self.policy.relation
    }

    /// Resolves the authenticated subject from request parts.
    /// Resolves the trusted principal attached to this validated route.
    pub fn resolve_principal(&self, parts: &Parts) -> Result<Subject, PolicyInputError> {
        self.policy
            .principal
            .as_ref()
            .expect("validated route policies have a principal source")
            .resolve(parts)
    }

    /// Resolves the trusted tenant or namespace attached to this validated route.
    pub fn resolve_tenant(&self, parts: &Parts) -> Result<super::TenantId, PolicyInputError> {
        self.policy
            .tenant
            .as_ref()
            .expect("validated route policies have a tenant source")
            .resolve(parts)
    }

    /// Resolves the object identifier from request parts.
    /// Resolves the object identifier attached to this validated route.
    pub fn resolve_object_id(&self, parts: &Parts) -> Result<EntityId, PolicyInputError> {
        self.policy
            .object_id
            .as_ref()
            .expect("validated route policies have an object ID source")
            .resolve(parts)
    }

    /// Reports whether the route needs matched path captures in request extensions.
    /// Reports whether a router must provide matched path captures.
    pub fn requires_path_params(&self) -> bool {
        self.policy
            .object_id
            .as_ref()
            .is_some_and(ObjectIdSource::requires_path_params)
    }

    /// Resolves configured condition values into their condition namespaces.
    pub async fn resolve_context(
        &self,
        parts: &Parts,
    ) -> Result<BTreeMap<String, BTreeMap<String, Value>>, PolicyInputError> {
        let mut resolved = BTreeMap::new();
        for binding in &self.policy.context_bindings {
            let value = binding.provider.resolve(parts).await?;
            resolved
                .entry(binding.condition.clone())
                .or_insert_with(BTreeMap::new)
                .insert(binding.parameter.clone(), value.value);
        }
        Ok(resolved)
    }
}

impl<State> FgaAuthz<State> {
    /// Describes the branch-preserving requirements reachable from one relation.
    pub fn requirements(
        &self,
        object_type: &str,
        relation: &str,
    ) -> Result<AuthorizationRequirements, PolicyError> {
        build_requirements(&self.compiled, object_type, relation)
    }

    /// Validates a fixed route policy and its typed input providers.
    pub fn validate_policy(
        &self,
        policy: RoutePolicy,
    ) -> Result<ValidatedRoutePolicy, PolicyError> {
        if policy.principal.is_none() {
            return Err(PolicyError::MissingPrincipalSource);
        }
        if policy.tenant.is_none() {
            return Err(PolicyError::MissingTenantSource);
        }
        if policy.object_id.is_none() {
            return Err(PolicyError::MissingObjectIdSource);
        }
        if let Some(object_id) = &policy.object_id
            && object_id.requires_path_params()
            && object_id.name().is_empty()
        {
            return Err(PolicyError::EmptyPathParameter);
        }

        let requirements = self.requirements(&policy.object_type, &policy.relation)?;
        let schema = self.compiled.schema();
        let mut seen = BTreeSet::new();
        for binding in &policy.context_bindings {
            let key = (binding.condition.clone(), binding.parameter.clone());
            if !seen.insert(key.clone()) {
                return Err(PolicyError::DuplicateBinding {
                    condition: key.0,
                    parameter: key.1,
                });
            }
            let condition = schema
                .condition_definitions
                .iter()
                .find(|condition| condition.name == binding.condition)
                .ok_or_else(|| PolicyError::UndeclaredCondition(binding.condition.clone()))?;
            let parameter = condition
                .parameters
                .iter()
                .find(|parameter| parameter.name == binding.parameter)
                .ok_or_else(|| PolicyError::UndeclaredParameter {
                    condition: binding.condition.clone(),
                    parameter: binding.parameter.clone(),
                })?;
            let expected = ContextValueType::from_parameter_type(&parameter.param_type)
                .ok_or_else(|| PolicyError::UnsupportedConditionParameter {
                    condition: binding.condition.clone(),
                    parameter: binding.parameter.clone(),
                })?;
            if expected != *binding.provider.value_type() {
                return Err(PolicyError::ProviderTypeMismatch {
                    condition: binding.condition.clone(),
                    parameter: binding.parameter.clone(),
                    expected,
                    actual: binding.provider.value_type().clone(),
                });
            }
        }

        Ok(ValidatedRoutePolicy {
            policy,
            requirements,
        })
    }
}

fn build_requirements(
    compiled: &CompiledModel,
    object_type: &str,
    relation: &str,
) -> Result<AuthorizationRequirements, PolicyError> {
    let root = RelationKey::new(object_type, relation);
    let root_type_id = compiled
        .type_id(object_type)
        .ok_or_else(|| PolicyError::UnknownObjectType(object_type.to_owned()))?;
    let root_relation_id = compiled
        .relation_id(root_type_id, relation)
        .ok_or_else(|| PolicyError::UnknownRelation {
            object_type: object_type.to_owned(),
            relation: relation.to_owned(),
        })?;
    let mut pending = vec![root_relation_id];
    let mut visited = std::collections::HashSet::new();
    let mut relations = BTreeMap::new();
    while let Some(relation_id) = pending.pop() {
        if !visited.insert(relation_id) {
            continue;
        }
        let owner_type_id = compiled.relation_owner_type_id(relation_id);
        let key = RelationKey::new(
            compiled.type_name(owner_type_id),
            compiled.relation_name(relation_id),
        );
        let mut dependencies = Vec::new();
        let expression_id = compiled.relation_expression_id(relation_id);
        let expression = describe_compiled_expression(compiled, expression_id, &mut dependencies)?;
        relations.insert(key.clone(), RelationRequirements { key, expression });
        pending.extend(dependencies);
    }
    Ok(AuthorizationRequirements { root, relations })
}

fn describe_compiled_expression(
    compiled: &CompiledModel,
    expression_id: usize,
    dependencies: &mut Vec<usize>,
) -> Result<RequirementExpression, PolicyError> {
    Ok(match compiled.expression(expression_id) {
        CompiledExpression::DirectAssignment(targets) => {
            let mut assignments = Vec::with_capacity(targets.len);
            for target_id in targets.start..targets.start + targets.len {
                let target = compiled.target(target_id);
                let subject_relation = match target.restriction {
                    CompiledTargetRestriction::Direct | CompiledTargetRestriction::Wildcard => None,
                    CompiledTargetRestriction::Userset(relation_id) => {
                        dependencies.push(relation_id);
                        Some(compiled.relation_name(relation_id).to_owned())
                    }
                };
                let condition = target
                    .condition_id
                    .map(|condition_id| {
                        describe_condition(compiled.condition_definition(condition_id))
                    })
                    .transpose()?;
                assignments.push(AssignmentRequirement {
                    subject_type: compiled.type_name(target.type_id).to_owned(),
                    subject_relation,
                    wildcard: matches!(target.restriction, CompiledTargetRestriction::Wildcard),
                    condition,
                });
            }
            RequirementExpression::DirectAssignment(assignments)
        }
        CompiledExpression::ComputedUserset(relation_id) => {
            dependencies.push(relation_id);
            let dependency = RelationKey::new(
                compiled.type_name(compiled.relation_owner_type_id(relation_id)),
                compiled.relation_name(relation_id),
            );
            RequirementExpression::ComputedUserset(dependency)
        }
        CompiledExpression::TupleToUserset {
            tupleset_relation_id,
            edge_range,
        } => {
            let tupleset = tupleset_relation_id;
            dependencies.push(tupleset);
            let mut computed_usersets = BTreeSet::new();
            for edge_id in edge_range.start..edge_range.start + edge_range.len {
                let edge = compiled.tuple_to_userset_edge(edge_id);
                let target = compiled.target(edge.target_id);
                if matches!(target.restriction, CompiledTargetRestriction::Wildcard) {
                    continue;
                }
                // Target types without the computed relation cannot grant and
                // are skipped by evaluation.
                let Some(computed_relation_id) = edge.computed_relation_id else {
                    continue;
                };
                dependencies.push(computed_relation_id);
                computed_usersets.insert(RelationKey::new(
                    compiled.type_name(compiled.relation_owner_type_id(computed_relation_id)),
                    compiled.relation_name(computed_relation_id),
                ));
            }
            RequirementExpression::TupleToUserset {
                tupleset: RelationKey::new(
                    compiled.type_name(compiled.relation_owner_type_id(tupleset)),
                    compiled.relation_name(tupleset),
                ),
                computed_usersets: computed_usersets.into_iter().collect(),
            }
        }
        CompiledExpression::Union { left, right } => RequirementExpression::Union(
            Box::new(describe_compiled_expression(compiled, left, dependencies)?),
            Box::new(describe_compiled_expression(compiled, right, dependencies)?),
        ),
        CompiledExpression::Intersection { left, right } => RequirementExpression::Intersection(
            Box::new(describe_compiled_expression(compiled, left, dependencies)?),
            Box::new(describe_compiled_expression(compiled, right, dependencies)?),
        ),
        CompiledExpression::Difference { left, right } => RequirementExpression::Difference(
            Box::new(describe_compiled_expression(compiled, left, dependencies)?),
            Box::new(describe_compiled_expression(compiled, right, dependencies)?),
        ),
    })
}

fn describe_condition(
    definition: &ConditionDefinition,
) -> Result<ConditionRequirement, PolicyError> {
    let parameters = definition
        .parameters
        .iter()
        .map(|parameter| {
            let value_type = ContextValueType::from_parameter_type(&parameter.param_type)
                .ok_or_else(|| PolicyError::UnsupportedConditionParameter {
                    condition: definition.name.clone(),
                    parameter: parameter.name.clone(),
                })?;
            Ok(ConditionParameterRequirement {
                name: parameter.name.clone(),
                value_type,
            })
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    Ok(ConditionRequirement {
        name: definition.name.clone(),
        parameters,
    })
}
