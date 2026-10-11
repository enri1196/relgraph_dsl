//! Compiled CEL conditions and schema-directed context conversion.
//!
//! The runtime pins `cel-core` 0.5.1. Its checked environment supplies CEL
//! parsing, type checking, timestamps, durations, lists, and maps. This local
//! profile accepts bool, int, uint, double, string, duration, timestamp,
//! `list<T>`, and `map<T>` declarations where `T` is one of those scalar types.
//! Conditions may use CEL operators, indexing/member access, `has`, `size`,
//! `contains`, `startsWith`, `endsWith`, `matches`, and scalar conversion/time
//! functions (`int`, `uint`, `double`, `string`, `bytes`, `duration`,
//! `timestamp`). Extensions, custom/message types, `ipaddress`, and comprehension
//! macros (`all`, `exists`, `map`, `filter`, and related forms) are rejected at
//! construction. The deterministic cost estimate below is a local upper-bound
//! profile, not a claim to reproduce the OpenFGA server's CEL cost estimator.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::parameter_profile::{RuntimeParameterType, RuntimeScalarType};
use cel_core::types::{Expr, SpannedExpr};
use cel_core::{CelType, Env, MapActivation, Program, Value};
use relgraph_dsl::{ConditionDefinition, ParameterType, Schema};
use serde_json::Value as JsonValue;

use super::request::{AuthorizationError, ConditionContextSource, ConstructionError};

const MAX_CONDITION_SOURCE_BYTES: usize = 65_536;
const MAX_CONDITION_AST_NODES: usize = 10_000;
/// String bytes per CEL cost unit, after cel-go's string traversal factor.
const STRING_BYTES_PER_COST_UNIT: usize = 10;
/// Regex pattern bytes per CEL cost unit, after cel-go's regex length factor.
const REGEX_PATTERN_BYTES_PER_COST_UNIT: usize = 4;

#[derive(Debug)]
pub(crate) struct CompiledCondition {
    name: String,
    parameters: HashMap<String, ParameterType>,
    /// Declared parameters referenced by the expression, in sorted order.
    used_parameters: Vec<String>,
    program: Program,
    static_cost: usize,
    has_regex: bool,
    regex_pattern_bytes: usize,
}

/// Size accounting for one stored tuple context or one request value.
///
/// Byte and element limits apply to each context independently, so a check
/// that visits many conditioned tuples is bounded by the evaluator's tuple and
/// work budgets rather than failing on a sum of individually valid contexts.
/// Sizes are charged before values are cloned or allocated.
#[derive(Default)]
struct ContextBudget {
    bytes: usize,
    elements: usize,
    work: usize,
}

impl ContextBudget {
    fn charge_bytes(&mut self, amount: usize) -> Result<(), String> {
        let total = self.bytes.saturating_add(amount);
        if total > super::store::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES {
            return Err(format!(
                "condition context totaling at most {} bytes",
                super::store::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES
            ));
        }
        self.bytes = total;
        Ok(())
    }

    fn charge_elements(&mut self, amount: usize) -> Result<(), String> {
        let total = self.elements.saturating_add(amount);
        if total > super::store::MAX_CONDITION_CONTEXT_ELEMENTS {
            return Err(format!(
                "condition context with at most {} elements",
                super::store::MAX_CONDITION_CONTEXT_ELEMENTS
            ));
        }
        self.elements = total;
        Ok(())
    }

    fn charge_string(&mut self, length: usize) -> Result<InputCost, String> {
        self.charge_bytes(length)?;
        let units = string_cost(length);
        self.work = self.work.saturating_add(units);
        Ok(InputCost {
            units,
            string_bytes: length,
        })
    }

    fn charge_scalar(&mut self) -> InputCost {
        self.work = self.work.saturating_add(1);
        InputCost {
            units: 1,
            string_bytes: 0,
        }
    }
}

/// Request values converted once per check, keyed by condition name and the
/// index of the parameter in [`CompiledCondition::used_parameters`].
///
/// A request is immutable for the duration of a check, so each value resolves
/// identically for every tuple that uses the condition. Conversion failures are
/// cached as the expected-type description of the resulting error.
#[derive(Default)]
pub(crate) struct RequestValueCache {
    conditions: HashMap<String, Vec<Option<Result<PreparedConditionValue, String>>>>,
}

#[derive(Debug)]
pub(crate) struct PreparedConditionContext {
    values: BTreeMap<String, PreparedConditionValue>,
}

#[derive(Clone, Debug)]
struct PreparedConditionValue {
    value: Value,
    input_cost: InputCost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConditionEvaluation {
    pub allowed: bool,
}

#[derive(Default)]
struct ExpressionProfile {
    nodes: usize,
    literal_bytes: usize,
    identifiers: BTreeSet<String>,
    has_regex: bool,
    regex_pattern_bytes: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct InputCost {
    units: usize,
    string_bytes: usize,
}

pub(crate) fn compile_all(
    schema: &Schema,
) -> Result<HashMap<String, CompiledCondition>, ConstructionError> {
    let mut conditions = HashMap::with_capacity(schema.condition_definitions.len());
    for definition in &schema.condition_definitions {
        let condition =
            compile_one(definition).map_err(|message| ConstructionError::ConditionCompilation {
                condition: definition.name.clone(),
                span: definition.span.clone(),
                message,
            })?;
        conditions.insert(definition.name.clone(), condition);
    }
    Ok(conditions)
}

fn compile_one(definition: &ConditionDefinition) -> Result<CompiledCondition, String> {
    if definition.expression.len() > MAX_CONDITION_SOURCE_BYTES {
        return Err(format!(
            "condition expression exceeds the {MAX_CONDITION_SOURCE_BYTES}-byte source limit"
        ));
    }

    let mut parameter_types = HashMap::with_capacity(definition.parameters.len());
    let mut environment = Env::with_standard_library();
    for parameter in &definition.parameters {
        let cel_type = cel_type(&parameter.param_type).ok_or_else(|| {
            format!(
                "parameter '{}' has a type outside the supported CEL profile",
                parameter.name
            )
        })?;
        parameter_types.insert(parameter.name.clone(), parameter.param_type.clone());
        environment = environment.with_variable(parameter.name.clone(), cel_type);
    }

    let ast = environment
        .compile(&definition.expression)
        .map_err(|error| format!("CEL compilation failed: {error}"))?;
    if ast.result_type() != Some(&CelType::Bool) {
        return Err("condition expression must have CEL type bool".into());
    }

    let mut profile = ExpressionProfile::default();
    inspect_expression(ast.expr(), &mut profile)?;
    if profile.nodes > MAX_CONDITION_AST_NODES {
        return Err(format!(
            "condition AST exceeds the {MAX_CONDITION_AST_NODES}-node construction limit"
        ));
    }
    let used_parameters = profile
        .identifiers
        .into_iter()
        .filter(|name| parameter_types.contains_key(name))
        .collect();
    let program = environment
        .program(&ast)
        .map_err(|error| format!("CEL program creation failed: {error}"))?;

    Ok(CompiledCondition {
        name: definition.name.clone(),
        parameters: parameter_types,
        used_parameters,
        program,
        static_cost: profile
            .nodes
            .saturating_add(profile.literal_bytes.div_ceil(STRING_BYTES_PER_COST_UNIT)),
        has_regex: profile.has_regex,
        regex_pattern_bytes: profile.regex_pattern_bytes,
    })
}

fn inspect_expression(
    expression: &SpannedExpr,
    profile: &mut ExpressionProfile,
) -> Result<(), String> {
    profile.nodes = profile.nodes.saturating_add(1);
    if profile.nodes > MAX_CONDITION_AST_NODES {
        return Err(format!(
            "condition AST exceeds the {MAX_CONDITION_AST_NODES}-node construction limit"
        ));
    }

    match &expression.node {
        Expr::Null | Expr::Bool(_) | Expr::Int(_) | Expr::UInt(_) | Expr::Float(_) => {}
        Expr::String(value) => {
            profile.literal_bytes = profile.literal_bytes.saturating_add(value.len());
        }
        Expr::Bytes(value) => {
            profile.literal_bytes = profile.literal_bytes.saturating_add(value.len());
        }
        Expr::Ident(name) => {
            profile.identifiers.insert(name.clone());
        }
        Expr::RootIdent(_) => {
            return Err("root-qualified identifiers are outside the supported CEL profile".into());
        }
        Expr::List(values) => {
            for value in values {
                if value.optional {
                    return Err(
                        "optional list elements are outside the supported CEL profile".into(),
                    );
                }
                inspect_expression(&value.expr, profile)?;
            }
        }
        Expr::Map(entries) => {
            for entry in entries {
                if entry.optional {
                    return Err("optional map entries are outside the supported CEL profile".into());
                }
                if !matches!(entry.key.node, Expr::String(_)) {
                    return Err("map literals must use string keys in this CEL profile".into());
                }
                inspect_expression(&entry.key, profile)?;
                inspect_expression(&entry.value, profile)?;
            }
        }
        Expr::Unary { expr, .. } => inspect_expression(expr, profile)?,
        Expr::Binary { left, right, .. } => {
            inspect_expression(left, profile)?;
            inspect_expression(right, profile)?;
        }
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            inspect_expression(cond, profile)?;
            inspect_expression(then_expr, profile)?;
            inspect_expression(else_expr, profile)?;
        }
        Expr::Member { expr, optional, .. } => {
            if *optional {
                return Err("optional field selection is outside the supported CEL profile".into());
            }
            inspect_expression(expr, profile)?;
        }
        Expr::Index {
            expr,
            index,
            optional,
        } => {
            if *optional {
                return Err("optional indexing is outside the supported CEL profile".into());
            }
            inspect_expression(expr, profile)?;
            inspect_expression(index, profile)?;
        }
        Expr::Call { expr, args } => {
            let function = call_name(expr).ok_or_else(|| {
                "indirect or dynamically selected CEL calls are unsupported".to_owned()
            })?;
            if !supported_function(function) {
                return Err(format!(
                    "CEL function '{function}' is outside the supported function profile"
                ));
            }
            if function == "matches" {
                profile.has_regex = true;
                profile.regex_pattern_bytes = profile
                    .regex_pattern_bytes
                    .saturating_add(args.iter().map(expression_literal_bytes).sum::<usize>());
            }
            inspect_expression(expr, profile)?;
            for argument in args {
                inspect_expression(argument, profile)?;
            }
        }
        Expr::MemberTestOnly { expr, .. } => inspect_expression(expr, profile)?,
        Expr::Struct { .. } => {
            return Err("CEL message and struct values are unsupported".into());
        }
        Expr::Comprehension(_) => {
            return Err("CEL comprehension macros are outside the supported profile".into());
        }
        Expr::Bind { .. } => {
            return Err("CEL bind expressions are outside the supported profile".into());
        }
        Expr::Error => return Err("CEL parser produced an error expression".into()),
    }
    Ok(())
}

fn expression_literal_bytes(expression: &SpannedExpr) -> usize {
    match &expression.node {
        Expr::String(value) => value.len(),
        Expr::Bytes(value) => value.len(),
        Expr::List(values) => values
            .iter()
            .map(|value| expression_literal_bytes(&value.expr))
            .sum(),
        Expr::Map(entries) => entries
            .iter()
            .map(|entry| {
                expression_literal_bytes(&entry.key)
                    .saturating_add(expression_literal_bytes(&entry.value))
            })
            .sum(),
        Expr::Unary { expr, .. }
        | Expr::Member { expr, .. }
        | Expr::MemberTestOnly { expr, .. } => expression_literal_bytes(expr),
        Expr::Binary { left, right, .. } => {
            expression_literal_bytes(left).saturating_add(expression_literal_bytes(right))
        }
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => expression_literal_bytes(cond)
            .saturating_add(expression_literal_bytes(then_expr))
            .saturating_add(expression_literal_bytes(else_expr)),
        Expr::Index { expr, index, .. } => {
            expression_literal_bytes(expr).saturating_add(expression_literal_bytes(index))
        }
        Expr::Call { expr, args } => args
            .iter()
            .fold(expression_literal_bytes(expr), |total, arg| {
                total.saturating_add(expression_literal_bytes(arg))
            }),
        Expr::Struct { .. }
        | Expr::Comprehension(_)
        | Expr::Bind { .. }
        | Expr::Error
        | Expr::Null
        | Expr::Bool(_)
        | Expr::Int(_)
        | Expr::UInt(_)
        | Expr::Float(_)
        | Expr::Ident(_)
        | Expr::RootIdent(_) => 0,
    }
}

fn call_name(expression: &SpannedExpr) -> Option<&str> {
    match &expression.node {
        Expr::Ident(name) => Some(name),
        Expr::Member { field, .. } => Some(field),
        _ => None,
    }
}

fn supported_function(name: &str) -> bool {
    matches!(
        name,
        "has"
            | "size"
            | "contains"
            | "startsWith"
            | "endsWith"
            | "matches"
            | "int"
            | "uint"
            | "double"
            | "string"
            | "bytes"
            | "duration"
            | "timestamp"
    )
}

pub(super) fn cel_type(parameter_type: &ParameterType) -> Option<CelType> {
    let runtime_type = RuntimeParameterType::from_dsl(parameter_type)?;
    let to_cel_scalar = |scalar| match scalar {
        RuntimeScalarType::Bool => CelType::Bool,
        RuntimeScalarType::Int => CelType::Int,
        RuntimeScalarType::Uint => CelType::UInt,
        RuntimeScalarType::Double => CelType::Double,
        RuntimeScalarType::String => CelType::String,
        RuntimeScalarType::Duration => CelType::Duration,
        RuntimeScalarType::Timestamp => CelType::Timestamp,
    };

    Some(match runtime_type {
        RuntimeParameterType::Scalar(scalar) => to_cel_scalar(scalar),
        RuntimeParameterType::List(scalar) => CelType::list(to_cel_scalar(scalar)),
        RuntimeParameterType::Map(scalar) => CelType::map(CelType::String, to_cel_scalar(scalar)),
    })
}

impl CompiledCondition {
    /// Validates all supplied tuple metadata while allowing the request to fill
    /// parameters that the persisted context omitted.
    ///
    /// Conversion work is added to `work` whether or not validation succeeds.
    pub(crate) fn validate_stored_context(
        &self,
        values: &BTreeMap<String, JsonValue>,
        work: &mut usize,
    ) -> Result<PreparedConditionContext, AuthorizationError> {
        let mut budget = ContextBudget::default();
        let prepared = self.prepare_stored_context(values, &mut budget);
        *work = work.saturating_add(budget.work);
        prepared
    }

    fn prepare_stored_context(
        &self,
        values: &BTreeMap<String, JsonValue>,
        budget: &mut ContextBudget,
    ) -> Result<PreparedConditionContext, AuthorizationError> {
        let source = ConditionContextSource::StoredTuple;
        budget
            .charge_elements(values.len())
            .map_err(|expected| invalid_context(&self.name, "<context>", source, expected))?;
        let mut prepared = BTreeMap::new();
        for (name, value) in values {
            budget
                .charge_bytes(name.len())
                .map_err(|expected| invalid_context(&self.name, name, source, expected))?;
            budget.work = budget.work.saturating_add(1);
            let Some(parameter_type) = self.parameters.get(name) else {
                return Err(AuthorizationError::UndeclaredConditionContext {
                    condition: self.name.clone(),
                    parameter: name.clone(),
                    source,
                });
            };
            let (converted, input_cost) = convert_value(value, parameter_type, budget)
                .map_err(|expected| invalid_context(&self.name, name, source, expected))?;
            prepared.insert(
                name.clone(),
                PreparedConditionValue {
                    value: converted,
                    input_cost,
                },
            );
        }
        Ok(PreparedConditionContext { values: prepared })
    }

    /// Evaluates the condition with stored values taking precedence over
    /// condition-scoped and then global request values.
    ///
    /// `maximum_cost` bounds this one evaluation. Its estimated cost and any
    /// request conversion work are added to `work` even when evaluation fails,
    /// so the evaluator's work budget bounds the check as a whole.
    pub(crate) fn evaluate(
        &self,
        mut tuple_values: Option<PreparedConditionContext>,
        condition_request_values: Option<&BTreeMap<String, JsonValue>>,
        request_values: &BTreeMap<String, JsonValue>,
        request_cache: &mut RequestValueCache,
        maximum_cost: usize,
        work: &mut usize,
    ) -> Result<ConditionEvaluation, AuthorizationError> {
        // A failed CEL attempt still consumes its static evaluation work.
        *work = work.saturating_add(self.static_cost);
        check_cost(self.static_cost, maximum_cost)?;
        let mut activation = MapActivation::new();
        let mut input_cost = InputCost::default();
        for (index, name) in self.used_parameters.iter().enumerate() {
            let prepared = if let Some(value) = tuple_values
                .as_mut()
                .and_then(|context| context.values.remove(name))
            {
                value
            } else {
                let Some(value) = condition_request_values
                    .and_then(|values| values.get(name))
                    .or_else(|| request_values.get(name))
                else {
                    return Err(AuthorizationError::MissingConditionContext {
                        condition: self.name.clone(),
                        parameter: name.clone(),
                    });
                };
                self.cached_request_value(index, value, request_cache, work)?
            };
            input_cost.units = input_cost.units.saturating_add(prepared.input_cost.units);
            input_cost.string_bytes = input_cost
                .string_bytes
                .saturating_add(prepared.input_cost.string_bytes);
            activation.insert(name.clone(), prepared.value);
        }

        let mut cost = self.static_cost.saturating_add(input_cost.units);
        if self.has_regex {
            cost = cost.saturating_add(
                string_cost(input_cost.string_bytes).saturating_mul(
                    self.regex_pattern_bytes
                        .div_ceil(REGEX_PATTERN_BYTES_PER_COST_UNIT)
                        .max(1),
                ),
            );
        }
        *work = work.saturating_add(cost - self.static_cost);
        check_cost(cost, maximum_cost)?;

        let result = self.program.eval(&activation);
        let allowed = match result {
            Value::Bool(value) => value,
            Value::Error(error) => {
                return Err(AuthorizationError::ConditionEvaluationFailed {
                    condition: self.name.clone(),
                    message: error.to_string(),
                });
            }
            _ => {
                return Err(AuthorizationError::ConditionEvaluationFailed {
                    condition: self.name.clone(),
                    message: "CEL evaluator returned a non-boolean value".into(),
                });
            }
        };
        Ok(ConditionEvaluation { allowed })
    }

    /// Converts one request value on first use in a check and reuses it after.
    fn cached_request_value(
        &self,
        index: usize,
        value: &JsonValue,
        cache: &mut RequestValueCache,
        work: &mut usize,
    ) -> Result<PreparedConditionValue, AuthorizationError> {
        if !cache.conditions.contains_key(self.name.as_str()) {
            cache
                .conditions
                .insert(self.name.clone(), vec![None; self.used_parameters.len()]);
        }
        let slot = &mut cache
            .conditions
            .get_mut(self.name.as_str())
            .expect("condition cache entry was inserted above")[index];
        let name = &self.used_parameters[index];
        let cached = slot.get_or_insert_with(|| {
            let parameter_type = self
                .parameters
                .get(name)
                .expect("used CEL variable is declared in the condition schema");
            let mut budget = ContextBudget::default();
            let converted = convert_value(value, parameter_type, &mut budget);
            *work = work.saturating_add(budget.work);
            converted.map(|(value, input_cost)| PreparedConditionValue { value, input_cost })
        });
        cached.clone().map_err(|expected| {
            invalid_context(&self.name, name, ConditionContextSource::Request, expected)
        })
    }
}

/// Rejects an evaluation whose estimated cost exceeds the per-evaluation limit.
fn check_cost(estimated_cost: usize, maximum_cost: usize) -> Result<(), AuthorizationError> {
    if estimated_cost > maximum_cost {
        return Err(AuthorizationError::ConditionCostLimitExceeded {
            maximum_cost,
            estimated_cost,
        });
    }
    Ok(())
}

/// CEL cost of traversing a string of `length` bytes; never less than one.
fn string_cost(length: usize) -> usize {
    length.div_ceil(STRING_BYTES_PER_COST_UNIT).max(1)
}

/// Converts one JSON value to its declared CEL type.
///
/// Errors describe the expected value for an `InvalidConditionContext` error.
fn convert_value(
    value: &JsonValue,
    parameter_type: &ParameterType,
    budget: &mut ContextBudget,
) -> Result<(Value, InputCost), String> {
    match parameter_type {
        ParameterType::Simple(name) => {
            let expected = || format!("a {name} value");
            let input_cost = match value.as_str() {
                Some(text) => budget.charge_string(text.len())?,
                None => budget.charge_scalar(),
            };
            let converted = match name.as_str() {
                "bool" => match value {
                    JsonValue::Bool(value) => Some(Value::Bool(*value)),
                    JsonValue::String(value) if value == "true" => Some(Value::Bool(true)),
                    JsonValue::String(value) if value == "false" => Some(Value::Bool(false)),
                    _ => None,
                },
                "int" => value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
                    .map(Value::Int),
                "uint" => value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
                    .map(Value::UInt),
                "double" => {
                    let value = match value {
                        JsonValue::Number(number) => exact_double(number),
                        JsonValue::String(text) => {
                            text.parse::<f64>().ok().filter(|value| value.is_finite())
                        }
                        _ => None,
                    };
                    return value
                        .map(|value| (Value::Double(value), input_cost))
                        .ok_or_else(|| "a finite double value without a lossy conversion".into());
                }
                "string" => value
                    .as_str()
                    .map(|value| Value::String(value.to_owned().into())),
                "duration" => {
                    return value
                        .as_str()
                        .and_then(|value| cel_core::time::parse_duration(value).ok())
                        .map(|value| (Value::from(value), input_cost))
                        .ok_or_else(|| "a valid CEL duration string".into());
                }
                "timestamp" => {
                    return value
                        .as_str()
                        .and_then(|value| cel_core::time::parse_timestamp(value).ok())
                        .map(|value| (Value::from(value), input_cost))
                        .ok_or_else(|| "an RFC3339 timestamp string".into());
                }
                _ => return Err("a value with a supported CEL scalar type".into()),
            };
            converted
                .map(|value| (value, input_cost))
                .ok_or_else(expected)
        }
        ParameterType::Generic { container, inner } => {
            let inner_type = ParameterType::Simple(inner.clone());
            match (container.as_str(), value) {
                ("list", JsonValue::Array(values)) => {
                    budget.charge_elements(values.len())?;
                    budget.work = budget.work.saturating_add(1);
                    let mut converted = Vec::with_capacity(values.len());
                    let mut total = InputCost {
                        units: 1,
                        string_bytes: 0,
                    };
                    for value in values {
                        let (value, cost) = convert_value(value, &inner_type, budget)?;
                        total.units = total.units.saturating_add(cost.units);
                        total.string_bytes = total.string_bytes.saturating_add(cost.string_bytes);
                        converted.push(value);
                    }
                    Ok((Value::list(converted), total))
                }
                ("map", JsonValue::Object(values)) => {
                    budget.charge_elements(values.len())?;
                    budget.work = budget.work.saturating_add(1);
                    let mut converted = Vec::with_capacity(values.len());
                    let mut total = InputCost {
                        units: 1,
                        string_bytes: 0,
                    };
                    for (key, value) in values {
                        let key_cost = budget.charge_string(key.len())?;
                        let (value, cost) = convert_value(value, &inner_type, budget)?;
                        total.units = total
                            .units
                            .saturating_add(key_cost.units)
                            .saturating_add(cost.units);
                        total.string_bytes = total
                            .string_bytes
                            .saturating_add(key_cost.string_bytes)
                            .saturating_add(cost.string_bytes);
                        converted.push((key.clone(), value));
                    }
                    Ok((Value::map(converted), total))
                }
                ("list", _) => Err("a list value".into()),
                ("map", _) => Err("a string-keyed map value".into()),
                _ => Err("a value with a supported CEL collection type".into()),
            }
        }
    }
}

fn invalid_context(
    condition: &str,
    parameter: &str,
    source: ConditionContextSource,
    expected: String,
) -> AuthorizationError {
    AuthorizationError::InvalidConditionContext {
        condition: condition.to_owned(),
        parameter: parameter.to_owned(),
        expected,
        source,
    }
}

fn exact_double(number: &serde_json::Number) -> Option<f64> {
    if let Some(value) = number.as_i64() {
        const MAX_EXACT_INTEGER: i64 = 9_007_199_254_740_992;
        return (-MAX_EXACT_INTEGER..=MAX_EXACT_INTEGER)
            .contains(&value)
            .then_some(value as f64);
    }
    if let Some(value) = number.as_u64() {
        const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_992;
        return (value <= MAX_EXACT_INTEGER).then_some(value as f64);
    }
    number.as_f64().filter(|value| value.is_finite())
}
