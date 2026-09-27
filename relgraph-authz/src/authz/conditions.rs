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

use cel_core::types::{Expr, SpannedExpr};
use cel_core::{CelType, Env, MapActivation, Program, Value};
use relgraph_dsl::{ConditionDefinition, ParameterType, Schema};
use serde_json::Value as JsonValue;

use super::request::{AuthorizationError, ConditionContextSource, ConstructionError};

const MAX_CONDITION_SOURCE_BYTES: usize = 65_536;
const MAX_CONDITION_AST_NODES: usize = 10_000;
const MAX_CONTEXT_VALUE_BYTES: usize = 65_536;

#[derive(Debug)]
pub(crate) struct CompiledCondition {
    name: String,
    parameters: HashMap<String, ParameterType>,
    used_parameters: BTreeSet<String>,
    program: Program,
    static_cost: usize,
    has_regex: bool,
    regex_pattern_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConditionEvaluation {
    pub allowed: bool,
    pub cost: usize,
}

#[derive(Default)]
struct ExpressionProfile {
    nodes: usize,
    literal_bytes: usize,
    identifiers: BTreeSet<String>,
    has_regex: bool,
    regex_pattern_bytes: usize,
}

#[derive(Default)]
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
        static_cost: profile.nodes.saturating_add(profile.literal_bytes),
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
                profile.regex_pattern_bytes = profile.regex_pattern_bytes.saturating_add(
                    args.iter()
                        .map(|arg| expression_literal_bytes(arg))
                        .sum::<usize>(),
                );
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

fn cel_type(parameter_type: &ParameterType) -> Option<CelType> {
    match parameter_type {
        ParameterType::Simple(name) => simple_cel_type(name),
        ParameterType::Generic { container, inner } => {
            let inner_type = simple_cel_type(inner)?;
            match container.as_str() {
                "list" => Some(CelType::list(inner_type)),
                "map" => Some(CelType::map(CelType::String, inner_type)),
                _ => None,
            }
        }
    }
}

fn simple_cel_type(name: &str) -> Option<CelType> {
    match name {
        "bool" => Some(CelType::Bool),
        "int" => Some(CelType::Int),
        "uint" => Some(CelType::UInt),
        "double" => Some(CelType::Double),
        "string" => Some(CelType::String),
        "duration" => Some(CelType::Duration),
        "timestamp" => Some(CelType::Timestamp),
        _ => None,
    }
}

impl CompiledCondition {
    /// Validates all supplied tuple metadata while allowing the request to fill
    /// parameters that the persisted context omitted.
    pub(crate) fn validate_stored_context(
        &self,
        values: &BTreeMap<String, JsonValue>,
    ) -> Result<(), AuthorizationError> {
        for (name, value) in values {
            let Some(parameter_type) = self.parameters.get(name) else {
                return Err(AuthorizationError::UndeclaredConditionContext {
                    condition: self.name.clone(),
                    parameter: name.clone(),
                    source: ConditionContextSource::StoredTuple,
                });
            };
            convert_value(
                value,
                parameter_type,
                &self.name,
                name,
                ConditionContextSource::StoredTuple,
            )?;
        }
        Ok(())
    }

    pub(crate) fn evaluate(
        &self,
        tuple_values: Option<&BTreeMap<String, JsonValue>>,
        condition_request_values: Option<&BTreeMap<String, JsonValue>>,
        request_values: &BTreeMap<String, JsonValue>,
        available_cost: usize,
    ) -> Result<ConditionEvaluation, AuthorizationError> {
        let mut activation = MapActivation::new();
        let mut input_cost = InputCost::default();
        for name in &self.used_parameters {
            let parameter_type = self
                .parameters
                .get(name)
                .expect("used CEL variable is declared in the condition schema");
            let (value, source) = if let Some(value) =
                tuple_values.and_then(|values| values.get(name))
            {
                (value, ConditionContextSource::StoredTuple)
            } else if let Some(value) = condition_request_values.and_then(|values| values.get(name))
            {
                (value, ConditionContextSource::Request)
            } else if let Some(value) = request_values.get(name) {
                (value, ConditionContextSource::Request)
            } else {
                return Err(AuthorizationError::MissingConditionContext {
                    condition: self.name.clone(),
                    parameter: name.clone(),
                });
            };
            let contribution = estimate_input_cost(value, parameter_type).map_err(|expected| {
                AuthorizationError::InvalidConditionContext {
                    condition: self.name.clone(),
                    parameter: name.clone(),
                    expected,
                    source,
                }
            })?;
            input_cost.units = input_cost.units.saturating_add(contribution.units);
            input_cost.string_bytes = input_cost
                .string_bytes
                .saturating_add(contribution.string_bytes);
            if input_cost.string_bytes > MAX_CONTEXT_VALUE_BYTES {
                return Err(AuthorizationError::InvalidConditionContext {
                    condition: self.name.clone(),
                    parameter: name.clone(),
                    expected: format!("a value no larger than {MAX_CONTEXT_VALUE_BYTES} bytes"),
                    source,
                });
            }
            let converted = convert_value(value, parameter_type, &self.name, name, source)?;
            activation.insert(name.clone(), converted);
        }

        let mut cost = self.static_cost.saturating_add(input_cost.units);
        if self.has_regex {
            cost = cost.saturating_add(
                self.regex_pattern_bytes
                    .max(1)
                    .saturating_mul(input_cost.string_bytes.max(1)),
            );
        }
        if cost > available_cost {
            return Err(AuthorizationError::ConditionCostLimitExceeded {
                maximum_cost: available_cost,
                estimated_cost: cost,
            });
        }

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
        Ok(ConditionEvaluation { allowed, cost })
    }
}

fn estimate_input_cost(
    value: &JsonValue,
    parameter_type: &ParameterType,
) -> Result<InputCost, String> {
    match parameter_type {
        ParameterType::Simple(name) => {
            let units = match name.as_str() {
                "bool" => match value {
                    JsonValue::Bool(_) => 1,
                    JsonValue::String(value) if matches!(value.as_str(), "true" | "false") => {
                        value.len()
                    }
                    _ => return Err("a bool value".into()),
                },
                "int" => match value {
                    JsonValue::Number(number) if number.as_i64().is_some() => 1,
                    JsonValue::String(text) if text.parse::<i64>().is_ok() => text.len(),
                    _ => return Err("a signed 64-bit integer value".into()),
                },
                "uint" => match value {
                    JsonValue::Number(number) if number.as_u64().is_some() => 1,
                    JsonValue::String(text) if text.parse::<u64>().is_ok() => text.len(),
                    _ => return Err("an unsigned 64-bit integer value".into()),
                },
                "double" => match value {
                    JsonValue::Number(number) if exact_double(number).is_some() => 1,
                    JsonValue::String(text)
                        if text.parse::<f64>().is_ok_and(|value| value.is_finite()) =>
                    {
                        text.len()
                    }
                    _ => return Err("a finite double value without a lossy conversion".into()),
                },
                "string" => match value {
                    JsonValue::String(value) => value.len().max(1),
                    _ => return Err("a string value".into()),
                },
                "duration" => match value {
                    JsonValue::String(value) if cel_core::time::parse_duration(value).is_ok() => {
                        value.len().max(1)
                    }
                    _ => return Err("a CEL duration string".into()),
                },
                "timestamp" => match value {
                    JsonValue::String(value) if cel_core::time::parse_timestamp(value).is_ok() => {
                        value.len().max(1)
                    }
                    _ => return Err("an RFC3339 timestamp string".into()),
                },
                _ => return Err("a value with a supported CEL scalar type".into()),
            };
            Ok(InputCost {
                units: units.max(1),
                string_bytes: value.as_str().map_or(0, str::len),
            })
        }
        ParameterType::Generic { container, inner } => match (container.as_str(), value) {
            ("list", JsonValue::Array(values)) => {
                let inner = ParameterType::Simple(inner.clone());
                let mut total = InputCost {
                    units: 1,
                    string_bytes: 0,
                };
                for value in values {
                    let cost = estimate_input_cost(value, &inner)?;
                    total.units = total.units.saturating_add(cost.units);
                    total.string_bytes = total.string_bytes.saturating_add(cost.string_bytes);
                }
                Ok(total)
            }
            ("map", JsonValue::Object(values)) => {
                let inner = ParameterType::Simple(inner.clone());
                let mut total = InputCost {
                    units: 1,
                    string_bytes: 0,
                };
                for (key, value) in values {
                    let cost = estimate_input_cost(value, &inner)?;
                    total.units = total
                        .units
                        .saturating_add(key.len().max(1))
                        .saturating_add(cost.units);
                    total.string_bytes = total
                        .string_bytes
                        .saturating_add(key.len())
                        .saturating_add(cost.string_bytes);
                }
                Ok(total)
            }
            ("list", _) => Err("a list value".into()),
            ("map", _) => Err("a string-keyed map value".into()),
            _ => Err("a value with a supported CEL collection type".into()),
        },
    }
}

fn convert_value(
    value: &JsonValue,
    parameter_type: &ParameterType,
    condition: &str,
    parameter: &str,
    source: ConditionContextSource,
) -> Result<Value, AuthorizationError> {
    let invalid = |expected: String| AuthorizationError::InvalidConditionContext {
        condition: condition.to_owned(),
        parameter: parameter.to_owned(),
        expected,
        source,
    };
    match parameter_type {
        ParameterType::Simple(name) => {
            let expected = format!("a {name} value");
            match name.as_str() {
                "bool" => match value {
                    JsonValue::Bool(value) => Ok(Value::Bool(*value)),
                    JsonValue::String(value) if value == "true" => Ok(Value::Bool(true)),
                    JsonValue::String(value) if value == "false" => Ok(Value::Bool(false)),
                    _ => Err(invalid(expected)),
                },
                "int" => {
                    let value = value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|text| text.parse().ok()));
                    value.map(Value::Int).ok_or_else(|| invalid(expected))
                }
                "uint" => {
                    let value = value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|text| text.parse().ok()));
                    value.map(Value::UInt).ok_or_else(|| invalid(expected))
                }
                "double" => {
                    let value = match value {
                        JsonValue::Number(number) => exact_double(number),
                        JsonValue::String(text) => {
                            text.parse::<f64>().ok().filter(|value| value.is_finite())
                        }
                        _ => None,
                    };
                    value.map(Value::Double).ok_or_else(|| {
                        invalid("a finite double value without a lossy conversion".into())
                    })
                }
                "string" => value
                    .as_str()
                    .map(|value| Value::String(value.to_owned().into()))
                    .ok_or_else(|| invalid(expected)),
                "duration" => value
                    .as_str()
                    .and_then(|value| cel_core::time::parse_duration(value).ok())
                    .map(Value::from)
                    .ok_or_else(|| invalid("a valid CEL duration string".into())),
                "timestamp" => value
                    .as_str()
                    .and_then(|value| cel_core::time::parse_timestamp(value).ok())
                    .map(Value::from)
                    .ok_or_else(|| invalid("an RFC3339 timestamp string".into())),
                _ => Err(invalid("a value with a supported CEL scalar type".into())),
            }
        }
        ParameterType::Generic { container, inner } => {
            let inner_type = ParameterType::Simple(inner.clone());
            match (container.as_str(), value) {
                ("list", JsonValue::Array(values)) => values
                    .iter()
                    .map(|value| convert_value(value, &inner_type, condition, parameter, source))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Value::list),
                ("map", JsonValue::Object(values)) => values
                    .iter()
                    .map(|(key, value)| {
                        convert_value(value, &inner_type, condition, parameter, source)
                            .map(|value| (key.clone(), value))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Value::map),
                ("list", _) => Err(invalid("a list value".into())),
                ("map", _) => Err(invalid("a string-keyed map value".into())),
                _ => Err(invalid(
                    "a value with a supported CEL collection type".into(),
                )),
            }
        }
    }
}

fn exact_double(number: &serde_json::Number) -> Option<f64> {
    if let Some(value) = number.as_i64() {
        const MAX_EXACT_INTEGER: i64 = 9_007_199_254_740_992;
        return (value >= -MAX_EXACT_INTEGER && value <= MAX_EXACT_INTEGER).then_some(value as f64);
    }
    if let Some(value) = number.as_u64() {
        const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_992;
        return (value <= MAX_EXACT_INTEGER).then_some(value as f64);
    }
    number.as_f64().filter(|value| value.is_finite())
}
