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
const MAX_CONTEXT_CONVERSIONS: usize = 10_000;

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

/// Per-check accounting for condition input conversion and CEL execution.
///
/// Work is charged before parsing, cloning, or allocating converted values so
/// failed attempts and unused persisted values consume the same bounded budget.
pub(crate) struct ConditionBudget {
    maximum_cost: usize,
    cost_used: usize,
    context_bytes_used: usize,
    context_elements_used: usize,
    conversions_used: usize,
}

impl ConditionBudget {
    pub(crate) fn new(maximum_cost: usize) -> Self {
        Self {
            maximum_cost,
            cost_used: 0,
            context_bytes_used: 0,
            context_elements_used: 0,
            conversions_used: 0,
        }
    }

    fn charge_work(&mut self, amount: usize) -> Result<(), AuthorizationError> {
        let estimated_cost = self.cost_used.saturating_add(amount);
        if estimated_cost > self.maximum_cost {
            self.cost_used = self.maximum_cost;
            return Err(AuthorizationError::ConditionCostLimitExceeded {
                maximum_cost: self.maximum_cost,
                estimated_cost,
            });
        }
        self.cost_used = estimated_cost;
        Ok(())
    }

    fn ensure_work(&mut self, amount: usize) -> Result<(), AuthorizationError> {
        let estimated_cost = self.cost_used.saturating_add(amount);
        if estimated_cost > self.maximum_cost {
            self.cost_used = self.maximum_cost;
            return Err(AuthorizationError::ConditionCostLimitExceeded {
                maximum_cost: self.maximum_cost,
                estimated_cost,
            });
        }
        Ok(())
    }

    fn charge_context_bytes(
        &mut self,
        amount: usize,
        condition: &str,
        parameter: &str,
        source: ConditionContextSource,
    ) -> Result<(), AuthorizationError> {
        let total = self.context_bytes_used.saturating_add(amount);
        if total > super::store::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES {
            self.context_bytes_used = super::store::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES;
            return Err(invalid_context(
                condition,
                parameter,
                source,
                format!(
                    "condition context totaling at most {} bytes",
                    super::store::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES
                ),
            ));
        }
        self.context_bytes_used = total;
        Ok(())
    }

    fn charge_elements(
        &mut self,
        amount: usize,
        condition: &str,
        parameter: &str,
        source: ConditionContextSource,
    ) -> Result<(), AuthorizationError> {
        let total = self.context_elements_used.saturating_add(amount);
        if total > super::store::MAX_CONDITION_CONTEXT_ELEMENTS {
            self.context_elements_used = super::store::MAX_CONDITION_CONTEXT_ELEMENTS;
            return Err(invalid_context(
                condition,
                parameter,
                source,
                format!(
                    "condition context with at most {} elements",
                    super::store::MAX_CONDITION_CONTEXT_ELEMENTS
                ),
            ));
        }
        self.context_elements_used = total;
        Ok(())
    }

    fn ensure_conversions(
        &mut self,
        amount: usize,
        condition: &str,
        parameter: &str,
        source: ConditionContextSource,
    ) -> Result<(), AuthorizationError> {
        if self.conversions_used.saturating_add(amount) > MAX_CONTEXT_CONVERSIONS {
            self.conversions_used = MAX_CONTEXT_CONVERSIONS;
            return Err(invalid_context(
                condition,
                parameter,
                source,
                format!("at most {MAX_CONTEXT_CONVERSIONS} converted condition values"),
            ));
        }
        Ok(())
    }

    fn charge_conversion(
        &mut self,
        condition: &str,
        parameter: &str,
        source: ConditionContextSource,
    ) -> Result<(), AuthorizationError> {
        self.ensure_conversions(1, condition, parameter, source)?;
        self.conversions_used += 1;
        Ok(())
    }

    fn charge_string(
        &mut self,
        length: usize,
        condition: &str,
        parameter: &str,
        source: ConditionContextSource,
    ) -> Result<InputCost, AuthorizationError> {
        self.charge_context_bytes(length, condition, parameter, source)?;
        self.charge_work(length.max(1))?;
        Ok(InputCost {
            units: length.max(1),
            string_bytes: length,
        })
    }

    fn charge_map_key(
        &mut self,
        key: &str,
        condition: &str,
        parameter: &str,
        source: ConditionContextSource,
    ) -> Result<usize, AuthorizationError> {
        self.charge_context_bytes(key.len(), condition, parameter, source)?;
        self.charge_work(key.len().max(1))?;
        Ok(key.len().max(1))
    }

    fn charge_parameter_key(
        &mut self,
        key: &str,
        condition: &str,
        parameter: &str,
        source: ConditionContextSource,
    ) -> Result<(), AuthorizationError> {
        self.charge_context_bytes(key.len(), condition, parameter, source)?;
        self.charge_work(1)
    }
}

#[derive(Debug)]
pub(crate) struct PreparedConditionContext {
    values: BTreeMap<String, PreparedConditionValue>,
}

#[derive(Debug)]
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
        budget: &mut ConditionBudget,
    ) -> Result<PreparedConditionContext, AuthorizationError> {
        budget.charge_elements(
            values.len(),
            &self.name,
            "<context>",
            ConditionContextSource::StoredTuple,
        )?;
        budget.ensure_conversions(
            values.len(),
            &self.name,
            "<context>",
            ConditionContextSource::StoredTuple,
        )?;
        budget.ensure_work(values.len())?;
        let mut prepared = BTreeMap::new();
        for (name, value) in values {
            budget.charge_parameter_key(
                name,
                &self.name,
                name,
                ConditionContextSource::StoredTuple,
            )?;
            let Some(parameter_type) = self.parameters.get(name) else {
                return Err(AuthorizationError::UndeclaredConditionContext {
                    condition: self.name.clone(),
                    parameter: name.clone(),
                    source: ConditionContextSource::StoredTuple,
                });
            };
            let (converted, input_cost) = convert_value(
                value,
                parameter_type,
                &self.name,
                name,
                ConditionContextSource::StoredTuple,
                budget,
            )?;
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

    pub(crate) fn evaluate(
        &self,
        mut tuple_values: Option<PreparedConditionContext>,
        condition_request_values: Option<&BTreeMap<String, JsonValue>>,
        request_values: &BTreeMap<String, JsonValue>,
        budget: &mut ConditionBudget,
    ) -> Result<ConditionEvaluation, AuthorizationError> {
        // A failed CEL attempt still consumes its static evaluation work.
        budget.charge_work(self.static_cost)?;
        let mut activation = MapActivation::new();
        let mut input_cost = InputCost::default();
        for name in &self.used_parameters {
            let parameter_type = self
                .parameters
                .get(name)
                .expect("used CEL variable is declared in the condition schema");
            let (converted, contribution) = if let Some(value) = tuple_values
                .as_mut()
                .and_then(|context| context.values.remove(name))
            {
                (value.value, value.input_cost)
            } else if let Some(value) = condition_request_values.and_then(|values| values.get(name))
            {
                convert_value(
                    value,
                    parameter_type,
                    &self.name,
                    name,
                    ConditionContextSource::Request,
                    budget,
                )?
            } else if let Some(value) = request_values.get(name) {
                convert_value(
                    value,
                    parameter_type,
                    &self.name,
                    name,
                    ConditionContextSource::Request,
                    budget,
                )?
            } else {
                return Err(AuthorizationError::MissingConditionContext {
                    condition: self.name.clone(),
                    parameter: name.clone(),
                });
            };
            input_cost.units = input_cost.units.saturating_add(contribution.units);
            input_cost.string_bytes = input_cost
                .string_bytes
                .saturating_add(contribution.string_bytes);
            activation.insert(name.clone(), converted);
        }

        if self.has_regex {
            let regex_cost = self
                .regex_pattern_bytes
                .max(1)
                .saturating_mul(input_cost.string_bytes.max(1));
            budget.charge_work(regex_cost)?;
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
        Ok(ConditionEvaluation { allowed })
    }
}

fn convert_value(
    value: &JsonValue,
    parameter_type: &ParameterType,
    condition: &str,
    parameter: &str,
    source: ConditionContextSource,
    budget: &mut ConditionBudget,
) -> Result<(Value, InputCost), AuthorizationError> {
    budget.charge_conversion(condition, parameter, source)?;
    match parameter_type {
        ParameterType::Simple(name) => {
            let expected = format!("a {name} value");
            let input_cost = if let Some(text) = value.as_str() {
                budget.charge_string(text.len(), condition, parameter, source)?
            } else {
                budget.charge_work(1)?;
                InputCost {
                    units: 1,
                    string_bytes: 0,
                }
            };
            match name.as_str() {
                "bool" => match value {
                    JsonValue::Bool(value) => Ok((Value::Bool(*value), input_cost)),
                    JsonValue::String(value) if value == "true" => {
                        Ok((Value::Bool(true), input_cost))
                    }
                    JsonValue::String(value) if value == "false" => {
                        Ok((Value::Bool(false), input_cost))
                    }
                    _ => Err(invalid_context(condition, parameter, source, expected)),
                },
                "int" => {
                    let value = value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|text| text.parse().ok()));
                    value
                        .map(|value| (Value::Int(value), input_cost))
                        .ok_or_else(|| invalid_context(condition, parameter, source, expected))
                }
                "uint" => {
                    let value = value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|text| text.parse().ok()));
                    value
                        .map(|value| (Value::UInt(value), input_cost))
                        .ok_or_else(|| invalid_context(condition, parameter, source, expected))
                }
                "double" => {
                    let value = match value {
                        JsonValue::Number(number) => exact_double(number),
                        JsonValue::String(text) => {
                            text.parse::<f64>().ok().filter(|value| value.is_finite())
                        }
                        _ => None,
                    };
                    value
                        .map(|value| (Value::Double(value), input_cost))
                        .ok_or_else(|| {
                            invalid_context(
                                condition,
                                parameter,
                                source,
                                "a finite double value without a lossy conversion".into(),
                            )
                        })
                }
                "string" => value
                    .as_str()
                    .map(|value| (Value::String(value.to_owned().into()), input_cost))
                    .ok_or_else(|| invalid_context(condition, parameter, source, expected)),
                "duration" => value
                    .as_str()
                    .and_then(|value| cel_core::time::parse_duration(value).ok())
                    .map(|value| (Value::from(value), input_cost))
                    .ok_or_else(|| {
                        invalid_context(
                            condition,
                            parameter,
                            source,
                            "a valid CEL duration string".into(),
                        )
                    }),
                "timestamp" => value
                    .as_str()
                    .and_then(|value| cel_core::time::parse_timestamp(value).ok())
                    .map(|value| (Value::from(value), input_cost))
                    .ok_or_else(|| {
                        invalid_context(
                            condition,
                            parameter,
                            source,
                            "an RFC3339 timestamp string".into(),
                        )
                    }),
                _ => Err(invalid_context(
                    condition,
                    parameter,
                    source,
                    "a value with a supported CEL scalar type".into(),
                )),
            }
        }
        ParameterType::Generic { container, inner } => {
            let inner_type = ParameterType::Simple(inner.clone());
            match (container.as_str(), value) {
                ("list", JsonValue::Array(values)) => {
                    budget.charge_work(1)?;
                    budget.charge_elements(values.len(), condition, parameter, source)?;
                    budget.ensure_conversions(values.len(), condition, parameter, source)?;
                    budget.ensure_work(values.len())?;
                    let mut converted = Vec::new();
                    let mut total = InputCost {
                        units: 1,
                        string_bytes: 0,
                    };
                    for value in values {
                        let (value, cost) = convert_value(
                            value,
                            &inner_type,
                            condition,
                            parameter,
                            source,
                            budget,
                        )?;
                        total.units = total.units.saturating_add(cost.units);
                        total.string_bytes = total.string_bytes.saturating_add(cost.string_bytes);
                        converted.push(value);
                    }
                    Ok((Value::list(converted), total))
                }
                ("map", JsonValue::Object(values)) => {
                    budget.charge_work(1)?;
                    budget.charge_elements(values.len(), condition, parameter, source)?;
                    budget.ensure_conversions(values.len(), condition, parameter, source)?;
                    budget.ensure_work(values.len().saturating_mul(2))?;
                    let mut converted = Vec::new();
                    let mut total = InputCost {
                        units: 1,
                        string_bytes: 0,
                    };
                    for (key, value) in values {
                        let key_cost = budget.charge_map_key(key, condition, parameter, source)?;
                        let (value, cost) = convert_value(
                            value,
                            &inner_type,
                            condition,
                            parameter,
                            source,
                            budget,
                        )?;
                        total.units = total
                            .units
                            .saturating_add(key_cost)
                            .saturating_add(cost.units);
                        total.string_bytes = total
                            .string_bytes
                            .saturating_add(key.len())
                            .saturating_add(cost.string_bytes);
                        converted.push((key.clone(), value));
                    }
                    Ok((Value::map(converted), total))
                }
                ("list", _) => Err(invalid_context(
                    condition,
                    parameter,
                    source,
                    "a list value".into(),
                )),
                ("map", _) => Err(invalid_context(
                    condition,
                    parameter,
                    source,
                    "a string-keyed map value".into(),
                )),
                _ => Err(invalid_context(
                    condition,
                    parameter,
                    source,
                    "a value with a supported CEL collection type".into(),
                )),
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
        return (value >= -MAX_EXACT_INTEGER && value <= MAX_EXACT_INTEGER).then_some(value as f64);
    }
    if let Some(value) = number.as_u64() {
        const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_992;
        return (value <= MAX_EXACT_INTEGER).then_some(value as f64);
    }
    number.as_f64().filter(|value| value.is_finite())
}
