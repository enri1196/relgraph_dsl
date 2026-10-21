use relgraph_authz::{
    ConditionContext, ObjectRef, RelationName, RelationshipTuple, StoreError, StoreErrorKind,
    Subject, TenantId, TupleSubject, TypeName,
};
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Row, postgres::PgRow};
use std::collections::BTreeMap;

const CORRUPT_ROW: &str = "persisted relationship tuple is malformed";
const SERIALIZATION_FAILURE: &str = "relationship tuple serialization failed";
const OVERSIZED_WRITE_CONTEXT: &str = "relationship tuple condition context exceeds storage limits";
const IDENTITY_PREFIX: &[u8] = b"relgraph-authz.relationship-tuple";
const IDENTITY_VERSION: u8 = 1;

/// Returns a subject's `subject_kind`, `subject_type`, `subject_id` and
/// `subject_relation` column values, the form both writes and reverse lookups
/// bind.
pub(crate) fn subject_columns(
    subject: &TupleSubject,
) -> (&'static str, &str, Option<&str>, Option<&str>) {
    match subject {
        TupleSubject::Direct(subject) => (
            "direct",
            subject.type_name().as_str(),
            Some(subject.id().as_str()),
            None,
        ),
        TupleSubject::Userset { object, relation } => (
            "userset",
            object.type_name().as_str(),
            Some(object.id().as_str()),
            Some(relation.as_str()),
        ),
        TupleSubject::TypedWildcard(type_name) => {
            ("typed_wildcard", type_name.as_str(), None, None)
        }
    }
}

/// Owned representation of one database row. `tuple_id` is absent when the
/// row is prepared for insertion and present when it is decoded from PostgreSQL.
#[derive(Debug)]
pub(crate) struct TupleRow {
    pub(crate) tuple_id: Option<i64>,
    pub(crate) tenant: String,
    pub(crate) object_type: String,
    pub(crate) object_id: String,
    pub(crate) relation: String,
    pub(crate) subject_kind: String,
    pub(crate) subject_type: String,
    pub(crate) subject_id: Option<String>,
    pub(crate) subject_relation: Option<String>,
    pub(crate) condition_name: Option<String>,
    pub(crate) context_json: Option<String>,
    pub(crate) context_json_oversized: bool,
    pub(crate) identity_digest: Vec<u8>,
}

impl<'r> FromRow<'r, PgRow> for TupleRow {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            tuple_id: Some(row.try_get("tuple_id")?),
            tenant: row.try_get("tenant")?,
            object_type: row.try_get("object_type")?,
            object_id: row.try_get("object_id")?,
            relation: row.try_get("relation")?,
            subject_kind: row.try_get("subject_kind")?,
            subject_type: row.try_get("subject_type")?,
            subject_id: row.try_get("subject_id")?,
            subject_relation: row.try_get("subject_relation")?,
            condition_name: row.try_get("condition_name")?,
            context_json: row.try_get("context_json")?,
            context_json_oversized: row.try_get("context_json_oversized")?,
            identity_digest: row.try_get("identity_digest")?,
        })
    }
}

impl TupleRow {
    /// Prepares a caller-supplied tuple for writing. An oversized condition
    /// context is rejected as invalid input rather than corrupt stored data.
    pub(crate) fn from_tuple(tuple: &RelationshipTuple) -> Result<Self, StoreError> {
        let (subject_kind, subject_type, subject_id, subject_relation) =
            subject_columns(tuple.subject());

        let (condition_name, context_json) = match tuple.condition() {
            None => (None, None),
            Some(context) => {
                context.serialized_size().map_err(oversized_write_context)?;
                let json = serde_json::to_string(context.values())
                    .map_err(|_| internal_error(SERIALIZATION_FAILURE))?;
                (Some(context.name().as_str().to_owned()), Some(json))
            }
        };

        Ok(Self {
            tuple_id: None,
            tenant: tuple.tenant().as_str().to_owned(),
            object_type: tuple.object().type_name().as_str().to_owned(),
            object_id: tuple.object().id().as_str().to_owned(),
            relation: tuple.relation().as_str().to_owned(),
            subject_kind: subject_kind.to_owned(),
            subject_type: subject_type.to_owned(),
            subject_id: subject_id.map(str::to_owned),
            subject_relation: subject_relation.map(str::to_owned),
            condition_name,
            context_json,
            context_json_oversized: false,
            identity_digest: tuple_identity_digest(tuple)?.to_vec(),
        })
    }

    pub(crate) fn into_tuple(self) -> Result<RelationshipTuple, StoreError> {
        if self.context_json_oversized
            || self.context_json.as_ref().is_some_and(|json| {
                json.len() > relgraph_authz::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES
            })
        {
            return Err(corrupt_error());
        }
        if self.identity_digest.len() != 32 {
            return Err(corrupt_error());
        }

        let tenant = TenantId::new(self.tenant).map_err(|_| corrupt_error())?;
        let object =
            ObjectRef::new(self.object_type, self.object_id).map_err(|_| corrupt_error())?;
        let relation = RelationName::new(self.relation).map_err(|_| corrupt_error())?;

        let subject = match (
            self.subject_kind.as_str(),
            self.subject_id,
            self.subject_relation,
        ) {
            ("direct", Some(id), None) => {
                let subject = Subject::new(self.subject_type, id).map_err(|_| corrupt_error())?;
                TupleSubject::Direct(subject)
            }
            ("userset", Some(id), Some(subject_relation)) => {
                let object = ObjectRef::new(self.subject_type, id).map_err(|_| corrupt_error())?;
                let relation = RelationName::new(subject_relation).map_err(|_| corrupt_error())?;
                TupleSubject::Userset { object, relation }
            }
            ("typed_wildcard", None, None) => TupleSubject::TypedWildcard(
                TypeName::new(self.subject_type).map_err(|_| corrupt_error())?,
            ),
            _ => return Err(corrupt_error()),
        };

        let condition = match (self.condition_name, self.context_json) {
            (None, None) => None,
            (Some(name), Some(json)) => {
                let values = serde_json::from_str::<BTreeMap<String, Value>>(&json)
                    .map_err(|_| corrupt_error())?;
                let context = ConditionContext::new(name, values).map_err(|_| corrupt_error())?;
                context.serialized_size().map_err(|_| corrupt_error())?;
                Some(context)
            }
            _ => return Err(corrupt_error()),
        };

        let mut tuple = RelationshipTuple::new(tenant, object, relation, subject);
        if let Some(condition) = condition {
            tuple = tuple.with_condition(condition);
        }

        let expected_digest = tuple_identity_digest(&tuple)?;
        if self.identity_digest.as_slice() != expected_digest.as_slice() {
            return Err(corrupt_error());
        }

        Ok(tuple)
    }
}

pub(crate) fn tuple_identity_digest(tuple: &RelationshipTuple) -> Result<[u8; 32], StoreError> {
    let canonical = canonical_identity(tuple)?;
    Ok(Sha256::digest(canonical).into())
}

fn canonical_identity(tuple: &RelationshipTuple) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(IDENTITY_PREFIX);
    bytes.push(IDENTITY_VERSION);

    append_field(&mut bytes, 0x01, tuple.tenant().as_str())?;
    append_field(&mut bytes, 0x02, tuple.object().type_name().as_str())?;
    append_field(&mut bytes, 0x03, tuple.object().id().as_str())?;
    append_field(&mut bytes, 0x04, tuple.relation().as_str())?;

    match tuple.subject() {
        TupleSubject::Direct(subject) => {
            bytes.extend_from_slice(&[0x05, 0x01]);
            append_field(&mut bytes, 0x11, subject.type_name().as_str())?;
            append_field(&mut bytes, 0x12, subject.id().as_str())?;
        }
        TupleSubject::Userset { object, relation } => {
            bytes.extend_from_slice(&[0x05, 0x02]);
            append_field(&mut bytes, 0x21, object.type_name().as_str())?;
            append_field(&mut bytes, 0x22, object.id().as_str())?;
            append_field(&mut bytes, 0x23, relation.as_str())?;
        }
        TupleSubject::TypedWildcard(type_name) => {
            bytes.extend_from_slice(&[0x05, 0x03]);
            append_field(&mut bytes, 0x31, type_name.as_str())?;
        }
    }

    match tuple.condition() {
        None => bytes.extend_from_slice(&[0x06, 0x00]),
        Some(context) => {
            bytes.extend_from_slice(&[0x06, 0x01]);
            append_string(&mut bytes, context.name().as_str())?;
            append_map(&mut bytes, context.values())?;
        }
    }

    Ok(bytes)
}

fn append_field(bytes: &mut Vec<u8>, tag: u8, value: &str) -> Result<(), StoreError> {
    bytes.push(tag);
    append_string(bytes, value)
}

fn append_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), StoreError> {
    append_length(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), StoreError> {
    let length = u64::try_from(length).map_err(|_| internal_error(SERIALIZATION_FAILURE))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn append_map(bytes: &mut Vec<u8>, values: &BTreeMap<String, Value>) -> Result<(), StoreError> {
    bytes.push(0x20);
    append_length(bytes, values.len())?;
    for (key, value) in values {
        append_string(bytes, key)?;
        append_value(bytes, value)?;
    }
    Ok(())
}

fn append_value(bytes: &mut Vec<u8>, value: &Value) -> Result<(), StoreError> {
    match value {
        Value::Null => bytes.push(0x00),
        Value::Bool(value) => bytes.extend_from_slice(&[0x01, u8::from(*value)]),
        Value::Number(number) => append_number(bytes, number)?,
        Value::String(value) => {
            bytes.push(0x03);
            append_string(bytes, value)?;
        }
        Value::Array(values) => {
            bytes.push(0x04);
            append_length(bytes, values.len())?;
            for value in values {
                append_value(bytes, value)?;
            }
        }
        Value::Object(values) => {
            bytes.push(0x05);
            append_length(bytes, values.len())?;
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (key, value) in entries {
                append_string(bytes, key)?;
                append_value(bytes, value)?;
            }
        }
    }
    Ok(())
}

fn append_number(bytes: &mut Vec<u8>, number: &Number) -> Result<(), StoreError> {
    if number.is_f64() {
        let value = number
            .as_f64()
            .ok_or_else(|| internal_error(SERIALIZATION_FAILURE))?;
        if !value.is_finite() {
            return Err(internal_error(SERIALIZATION_FAILURE));
        }
        bytes.extend_from_slice(&[0x02, 0x02]);
        let bits = if value == 0.0 { 0 } else { value.to_bits() };
        bytes.extend_from_slice(&bits.to_be_bytes());
    } else if let Some(value) = number.as_i64() {
        bytes.extend_from_slice(&[0x02, 0x01]);
        append_string(bytes, &value.to_string())?;
    } else if let Some(value) = number.as_u64() {
        bytes.extend_from_slice(&[0x02, 0x01]);
        append_string(bytes, &value.to_string())?;
    } else {
        return Err(internal_error(SERIALIZATION_FAILURE));
    }
    Ok(())
}

fn corrupt_error() -> StoreError {
    StoreError::new(StoreErrorKind::CorruptData, CORRUPT_ROW)
}

fn oversized_write_context(error: StoreError) -> StoreError {
    if error.kind() == StoreErrorKind::CorruptData {
        StoreError::new(StoreErrorKind::InvalidInput, OVERSIZED_WRITE_CONTEXT)
    } else {
        error
    }
}

fn internal_error(message: &'static str) -> StoreError {
    StoreError::new(StoreErrorKind::Internal, message)
}

#[cfg(test)]
mod tests {
    use super::{TupleRow, tuple_identity_digest};
    use relgraph_authz::{
        ConditionContext, ObjectRef, RelationName, RelationshipTuple, StoreErrorKind, Subject,
        TenantId, TupleSubject, TypeName,
    };
    use serde_json::{Number, Value, json};
    use std::collections::BTreeMap;

    fn tuple(subject: TupleSubject) -> RelationshipTuple {
        RelationshipTuple::new(
            TenantId::new("tenant-a").unwrap(),
            ObjectRef::new("document", "doc-1").unwrap(),
            RelationName::new("viewer").unwrap(),
            subject,
        )
    }

    fn round_trip(tuple: &RelationshipTuple) -> RelationshipTuple {
        TupleRow::from_tuple(tuple).unwrap().into_tuple().unwrap()
    }

    fn context(values: BTreeMap<String, Value>) -> ConditionContext {
        ConditionContext::new("valid_grant", values).unwrap()
    }

    #[test]
    fn every_subject_variant_round_trips_with_partial_eq() {
        let direct = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()));
        let userset = tuple(TupleSubject::Userset {
            object: ObjectRef::new("group", "editors").unwrap(),
            relation: RelationName::new("member").unwrap(),
        });
        let wildcard = tuple(TupleSubject::TypedWildcard(TypeName::new("user").unwrap()));
        assert_eq!(round_trip(&direct), direct);
        assert_eq!(round_trip(&userset), userset);
        assert_eq!(round_trip(&wildcard), wildcard);
    }

    #[test]
    fn direct_star_is_distinct_from_typed_wildcard() {
        let direct = tuple(TupleSubject::Direct(Subject::new("user", "*").unwrap()));
        let wildcard = tuple(TupleSubject::TypedWildcard(TypeName::new("user").unwrap()));
        assert_ne!(
            tuple_identity_digest(&direct).unwrap(),
            tuple_identity_digest(&wildcard).unwrap()
        );
        assert_ne!(round_trip(&direct), round_trip(&wildcard));
    }

    #[test]
    fn inline_condition_identity_covers_expression_and_parameter_types() {
        let inline = |expression: &str, count_type: &str| {
            tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap())).with_condition(
                ConditionContext::new(
                    "$expression",
                    BTreeMap::from([
                        ("expression".to_owned(), json!(expression)),
                        ("parameters".to_owned(), json!({ "count": count_type })),
                    ]),
                )
                .unwrap(),
            )
        };
        let low = inline("count > 5", "int");
        let high = inline("count > 50", "int");
        let retyped = inline("count > 5", "uint");
        let digest = |tuple: &RelationshipTuple| tuple_identity_digest(tuple).unwrap();
        assert_ne!(digest(&low), digest(&high));
        assert_ne!(digest(&low), digest(&retyped));
        assert_eq!(digest(&low), digest(&inline("count > 5", "int")));
        // The existing row shape holds the source; no migration is needed.
        let row = TupleRow::from_tuple(&low).unwrap();
        assert_eq!(row.condition_name.as_deref(), Some("$expression"));
        assert_eq!(round_trip(&low), low);
    }

    #[test]
    fn conditional_tuple_round_trips_including_empty_context() {
        let base = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()));
        let empty = base.clone().with_condition(context(BTreeMap::new()));
        let row = TupleRow::from_tuple(&empty).unwrap();
        assert_eq!(row.context_json.as_deref(), Some("{}"));
        assert_eq!(round_trip(&empty), empty);

        let without_condition = TupleRow::from_tuple(&base).unwrap();
        assert_eq!(without_condition.condition_name, None);
        assert_eq!(without_condition.context_json, None);
    }

    #[test]
    fn context_round_trip_preserves_nested_values_and_difficult_floats() {
        let floats = [0.1, f64::MIN_POSITIVE, f64::MAX, std::f64::consts::PI];
        let mut values = BTreeMap::new();
        for (index, float) in floats.into_iter().enumerate() {
            values.insert(
                format!("float-{index}"),
                Value::Number(Number::from_f64(float).unwrap()),
            );
        }
        values.insert("i64-min".to_owned(), json!(i64::MIN));
        values.insert("u64-max".to_owned(), json!(u64::MAX));
        values.insert(
            "nested".to_owned(),
            json!({"z": [null, true, "nul\u{0}é", {"b": 2, "a": 1}], "a": -0.0}),
        );
        let original = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()))
            .with_condition(context(values));
        let row = TupleRow::from_tuple(&original).unwrap();
        assert!(row.context_json.as_deref().unwrap().contains("\\u0000"));
        assert_eq!(round_trip(&original), original);
    }

    #[test]
    fn canonical_identity_sorts_object_keys_preserves_arrays_and_number_kinds() {
        let base = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()));
        let left = base.clone().with_condition(context(
            serde_json::from_str(r#"{"nested":{"z":1,"a":2},"array":[1,2]}"#).unwrap(),
        ));
        let reordered = base.clone().with_condition(context(
            serde_json::from_str(r#"{"array":[1,2],"nested":{"a":2,"z":1}}"#).unwrap(),
        ));
        let reordered_array = base.clone().with_condition(context(
            serde_json::from_str(r#"{"array":[2,1],"nested":{"a":2,"z":1}}"#).unwrap(),
        ));
        let integer = base
            .clone()
            .with_condition(context(BTreeMap::from([("n".to_owned(), json!(1))])));
        let float = base.clone().with_condition(context(BTreeMap::from([(
            "n".to_owned(),
            Value::Number(Number::from_f64(1.0).unwrap()),
        )])));

        assert_eq!(
            tuple_identity_digest(&left).unwrap(),
            tuple_identity_digest(&reordered).unwrap()
        );
        assert_ne!(
            tuple_identity_digest(&left).unwrap(),
            tuple_identity_digest(&reordered_array).unwrap()
        );
        assert_ne!(
            tuple_identity_digest(&integer).unwrap(),
            tuple_identity_digest(&float).unwrap()
        );
        assert_eq!(round_trip(&left), left);
    }

    #[test]
    fn floating_signed_zero_has_one_identity() {
        let base = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()));
        let negative_zero = base.clone().with_condition(context(BTreeMap::from([(
            "zero".to_owned(),
            Value::Number(Number::from_f64(-0.0).unwrap()),
        )])));
        let positive_zero = base.with_condition(context(BTreeMap::from([(
            "zero".to_owned(),
            Value::Number(Number::from_f64(0.0).unwrap()),
        )])));

        assert_eq!(negative_zero, positive_zero);
        assert_eq!(
            tuple_identity_digest(&negative_zero).unwrap(),
            tuple_identity_digest(&positive_zero).unwrap()
        );
        assert_eq!(round_trip(&negative_zero), negative_zero);
    }

    #[test]
    fn tuple_partial_eq_and_identity_digest_cover_the_same_fields() {
        let base = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()));
        let base_context = base.clone().with_condition(context(BTreeMap::from([(
            "role".to_owned(),
            json!("reader"),
        )])));
        let variants = [
            tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap())),
            RelationshipTuple::new(
                TenantId::new("tenant-b").unwrap(),
                ObjectRef::new("document", "doc-1").unwrap(),
                RelationName::new("viewer").unwrap(),
                Subject::new("user", "alice").unwrap(),
            ),
            RelationshipTuple::new(
                TenantId::new("tenant-a").unwrap(),
                ObjectRef::new("folder", "doc-1").unwrap(),
                RelationName::new("viewer").unwrap(),
                Subject::new("user", "alice").unwrap(),
            ),
            RelationshipTuple::new(
                TenantId::new("tenant-a").unwrap(),
                ObjectRef::new("document", "doc-2").unwrap(),
                RelationName::new("viewer").unwrap(),
                Subject::new("user", "alice").unwrap(),
            ),
            RelationshipTuple::new(
                TenantId::new("tenant-a").unwrap(),
                ObjectRef::new("document", "doc-1").unwrap(),
                RelationName::new("editor").unwrap(),
                Subject::new("user", "alice").unwrap(),
            ),
            tuple(TupleSubject::Direct(
                Subject::new("service", "alice").unwrap(),
            )),
            tuple(TupleSubject::Direct(Subject::new("user", "bob").unwrap())),
            tuple(TupleSubject::Userset {
                object: ObjectRef::new("group", "alice").unwrap(),
                relation: RelationName::new("member").unwrap(),
            }),
            tuple(TupleSubject::TypedWildcard(TypeName::new("user").unwrap())),
            base.clone().with_condition(context(BTreeMap::new())),
            base_context.clone(),
            base.clone().with_condition(
                ConditionContext::new(
                    "other_condition",
                    BTreeMap::from([("role".to_owned(), json!("reader"))]),
                )
                .unwrap(),
            ),
            base.clone().with_condition(context(BTreeMap::from([(
                "role".to_owned(),
                json!("writer"),
            )]))),
        ];

        for left in &variants {
            for right in &variants {
                assert_eq!(
                    left == right,
                    tuple_identity_digest(left).unwrap() == tuple_identity_digest(right).unwrap()
                );
            }
        }
    }

    #[test]
    fn maximum_multibyte_identifiers_fit_the_lookup_index_budget() {
        let tenant = "é".repeat(64);
        let object_type = "界".repeat(42) + "ab";
        let object_id = "é".repeat(128);
        let relation = "ß".repeat(64);
        let fixture = RelationshipTuple::new(
            TenantId::new(tenant).unwrap(),
            ObjectRef::new(object_type, object_id).unwrap(),
            RelationName::new(relation).unwrap(),
            Subject::new("user", "alice").unwrap(),
        );
        let row = TupleRow::from_tuple(&fixture).unwrap();
        let bytes = [
            row.tenant.len(),
            row.object_type.len(),
            row.object_id.len(),
            row.relation.len(),
        ];
        assert_eq!(bytes, [128, 128, 256, 128]);
        assert!(bytes.into_iter().sum::<usize>() + 128 < 2_704);
        assert_eq!(round_trip(&fixture), fixture);
        assert!(TenantId::new("é".repeat(65)).is_err());
    }

    #[test]
    fn maximum_multibyte_identifiers_fit_the_subject_lookup_index_budget() {
        let name = || "ß".repeat(64);
        let fixture = RelationshipTuple::new(
            TenantId::new(name()).unwrap(),
            ObjectRef::new(name(), "x").unwrap(),
            RelationName::new(name()).unwrap(),
            TupleSubject::Userset {
                object: ObjectRef::new(name(), "é".repeat(128)).unwrap(),
                relation: RelationName::new(name()).unwrap(),
            },
        );
        let row = TupleRow::from_tuple(&fixture).unwrap();
        let bytes = [
            row.tenant.len(),
            row.object_type.len(),
            row.relation.len(),
            "typed_wildcard".len(),
            row.subject_type.len(),
            row.subject_id.as_ref().unwrap().len(),
            row.subject_relation.as_ref().unwrap().len(),
        ];
        assert_eq!(bytes, [128, 128, 128, 14, 128, 256, 128]);
        // Index columns plus `tuple_id` and per-column headers stay well
        // inside PostgreSQL's B-tree entry limit.
        assert!(bytes.into_iter().sum::<usize>() + 8 + 128 < 2_704);
        assert_eq!(round_trip(&fixture), fixture);
    }

    #[test]
    fn malformed_shapes_context_and_digests_are_corrupt_data() {
        let fixture = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()));

        let mut malformed_subject = TupleRow::from_tuple(&fixture).unwrap();
        malformed_subject.subject_relation = Some("member".to_owned());
        assert_eq!(
            malformed_subject.into_tuple().unwrap_err().kind(),
            StoreErrorKind::CorruptData
        );

        let conditional = fixture.clone().with_condition(context(BTreeMap::new()));
        let mut malformed_context = TupleRow::from_tuple(&conditional).unwrap();
        malformed_context.context_json = Some("[]".to_owned());
        assert_eq!(
            malformed_context.into_tuple().unwrap_err().kind(),
            StoreErrorKind::CorruptData
        );

        let mut bad_digest = TupleRow::from_tuple(&fixture).unwrap();
        bad_digest.identity_digest[0] ^= 0xff;
        assert_eq!(
            bad_digest.into_tuple().unwrap_err().kind(),
            StoreErrorKind::CorruptData
        );
    }

    #[test]
    fn persisted_context_byte_and_element_limits_are_enforced() {
        let fixture = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()));
        let byte_limit = relgraph_authz::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES;
        let element_limit = relgraph_authz::MAX_CONDITION_CONTEXT_ELEMENTS;

        let oversized_write = fixture.clone().with_condition(context(BTreeMap::from([(
            "payload".to_owned(),
            Value::String("x".repeat(byte_limit)),
        )])));
        assert_eq!(
            TupleRow::from_tuple(&oversized_write).unwrap_err().kind(),
            StoreErrorKind::InvalidInput
        );

        let too_many_values = || {
            context(BTreeMap::from([(
                "items".to_owned(),
                Value::Array(vec![Value::Null; element_limit + 1]),
            )]))
        };
        let oversized_elements_write = fixture.clone().with_condition(too_many_values());
        assert_eq!(
            TupleRow::from_tuple(&oversized_elements_write)
                .unwrap_err()
                .kind(),
            StoreErrorKind::InvalidInput
        );

        let empty_condition = fixture.clone().with_condition(context(BTreeMap::new()));
        let mut oversized_decode = TupleRow::from_tuple(&empty_condition).unwrap();
        // Whitespace is valid JSON and would otherwise decode to the same empty
        // context and digest, so this specifically verifies the raw-byte guard.
        oversized_decode.context_json = Some(format!("{}{{}}", " ".repeat(byte_limit)));
        assert_eq!(
            oversized_decode.into_tuple().unwrap_err().kind(),
            StoreErrorKind::CorruptData
        );

        let decoded_context = too_many_values();
        let oversized_tuple = fixture.clone().with_condition(decoded_context.clone());
        let mut oversized_elements_decode = TupleRow::from_tuple(&empty_condition).unwrap();
        oversized_elements_decode.context_json =
            Some(serde_json::to_string(decoded_context.values()).unwrap());
        oversized_elements_decode.identity_digest =
            tuple_identity_digest(&oversized_tuple).unwrap().to_vec();
        assert_eq!(
            oversized_elements_decode.into_tuple().unwrap_err().kind(),
            StoreErrorKind::CorruptData
        );
    }

    #[test]
    fn context_presence_must_match_and_identifier_constructors_validate_rows() {
        let fixture = tuple(TupleSubject::Direct(Subject::new("user", "alice").unwrap()));
        let mut one_sided_context = TupleRow::from_tuple(&fixture).unwrap();
        one_sided_context.context_json = Some("{}".to_owned());
        assert_eq!(
            one_sided_context.into_tuple().unwrap_err().kind(),
            StoreErrorKind::CorruptData
        );

        let mut invalid_tenant = TupleRow::from_tuple(&fixture).unwrap();
        invalid_tenant.tenant = "\n".to_owned();
        assert_eq!(
            invalid_tenant.into_tuple().unwrap_err().kind(),
            StoreErrorKind::CorruptData
        );
    }
}
