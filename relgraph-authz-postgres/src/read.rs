use crate::{PostgresRelationshipStore, mapping::TupleRow};
use relgraph_authz::{
    ObjectRef, RelationName, RelationshipPage, RelationshipReadSession, RelationshipStore,
    RelationshipTuple, StoreCursor, StoreError, StoreErrorKind, StoreFuture, TenantId,
};
use sqlx::{Postgres, Transaction};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

const MAX_PAGE_SIZE: usize = 128;
const CURSOR_MAGIC: &[u8; 4] = b"FGRD";
const CURSOR_VERSION: u8 = 1;
const MAX_CURSOR_BYTES: usize = 2_048;
const MAX_CURSOR_COMPONENT_BYTES: usize = 512;
const READ_UNAVAILABLE: &str = "PostgreSQL relationship store is unavailable";
const READ_FAILURE: &str = "PostgreSQL relationship store operation failed";
const CORRUPT_ROW: &str = "persisted relationship tuple is malformed";
const INVALID_CURSOR: &str = "relationship page cursor is invalid for this read";
const CURSOR_ENCODING_FAILURE: &str = "relationship page cursor could not be encoded";

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

const SELECT_PAGE: &str = "SELECT tuple_id, tenant, object_type, object_id, relation, \
    subject_kind, subject_type, subject_id, subject_relation, condition_name, \
    context_json, identity_digest \
    FROM relgraph_authz.relationship_tuples \
    WHERE tenant = $1 AND object_type = $2 AND object_id = $3 AND relation = $4 \
    AND tuple_id > $5 ORDER BY tuple_id LIMIT $6";

const SELECT_EXISTS: &str = "SELECT EXISTS( \
    SELECT 1 FROM relgraph_authz.relationship_tuples \
    WHERE tenant = $1 AND object_type = $2 AND object_id = $3 AND relation = $4 \
    )";

/// A database read snapshot held for one authorization check.
///
/// Dropping the session drops its SQLx transaction. SQLx schedules rollback
/// cleanup before the connection can be reused; that asynchronous cleanup is
/// eventual rather than synchronous with `Drop`.
pub struct PostgresReadSession {
    transaction: Mutex<Transaction<'static, Postgres>>,
    tenant: TenantId,
    session_id: u64,
}

impl RelationshipStore for PostgresRelationshipStore {
    type ReadSession = PostgresReadSession;

    fn begin_read<'a>(
        &'a self,
        tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        Box::pin(async move {
            let mut transaction = (&self.pool)
                .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .await
                .map_err(|error| map_sqlx_error(&error))?;

            // A repeatable-read snapshot is assigned by the first query. Force
            // that query here so every later page uses the same snapshot.
            sqlx::query_scalar::<_, String>("SELECT pg_current_snapshot()::text")
                .fetch_one(&mut *transaction)
                .await
                .map_err(|error| map_sqlx_error(&error))?;

            let session_id = next_session_id()?;
            Ok(PostgresReadSession {
                transaction: Mutex::new(transaction),
                tenant: tenant.clone(),
                session_id,
            })
        })
    }
}

impl RelationshipReadSession for PostgresReadSession {
    fn tuples<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        Box::pin(async move {
            let mut transaction = self.transaction.lock().await;

            if maximum == 0 {
                let exists = sqlx::query_scalar::<_, bool>(SELECT_EXISTS)
                    .bind(self.tenant.as_str())
                    .bind(object.type_name().as_str())
                    .bind(object.id().as_str())
                    .bind(relation.as_str())
                    .fetch_one(&mut **transaction)
                    .await
                    .map_err(|error| map_sqlx_error(&error))?;
                return if exists {
                    Err(tuple_limit_error(0))
                } else {
                    Ok(Vec::new())
                };
            }

            let mut tuples = Vec::new();
            let mut cursor: Option<StoreCursor> = None;
            loop {
                let remaining = maximum - tuples.len();
                let page_size = remaining.min(MAX_PAGE_SIZE);
                let after_id = match cursor.as_ref() {
                    Some(cursor) => Some(decode_cursor(
                        cursor,
                        self.session_id,
                        &self.tenant,
                        object,
                        relation,
                    )?),
                    None => None,
                };
                let page = query_page(
                    &mut transaction,
                    self.session_id,
                    &self.tenant,
                    object,
                    relation,
                    after_id,
                    page_size,
                )
                .await?;

                if page.tuples.is_empty() && page.next_cursor.is_some() {
                    return Err(incomplete_read_error());
                }
                tuples.extend(page.tuples);
                match page.next_cursor {
                    Some(_) if tuples.len() >= maximum => {
                        return Err(tuple_limit_error(maximum));
                    }
                    Some(next_cursor) => cursor = Some(next_cursor),
                    None => return Ok(tuples),
                }
            }
        })
    }

    fn tuples_page<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        cursor: Option<StoreCursor>,
        maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
        Box::pin(async move {
            if maximum == 0 {
                return Err(incomplete_read_error());
            }

            let after_id = cursor
                .as_ref()
                .map(|cursor| {
                    decode_cursor(cursor, self.session_id, &self.tenant, object, relation)
                })
                .transpose()?;

            let page_size = maximum.min(MAX_PAGE_SIZE);
            let mut transaction = self.transaction.lock().await;
            query_page(
                &mut transaction,
                self.session_id,
                &self.tenant,
                object,
                relation,
                after_id,
                page_size,
            )
            .await
        })
    }
}

async fn query_page(
    transaction: &mut Transaction<'static, Postgres>,
    session_id: u64,
    tenant: &TenantId,
    object: &ObjectRef,
    relation: &RelationName,
    after_id: Option<i64>,
    page_size: usize,
) -> Result<RelationshipPage, StoreError> {
    debug_assert!(page_size > 0 && page_size <= MAX_PAGE_SIZE);
    let fetch_limit = i64::try_from(page_size + 1)
        .map_err(|_| StoreError::new(StoreErrorKind::Internal, READ_FAILURE))?;
    let rows = sqlx::query_as::<_, TupleRow>(SELECT_PAGE)
        .bind(tenant.as_str())
        .bind(object.type_name().as_str())
        .bind(object.id().as_str())
        .bind(relation.as_str())
        .bind(after_id.unwrap_or(0))
        .bind(fetch_limit)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| map_sqlx_error(&error))?;

    let has_more = rows.len() > page_size;
    let mut decoded = Vec::with_capacity(rows.len().min(page_size + 1));
    for row in rows {
        let tuple_id = row.tuple_id.ok_or_else(corrupt_row_error)?;
        if tuple_id <= 0 {
            return Err(corrupt_row_error());
        }
        let tuple = row.into_tuple()?;
        decoded.push((tuple_id, tuple));
    }

    if has_more && decoded.len() <= page_size {
        return Err(corrupt_row_error());
    }
    let next_cursor = if has_more {
        let last_id = decoded
            .get(page_size - 1)
            .map(|(tuple_id, _)| *tuple_id)
            .ok_or_else(corrupt_row_error)?;
        Some(encode_cursor(
            session_id, tenant, object, relation, last_id,
        )?)
    } else {
        None
    };

    Ok(RelationshipPage {
        tuples: decoded
            .into_iter()
            .take(page_size)
            .map(|(_, tuple)| tuple)
            .collect(),
        next_cursor,
    })
}

fn next_session_id() -> Result<u64, StoreError> {
    NEXT_SESSION_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| {
            StoreError::new(
                StoreErrorKind::Internal,
                "relationship read session identifier space is exhausted",
            )
        })
}

fn encode_cursor(
    session_id: u64,
    tenant: &TenantId,
    object: &ObjectRef,
    relation: &RelationName,
    last_id: i64,
) -> Result<StoreCursor, StoreError> {
    if last_id <= 0 {
        return Err(corrupt_row_error());
    }

    let parts = [
        tenant.as_str().as_bytes(),
        object.type_name().as_str().as_bytes(),
        object.id().as_str().as_bytes(),
        relation.as_str().as_bytes(),
    ];
    let total_len = parts.iter().try_fold(4usize + 1 + 8 + 8, |total, part| {
        total.checked_add(4)?.checked_add(part.len())
    });
    let total_len = total_len.ok_or_else(cursor_encoding_error)?;
    if total_len > MAX_CURSOR_BYTES
        || parts
            .iter()
            .any(|part| part.len() > MAX_CURSOR_COMPONENT_BYTES)
    {
        return Err(cursor_encoding_error());
    }

    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(CURSOR_MAGIC);
    bytes.push(CURSOR_VERSION);
    bytes.extend_from_slice(&session_id.to_be_bytes());
    for part in parts {
        let length = u32::try_from(part.len()).map_err(|_| cursor_encoding_error())?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(part);
    }
    bytes.extend_from_slice(&last_id.to_be_bytes());
    Ok(StoreCursor::from_bytes(bytes))
}

fn decode_cursor(
    cursor: &StoreCursor,
    session_id: u64,
    tenant: &TenantId,
    object: &ObjectRef,
    relation: &RelationName,
) -> Result<i64, StoreError> {
    let bytes = cursor.as_bytes();
    if bytes.len() > MAX_CURSOR_BYTES || bytes.len() < 4 + 1 + 8 + 4 * 4 + 8 {
        return Err(incomplete_read_error());
    }
    if &bytes[..4] != CURSOR_MAGIC || bytes[4] != CURSOR_VERSION {
        return Err(incomplete_read_error());
    }

    let mut offset = 5;
    let encoded_session = take_u64(bytes, &mut offset).ok_or_else(incomplete_read_error)?;
    let expected_parts = [
        tenant.as_str().as_bytes(),
        object.type_name().as_str().as_bytes(),
        object.id().as_str().as_bytes(),
        relation.as_str().as_bytes(),
    ];
    for expected in expected_parts {
        let encoded = take_component(bytes, &mut offset).ok_or_else(incomplete_read_error)?;
        if encoded != expected {
            return Err(incomplete_read_error());
        }
    }
    let last_id = take_i64(bytes, &mut offset).ok_or_else(incomplete_read_error)?;
    if offset != bytes.len() || encoded_session != session_id || last_id <= 0 {
        return Err(incomplete_read_error());
    }
    Ok(last_id)
}

fn take_component<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let length = usize::try_from(take_u32(bytes, offset)?).ok()?;
    if length > MAX_CURSOR_COMPONENT_BYTES {
        return None;
    }
    let end = (*offset).checked_add(length)?;
    let component = bytes.get(*offset..end)?;
    *offset = end;
    Some(component)
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    let end = (*offset).checked_add(4)?;
    let value = u32::from_be_bytes(bytes.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    Some(value)
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    let end = (*offset).checked_add(8)?;
    let value = u64::from_be_bytes(bytes.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    Some(value)
}

fn take_i64(bytes: &[u8], offset: &mut usize) -> Option<i64> {
    let end = (*offset).checked_add(8)?;
    let value = i64::from_be_bytes(bytes.get(*offset..end)?.try_into().ok()?);
    *offset = end;
    Some(value)
}

fn incomplete_read_error() -> StoreError {
    StoreError::new(StoreErrorKind::IncompleteRead, INVALID_CURSOR)
}

fn tuple_limit_error(maximum: usize) -> StoreError {
    StoreError::new(
        StoreErrorKind::TupleLimitExceeded,
        format!("more than {maximum} matching tuples were present"),
    )
}

fn cursor_encoding_error() -> StoreError {
    StoreError::new(StoreErrorKind::Internal, CURSOR_ENCODING_FAILURE)
}

/// Maps SQLx failures to fixed public errors without including database details.
pub(crate) fn map_sqlx_error(error: &sqlx::Error) -> StoreError {
    match error {
        sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::Protocol(_)
        | sqlx::Error::WorkerCrashed => {
            StoreError::new(StoreErrorKind::Unavailable, READ_UNAVAILABLE)
        }
        sqlx::Error::Database(database) => {
            let unavailable = database.code().as_deref().is_some_and(|code| {
                code.starts_with("08")
                    || matches!(code, "57014" | "53300" | "57P01" | "57P02" | "57P03")
            });
            if unavailable {
                StoreError::new(StoreErrorKind::Unavailable, READ_UNAVAILABLE)
            } else {
                StoreError::new(StoreErrorKind::Internal, READ_FAILURE)
            }
        }
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => corrupt_row_error(),
        _ => StoreError::new(StoreErrorKind::Internal, READ_FAILURE),
    }
}

pub(crate) fn corrupt_row_error() -> StoreError {
    StoreError::new(StoreErrorKind::CorruptData, CORRUPT_ROW)
}

#[cfg(test)]
mod tests {
    use super::{MAX_CURSOR_BYTES, MAX_CURSOR_COMPONENT_BYTES, decode_cursor, encode_cursor};
    use relgraph_authz::{ObjectRef, RelationName, StoreCursor, StoreErrorKind, TenantId};

    fn query() -> (TenantId, ObjectRef, RelationName) {
        (
            TenantId::new("tenant-a").unwrap(),
            ObjectRef::new("document", "report-1").unwrap(),
            RelationName::new("viewer").unwrap(),
        )
    }

    #[test]
    fn cursor_round_trips_for_its_session_and_query() {
        let (tenant, object, relation) = query();
        let cursor = encode_cursor(17, &tenant, &object, &relation, 9_223).unwrap();
        assert_eq!(
            decode_cursor(&cursor, 17, &tenant, &object, &relation).unwrap(),
            9_223
        );
    }

    #[test]
    fn cursor_rejects_other_sessions_tenants_objects_and_relations() {
        let (tenant, object, relation) = query();
        let cursor = encode_cursor(17, &tenant, &object, &relation, 9).unwrap();
        let other_tenant = TenantId::new("tenant-b").unwrap();
        let other_object = ObjectRef::new("document", "report-2").unwrap();
        let other_relation = RelationName::new("editor").unwrap();

        assert_eq!(
            decode_cursor(&cursor, 18, &tenant, &object, &relation)
                .unwrap_err()
                .kind(),
            StoreErrorKind::IncompleteRead
        );
        assert_eq!(
            decode_cursor(&cursor, 17, &other_tenant, &object, &relation)
                .unwrap_err()
                .kind(),
            StoreErrorKind::IncompleteRead
        );
        assert_eq!(
            decode_cursor(&cursor, 17, &tenant, &other_object, &relation)
                .unwrap_err()
                .kind(),
            StoreErrorKind::IncompleteRead
        );
        assert_eq!(
            decode_cursor(&cursor, 17, &tenant, &object, &other_relation)
                .unwrap_err()
                .kind(),
            StoreErrorKind::IncompleteRead
        );
    }

    #[test]
    fn cursor_rejects_truncation_trailing_bytes_bad_versions_and_oversized_data() {
        let (tenant, object, relation) = query();
        let cursor = encode_cursor(17, &tenant, &object, &relation, 9).unwrap();
        for bytes in [
            cursor.as_bytes()[..cursor.as_bytes().len() - 1].to_vec(),
            [cursor.as_bytes(), &[0]].concat(),
            {
                let mut bytes = cursor.as_bytes().to_vec();
                bytes[4] = 2;
                bytes
            },
            vec![0; MAX_CURSOR_BYTES + 1],
        ] {
            let malformed = StoreCursor::from_bytes(bytes);
            assert_eq!(
                decode_cursor(&malformed, 17, &tenant, &object, &relation)
                    .unwrap_err()
                    .kind(),
                StoreErrorKind::IncompleteRead
            );
        }
    }

    #[test]
    fn cursor_rejects_invalid_or_oversized_key_fields() {
        let (tenant, object, relation) = query();
        for last_id in [0, -1] {
            assert!(encode_cursor(17, &tenant, &object, &relation, last_id).is_err());
        }

        let mut bytes = encode_cursor(17, &tenant, &object, &relation, 1)
            .unwrap()
            .as_bytes()
            .to_vec();
        // The first component length starts immediately after magic, version,
        // and session identity.
        let component_length_offset = 4 + 1 + 8;
        bytes[component_length_offset..component_length_offset + 4]
            .copy_from_slice(&((MAX_CURSOR_COMPONENT_BYTES as u32) + 1).to_be_bytes());
        assert_eq!(
            decode_cursor(
                &StoreCursor::from_bytes(bytes),
                17,
                &tenant,
                &object,
                &relation,
            )
            .unwrap_err()
            .kind(),
            StoreErrorKind::IncompleteRead
        );
    }

    #[test]
    fn malformed_empty_cursor_is_an_incomplete_read() {
        let (tenant, object, relation) = query();
        assert_eq!(
            decode_cursor(
                &StoreCursor::from_bytes(Vec::new()),
                17,
                &tenant,
                &object,
                &relation,
            )
            .unwrap_err()
            .kind(),
            StoreErrorKind::IncompleteRead
        );
    }
}
