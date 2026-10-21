use crate::{PostgresRelationshipStore, mapping::TupleRow};
use relgraph_authz::{
    ObjectRef, RelationName, RelationshipPage, RelationshipReadSession, RelationshipStore,
    RelationshipTuple, ReverseLookupSession, StoreCursor, StoreError, StoreErrorKind, StoreFuture,
    TenantId, TupleSubject, TypeName,
};
use sqlx::{Postgres, Transaction};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

const MAX_PAGE_SIZE: usize = 128;
/// Marks a cursor of the object/relation query (`tuples_page`).
const OBJECT_CURSOR_MAGIC: &[u8; 4] = b"FGRD";
/// Marks a cursor of the object-type/relation/subject query
/// (`tuples_by_subject_page`), so neither query accepts the other's cursor.
const SUBJECT_CURSOR_MAGIC: &[u8; 4] = b"FGRS";
const CURSOR_VERSION: u8 = 1;
const MAX_CURSOR_BYTES: usize = 2_048;
const MAX_CURSOR_COMPONENT_BYTES: usize = 512;
const READ_UNAVAILABLE: &str = "PostgreSQL relationship store is unavailable";
const READ_FAILURE: &str = "PostgreSQL relationship store operation failed";
const CORRUPT_ROW: &str = "persisted relationship tuple is malformed";
const INVALID_CURSOR: &str = "relationship page cursor is invalid for this read";
const CURSOR_ENCODING_FAILURE: &str = "relationship page cursor could not be encoded";

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Builds a page query over the decoded tuple columns. Oversized condition
/// contexts are masked by `$context_limit` before SQLx materializes them.
macro_rules! select_tuple_page {
    ($context_limit:literal, $filter:literal) => {
        concat!(
            "SELECT tuple_id, tenant, object_type, object_id, relation, \
             subject_kind, subject_type, subject_id, subject_relation, condition_name, \
             CASE WHEN context_json IS NOT NULL AND octet_length(context_json) > ",
            $context_limit,
            " THEN NULL::text ELSE context_json END AS context_json, \
             COALESCE(octet_length(context_json) > ",
            $context_limit,
            ", false) AS context_json_oversized, \
             identity_digest \
             FROM relgraph_authz.relationship_tuples WHERE ",
            $filter
        )
    };
}

const SELECT_PAGE: &str = select_tuple_page!(
    "$7",
    "tenant = $1 AND object_type = $2 AND object_id = $3 AND relation = $4 \
     AND tuple_id > $5 ORDER BY tuple_id LIMIT $6"
);

/// Reverse lookup by exact subject. A missing subject ID or relation is
/// compared as `''`, which no stored value can equal (the schema requires one
/// byte or more), so all three subject kinds share one query shape and the
/// `relationship_tuples_subject_lookup_idx` expression index of migration
/// 0002: every predicate before `tuple_id` is an equality, so the index
/// returns rows in keyset order without a sort.
const SELECT_SUBJECT_PAGE: &str = select_tuple_page!(
    "$10",
    "tenant = $1 AND object_type = $2 AND relation = $3 \
     AND subject_kind = $4 AND subject_type = $5 \
     AND COALESCE(subject_id, '') = $6 AND COALESCE(subject_relation, '') = $7 \
     AND tuple_id > $8 ORDER BY tuple_id LIMIT $9"
);

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
            let mut transaction = self
                .pool
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

            let query = PageQuery::Object { object, relation };
            let mut tuples = Vec::new();
            let mut cursor: Option<StoreCursor> = None;
            loop {
                let remaining = maximum - tuples.len();
                let page_size = remaining.min(MAX_PAGE_SIZE);
                let after_id = match cursor.as_ref() {
                    Some(cursor) => {
                        Some(decode_cursor(cursor, self.session_id, &self.tenant, query)?)
                    }
                    None => None,
                };
                let page = query_page(
                    &mut transaction,
                    self.session_id,
                    &self.tenant,
                    query,
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
        self.page(PageQuery::Object { object, relation }, cursor, maximum)
    }
}

impl ReverseLookupSession for PostgresReadSession {
    /// Pages the session's tenant snapshot by exact subject in `tuple_id`
    /// order, on the same repeatable-read transaction as every other read.
    fn tuples_by_subject_page<'a>(
        &'a self,
        object_type: &'a TypeName,
        relation: &'a RelationName,
        subject: &'a TupleSubject,
        cursor: Option<StoreCursor>,
        maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
        self.page(
            PageQuery::Subject {
                object_type,
                relation,
                subject: SubjectKey::new(subject),
            },
            cursor,
            maximum,
        )
    }
}

impl PostgresReadSession {
    /// Reads one keyset page of `query`, continuing after the cursor's
    /// `tuple_id` once the cursor is proven to belong to this session, tenant
    /// and query.
    fn page<'a>(
        &'a self,
        query: PageQuery<'a>,
        cursor: Option<StoreCursor>,
        maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
        Box::pin(async move {
            if maximum == 0 {
                return Err(incomplete_read_error());
            }

            let after_id = cursor
                .as_ref()
                .map(|cursor| decode_cursor(cursor, self.session_id, &self.tenant, query))
                .transpose()?;

            let page_size = maximum.min(MAX_PAGE_SIZE);
            let mut transaction = self.transaction.lock().await;
            query_page(
                &mut transaction,
                self.session_id,
                &self.tenant,
                query,
                after_id,
                page_size,
            )
            .await
        })
    }
}

/// A subject in its stored column form; a missing ID or userset relation is
/// `""`, matching the `COALESCE(…, '')` of [`SELECT_SUBJECT_PAGE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SubjectKey<'a> {
    kind: &'static str,
    type_name: &'a str,
    id: &'a str,
    relation: &'a str,
}

impl<'a> SubjectKey<'a> {
    fn new(subject: &'a TupleSubject) -> Self {
        let (kind, type_name, id, relation) = crate::mapping::subject_columns(subject);
        Self {
            kind,
            type_name,
            id: id.unwrap_or(""),
            relation: relation.unwrap_or(""),
        }
    }
}

/// The query a page answers. Its fields are bound into the SQL and, with the
/// tenant and session, into every continuation cursor it issues.
#[derive(Clone, Copy, Debug)]
enum PageQuery<'a> {
    Object {
        object: &'a ObjectRef,
        relation: &'a RelationName,
    },
    Subject {
        object_type: &'a TypeName,
        relation: &'a RelationName,
        subject: SubjectKey<'a>,
    },
}

impl<'a> PageQuery<'a> {
    fn cursor_magic(self) -> &'static [u8; 4] {
        match self {
            Self::Object { .. } => OBJECT_CURSOR_MAGIC,
            Self::Subject { .. } => SUBJECT_CURSOR_MAGIC,
        }
    }

    /// The tenant followed by the query fields, as encoded in a cursor.
    fn cursor_parts(self, tenant: &'a TenantId) -> Vec<&'a [u8]> {
        let fields: Vec<&'a str> = match self {
            Self::Object { object, relation } => vec![
                object.type_name().as_str(),
                object.id().as_str(),
                relation.as_str(),
            ],
            Self::Subject {
                object_type,
                relation,
                subject,
            } => vec![
                object_type.as_str(),
                relation.as_str(),
                subject.kind,
                subject.type_name,
                subject.id,
                subject.relation,
            ],
        };
        std::iter::once(tenant.as_str())
            .chain(fields)
            .map(str::as_bytes)
            .collect()
    }
}

async fn query_page(
    transaction: &mut Transaction<'static, Postgres>,
    session_id: u64,
    tenant: &TenantId,
    query: PageQuery<'_>,
    after_id: Option<i64>,
    page_size: usize,
) -> Result<RelationshipPage, StoreError> {
    debug_assert!(page_size > 0 && page_size <= MAX_PAGE_SIZE);
    let fetch_limit = i64::try_from(page_size + 1)
        .map_err(|_| StoreError::new(StoreErrorKind::Internal, READ_FAILURE))?;
    let context_limit = relgraph_authz::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES as i32;
    let statement = match query {
        PageQuery::Object { object, relation } => sqlx::query_as::<_, TupleRow>(SELECT_PAGE)
            .bind(tenant.as_str())
            .bind(object.type_name().as_str())
            .bind(object.id().as_str())
            .bind(relation.as_str())
            .bind(after_id.unwrap_or(0))
            .bind(fetch_limit)
            .bind(context_limit),
        PageQuery::Subject {
            object_type,
            relation,
            subject,
        } => sqlx::query_as::<_, TupleRow>(SELECT_SUBJECT_PAGE)
            .bind(tenant.as_str())
            .bind(object_type.as_str())
            .bind(relation.as_str())
            .bind(subject.kind)
            .bind(subject.type_name)
            .bind(subject.id)
            .bind(subject.relation)
            .bind(after_id.unwrap_or(0))
            .bind(fetch_limit)
            .bind(context_limit),
    };
    let rows = statement
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
        Some(encode_cursor(session_id, tenant, query, last_id)?)
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

/// Encodes a continuation after `last_id`: the query kind's magic, the
/// version, the session ID, each length-prefixed tenant and query field, then
/// `last_id`.
fn encode_cursor(
    session_id: u64,
    tenant: &TenantId,
    query: PageQuery<'_>,
    last_id: i64,
) -> Result<StoreCursor, StoreError> {
    if last_id <= 0 {
        return Err(corrupt_row_error());
    }

    let parts = query.cursor_parts(tenant);
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
    bytes.extend_from_slice(query.cursor_magic());
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

/// Returns the `last_id` of a cursor that this session issued for this tenant
/// and query; any other cursor is an incomplete read.
fn decode_cursor(
    cursor: &StoreCursor,
    session_id: u64,
    tenant: &TenantId,
    query: PageQuery<'_>,
) -> Result<i64, StoreError> {
    let bytes = cursor.as_bytes();
    let expected_parts = query.cursor_parts(tenant);
    if bytes.len() > MAX_CURSOR_BYTES || bytes.len() < 4 + 1 + 8 + 4 * expected_parts.len() + 8 {
        return Err(incomplete_read_error());
    }
    if &bytes[..4] != query.cursor_magic() || bytes[4] != CURSOR_VERSION {
        return Err(incomplete_read_error());
    }

    let mut offset = 5;
    let encoded_session = take_u64(bytes, &mut offset).ok_or_else(incomplete_read_error)?;
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
    use super::{
        MAX_CURSOR_BYTES, MAX_CURSOR_COMPONENT_BYTES, PageQuery, SELECT_PAGE, SELECT_SUBJECT_PAGE,
        SubjectKey,
    };
    use relgraph_authz::{
        ObjectRef, RelationName, StoreCursor, StoreError, StoreErrorKind, Subject, TenantId,
        TupleSubject, TypeName,
    };

    /// Encodes an object/relation (`tuples_page`) cursor.
    fn encode_cursor(
        session_id: u64,
        tenant: &TenantId,
        object: &ObjectRef,
        relation: &RelationName,
        last_id: i64,
    ) -> Result<StoreCursor, StoreError> {
        super::encode_cursor(
            session_id,
            tenant,
            PageQuery::Object { object, relation },
            last_id,
        )
    }

    /// Decodes an object/relation (`tuples_page`) cursor.
    fn decode_cursor(
        cursor: &StoreCursor,
        session_id: u64,
        tenant: &TenantId,
        object: &ObjectRef,
        relation: &RelationName,
    ) -> Result<i64, StoreError> {
        super::decode_cursor(
            cursor,
            session_id,
            tenant,
            PageQuery::Object { object, relation },
        )
    }

    fn subject_query<'a>(
        object_type: &'a TypeName,
        relation: &'a RelationName,
        subject: &'a TupleSubject,
    ) -> PageQuery<'a> {
        PageQuery::Subject {
            object_type,
            relation,
            subject: SubjectKey::new(subject),
        }
    }

    fn subjects() -> [TupleSubject; 4] {
        [
            TupleSubject::Direct(Subject::new("user", "anne").unwrap()),
            TupleSubject::Direct(Subject::new("user", "*").unwrap()),
            TupleSubject::Userset {
                object: ObjectRef::new("user", "anne").unwrap(),
                relation: RelationName::new("member").unwrap(),
            },
            TupleSubject::TypedWildcard(TypeName::new("user").unwrap()),
        ]
    }

    #[test]
    fn subject_keys_bind_the_stored_column_form() {
        let [direct, star_id, userset, wildcard] = subjects();
        assert_eq!(
            SubjectKey::new(&direct),
            SubjectKey {
                kind: "direct",
                type_name: "user",
                id: "anne",
                relation: "",
            }
        );
        assert_eq!(
            SubjectKey::new(&star_id),
            SubjectKey {
                kind: "direct",
                type_name: "user",
                id: "*",
                relation: "",
            }
        );
        assert_eq!(
            SubjectKey::new(&userset),
            SubjectKey {
                kind: "userset",
                type_name: "user",
                id: "anne",
                relation: "member",
            }
        );
        assert_eq!(
            SubjectKey::new(&wildcard),
            SubjectKey {
                kind: "typed_wildcard",
                type_name: "user",
                id: "",
                relation: "",
            }
        );
    }

    #[test]
    fn subject_page_query_is_tenant_scoped_exact_and_keyset_ordered() {
        let sql = SELECT_SUBJECT_PAGE
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(sql.contains(
            "WHERE tenant = $1 AND object_type = $2 AND relation = $3 \
             AND subject_kind = $4 AND subject_type = $5 \
             AND COALESCE(subject_id, '') = $6 AND COALESCE(subject_relation, '') = $7 \
             AND tuple_id > $8 ORDER BY tuple_id LIMIT $9"
        ));
        assert!(sql.contains("octet_length(context_json) > $10"));
        assert!(sql.contains("THEN NULL::text ELSE context_json END AS context_json"));
        assert!(sql.contains("COALESCE(octet_length(context_json) > $10, false)"));
        // Both page queries decode the same columns.
        let columns = |sql: &str| sql.split(" WHERE ").next().unwrap().replace("$10", "$7");
        assert_eq!(columns(SELECT_SUBJECT_PAGE), columns(SELECT_PAGE));
    }

    #[test]
    fn subject_cursor_round_trips_for_its_session_tenant_and_query() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let object_type = TypeName::new("document").unwrap();
        let relation = RelationName::new("viewer").unwrap();
        for subject in subjects() {
            let query = subject_query(&object_type, &relation, &subject);
            let cursor = super::encode_cursor(17, &tenant, query, 42).unwrap();
            assert_eq!(
                super::decode_cursor(&cursor, 17, &tenant, query).unwrap(),
                42
            );
        }
    }

    #[test]
    fn subject_cursor_rejects_other_sessions_tenants_queries_and_subjects() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let object_type = TypeName::new("document").unwrap();
        let relation = RelationName::new("viewer").unwrap();
        let other_type = TypeName::new("folder").unwrap();
        let other_relation = RelationName::new("editor").unwrap();
        let other_tenant = TenantId::new("tenant-b").unwrap();
        let subjects = subjects();
        for (index, subject) in subjects.iter().enumerate() {
            let query = subject_query(&object_type, &relation, subject);
            let cursor = super::encode_cursor(17, &tenant, query, 9).unwrap();
            let mut rejected = vec![
                (18, &tenant, query),
                (17, &other_tenant, query),
                (17, &tenant, subject_query(&other_type, &relation, subject)),
                (
                    17,
                    &tenant,
                    subject_query(&object_type, &other_relation, subject),
                ),
            ];
            for (other_index, other) in subjects.iter().enumerate() {
                if other_index != index {
                    rejected.push((17, &tenant, subject_query(&object_type, &relation, other)));
                }
            }
            for (session_id, tenant, query) in rejected {
                assert_eq!(
                    super::decode_cursor(&cursor, session_id, tenant, query)
                        .unwrap_err()
                        .kind(),
                    StoreErrorKind::IncompleteRead
                );
            }
        }
    }

    #[test]
    fn object_and_subject_cursors_are_not_interchangeable() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let object = ObjectRef::new("document", "report-1").unwrap();
        let object_type = TypeName::new("document").unwrap();
        let relation = RelationName::new("viewer").unwrap();
        let subject = TupleSubject::Direct(Subject::new("user", "anne").unwrap());
        let object_query = PageQuery::Object {
            object: &object,
            relation: &relation,
        };
        let subject_query = subject_query(&object_type, &relation, &subject);

        let object_cursor = super::encode_cursor(17, &tenant, object_query, 9).unwrap();
        let subject_cursor = super::encode_cursor(17, &tenant, subject_query, 9).unwrap();
        for (cursor, query) in [
            (&object_cursor, subject_query),
            (&subject_cursor, object_query),
        ] {
            assert_eq!(
                super::decode_cursor(cursor, 17, &tenant, query)
                    .unwrap_err()
                    .kind(),
                StoreErrorKind::IncompleteRead
            );
        }
    }

    #[test]
    fn subject_cursor_rejects_truncation_trailing_bytes_and_bad_versions() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let object_type = TypeName::new("document").unwrap();
        let relation = RelationName::new("viewer").unwrap();
        let subject = TupleSubject::TypedWildcard(TypeName::new("user").unwrap());
        let query = subject_query(&object_type, &relation, &subject);
        let cursor = super::encode_cursor(17, &tenant, query, 9).unwrap();
        for bytes in [
            cursor.as_bytes()[..cursor.as_bytes().len() - 1].to_vec(),
            [cursor.as_bytes(), &[0]].concat(),
            {
                let mut bytes = cursor.as_bytes().to_vec();
                bytes[4] = 2;
                bytes
            },
            Vec::new(),
        ] {
            assert_eq!(
                super::decode_cursor(&StoreCursor::from_bytes(bytes), 17, &tenant, query)
                    .unwrap_err()
                    .kind(),
                StoreErrorKind::IncompleteRead
            );
        }
    }

    #[test]
    fn subject_cursor_of_the_largest_identifiers_fits_the_cursor_bound() {
        // The schema's per-column maxima: 128 bytes for names, 256 for IDs.
        let name = "n".repeat(128);
        let id = "i".repeat(256);
        let tenant = TenantId::new(name.clone()).unwrap();
        let object_type = TypeName::new(name.clone()).unwrap();
        let relation = RelationName::new(name.clone()).unwrap();
        let subject = TupleSubject::Userset {
            object: ObjectRef::new(name.clone(), id).unwrap(),
            relation: RelationName::new(name).unwrap(),
        };
        let query = subject_query(&object_type, &relation, &subject);
        let cursor = super::encode_cursor(17, &tenant, query, i64::MAX).unwrap();
        assert!(cursor.as_bytes().len() <= MAX_CURSOR_BYTES);
        assert_eq!(
            super::decode_cursor(&cursor, 17, &tenant, query).unwrap(),
            i64::MAX
        );
    }

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

    #[test]
    fn page_query_masks_oversized_context_before_sqlx_materializes_it() {
        assert!(SELECT_PAGE.contains("octet_length(context_json) > $7"));
        assert!(SELECT_PAGE.contains("THEN NULL::text ELSE context_json END AS context_json"));
        assert!(SELECT_PAGE.contains("AS context_json_oversized"));
    }
}
