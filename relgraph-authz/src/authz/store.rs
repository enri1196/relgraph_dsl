use super::request::{ConditionName, ObjectRef, RelationName, Subject, TenantId, TypeName};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// The boxed future type used by asynchronous relationship-store adapters.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Maximum compact JSON byte length for a persisted condition context.
pub const MAX_CONDITION_CONTEXT_SERIALIZED_BYTES: usize = 65_536;

/// Maximum number of entries across a persisted condition context's JSON maps and arrays.
pub const MAX_CONDITION_CONTEXT_ELEMENTS: usize = 10_000;

/// An opaque continuation token returned by a relationship store.
///
/// Callers should pass this value back unchanged. Its bytes are not a security
/// credential and callers must not interpret them. A cursor is valid only for
/// the read session and object/relation query that produced it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoreCursor(Vec<u8>);

impl StoreCursor {
    /// Creates an opaque cursor from backend-defined bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the backend-defined cursor bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Subject forms that may be stored in a relationship tuple.
///
/// The initial local evaluator accepts `Direct` tuples. Usersets and typed
/// wildcards are represented here for stores, then enabled by later evaluator
/// tasks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TupleSubject {
    Direct(Subject),
    Userset {
        object: ObjectRef,
        relation: RelationName,
    },
    TypedWildcard(TypeName),
}

impl From<Subject> for TupleSubject {
    fn from(subject: Subject) -> Self {
        Self::Direct(subject)
    }
}

/// A named condition and its persisted context values on a relationship tuple.
#[derive(Clone, Debug, PartialEq)]
pub struct ConditionContext {
    name: ConditionName,
    values: std::collections::BTreeMap<String, serde_json::Value>,
}

impl ConditionContext {
    pub fn new(
        name: impl Into<String>,
        values: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, super::request::IdentifierError> {
        Ok(Self {
            name: ConditionName::new(name)?,
            values,
        })
    }

    pub fn name(&self) -> &ConditionName {
        &self.name
    }

    pub fn values(&self) -> &std::collections::BTreeMap<String, serde_json::Value> {
        &self.values
    }

    /// Returns the compact JSON byte length when this context fits storage limits.
    ///
    /// Serialization is counted through a capped writer, so this check does not
    /// allocate a second JSON string. It also rejects contexts with more than
    /// [`MAX_CONDITION_CONTEXT_ELEMENTS`] entries across all nested maps and arrays.
    pub fn serialized_size(&self) -> Result<usize, StoreError> {
        validate_context_element_count(&self.values)?;
        let mut writer = CappedContextWriter::default();
        let result = serde_json::to_writer(&mut writer, &self.values);
        if writer.exceeded {
            return Err(StoreError::new(
                StoreErrorKind::CorruptData,
                "condition context exceeds the serialized byte limit",
            ));
        }
        if result.is_err() {
            return Err(StoreError::new(
                StoreErrorKind::Internal,
                "condition context JSON serialization failed",
            ));
        }
        Ok(writer.bytes)
    }
}

#[derive(Default)]
struct CappedContextWriter {
    bytes: usize,
    exceeded: bool,
}

impl std::io::Write for CappedContextWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes.saturating_add(buffer.len()) > MAX_CONDITION_CONTEXT_SERIALIZED_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "condition context exceeds the serialized byte limit",
            ));
        }
        self.bytes += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_context_element_count(
    values: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), StoreError> {
    let mut elements = values.len();
    if elements > MAX_CONDITION_CONTEXT_ELEMENTS {
        return Err(context_element_limit_error());
    }

    let mut pending: Vec<&serde_json::Value> = values.values().collect();
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::Array(values) => {
                elements = elements.saturating_add(values.len());
                if elements > MAX_CONDITION_CONTEXT_ELEMENTS {
                    return Err(context_element_limit_error());
                }
                pending.extend(values.iter());
            }
            serde_json::Value::Object(values) => {
                elements = elements.saturating_add(values.len());
                if elements > MAX_CONDITION_CONTEXT_ELEMENTS {
                    return Err(context_element_limit_error());
                }
                pending.extend(values.values());
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }
    Ok(())
}

fn context_element_limit_error() -> StoreError {
    StoreError::new(
        StoreErrorKind::CorruptData,
        "condition context exceeds the element limit",
    )
}

/// One namespaced authorization relationship.
#[derive(Clone, Debug, PartialEq)]
pub struct RelationshipTuple {
    tenant: TenantId,
    object: ObjectRef,
    relation: RelationName,
    subject: TupleSubject,
    condition: Option<ConditionContext>,
}

impl RelationshipTuple {
    pub fn new(
        tenant: TenantId,
        object: ObjectRef,
        relation: RelationName,
        subject: impl Into<TupleSubject>,
    ) -> Self {
        Self {
            tenant,
            object,
            relation,
            subject: subject.into(),
            condition: None,
        }
    }

    pub fn with_condition(mut self, condition: ConditionContext) -> Self {
        self.condition = Some(condition);
        self
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn object(&self) -> &ObjectRef {
        &self.object
    }

    pub fn relation(&self) -> &RelationName {
        &self.relation
    }

    pub fn subject(&self) -> &TupleSubject {
        &self.subject
    }

    pub fn condition(&self) -> Option<&ConditionContext> {
        self.condition.as_ref()
    }

    fn validate_condition_context_limits(&self) -> Result<(), StoreError> {
        if let Some(condition) = self.condition() {
            condition.serialized_size()?;
        }
        Ok(())
    }

    fn key(&self) -> TupleKey {
        (
            self.tenant.clone(),
            self.object.clone(),
            self.relation.clone(),
        )
    }
}

type TupleKey = (TenantId, ObjectRef, RelationName);
type RelationshipSnapshot = HashMap<TupleKey, Vec<RelationshipTuple>>;

/// A categorized adapter failure. Store errors stay distinct from authorization
/// denial and can retain adapter-safe diagnostics for application logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError {
    kind: StoreErrorKind,
    message: String,
}

impl StoreError {
    pub fn new(kind: StoreErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    fn tuple_limit(maximum: usize) -> Self {
        Self::new(
            StoreErrorKind::TupleLimitExceeded,
            format!("more than {maximum} matching tuples were present"),
        )
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", self.message, self.kind)
    }
}

impl std::error::Error for StoreError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreErrorKind {
    Unavailable,
    CorruptData,
    IncompleteRead,
    TupleLimitExceeded,
    Internal,
}

/// A per-check, tenant-scoped snapshot that can read relationship tuples.
pub trait RelationshipReadSession: Send {
    /// Returns the complete matching set when it fits within `maximum`.
    /// Implementations must return `TupleLimitExceeded` when more matches exist
    /// and must not silently truncate or report an incomplete read as empty.
    fn tuples<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>>;

    /// Returns one complete page from a tenant-scoped snapshot.
    ///
    /// The default adapts bounded complete-read stores as a single page. Stores
    /// that support pagination should override this method. A page must contain
    /// no more than `maximum` tuples; pages must preserve stable tuple ordering
    /// within this read-session snapshot. A continuation cursor is valid only
    /// for this session and object/relation query, and a page with a continuation
    /// must contain at least one tuple. This opaque cursor API is source-breaking
    /// for paged store implementations that used numeric offsets.
    fn tuples_page<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        cursor: Option<StoreCursor>,
        maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
        if maximum == 0 {
            return Box::pin(async {
                Err(StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "relationship page size must be greater than zero",
                ))
            });
        }
        if cursor.is_some() {
            return Box::pin(async {
                Err(StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "this relationship read session does not support continuation pages",
                ))
            });
        }
        let tuples = self.tuples(object, relation, maximum);
        Box::pin(async move {
            tuples.await.map(|tuples| RelationshipPage {
                tuples,
                next_cursor: None,
            })
        })
    }
}

/// One bounded relationship-store page and its optional continuation cursor.
#[derive(Clone, Debug, PartialEq)]
pub struct RelationshipPage {
    /// Tuples returned by this page.
    pub tuples: Vec<RelationshipTuple>,
    /// Cursor for the next page from the same read-session snapshot.
    pub next_cursor: Option<StoreCursor>,
}

/// An asynchronous relationship source. Each check opens one read session so
/// adapters can provide snapshot or equivalent consistency guarantees. Store
/// adapters should document the consistency level their sessions provide.
pub trait RelationshipStore: Send + Sync {
    type ReadSession: RelationshipReadSession;

    fn begin_read<'a>(
        &'a self,
        tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>>;
}

/// Optional tenant-scoped mutation capability for relationship stores.
///
/// Insertions are strict: inserting an exact duplicate tuple returns
/// [`StoreErrorKind::CorruptData`]. Removals match the complete tuple, including
/// condition context, and return `false` when no exact tuple exists.
pub trait RelationshipWriteStore: Send + Sync {
    /// Inserts one tuple for the supplied tenant.
    fn insert_tuple<'a>(
        &'a self,
        tenant: &'a TenantId,
        tuple: &'a RelationshipTuple,
    ) -> StoreFuture<'a, Result<(), StoreError>>;

    /// Removes one exact tuple for the supplied tenant.
    fn remove_tuple<'a>(
        &'a self,
        tenant: &'a TenantId,
        tuple: &'a RelationshipTuple,
    ) -> StoreFuture<'a, Result<bool, StoreError>>;
}

/// An in-memory implementation intended for examples, tests, and small local
/// deployments. Each read session observes an immutable snapshot.
#[derive(Clone, Default)]
pub struct InMemoryRelationshipStore {
    snapshot: Arc<RwLock<Arc<RelationshipSnapshot>>>,
}

impl InMemoryRelationshipStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, tuple: RelationshipTuple) -> Result<(), StoreError> {
        tuple.validate_condition_context_limits()?;
        let key = tuple.key();
        let mut current = self.snapshot.write().map_err(|_| {
            StoreError::new(
                StoreErrorKind::Internal,
                "in-memory relationship store lock was poisoned",
            )
        })?;
        if current
            .get(&key)
            .is_some_and(|values| values.contains(&tuple))
        {
            return Err(StoreError::new(
                StoreErrorKind::CorruptData,
                "duplicate relationship tuple",
            ));
        }
        Arc::make_mut(&mut *current)
            .entry(key)
            .or_default()
            .push(tuple);
        Ok(())
    }

    pub fn remove(&self, tuple: &RelationshipTuple) -> Result<bool, StoreError> {
        tuple.validate_condition_context_limits()?;
        let key = tuple.key();
        let mut current = self.snapshot.write().map_err(|_| {
            StoreError::new(
                StoreErrorKind::Internal,
                "in-memory relationship store lock was poisoned",
            )
        })?;
        let Some(index) = current
            .get(&key)
            .and_then(|existing| existing.iter().position(|candidate| candidate == tuple))
        else {
            return Ok(false);
        };
        let snapshot = Arc::make_mut(&mut *current);
        let values = snapshot.get_mut(&key).expect("key checked above");
        values.remove(index);
        if values.is_empty() {
            snapshot.remove(&key);
        }
        Ok(true)
    }
}

impl RelationshipStore for InMemoryRelationshipStore {
    type ReadSession = InMemoryReadSession;

    fn begin_read<'a>(
        &'a self,
        tenant: &'a TenantId,
    ) -> StoreFuture<'a, Result<Self::ReadSession, StoreError>> {
        let tenant = tenant.clone();
        Box::pin(async move {
            let snapshot = self.snapshot.read().map_err(|_| {
                StoreError::new(
                    StoreErrorKind::Internal,
                    "in-memory relationship store lock was poisoned",
                )
            })?;
            let session_id = next_in_memory_session_id()?;
            Ok(InMemoryReadSession {
                tenant,
                session_id,
                snapshot: Arc::clone(&snapshot),
            })
        })
    }
}

pub struct InMemoryReadSession {
    tenant: TenantId,
    session_id: u64,
    snapshot: Arc<RelationshipSnapshot>,
}

impl RelationshipReadSession for InMemoryReadSession {
    fn tuples<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        maximum: usize,
    ) -> StoreFuture<'a, Result<Vec<RelationshipTuple>, StoreError>> {
        Box::pin(async move {
            let key = (self.tenant.clone(), object.clone(), relation.clone());
            let tuples = self.snapshot.get(&key).map_or(&[][..], Vec::as_slice);
            if tuples.len() > maximum {
                return Err(StoreError::tuple_limit(maximum));
            }
            Ok(tuples.to_vec())
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
                return Err(StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "relationship page size must be greater than zero",
                ));
            }
            let key = (self.tenant.clone(), object.clone(), relation.clone());
            let tuples = self.snapshot.get(&key).map_or(&[][..], Vec::as_slice);
            let start = memory_cursor_offset(cursor, self.session_id, object, relation)?;
            if start > tuples.len() {
                return Err(StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "relationship page cursor is outside the read-session snapshot",
                ));
            }
            let page_size = maximum.min(IN_MEMORY_PAGE_SIZE);
            let end = start.saturating_add(page_size).min(tuples.len());
            let next_cursor = if end < tuples.len() {
                let mut bytes = memory_cursor_context(self.session_id, object, relation)?;
                let offset = u64::try_from(end).map_err(|_| {
                    StoreError::new(
                        StoreErrorKind::Internal,
                        "in-memory relationship cursor offset cannot be represented",
                    )
                })?;
                bytes.extend_from_slice(&offset.to_be_bytes());
                Some(StoreCursor::from_bytes(bytes))
            } else {
                None
            };
            Ok(RelationshipPage {
                tuples: tuples[start..end].to_vec(),
                next_cursor,
            })
        })
    }
}

const IN_MEMORY_PAGE_SIZE: usize = 128;

static NEXT_IN_MEMORY_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn next_in_memory_session_id() -> Result<u64, StoreError> {
    NEXT_IN_MEMORY_SESSION_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| {
            StoreError::new(
                StoreErrorKind::Internal,
                "in-memory relationship session identifier space is exhausted",
            )
        })
}

fn memory_cursor_context(
    session_id: u64,
    object: &ObjectRef,
    relation: &RelationName,
) -> Result<Vec<u8>, StoreError> {
    fn append_field(bytes: &mut Vec<u8>, value: &str) -> Result<(), StoreError> {
        let length = u64::try_from(value.len()).map_err(|_| {
            StoreError::new(
                StoreErrorKind::Internal,
                "in-memory relationship cursor field is too large",
            )
        })?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    let mut bytes = b"relgraph-authz/in-memory-cursor/v1".to_vec();
    bytes.extend_from_slice(&session_id.to_be_bytes());
    append_field(&mut bytes, object.type_name().as_str())?;
    append_field(&mut bytes, object.id().as_str())?;
    append_field(&mut bytes, relation.as_str())?;
    Ok(bytes)
}

fn memory_cursor_offset(
    cursor: Option<StoreCursor>,
    session_id: u64,
    object: &ObjectRef,
    relation: &RelationName,
) -> Result<usize, StoreError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let context = memory_cursor_context(session_id, object, relation)?;
    let bytes = cursor.as_bytes();
    if bytes.len() != context.len() + std::mem::size_of::<u64>() || !bytes.starts_with(&context) {
        return Err(StoreError::new(
            StoreErrorKind::IncompleteRead,
            "relationship page cursor does not belong to this read-session query",
        ));
    }
    let offset = u64::from_be_bytes(
        bytes[context.len()..]
            .try_into()
            .expect("cursor length checked above"),
    );
    usize::try_from(offset).map_err(|_| {
        StoreError::new(
            StoreErrorKind::IncompleteRead,
            "relationship page cursor offset cannot be represented",
        )
    })
}

impl RelationshipWriteStore for InMemoryRelationshipStore {
    fn insert_tuple<'a>(
        &'a self,
        tenant: &'a TenantId,
        tuple: &'a RelationshipTuple,
    ) -> StoreFuture<'a, Result<(), StoreError>> {
        if tuple.tenant() != tenant {
            return Box::pin(async {
                Err(StoreError::new(
                    StoreErrorKind::CorruptData,
                    "relationship tuple tenant does not match write tenant",
                ))
            });
        }
        if let Err(error) = tuple.validate_condition_context_limits() {
            return Box::pin(async move { Err(error) });
        }
        let tuple = tuple.clone();
        Box::pin(async move { self.insert(tuple) })
    }

    fn remove_tuple<'a>(
        &'a self,
        tenant: &'a TenantId,
        tuple: &'a RelationshipTuple,
    ) -> StoreFuture<'a, Result<bool, StoreError>> {
        if tuple.tenant() != tenant {
            return Box::pin(async {
                Err(StoreError::new(
                    StoreErrorKind::CorruptData,
                    "relationship tuple tenant does not match write tenant",
                ))
            });
        }
        if let Err(error) = tuple.validate_condition_context_limits() {
            return Box::pin(async move { Err(error) });
        }
        Box::pin(async move { self.remove(tuple) })
    }
}
