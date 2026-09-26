use super::request::{ConditionName, ObjectRef, RelationName, Subject, TenantId, TypeName};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

/// The boxed future type used by asynchronous relationship-store adapters.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
    /// no more than `maximum` tuples; a continuation cursor must advance from
    /// the supplied cursor and continue the same read-session snapshot.
    fn tuples_page<'a>(
        &'a self,
        object: &'a ObjectRef,
        relation: &'a RelationName,
        cursor: Option<usize>,
        maximum: usize,
    ) -> StoreFuture<'a, Result<RelationshipPage, StoreError>> {
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
    pub next_cursor: Option<usize>,
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
        let key = tuple.key();
        let mut current = self.snapshot.write().map_err(|_| {
            StoreError::new(
                StoreErrorKind::Internal,
                "in-memory relationship store lock was poisoned",
            )
        })?;
        let mut next = (**current).clone();
        let values = next.entry(key).or_default();
        if values.contains(&tuple) {
            return Err(StoreError::new(
                StoreErrorKind::CorruptData,
                "duplicate relationship tuple",
            ));
        }
        values.push(tuple);
        *current = Arc::new(next);
        Ok(())
    }

    pub fn remove(&self, tuple: &RelationshipTuple) -> Result<bool, StoreError> {
        let key = tuple.key();
        let mut current = self.snapshot.write().map_err(|_| {
            StoreError::new(
                StoreErrorKind::Internal,
                "in-memory relationship store lock was poisoned",
            )
        })?;
        let Some(existing) = current.get(&key) else {
            return Ok(false);
        };
        let Some(index) = existing.iter().position(|candidate| candidate == tuple) else {
            return Ok(false);
        };
        let mut next = (**current).clone();
        let values = next.get_mut(&key).expect("key checked above");
        values.remove(index);
        if values.is_empty() {
            next.remove(&key);
        }
        *current = Arc::new(next);
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
            Ok(InMemoryReadSession {
                tenant,
                snapshot: Arc::clone(&snapshot),
            })
        })
    }
}

pub struct InMemoryReadSession {
    tenant: TenantId,
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
        cursor: Option<usize>,
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
            let start = cursor.unwrap_or(0);
            if start > tuples.len() {
                return Err(StoreError::new(
                    StoreErrorKind::IncompleteRead,
                    "relationship page cursor is outside the read-session snapshot",
                ));
            }
            let page_size = maximum.min(IN_MEMORY_PAGE_SIZE);
            let end = start.saturating_add(page_size).min(tuples.len());
            let next_cursor = (end < tuples.len()).then_some(end);
            Ok(RelationshipPage {
                tuples: tuples[start..end].to_vec(),
                next_cursor,
            })
        })
    }
}

const IN_MEMORY_PAGE_SIZE: usize = 128;
