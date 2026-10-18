//! PostgreSQL tuple writes commit independently of read sessions.
//!
//! A session that already established its repeatable-read snapshot keeps
//! observing that snapshot; sessions opened after a committed write see it.
//! A change set commits in one transaction, so later sessions observe all of
//! it or none of it.

use super::{
    PostgresRelationshipStore,
    mapping::TupleRow,
    read::{corrupt_row_error, map_sqlx_error},
};
use relgraph_authz::{
    RelationshipTuple, RelationshipWriteStore, StoreError, StoreErrorKind, StoreFuture, TenantId,
};
use sqlx::PgConnection;

const DUPLICATE_TUPLE: &str = "relationship tuple identity already exists";
const MISSING_DELETION: &str = "relationship tuple to delete does not exist";
const TENANT_MISMATCH: &str = "relationship tuple tenant does not match the requested tenant";
const REMOVAL_MISMATCH: &str = "persisted relationship tuple changed during removal";
const IDENTITY_CONSTRAINT: &str = "relationship_tuples_identity_digest_key";
const SELECT_MATCHING_TUPLE_FOR_UPDATE: &str = r"SELECT tuple_id, tenant, object_type, object_id, relation, subject_kind,
                         subject_type, subject_id, subject_relation, condition_name,
                         CASE WHEN context_json IS NOT NULL AND octet_length(context_json) > $3
                              THEN NULL::text ELSE context_json END AS context_json,
                         COALESCE(octet_length(context_json) > $3, false) AS context_json_oversized,
                         identity_digest
                  FROM relgraph_authz.relationship_tuples
                  WHERE tenant = $1 AND identity_digest = $2
                  FOR UPDATE";

impl RelationshipWriteStore for PostgresRelationshipStore {
    fn insert_tuple<'a>(
        &'a self,
        tenant: &'a TenantId,
        tuple: &'a RelationshipTuple,
    ) -> StoreFuture<'a, Result<(), StoreError>> {
        let row = match write_row(tenant, tuple) {
            Ok(row) => row,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let pool = self.pool.clone();

        Box::pin(async move {
            let mut connection = pool
                .acquire()
                .await
                .map_err(|error| map_sqlx_error(&error))?;
            insert_row(&mut connection, &row).await
        })
    }

    fn remove_tuple<'a>(
        &'a self,
        tenant: &'a TenantId,
        tuple: &'a RelationshipTuple,
    ) -> StoreFuture<'a, Result<bool, StoreError>> {
        let expected_row = match write_row(tenant, tuple) {
            Ok(row) => row,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let pool = self.pool.clone();

        Box::pin(async move {
            let mut transaction = pool.begin().await.map_err(|error| map_sqlx_error(&error))?;
            let removed = remove_row(&mut transaction, &expected_row, tuple).await?;
            transaction
                .commit()
                .await
                .map_err(|error| map_sqlx_error(&error))?;
            Ok(removed)
        })
    }

    fn apply_changes<'a>(
        &'a self,
        tenant: &'a TenantId,
        inserts: &'a [RelationshipTuple],
        deletes: &'a [RelationshipTuple],
    ) -> StoreFuture<'a, Result<(), StoreError>> {
        let rows = |tuples: &[RelationshipTuple]| {
            tuples
                .iter()
                .map(|tuple| write_row(tenant, tuple))
                .collect::<Result<Vec<_>, _>>()
        };
        let (insert_rows, delete_rows) = match (rows(inserts), rows(deletes)) {
            (Ok(insert_rows), Ok(delete_rows)) => (insert_rows, delete_rows),
            (Err(error), _) | (_, Err(error)) => return Box::pin(async move { Err(error) }),
        };
        let pool = self.pool.clone();

        Box::pin(async move {
            if insert_rows.is_empty() && delete_rows.is_empty() {
                return Ok(());
            }
            // An early return drops the transaction, which rolls back every
            // change already made in it.
            let mut transaction = pool.begin().await.map_err(|error| map_sqlx_error(&error))?;
            for (row, tuple) in delete_rows.iter().zip(deletes) {
                if !remove_row(&mut transaction, row, tuple).await? {
                    return Err(StoreError::new(StoreErrorKind::Conflict, MISSING_DELETION));
                }
            }
            for row in &insert_rows {
                insert_row(&mut transaction, row).await?;
            }
            transaction
                .commit()
                .await
                .map_err(|error| map_sqlx_error(&error))
        })
    }
}

/// Checks tenant ownership and maps one caller-supplied tuple before any I/O.
fn write_row(tenant: &TenantId, tuple: &RelationshipTuple) -> Result<TupleRow, StoreError> {
    if tenant != tuple.tenant() {
        return Err(tenant_mismatch_error());
    }
    TupleRow::from_tuple(tuple)
}

async fn insert_row(connection: &mut PgConnection, row: &TupleRow) -> Result<(), StoreError> {
    let result = sqlx::query(
        r"INSERT INTO relgraph_authz.relationship_tuples
          (tenant, object_type, object_id, relation, subject_kind, subject_type,
           subject_id, subject_relation, condition_name, context_json, identity_digest)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(&row.tenant)
    .bind(&row.object_type)
    .bind(&row.object_id)
    .bind(&row.relation)
    .bind(&row.subject_kind)
    .bind(&row.subject_type)
    .bind(&row.subject_id)
    .bind(&row.subject_relation)
    .bind(&row.condition_name)
    .bind(&row.context_json)
    .bind(&row.identity_digest)
    .execute(connection)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(error) if is_identity_duplicate(&error) => {
            Err(StoreError::new(StoreErrorKind::Conflict, DUPLICATE_TUPLE))
        }
        Err(error) => Err(map_sqlx_error(&error)),
    }
}

/// Locks, verifies, and deletes the exact stored tuple inside the caller's
/// transaction. Returns `false` when no row has the tuple's identity.
async fn remove_row(
    connection: &mut PgConnection,
    expected_row: &TupleRow,
    tuple: &RelationshipTuple,
) -> Result<bool, StoreError> {
    let row = sqlx::query_as::<_, TupleRow>(SELECT_MATCHING_TUPLE_FOR_UPDATE)
        .bind(&expected_row.tenant)
        .bind(&expected_row.identity_digest)
        .bind(relgraph_authz::MAX_CONDITION_CONTEXT_SERIALIZED_BYTES as i32)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;

    let Some(row) = row else {
        return Ok(false);
    };

    let tuple_id = row.tuple_id.ok_or_else(corrupt_row_error)?;
    let stored_tuple = row.into_tuple()?;
    if &stored_tuple != tuple {
        return Err(corrupt_row_error());
    }

    let deleted = sqlx::query(
        r"DELETE FROM relgraph_authz.relationship_tuples
          WHERE tenant = $1 AND tuple_id = $2",
    )
    .bind(&expected_row.tenant)
    .bind(tuple_id)
    .execute(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;

    if deleted.rows_affected() != 1 {
        return Err(StoreError::new(
            StoreErrorKind::CorruptData,
            REMOVAL_MISMATCH,
        ));
    }
    Ok(true)
}

fn is_identity_duplicate(error: &sqlx::Error) -> bool {
    let sqlx::Error::Database(database_error) = error else {
        return false;
    };

    database_error.code().as_deref() == Some("23505")
        && database_error.constraint() == Some(IDENTITY_CONSTRAINT)
}

fn tenant_mismatch_error() -> StoreError {
    StoreError::new(StoreErrorKind::InvalidInput, TENANT_MISMATCH)
}

#[cfg(test)]
mod tests {
    use super::{PostgresRelationshipStore, SELECT_MATCHING_TUPLE_FOR_UPDATE};
    use relgraph_authz::{
        ObjectRef, RelationName, RelationshipTuple, RelationshipWriteStore, StoreErrorKind,
        Subject, TenantId,
    };
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn removal_query_masks_oversized_context_before_sqlx_materializes_it() {
        assert!(SELECT_MATCHING_TUPLE_FOR_UPDATE.contains("octet_length(context_json) > $3"));
        assert!(
            SELECT_MATCHING_TUPLE_FOR_UPDATE
                .contains("THEN NULL::text ELSE context_json END AS context_json")
        );
        assert!(SELECT_MATCHING_TUPLE_FOR_UPDATE.contains("AS context_json_oversized"));
    }

    #[tokio::test]
    async fn tenant_mismatch_is_rejected_before_pool_io() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:unused@127.0.0.1:1/no_database")
            .expect("a lazy pool should accept a syntactically valid URL without connecting");
        let store = PostgresRelationshipStore::new(pool);
        let tuple_tenant = TenantId::new("tenant-a").unwrap();
        let requested_tenant = TenantId::new("tenant-b").unwrap();
        let tuple = RelationshipTuple::new(
            tuple_tenant,
            ObjectRef::new("document", "doc-1").unwrap(),
            RelationName::new("viewer").unwrap(),
            Subject::new("user", "alice").unwrap(),
        );

        let insert_error = store
            .insert_tuple(&requested_tenant, &tuple)
            .await
            .expect_err("mismatched tenant must fail");
        assert_eq!(insert_error.kind(), StoreErrorKind::InvalidInput);

        let remove_error = store
            .remove_tuple(&requested_tenant, &tuple)
            .await
            .expect_err("mismatched tenant must fail");
        assert_eq!(remove_error.kind(), StoreErrorKind::InvalidInput);
    }
}
