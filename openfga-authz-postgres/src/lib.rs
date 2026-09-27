//! PostgreSQL relationship storage for `openfga-authz`.
//!
//! This crate's README describes the PostgreSQL 14+ schema, trusted tenant
//! boundary, role grants, and operational timeout guidance. This complete
//! `no_run` example mirrors its setup path. Cargo compiles the code during
//! doctests but never opens a connection, so it also works without a database.
//!
//! ```no_run
//! use std::{env, error::Error, str::FromStr, time::Duration};
//!
//! use openfga_authz::{
//!     CheckRequest, EvaluationLimits, FgaAuthz, ObjectRef, RelationName,
//!     RelationshipTuple, RelationshipWriteStore, Subject, TenantId,
//! };
//! use openfga_authz_postgres::{MIGRATION_0001, PostgresRelationshipStore};
//! use sqlx::{PgPool, postgres::{PgConnectOptions, PgPoolOptions, PgSslMode}};
//!
//! const MODEL: &str = r#"
//! model
//!   schema 1.1
//!
//! type user
//!
//! type document
//!   relations
//!     define viewer: [user]
//! "#;
//!
//! const MIGRATION_KEY: &str = "openfga-authz/0001_relationship_tuples";
//!
//! fn pool(
//!     url: &str,
//!     ca_certificate: &str,
//!     max_connections: u32,
//!     statement_timeout: &'static str,
//!     idle_transaction_timeout: &'static str,
//! ) -> Result<PgPool, Box<dyn Error>> {
//!     let connect_options = PgConnectOptions::from_str(url)?
//!         .ssl_mode(PgSslMode::VerifyFull)
//!         .ssl_root_cert(ca_certificate);
//!
//!     let pool = PgPoolOptions::new()
//!         .max_connections(max_connections)
//!         .acquire_timeout(Duration::from_secs(2))
//!         .after_connect(move |connection, _metadata| {
//!             Box::pin(async move {
//!                 sqlx::query("SELECT set_config('statement_timeout', $1, false)")
//!                     .bind(statement_timeout)
//!                     .execute(&mut *connection)
//!                     .await?;
//!                 sqlx::query(
//!                     "SELECT set_config('idle_in_transaction_session_timeout', $1, false)",
//!                 )
//!                 .bind(idle_transaction_timeout)
//!                 .execute(&mut *connection)
//!                 .await?;
//!                 Ok(())
//!             })
//!         })
//!         .connect_lazy_with(connect_options);
//!     Ok(pool)
//! }
//!
//! async fn apply_migration(pool: &PgPool) -> Result<(), Box<dyn Error>> {
//!     let mut transaction = pool.begin().await?;
//!
//!     // Use the same lock key in every instance that can run this migration.
//!     sqlx::query("SELECT pg_advisory_xact_lock($1)")
//!         .bind(0x4f46474100000001_i64)
//!         .fetch_one(&mut *transaction)
//!         .await?;
//!     sqlx::query("CREATE SCHEMA IF NOT EXISTS app_metadata")
//!         .execute(&mut *transaction)
//!         .await?;
//!     sqlx::query("REVOKE CREATE ON SCHEMA app_metadata FROM PUBLIC")
//!         .execute(&mut *transaction)
//!         .await?;
//!     sqlx::query(
//!         "CREATE TABLE IF NOT EXISTS app_metadata.schema_migrations (\
//!             migration_key TEXT PRIMARY KEY,\
//!             applied_at TIMESTAMPTZ NOT NULL DEFAULT now()\
//!         )",
//!     )
//!     .execute(&mut *transaction)
//!     .await?;
//!
//!     let already_applied: bool = sqlx::query_scalar(
//!         "SELECT EXISTS (SELECT 1 FROM app_metadata.schema_migrations WHERE migration_key = $1)",
//!     )
//!     .bind(MIGRATION_KEY)
//!     .fetch_one(&mut *transaction)
//!     .await?;
//!
//!     if !already_applied {
//!         sqlx::raw_sql(MIGRATION_0001)
//!             .execute(&mut *transaction)
//!             .await?;
//!         sqlx::query("INSERT INTO app_metadata.schema_migrations (migration_key) VALUES ($1)")
//!             .bind(MIGRATION_KEY)
//!             .execute(&mut *transaction)
//!             .await?;
//!     }
//!
//!     transaction.commit().await?;
//!     Ok(())
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     let ca_certificate = env::var("OPENFGA_POSTGRES_CA_CERT")?;
//!     let migration_pool = pool(
//!         &env::var("OPENFGA_POSTGRES_DDL_URL")?,
//!         &ca_certificate,
//!         2,
//!         "30s",
//!         "30s",
//!     )?;
//!     apply_migration(&migration_pool).await?;
//!     migration_pool.close().await;
//!
//!     let runtime_pool = pool(
//!         &env::var("OPENFGA_POSTGRES_URL")?,
//!         &ca_certificate,
//!         32,
//!         "2s",
//!         "5s",
//!     )?;
//!     let store = PostgresRelationshipStore::new(runtime_pool);
//!
//!     // Derive the tenant from authenticated server-side identity or trusted
//!     // application routing. Do not accept an arbitrary tenant from the caller.
//!     let tenant = TenantId::new("acme")?;
//!     let subject = Subject::new("user", "anne")?;
//!     let object = ObjectRef::new("document", "42")?;
//!     let relation = RelationName::new("viewer")?;
//!     let tuple = RelationshipTuple::new(
//!         tenant.clone(),
//!         object.clone(),
//!         relation.clone(),
//!         subject.clone(),
//!     );
//!
//!     store.insert_tuple(&tenant, &tuple).await?;
//!     let authorizer = FgaAuthz::new(MODEL)?
//!         .with_store(store.clone(), EvaluationLimits::default());
//!     let request = CheckRequest::new(tenant.clone(), subject, object, relation);
//!     let _decision =
//!         tokio::time::timeout(Duration::from_secs(3), authorizer.check(request)).await??;
//!     let _removed = store.remove_tuple(&tenant, &tuple).await?;
//!
//!     Ok(())
//! }
//! ```

//! PostgreSQL storage components for [`openfga_authz`].
//!
//! The initial schema supports PostgreSQL 14 and later. Apply
//! [`MIGRATION_0001`] transactionally through the application's migration
//! ledger before using the adapter. Constructing [`PostgresRelationshipStore`]
//! performs no database I/O and does not run migrations.
//!
//! The adapter was checked with Rust 1.94.0. The workspace does not currently
//! declare a minimum supported Rust version.
//!
//! Direct SQL writers must produce the same versioned tuple identity digest
//! as this crate. Database constraints validate field shape and digest length,
//! but cannot verify that a digest matches its tuple fields.

#[allow(dead_code)]
mod mapping;
mod read;
mod write;

pub use read::PostgresReadSession;

use sqlx::PgPool;

/// SQL schema migration for the initial relationship-tuple table.
pub const MIGRATION_0001: &str = include_str!("../migrations/0001_relationship_tuples.sql");

/// A cloneable handle to the fixed PostgreSQL relationship-tuple table.
///
/// Cloning this value clones the SQLx pool handle. Construction performs no
/// I/O; applications own migration execution and pool configuration.
#[derive(Clone)]
pub struct PostgresRelationshipStore {
    #[allow(dead_code)]
    pool: PgPool,
}

impl PostgresRelationshipStore {
    /// Creates a store using the supplied pool without connecting or running DDL.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(test)]
mod schema_tests {
    use super::MIGRATION_0001;

    #[test]
    fn migration_contains_fixed_schema_constraints_and_lookup_order() {
        let sql = MIGRATION_0001
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(sql.contains("create schema if not exists openfga_authz"));
        assert!(sql.contains("create table openfga_authz.relationship_tuples"));
        assert!(sql.contains("tuple_id bigint generated always as identity primary key"));
        assert!(sql.contains("identity_digest bytea not null"));
        assert!(sql.contains("octet_length(identity_digest) = 32"));
        assert!(sql.contains("unique (identity_digest)"));
        assert!(sql.contains("subject_kind = 'direct'"));
        assert!(sql.contains("subject_kind = 'userset'"));
        assert!(sql.contains("subject_kind = 'typed_wildcard'"));
        assert!(sql.contains("condition_name is null and context_json is null"));
        assert!(sql.contains("condition_name is not null and context_json is not null"));
        assert!(sql.contains(
            "on openfga_authz.relationship_tuples (tenant, object_type, object_id, relation, tuple_id)"
        ));
        assert!(sql.contains("collate \"c\""));
        assert!(!sql.contains("create table if not exists"));
        assert!(!sql.contains("jsonb"));
    }
}
