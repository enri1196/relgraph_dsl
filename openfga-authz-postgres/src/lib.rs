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
