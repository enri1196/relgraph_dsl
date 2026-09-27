# `relgraph-authz-postgres`

This crate implements the backend-neutral `RelationshipStore` and
`RelationshipWriteStore` contracts with PostgreSQL. It supports PostgreSQL
14 or newer. The core `relgraph-authz` crate stays usable with its in-memory
store and does not acquire a SQLx or PostgreSQL dependency.

## Add the adapter

The application depends directly on the adapter, SQLx, and its Tokio runtime.
Use the same SQLx version and features as the adapter:

```toml
[dependencies]
relgraph-authz = { version = "0.1", default-features = false }
relgraph-authz-postgres = "0.1"
sqlx = { version = "=0.8.6", default-features = false, features = ["postgres", "runtime-tokio", "tls-rustls-ring"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
```

## Pool, migration, writes, and check

`PostgresRelationshipStore::new` only retains the supplied pool; it does not
connect or run DDL. Keep a store handle for writes and clone it into the bound
authorizer. The sample below reads separate DDL and runtime connection URLs
and a CA certificate path from the application environment. Configure secret
values through your deployment's secret manager; the adapter does not read
environment variables.

The migration function demonstrates a small application-owned migration
ledger. It serializes concurrent startup runners with a transaction-scoped
advisory lock, records the migration in the same transaction as the DDL, and
does nothing when the version is already recorded. In an application with a
migration framework, register `MIGRATION_0001` with that framework's ledger
instead. Run migrations as a deployment/startup step with the DDL role, then
close that pool and serve requests with a separate runtime role.

The full sequence is also present as a `no_run` crate-level Rust documentation
example, so `cargo test -p relgraph-authz-postgres --doc` compiles it without
contacting PostgreSQL.

```rust,no_run
use std::{env, error::Error, str::FromStr, time::Duration};

use relgraph_authz::{
    CheckRequest, EvaluationLimits, FgaAuthz, ObjectRef, RelationName,
    RelationshipTuple, RelationshipWriteStore, Subject, TenantId,
};
use relgraph_authz_postgres::{MIGRATION_0001, PostgresRelationshipStore};
use sqlx::{PgPool, postgres::{PgConnectOptions, PgPoolOptions, PgSslMode}};

const MODEL: &str = r#"
model
  schema 1.1

type user

type document
  relations
    define viewer: [user]
"#;

const MIGRATION_KEY: &str = "relgraph-authz/0001_relationship_tuples";

fn pool(
    url: &str,
    ca_certificate: &str,
    max_connections: u32,
    statement_timeout: &'static str,
    idle_transaction_timeout: &'static str,
) -> Result<PgPool, Box<dyn Error>> {
    let connect_options = PgConnectOptions::from_str(url)?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_certificate);

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(2))
        .after_connect(move |connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                    .bind(statement_timeout)
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SELECT set_config('idle_in_transaction_session_timeout', $1, false)")
                    .bind(idle_transaction_timeout)
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_lazy_with(connect_options);
    Ok(pool)
}

async fn apply_migration(pool: &PgPool) -> Result<(), Box<dyn Error>> {
    let mut transaction = pool.begin().await?;

    // Use the same lock key in every instance that can run this migration.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x4f46474100000001_i64)
        .fetch_one(&mut *transaction)
        .await?;
    sqlx::query("CREATE SCHEMA IF NOT EXISTS app_metadata")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("REVOKE CREATE ON SCHEMA app_metadata FROM PUBLIC")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS app_metadata.schema_migrations (\
            migration_key TEXT PRIMARY KEY,\
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()\
        )",
    )
    .execute(&mut *transaction)
    .await?;

    let already_applied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM app_metadata.schema_migrations WHERE migration_key = $1)",
    )
    .bind(MIGRATION_KEY)
    .fetch_one(&mut *transaction)
    .await?;

    if !already_applied {
        sqlx::raw_sql(MIGRATION_0001)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO app_metadata.schema_migrations (migration_key) VALUES ($1)")
            .bind(MIGRATION_KEY)
            .execute(&mut *transaction)
            .await?;
    }

    transaction.commit().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ca_certificate = env::var("OPENFGA_POSTGRES_CA_CERT")?;
    let migration_pool = pool(
        &env::var("OPENFGA_POSTGRES_DDL_URL")?,
        &ca_certificate,
        2,
        "30s",
        "30s",
    )?;
    apply_migration(&migration_pool).await?;
    migration_pool.close().await;

    let runtime_pool = pool(
        &env::var("OPENFGA_POSTGRES_URL")?,
        &ca_certificate,
        32,
        "2s",
        "5s",
    )?;
    let store = PostgresRelationshipStore::new(runtime_pool);

    // Derive the tenant from authenticated server-side identity or trusted
    // application routing. Do not accept an arbitrary tenant from the caller.
    let tenant = TenantId::new("acme")?;
    let subject = Subject::new("user", "anne")?;
    let object = ObjectRef::new("document", "42")?;
    let relation = RelationName::new("viewer")?;
    let tuple = RelationshipTuple::new(
        tenant.clone(),
        object.clone(),
        relation.clone(),
        subject.clone(),
    );

    store.insert_tuple(&tenant, &tuple).await?;
    let authorizer = FgaAuthz::new(MODEL)?
        .with_store(store.clone(), EvaluationLimits::default());
    let request = CheckRequest::new(tenant.clone(), subject, object, relation);
    let _decision = tokio::time::timeout(Duration::from_secs(3), authorizer.check(request)).await??;
    let _removed = store.remove_tuple(&tenant, &tuple).await?;

    Ok(())
}
```

The example's URL variables and certificate path are application-owned. Use a
trusted CA bundle and `VerifyFull` for remote PostgreSQL so both the certificate
chain and server name are checked. Do not put credentials in source control or
logs. The adapter receives a configured pool and reads no environment settings
itself.

## Schema migration and database roles

`MIGRATION_0001` is plain versioned SQL for the fixed
`relgraph_authz.relationship_tuples` table. Apply it once transactionally with
your application's migration ledger. Store construction does not migrate the
database. PostgreSQL 14+ is the supported minimum.

Use a trusted dedicated `relgraph_authz` schema, owned by the DDL role. Do not
grant `CREATE` on that schema to `PUBLIC` or to untrusted roles. Grant the
runtime role only the privileges needed by this adapter after applying the
migration:

```sql
REVOKE CREATE ON SCHEMA relgraph_authz FROM PUBLIC;
GRANT USAGE ON SCHEMA relgraph_authz TO authz_runtime;
GRANT SELECT, INSERT, DELETE ON TABLE relgraph_authz.relationship_tuples TO authz_runtime;
GRANT UPDATE (tuple_id) ON TABLE relgraph_authz.relationship_tuples TO authz_runtime;
GRANT USAGE ON SEQUENCE relgraph_authz.relationship_tuples_tuple_id_seq TO authz_runtime;
```

`USAGE` on the identity sequence lets inserts allocate `tuple_id` values. The
adapter's exact removal locks its matching row with `SELECT ... FOR UPDATE`
before decoding and deleting it. PostgreSQL requires `UPDATE` privilege for
that locking clause even though the adapter issues no `UPDATE` statement, so
the grant is narrowed to the `tuple_id` column. Run DDL with a separate
migration/owner role and keep that credential out of the serving process when
your deployment model allows it. Direct SQL writers must maintain the adapter's
versioned identity digest encoding; prefer the adapter's write trait for tuple
mutations.

## Tenant boundary, snapshots, and timeouts

Every store read and write is scoped by the supplied `TenantId`, and the tuple
tenant must match it for writes. This is a data-isolation predicate, not caller
authentication. Derive the tenant from authenticated identity or trusted
server-side routing, and restrict access to the store/write handle to
authorized application code. Never let a request choose an arbitrary tenant
just because `TenantId::new` accepts its format.

Each `FgaAuthz::check` owns one read-only repeatable-read snapshot, established
before the store returns its session. Tuple pages and subsequent object/relation
lookups for that check share the snapshot. The session holds one pooled
connection until the check completes; cancellation drops the SQLx transaction,
whose rollback cleanup is asynchronous. Size the pool for the expected number
of simultaneous checks plus writes and other database work, within the server
and deployment-wide connection budget. A check that waits for a pool slot is
bounded by `acquire_timeout`; the example uses two seconds and 32 runtime pool
connections as starting values, not universal sizing recommendations.

The example applies a two-second PostgreSQL `statement_timeout`, a five-second
`idle_in_transaction_session_timeout`, and a three-second application check
deadline. Tune these together for the service's latency target. Evaluation
limits bound tuple and expression work but do not bound database waits or total
wall-clock time. The statement timeout bounds each SQL statement; the
application deadline bounds the whole check; the idle-in-transaction timeout
limits how long a delayed or abandoned task can leave a snapshot idle.

## Errors and write outcomes

Pool acquisition, closed-pool, transport, TLS, protocol, server cancellation,
and selected server-capacity errors map to a fixed `Unavailable` store error.
Malformed persisted rows and strict duplicate inserts map to `CorruptData`;
other database failures map to a fixed internal store error. SQL details are
not copied into public store messages. The evaluator does not treat a failed
read as an empty tuple result; it keeps its existing three-valued expression
combination rules, so whether a branch error is decisive depends on the
operator and the other branch results. A propagated store failure is an
authorization error, while an exhausted evaluation tuple limit remains an
evaluation-limit error.

An insert or removal may have reached PostgreSQL even when the client observes
a transport failure or its future is cancelled. The caller then cannot infer
whether the write committed from that error alone. This adapter does not retry
writes automatically and does not provide an idempotency key. Reconcile an
uncertain outcome through application-specific read/operation tracking before
retrying; do not assume a failed response means no mutation occurred.

The adapter does not add row-level security or an HTTP management API. Keep
tenant authentication, write authorization, migration policy, and credential
management in the application.
