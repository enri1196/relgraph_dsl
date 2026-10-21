use std::future::Future;
use std::panic::resume_unwind;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use relgraph_authz::{
    AuthorizationError, CheckRequest, ConditionContext, EvaluationLimits, FgaAuthz, ObjectRef,
    RelationName, RelationshipReadSession, RelationshipStore, RelationshipTuple,
    RelationshipWriteStore, StoreErrorKind, Subject, TenantId, TupleSubject,
};
use relgraph_authz_postgres::{MIGRATION_0001, MIGRATION_0002, PostgresRelationshipStore};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};

#[path = "../../relgraph-authz/tests/support/store_contract.rs"]
mod store_contract;

const ADMIN_DATABASE: &str = "postgres";
const MINIMUM_SERVER_VERSION: u32 = 140_000;
const DEFAULT_APP_POOL_SIZE: u32 = 8;
static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct AdditionalCleanup {
    roles: Vec<String>,
    pools: Vec<PgPool>,
}

struct TestDatabase {
    name: String,
    base_options: PgConnectOptions,
    maintenance_pool: PgPool,
    admin_database_pool: PgPool,
    app_pool: PgPool,
    additional_cleanup: Arc<Mutex<AdditionalCleanup>>,
}

#[derive(Clone)]
struct DatabaseAccess {
    name: String,
    admin_pool: PgPool,
    app_pool: PgPool,
    base_options: PgConnectOptions,
    additional_cleanup: Arc<Mutex<AdditionalCleanup>>,
}

impl TestDatabase {
    async fn provision(
        apply_migration: bool,
        app_pool_size: u32,
        app_acquire_timeout: Duration,
    ) -> Result<Self, &'static str> {
        let url = std::env::var("OPENFGA_POSTGRES_TEST_URL").map_err(
            |_| "OPENFGA_POSTGRES_TEST_URL is missing; set it to a disposable PostgreSQL URL",
        )?;
        if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
            return Err(
                "OPENFGA_POSTGRES_TEST_URL must be a PostgreSQL URL; its value is not displayed",
            );
        }
        let base_options = PgConnectOptions::from_str(&url)
            .map_err(|_| "OPENFGA_POSTGRES_TEST_URL is invalid; its value is not displayed")?;
        drop(url);

        // A pathless URL defaults to a driver-specific database. Set this
        // explicitly so database administration always uses the maintenance DB.
        let maintenance_pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(base_options.clone().database(ADMIN_DATABASE))
            .await
            .map_err(|_| {
                "could not connect to the configured PostgreSQL maintenance database; connection details are redacted"
            })?;

        let version_text = match sqlx::query_scalar::<_, String>("SHOW server_version_num")
            .fetch_one(&maintenance_pool)
            .await
        {
            Ok(version) => version,
            Err(_) => {
                maintenance_pool.close().await;
                return Err("could not verify the configured PostgreSQL server version");
            }
        };
        let version = match version_text.parse::<u32>() {
            Ok(version) => version,
            Err(_) => {
                maintenance_pool.close().await;
                return Err("the configured PostgreSQL server returned an invalid version number");
            }
        };
        if version < MINIMUM_SERVER_VERSION {
            maintenance_pool.close().await;
            return Err("PostgreSQL 14 or newer is required by these live tests");
        }

        let name = next_database_name();
        let quoted_name = quote_identifier(&name)?;
        let create_sql = format!("CREATE DATABASE {quoted_name}");
        if sqlx::query(AssertSqlSafe(create_sql))
            .execute(&maintenance_pool)
            .await
            .is_err()
        {
            maintenance_pool.close().await;
            return Err(
                "could not create a generated test database; the configured account needs CREATEDB",
            );
        }

        let admin_database_pool = match PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(base_options.clone().database(&name))
            .await
        {
            Ok(pool) => pool,
            Err(_) => {
                let _ = drop_generated_database(&maintenance_pool, &name).await;
                maintenance_pool.close().await;
                return Err("could not connect to the generated test database");
            }
        };
        let app_pool = match PgPoolOptions::new()
            .max_connections(app_pool_size)
            .acquire_timeout(app_acquire_timeout)
            .connect_with(base_options.clone().database(&name))
            .await
        {
            Ok(pool) => pool,
            Err(_) => {
                admin_database_pool.close().await;
                let _ = drop_generated_database(&maintenance_pool, &name).await;
                maintenance_pool.close().await;
                return Err(
                    "could not connect the application pool to the generated test database",
                );
            }
        };

        let database = Self {
            name,
            base_options,
            maintenance_pool,
            admin_database_pool,
            app_pool,
            additional_cleanup: Arc::new(Mutex::new(AdditionalCleanup::default())),
        };
        if apply_migration && database.apply_migration().await.is_err() {
            database
                .cleanup()
                .await
                .map_err(|_| "could not clean up a database after migration failure")?;
            return Err("the transactional relationship-tuple migration failed");
        }
        Ok(database)
    }

    async fn apply_migration(&self) -> Result<(), ()> {
        let mut transaction = self.admin_database_pool.begin().await.map_err(|_| ())?;
        for migration in [MIGRATION_0001, MIGRATION_0002] {
            sqlx::raw_sql(migration)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ())?;
        }
        transaction.commit().await.map_err(|_| ())
    }

    fn access(&self) -> DatabaseAccess {
        DatabaseAccess {
            name: self.name.clone(),
            admin_pool: self.admin_database_pool.clone(),
            app_pool: self.app_pool.clone(),
            base_options: self.base_options.clone(),
            additional_cleanup: Arc::clone(&self.additional_cleanup),
        }
    }

    async fn cleanup(self) -> Result<(), &'static str> {
        let (roles, additional_pools) = {
            let cleanup = self
                .additional_cleanup
                .lock()
                .expect("database cleanup registry is not poisoned");
            (cleanup.roles.clone(), cleanup.pools.clone())
        };
        for pool in additional_pools {
            pool.close().await;
        }
        self.app_pool.close().await;
        self.admin_database_pool.close().await;
        let database_drop = drop_generated_database(&self.maintenance_pool, &self.name).await;
        let mut role_cleanup_failed = false;
        let quoted_database = quote_identifier(&self.name)
            .expect("generated database name is a valid PostgreSQL identifier");
        for role in roles {
            let quoted_role = match quote_identifier(&role) {
                Ok(role) => role,
                Err(_) => {
                    role_cleanup_failed = true;
                    continue;
                }
            };
            if database_drop.is_err() {
                let revoke =
                    format!("REVOKE CONNECT ON DATABASE {quoted_database} FROM {quoted_role}");
                let _ = sqlx::query(AssertSqlSafe(revoke))
                    .execute(&self.maintenance_pool)
                    .await;
            }
            let drop_role = format!("DROP ROLE {quoted_role}");
            if sqlx::query(AssertSqlSafe(drop_role))
                .execute(&self.maintenance_pool)
                .await
                .is_err()
            {
                role_cleanup_failed = true;
            }
        }
        self.maintenance_pool.close().await;
        database_drop?;
        if role_cleanup_failed {
            return Err("could not drop a generated permission-test role");
        }
        Ok(())
    }
}

impl DatabaseAccess {
    fn register_role(&self, role: String) {
        self.additional_cleanup
            .lock()
            .expect("database cleanup registry is not poisoned")
            .roles
            .push(role);
    }

    fn register_pool(&self, pool: PgPool) {
        self.additional_cleanup
            .lock()
            .expect("database cleanup registry is not poisoned")
            .pools
            .push(pool);
    }
}

fn next_database_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let sequence = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
    let name = format!("rgt_{}_{}_{}", std::process::id(), nanos, sequence);
    assert!(
        name.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    );
    assert!(
        name.len() <= 63,
        "generated database name exceeds PostgreSQL's identifier limit"
    );
    name
}

fn quote_identifier(identifier: &str) -> Result<String, &'static str> {
    if identifier.is_empty() || identifier.len() > 63 || identifier.as_bytes().contains(&0) {
        return Err("invalid PostgreSQL identifier");
    }
    Ok(format!("\"{}\"", identifier.replace('"', "\"\"")))
}

fn quote_test_password(password: &str) -> Result<String, &'static str> {
    if password.is_empty()
        || !password
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("invalid generated test password");
    }
    Ok(format!("'{password}'"))
}

async fn drop_generated_database(pool: &PgPool, database_name: &str) -> Result<(), &'static str> {
    let quoted_name = quote_identifier(database_name)?;
    let statement = format!("DROP DATABASE {quoted_name}");
    if sqlx::query(AssertSqlSafe(statement))
        .execute(pool)
        .await
        .is_ok()
    {
        return Ok(());
    }

    // A cancelled query can leave a server session briefly attached while
    // SQLx finishes rollback-on-drop cleanup. The name is generated locally;
    // FORCE can therefore disconnect only this test's disposable database.
    let force_statement = format!("DROP DATABASE {quoted_name} WITH (FORCE)");
    sqlx::query(AssertSqlSafe(force_statement))
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| "could not drop the generated test database after forced cleanup")
}

async fn with_database<F, Fut>(
    apply_migration: bool,
    app_pool_size: u32,
    app_acquire_timeout: Duration,
    test: F,
) where
    F: FnOnce(DatabaseAccess) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let database = TestDatabase::provision(apply_migration, app_pool_size, app_acquire_timeout)
        .await
        .unwrap_or_else(|message| panic!("{message}"));
    let outcome = tokio::spawn(test(database.access())).await;
    database
        .cleanup()
        .await
        .unwrap_or_else(|message| panic!("{message}"));
    match outcome {
        Ok(()) => {}
        Err(error) if error.is_panic() => resume_unwind(error.into_panic()),
        Err(_) => panic!("the live database test task was cancelled"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn postgres_satisfies_the_shared_store_contract() {
    with_database(
        true,
        DEFAULT_APP_POOL_SIZE,
        Duration::from_secs(10),
        |database| async move {
            store_contract::run_store_contracts(PostgresRelationshipStore::new(database.app_pool))
                .await;
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn postgres_reports_real_repeatable_read_and_read_only_modes() {
    with_database(
        true,
        DEFAULT_APP_POOL_SIZE,
        Duration::from_secs(10),
        |database| async move {
            let mut transaction = database
                .app_pool
                .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .await
                .expect("PostgreSQL accepts the required read transaction mode");
            let isolation = sqlx::query_scalar::<_, String>("SHOW transaction_isolation")
                .fetch_one(&mut *transaction)
                .await
                .expect("read transaction isolation is visible on the server");
            let read_only = sqlx::query_scalar::<_, String>("SHOW transaction_read_only")
                .fetch_one(&mut *transaction)
                .await
                .expect("read-only mode is visible on the server");
            assert_eq!(isolation, "repeatable read");
            assert_eq!(read_only, "on");
            transaction
                .rollback()
                .await
                .expect("read-only transaction rolls back cleanly");
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn missing_migration_errors_propagate_through_the_evaluator() {
    with_database(
        false,
        DEFAULT_APP_POOL_SIZE,
        Duration::from_secs(10),
        |database| async move {
            let authz = FgaAuthz::new(
                "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n",
            )
            .expect("test model compiles")
            .with_store(
                PostgresRelationshipStore::new(database.app_pool),
                EvaluationLimits::default(),
            );
            let result = authz
                .check(CheckRequest::new(
                    TenantId::new("missing-migration").unwrap(),
                    Subject::new("user", "alice").unwrap(),
                    ObjectRef::new("document", "missing-migration").unwrap(),
                    RelationName::new("viewer").unwrap(),
                ))
                .await;
            assert!(matches!(
                result,
                Err(AuthorizationError::Store(error))
                    if error.kind() == StoreErrorKind::Internal
            ));
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn table_permission_errors_propagate_when_role_creation_is_available() {
    with_database(
        true,
        DEFAULT_APP_POOL_SIZE,
        Duration::from_secs(10),
        |database| async move {
            let can_create_role = sqlx::query_scalar::<_, bool>(
                "SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user",
            )
            .fetch_one(&database.admin_pool)
            .await
            .expect("configured role capability is readable");
            if !can_create_role {
                eprintln!("permission case skipped because the configured role lacks CREATEROLE");
                return;
            }

            let role = format!("r_{}", database.name);
            let password = format!(
                "p_{}_{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock is after the Unix epoch")
                    .as_nanos()
            );
            let quoted_role =
                quote_identifier(&role).expect("generated role is a valid PostgreSQL identifier");
            let quoted_password = quote_test_password(&password)
                .expect("generated password uses a safe alphabet");
            let create_role =
                format!("CREATE ROLE {quoted_role} LOGIN PASSWORD {quoted_password}");
            if let Err(error) = sqlx::query(AssertSqlSafe(create_role))
                .execute(&database.admin_pool)
                .await
            {
                let insufficient_privilege = error
                    .as_database_error()
                    .and_then(|database_error| database_error.code())
                    .is_some_and(|code| code == "42501");
                if insufficient_privilege {
                    eprintln!("permission case skipped because the configured role lacks CREATEROLE");
                    return;
                }
                panic!("could not create the generated permission-test role");
            }
            database.register_role(role.clone());

            let quoted_database = quote_identifier(&database.name)
                .expect("generated database name is a valid PostgreSQL identifier");
            let grant_connect =
                format!("GRANT CONNECT ON DATABASE {quoted_database} TO {quoted_role}");
            sqlx::query(AssertSqlSafe(grant_connect))
                .execute(&database.admin_pool)
                .await
                .expect("generated role receives access to only the generated database");
            let grant_schema = format!("GRANT USAGE ON SCHEMA relgraph_authz TO {quoted_role}");
            sqlx::query(AssertSqlSafe(grant_schema))
                .execute(&database.admin_pool)
                .await
                .expect("generated role can resolve the adapter schema");
            let has_select = sqlx::query_scalar::<_, bool>(
                "SELECT has_table_privilege($1, \
                 'relgraph_authz.relationship_tuples', 'SELECT')",
            )
            .bind(&role)
            .fetch_one(&database.admin_pool)
            .await
            .expect("table privilege is readable by the admin connection");
            assert!(!has_select, "generated role must not read relationship rows");

            let restricted_pool = PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(10))
                .connect_with(
                    database
                        .base_options
                        .clone()
                        .username(&role)
                        .password(&password)
                        .database(&database.name),
                )
                .await
                .unwrap_or_else(|_| panic!("generated restricted role could not connect"));
            database.register_pool(restricted_pool.clone());

            let authz = FgaAuthz::new(
                "model\nschema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]\n",
            )
            .expect("permission test model compiles")
            .with_store(
                PostgresRelationshipStore::new(restricted_pool.clone()),
                EvaluationLimits::default(),
            );
            let result = authz
                .check(CheckRequest::new(
                    TenantId::new("permission-denied").unwrap(),
                    Subject::new("user", "alice").unwrap(),
                    ObjectRef::new("document", "permission-denied").unwrap(),
                    RelationName::new("viewer").unwrap(),
                ))
                .await;
            assert!(matches!(
                result,
                Err(AuthorizationError::Store(error))
                    if error.kind() == StoreErrorKind::Internal
            ));
            restricted_pool.close().await;
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn concurrent_duplicate_inserts_and_removals_are_strict() {
    with_database(
        true,
        DEFAULT_APP_POOL_SIZE,
        Duration::from_secs(10),
        |database| async move {
            let store = PostgresRelationshipStore::new(database.app_pool);
            let tenant = TenantId::new("concurrent-contract").unwrap();
            let tuple = test_tuple("concurrent-contract", "same-insert", "alice");
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
            let left = {
                let store = store.clone();
                let tenant = tenant.clone();
                let tuple = tuple.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.insert_tuple(&tenant, &tuple).await
                })
            };
            let right = {
                let store = store.clone();
                let tenant = tenant.clone();
                let tuple = tuple.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.insert_tuple(&tenant, &tuple).await
                })
            };
            barrier.wait().await;
            let left = left
                .await
                .unwrap_or_else(|_| panic!("left insert task panicked"));
            let right = right
                .await
                .unwrap_or_else(|_| panic!("right insert task panicked"));
            assert_ne!(left.is_ok(), right.is_ok());
            for result in [left, right] {
                if let Err(error) = result {
                    assert_eq!(error.kind(), StoreErrorKind::Conflict);
                }
            }

            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
            let left = {
                let store = store.clone();
                let tenant = tenant.clone();
                let tuple = tuple.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.remove_tuple(&tenant, &tuple).await
                })
            };
            let right = {
                let store = store.clone();
                let tenant = tenant.clone();
                let tuple = tuple.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    store.remove_tuple(&tenant, &tuple).await
                })
            };
            barrier.wait().await;
            let left = left
                .await
                .unwrap_or_else(|_| panic!("left remove task panicked"))
                .unwrap();
            let right = right
                .await
                .unwrap_or_else(|_| panic!("right remove task panicked"))
                .unwrap();
            assert_ne!(left, right);
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn context_codec_preserves_nested_json_numbers_and_large_values() {
    with_database(
        true,
        DEFAULT_APP_POOL_SIZE,
        Duration::from_secs(10),
        |database| async move {
            let store = PostgresRelationshipStore::new(database.app_pool);
            let tenant = TenantId::new("codec-contract").unwrap();
            let object = ObjectRef::new("document", "codec-contract").unwrap();
            let relation = RelationName::new("viewer").unwrap();
            let reordered_a = serde_json::from_str::<serde_json::Value>(
                r#"{"outer":{"z":1,"a":2},"array":[1,2]}"#,
            )
            .unwrap();
            let reordered_b = serde_json::from_str::<serde_json::Value>(
                r#"{"array":[1,2],"outer":{"a":2,"z":1}}"#,
            )
            .unwrap();
            let reordered = |value| {
                RelationshipTuple::new(
                    tenant.clone(),
                    object.clone(),
                    relation.clone(),
                    Subject::new("user", "reordered").unwrap(),
                )
                .with_condition(
                    ConditionContext::new(
                        "codec",
                        std::collections::BTreeMap::from([("nested".to_owned(), value)]),
                    )
                    .unwrap(),
                )
            };
            let reordered_tuple = reordered(reordered_a);
            store.insert_tuple(&tenant, &reordered_tuple).await.unwrap();
            assert!(matches!(
                store
                    .insert_tuple(&tenant, &reordered(reordered_b))
                    .await,
                Err(error) if error.kind() == StoreErrorKind::Conflict
            ));

            let values = std::collections::BTreeMap::from([
                ("null".to_owned(), serde_json::Value::Null),
                ("bool".to_owned(), serde_json::json!(true)),
                ("escaped".to_owned(), serde_json::json!("nul\u{0}é雪")),
                (
                    "nested".to_owned(),
                    serde_json::json!({"z": [null, false, {"b": 2, "a": 1}], "a": "é"}),
                ),
                ("i64-min".to_owned(), serde_json::json!(i64::MIN)),
                ("u64-max".to_owned(), serde_json::json!(u64::MAX)),
                ("integer".to_owned(), serde_json::json!(1)),
                (
                    "float".to_owned(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(1.0).expect("finite test float"),
                    ),
                ),
                (
                    "signed-zero".to_owned(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(-0.0).expect("finite signed zero"),
                    ),
                ),
                (
                    "difficult-float".to_owned(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(std::f64::consts::PI)
                            .expect("finite test float"),
                    ),
                ),
                (
                    "large".to_owned(),
                    serde_json::Value::String("x".repeat(32_768)),
                ),
            ]);
            let full_tuple = RelationshipTuple::new(
                tenant.clone(),
                object.clone(),
                relation.clone(),
                Subject::new("user", "all-values").unwrap(),
            )
            .with_condition(ConditionContext::new("codec", values).unwrap());
            let integer_tuple = RelationshipTuple::new(
                tenant.clone(),
                object.clone(),
                relation.clone(),
                Subject::new("user", "number-kind").unwrap(),
            )
            .with_condition(
                ConditionContext::new(
                    "codec",
                    std::collections::BTreeMap::from([("number".to_owned(), serde_json::json!(1))]),
                )
                .unwrap(),
            );
            let float_tuple = RelationshipTuple::new(
                tenant.clone(),
                object.clone(),
                relation.clone(),
                Subject::new("user", "number-kind").unwrap(),
            )
            .with_condition(
                ConditionContext::new(
                    "codec",
                    std::collections::BTreeMap::from([(
                        "number".to_owned(),
                        serde_json::Value::Number(
                            serde_json::Number::from_f64(1.0).expect("finite test float"),
                        ),
                    )]),
                )
                .unwrap(),
            );
            store.insert_tuple(&tenant, &full_tuple).await.unwrap();
            store.insert_tuple(&tenant, &integer_tuple).await.unwrap();
            store.insert_tuple(&tenant, &float_tuple).await.unwrap();

            let session = store.begin_read(&tenant).await.unwrap();
            assert_eq!(
                session.tuples(&object, &relation, 10).await.unwrap(),
                [reordered_tuple, full_tuple, integer_tuple, float_tuple]
            );
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn digest_collisions_and_malformed_persisted_rows_fail_safely() {
    with_database(
        true,
        DEFAULT_APP_POOL_SIZE,
        Duration::from_secs(10),
        |database| async move {
            let store = PostgresRelationshipStore::new(database.app_pool.clone());
            let tenant = TenantId::new("corrupt-contract").unwrap();
            let document = ObjectRef::new("document", "digest-collision").unwrap();
            let relation = RelationName::new("viewer").unwrap();
            let original = RelationshipTuple::new(
                tenant.clone(),
                document.clone(),
                relation.clone(),
                Subject::new("user", "alice").unwrap(),
            );
            store.insert_tuple(&tenant, &original).await.unwrap();
            sqlx::query(
                "UPDATE relgraph_authz.relationship_tuples SET subject_id = $1 \
                 WHERE tenant = $2 AND object_type = $3 AND object_id = $4 AND relation = $5",
            )
            .bind("mallory")
            .bind(tenant.as_str())
            .bind(document.type_name().as_str())
            .bind(document.id().as_str())
            .bind(relation.as_str())
            .execute(&database.admin_pool)
            .await
            .expect("bound test update corrupts only the generated database tuple");

            // The insert cannot see the corruption without reading the row;
            // the identity digest still collides, so it fails as a conflict.
            assert!(matches!(
                store.insert_tuple(&tenant, &original).await,
                Err(error) if error.kind() == StoreErrorKind::Conflict
            ));
            assert!(matches!(
                store.remove_tuple(&tenant, &original).await,
                Err(error) if error.kind() == StoreErrorKind::CorruptData
            ));
            let row_count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM relgraph_authz.relationship_tuples \
                 WHERE tenant = $1 AND object_type = $2 AND object_id = $3 AND relation = $4",
            )
            .bind(tenant.as_str())
            .bind(document.type_name().as_str())
            .bind(document.id().as_str())
            .bind(relation.as_str())
            .fetch_one(&database.admin_pool)
            .await
            .expect("test row count is readable");
            assert_eq!(row_count, 1, "failed removal preserves the malformed row");

            let conditional = RelationshipTuple::new(
                tenant.clone(),
                ObjectRef::new("document", "malformed-context").unwrap(),
                relation.clone(),
                Subject::new("user", "alice").unwrap(),
            )
            .with_condition(
                ConditionContext::new(
                    "grant",
                    std::collections::BTreeMap::from([(
                        "enabled".to_owned(),
                        serde_json::json!(true),
                    )]),
                )
                .unwrap(),
            );
            store.insert_tuple(&tenant, &conditional).await.unwrap();
            sqlx::query(
                "UPDATE relgraph_authz.relationship_tuples SET context_json = $1 \
                 WHERE tenant = $2 AND object_id = $3",
            )
            .bind("[]")
            .bind(tenant.as_str())
            .bind("malformed-context")
            .execute(&database.admin_pool)
            .await
            .expect("bound test update stores malformed condition context");
            let session = store.begin_read(&tenant).await.unwrap();
            assert!(matches!(
                session
                    .tuples(
                        &ObjectRef::new("document", "malformed-context").unwrap(),
                        &relation,
                        10,
                    )
                    .await,
                Err(error) if error.kind() == StoreErrorKind::CorruptData
            ));
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn exhausted_single_connection_pool_times_out_as_unavailable() {
    with_database(true, 1, Duration::from_millis(150), |database| async move {
        let store = PostgresRelationshipStore::new(database.app_pool.clone());
        let tenant = TenantId::new("pool-exhaustion").unwrap();
        let held_connection = database
            .app_pool
            .acquire()
            .await
            .expect("the one application connection is acquired");
        let result = store.begin_read(&tenant).await;
        assert!(matches!(
            result,
            Err(error) if error.kind() == StoreErrorKind::Unavailable
        ));
        drop(held_connection);
        assert_pool_connection_is_clean(&database.app_pool).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn closed_application_pool_maps_to_unavailable() {
    with_database(true, 1, Duration::from_secs(2), |database| async move {
        let store = PostgresRelationshipStore::new(database.app_pool.clone());
        database.app_pool.close().await;
        assert!(matches!(
            store
                .begin_read(&TenantId::new("closed-pool").unwrap())
                .await,
            Err(error) if error.kind() == StoreErrorKind::Unavailable
        ));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn statement_timeout_is_mapped_and_the_failed_transaction_is_cleaned_up() {
    with_database(true, 1, Duration::from_secs(5), |database| async move {
        let mut connection = database
            .app_pool
            .acquire()
            .await
            .expect("one application connection is available");
        sqlx::query("SELECT set_config('statement_timeout', $1, false)")
            .bind("250ms")
            .execute(&mut *connection)
            .await
            .expect("statement timeout is configured on the pooled connection");
        drop(connection);

        let mut blocker = database
            .admin_pool
            .begin()
            .await
            .expect("admin transaction starts");
        sqlx::query("LOCK TABLE relgraph_authz.relationship_tuples IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .expect("admin transaction holds the relationship table lock");

        let store = PostgresRelationshipStore::new(database.app_pool.clone());
        let tenant = TenantId::new("statement-timeout").unwrap();
        let session = store
            .begin_read(&tenant)
            .await
            .expect("snapshot can be established before touching the locked table");
        let page_result = tokio::time::timeout(
            Duration::from_secs(5),
            session.tuples_page(
                &ObjectRef::new("document", "timeout").unwrap(),
                &RelationName::new("viewer").unwrap(),
                None,
                1,
            ),
        )
        .await
        .expect("the server statement timeout bounds the locked query");
        match page_result {
            Err(error) => assert_eq!(error.kind(), StoreErrorKind::Unavailable),
            Ok(_) => panic!("locked table query unexpectedly completed"),
        }
        drop(session);
        blocker
            .commit()
            .await
            .expect("table lock is released after the timed-out query");
        assert_pool_connection_is_clean(&database.app_pool).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENFGA_POSTGRES_TEST_URL pointing to a disposable PostgreSQL database"]
async fn cancelling_a_locked_query_releases_the_single_pool_connection() {
    with_database(true, 1, Duration::from_secs(10), |database| async move {
        let mut blocker = database
            .admin_pool
            .begin()
            .await
            .expect("admin transaction starts");
        sqlx::query("LOCK TABLE relgraph_authz.relationship_tuples IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .expect("admin transaction holds the relationship table lock");

        let store = PostgresRelationshipStore::new(database.app_pool.clone());
        let session = store
            .begin_read(&TenantId::new("cancelled-query").unwrap())
            .await
            .expect("read snapshot is established");
        let task = tokio::spawn(async move {
            session
                .tuples_page(
                    &ObjectRef::new("document", "cancelled-query").unwrap(),
                    &RelationName::new("viewer").unwrap(),
                    None,
                    1,
                )
                .await
        });
        wait_for_locked_relationship_query(&database).await;
        task.abort();
        match task.await {
            Err(error) if error.is_cancelled() => {}
            _ => panic!("the blocked page task was not cancelled"),
        }
        blocker
            .commit()
            .await
            .expect("table lock is released after cancellation");
        assert_pool_connection_is_clean(&database.app_pool).await;
    })
    .await;
}

async fn wait_for_locked_relationship_query(database: &DatabaseAccess) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (\
                 SELECT 1 FROM pg_stat_activity \
                 WHERE datname = $1 AND state = 'active' \
                   AND wait_event_type = 'Lock' \
                   AND query LIKE '%relgraph_authz.relationship_tuples%'\
             )",
        )
        .bind(&database.name)
        .fetch_one(&database.admin_pool)
        .await
        .expect("PostgreSQL reports the blocked adapter query");
        if blocked {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the adapter query did not reach the table-lock barrier before its deadline"
        );
        tokio::task::yield_now().await;
    }
}

async fn assert_pool_connection_is_clean(pool: &PgPool) {
    let mut connection = tokio::time::timeout(Duration::from_secs(5), pool.acquire())
        .await
        .expect("application connection is returned before the deadline")
        .expect("application pool remains usable");
    let value = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&mut *connection),
    )
    .await
    .expect("fresh pooled query completes before the deadline")
    .expect("fresh pooled query succeeds");
    assert_eq!(value, 1);
    let read_only = sqlx::query_scalar::<_, String>("SHOW transaction_read_only")
        .fetch_one(&mut *connection)
        .await
        .expect("reused connection reports its transaction mode");
    assert_eq!(
        read_only, "off",
        "the read snapshot was rolled back before pool reuse"
    );
}

#[test]
fn dynamic_postgres_identifiers_are_quoted_and_bounded() {
    assert_eq!(
        quote_identifier("generated_name").unwrap(),
        "\"generated_name\""
    );
    assert_eq!(
        quote_identifier("name\"; DROP TABLE users; --").unwrap(),
        "\"name\"\"; DROP TABLE users; --\""
    );
    assert!(quote_identifier(&"x".repeat(64)).is_err());
    assert!(quote_identifier("name\0suffix").is_err());

    assert_eq!(quote_test_password("p_123_456").unwrap(), "'p_123_456'");
    assert!(quote_test_password("p_123'; DROP ROLE x; --").is_err());
}

fn test_tuple(tenant_name: &str, object_id: &str, subject_id: &str) -> RelationshipTuple {
    RelationshipTuple::new(
        TenantId::new(tenant_name).unwrap(),
        ObjectRef::new("document", object_id).unwrap(),
        RelationName::new("viewer").unwrap(),
        TupleSubject::Direct(Subject::new("user", subject_id).unwrap()),
    )
}
