use sqlx::PgPool;

// Migration version: 027 - tenant_scope_indexes
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
