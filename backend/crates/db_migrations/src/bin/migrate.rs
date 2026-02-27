use sqlx::postgres::PgPoolOptions;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/idaas".to_string());

    tracing::info!("Connecting to database");

    let pool = PgPoolOptions::new()
        .connect(&database_url)
        .await?;

    tracing::info!("Running migrations...");
    db_migrations::run_migrations(&pool).await?;
    
    tracing::info!("Migrations complete!");
    Ok(())
}
