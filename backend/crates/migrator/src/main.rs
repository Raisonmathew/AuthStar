use sqlx::postgres::PgPoolOptions;
use anyhow::Result;
use tracing::{info, warn, error};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        tracing::error!("MIGRATION ERROR: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    info!("Migrator started");
    let root_url = std::env::var("ROOT_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/postgres".to_string());
    info!("Connecting to root DB");
    
    // Connect to 'postgres' database
    match PgPoolOptions::new().idle_timeout(std::time::Duration::from_secs(2)).connect(&root_url).await {
        Ok(root_pool) => {
            info!("Connected. Checking 'idaas_user'...");
            let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM pg_roles WHERE rolname = 'idaas_user'")
                .fetch_optional(&root_pool).await.unwrap_or(None);

            if row.is_none() {
                info!("Creating 'idaas_user'...");
                if let Err(e) = sqlx::query("CREATE USER idaas_user WITH PASSWORD 'password' SUPERUSER LOGIN").execute(&root_pool).await {
                    warn!("Error creating user (might exist): {}", e);
                }
            } else {
                info!("'idaas_user' exists.");
            }

            info!("Checking 'idaas' database...");
            let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM pg_database WHERE datname = 'idaas'")
                .fetch_optional(&root_pool).await.unwrap_or(None);

            if row.is_none() {
                info!("Creating 'idaas' database...");
                // Note: CREATE DATABASE requires no transaction. Execute on pool should be fine.
                if let Err(e) = sqlx::query("CREATE DATABASE idaas OWNER idaas_user").execute(&root_pool).await {
                     warn!("Error creating DB (might exist): {}", e);
                }
            } else {
                info!("'idaas' database exists.");
            }
            root_pool.close().await;
        },
        Err(e) => error!("Failed to connect to root DB: {}", e),
    }

    info!("Proceeding to migrations...");
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://idaas_user:password@localhost:5432/idaas".to_string());
    info!("Connecting to target DB");

    let pool = PgPoolOptions::new().connect(&db_url).await?;

    info!("Running migrations...");
    let m = sqlx::migrate::Migrator::new(std::path::Path::new("crates/db_migrations/migrations")).await?;
    m.run(&pool).await?;
    
    info!("Migrations completed successfully!");
    Ok(())
}
