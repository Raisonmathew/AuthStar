mod config;
mod state;
mod router;
mod routes;
mod services;
mod clients;
mod capsules;
mod middleware;

use config::Config;
use state::AppState;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
mod bootstrap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,api_server=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Configuration loaded");

    // Initialize application state
    let state = AppState::new(config.clone()).await?;
    tracing::info!("Application state initialized");

    // Create router
    let app = router::create_router(state.clone());

    // Start background jobs
    let baseline_job = risk_engine::jobs::BaselineComputationJob::new(state.db.clone());
    baseline_job.spawn_periodic(1); // Run every hour (1 hour interval)
    tracing::info!("Baseline computation job spawned");

    // Seed System Organization and Policies (Shared with tests)
    bootstrap::seed_system_org(&state.db).await?;
    tracing::info!("System bootstrap verified");

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    tracing::info!("🚀 Server listening on {}", addr);
    
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;

    Ok(())
}
