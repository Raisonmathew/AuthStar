mod audit;
mod cache;
mod capsules;
mod clients;
mod config;
mod coordination;
mod db;
mod middleware;
mod redis;
mod router;
mod routes;
mod services;
mod state;
mod telemetry;

use config::Config;
use state::AppState;
mod bootstrap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // HIGH-19 FIX: Initialize OpenTelemetry distributed tracing.
    // Replaces the inline tracing_subscriber setup. When OTEL_EXPORTER_OTLP_ENDPOINT
    // is set, spans are exported to the configured collector (Jaeger/Tempo).
    // Falls back to stdout-only tracing if OTel is disabled or the exporter fails.
    telemetry::init_tracing();

    // D-2: Install the Prometheus metrics recorder.
    // This must happen before any metrics are recorded (i.e. before the router is built
    // and before any background jobs start). The `PrometheusHandle` is used by the
    // GET /metrics handler to render the current snapshot in Prometheus text format.
    //
    // We use `build_recorder()` rather than `install()` so we can inject the handle
    // into the router via axum::Extension without relying on the global recorder.
    // The recorder is still installed globally via `metrics::set_global_recorder()` so
    // that call-site macros (metrics::counter!, metrics::histogram!, etc.) work without
    // needing to pass the handle around.
    let prometheus_handle = {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new()
            // Histogram buckets tuned for HTTP request latencies (seconds)
            .set_buckets(&[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ])
            .map_err(|e| anyhow::anyhow!("Failed to configure Prometheus buckets: {e}"))?
            .build_recorder();
        let handle = recorder.handle();
        metrics::set_global_recorder(recorder)
            .map_err(|e| anyhow::anyhow!("Failed to install Prometheus recorder: {e}"))?;
        tracing::info!("Prometheus metrics recorder installed (GET /metrics)");
        handle
    };

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Configuration loaded");

    // Initialize application state
    let state = AppState::new(config.clone()).await?;
    tracing::info!("Application state initialized");

    // Create router and inject the PrometheusHandle as an Extension so the
    // GET /metrics handler can render the current snapshot.
    let app = router::create_router(state.clone()).layer(axum::Extension(prometheus_handle));

    // Phase 7: Create a shutdown broadcast channel.
    // All background tasks listen on this channel to coordinate graceful shutdown.
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);

    // Phase 6: Start background jobs with leader election.
    // Only the elected leader replica runs the baseline computation job.
    // Other replicas participate in heartbeats and take over if the leader dies.
    {
        let replica_id = {
            let hostname = hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string());
            format!("{}:{}", hostname, std::process::id())
        };

        let election = coordination::leader_election::LeaderElection::new(
            state.redis.clone(),
            replica_id.clone(),
            "baseline_computation".to_string(),
        );

        let db_for_job = state.db.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(coordination::leader_election::run_with_leader_election(
            election,
            std::time::Duration::from_secs(3600), // Run every hour
            move || {
                let db = db_for_job.clone();
                async move {
                    let job = risk_engine::jobs::BaselineComputationJob::new(db);
                    job.run_all().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                    Ok(())
                }
            },
            shutdown_rx,
        ));
        tracing::info!(
            replica = %replica_id,
            "Baseline computation job registered with leader election"
        );
    }

    // Spawn the auth_attempts pruning loop. Runs on every replica (cheap, idempotent
    // DELETE) so the table stays bounded even if leader-election is misconfigured.
    risk_engine::jobs::AuthAttemptsPruneJob::new(state.db.clone()).spawn();
    tracing::info!("auth_attempts prune job spawned (retention: 7 days, interval: 1h)");

    // Seed System Organization and Policies (Shared with tests)
    bootstrap::seed_system_org(&state.db).await?;
    tracing::info!("System bootstrap verified");

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("🚀 Server listening on {}", addr);

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    // Phase 7: Graceful shutdown with draining
    //
    // 1. Receive SIGTERM/SIGINT
    // 2. Signal background tasks to stop (shutdown_tx)
    // 3. Stop accepting new connections (axum handles this)
    // 4. Wait for in-flight requests to complete (axum graceful shutdown)
    // 5. Flush OTel spans
    let shutdown_signal = {
        let shutdown_tx = shutdown_tx.clone();
        async move {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C signal handler");
            tracing::info!("Shutdown signal received, starting graceful shutdown...");

            // Signal all background tasks (leader election, overflow worker, etc.)
            let _ = shutdown_tx.send(true);

            // Give background tasks a moment to release leadership and flush state
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            tracing::info!("Background tasks signaled, draining in-flight requests...");
        }
    };

    server.with_graceful_shutdown(shutdown_signal).await?;

    tracing::info!("Server stopped, flushing telemetry...");

    // Flush and shut down OTel tracer provider (exports remaining spans)
    telemetry::shutdown_tracer_provider();

    tracing::info!("Graceful shutdown complete");
    Ok(())
}
