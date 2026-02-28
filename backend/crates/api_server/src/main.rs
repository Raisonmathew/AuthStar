mod config;
mod state;
mod router;
mod routes;
mod services;
mod clients;
mod capsules;
mod middleware;
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
            .set_buckets(&[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
            .map_err(|e| anyhow::anyhow!("Failed to configure Prometheus buckets: {}", e))?
            .build_recorder();
        let handle = recorder.handle();
        metrics::set_global_recorder(recorder)
            .map_err(|e| anyhow::anyhow!("Failed to install Prometheus recorder: {}", e))?;
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
    let app = router::create_router(state.clone())
        .layer(axum::Extension(prometheus_handle));

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
    
    // HIGH-19 FIX: Use graceful shutdown to flush pending OTel spans before exit.
    // Without this, the last batch of spans is lost when the process terminates.
    let server = axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    // Handle SIGTERM/SIGINT for graceful shutdown
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        tracing::info!("Shutdown signal received, flushing telemetry...");
    };

    server.with_graceful_shutdown(shutdown_signal).await?;

    // Flush and shut down OTel tracer provider (exports remaining spans)
    telemetry::shutdown_tracer_provider();

    Ok(())
}
