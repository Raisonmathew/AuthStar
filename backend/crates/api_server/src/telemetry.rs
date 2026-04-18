//! OpenTelemetry Distributed Tracing Initialization
//!
//! ## HIGH-19 FIX: Distributed Tracing
//!
//! Without distributed tracing, debugging auth failures across the API server,
//! EIAA runtime, and database requires correlating logs by timestamp — error-prone
//! and slow. With OTel, every request gets a trace_id that propagates through all
//! service calls, enabling end-to-end visibility in Jaeger/Grafana Tempo.
//!
//! ## Architecture
//! - **Exporter**: OTLP/gRPC → OpenTelemetry Collector → Jaeger/Tempo
//! - **Propagation**: W3C TraceContext (`traceparent` header) for cross-service correlation
//! - **Sampling**: 100% in dev, configurable via `OTEL_TRACES_SAMPLER_ARG` in production
//! - **Resource**: Service name = `authstar-api`, version from `CARGO_PKG_VERSION`
//!
//! ## Configuration
//! - `OTEL_EXPORTER_OTLP_ENDPOINT`: gRPC endpoint (default: `http://localhost:4317`)
//! - `OTEL_SERVICE_NAME`: Override service name (default: `authstar-api`)
//! - `OTEL_TRACES_SAMPLER_ARG`: Sampling ratio 0.0–1.0 (default: `1.0`)
//! - `OTEL_SDK_DISABLED`: Set to `true` to disable OTel entirely (e.g., in unit tests)
//!
//! ## Shutdown
//! Call `shutdown_tracer_provider()` on graceful shutdown to flush pending spans.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{self as sdktrace, RandomIdGenerator, Sampler},
    Resource,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the global tracing subscriber with OpenTelemetry OTLP export.
///
/// Returns `true` if OTel was successfully initialized, `false` if disabled or failed.
/// On failure, falls back to stdout-only tracing (non-fatal).
///
/// # Panics
/// Does not panic — all errors are logged and fall back gracefully.
pub fn init_tracing() -> bool {
    // Allow disabling OTel entirely (useful in unit tests / CI)
    if std::env::var("OTEL_SDK_DISABLED")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        init_stdout_only();
        tracing::info!("OpenTelemetry disabled via OTEL_SDK_DISABLED=true");
        return false;
    }

    // Auto-disable in local dev: if no explicit endpoint is set, skip OTel
    // to avoid noisy "connection refused" errors when no collector is running.
    let otlp_endpoint = match std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        Ok(ep) => ep,
        Err(_) => {
            init_stdout_only();
            tracing::info!(
                "OpenTelemetry disabled: OTEL_EXPORTER_OTLP_ENDPOINT not set. \
                 Set it to enable distributed tracing, or set OTEL_SDK_DISABLED=true to silence this."
            );
            return false;
        }
    };

    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "authstar-api".to_string());

    // Sampling ratio: 1.0 = 100% (all traces), 0.1 = 10%, etc.
    let sample_ratio: f64 = std::env::var("OTEL_TRACES_SAMPLER_ARG")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0_f64)
        .clamp(0.0_f64, 1.0_f64);

    // Build resource attributes (service.name, service.version, deployment.environment)
    let resource = Resource::new(vec![
        KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME,
            service_name.clone(),
        ),
        KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
            env!("CARGO_PKG_VERSION"),
        ),
        KeyValue::new(
            opentelemetry_semantic_conventions::resource::DEPLOYMENT_ENVIRONMENT,
            std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
        ),
    ]);

    // Build OTLP exporter
    let exporter = match opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(&otlp_endpoint)
        .build_span_exporter()
    {
        Ok(e) => e,
        Err(err) => {
            // Non-fatal: fall back to stdout-only tracing
            eprintln!(
                "WARNING: Failed to build OTLP span exporter (endpoint={otlp_endpoint}): {err}. \
                 Falling back to stdout-only tracing."
            );
            init_stdout_only();
            return false;
        }
    };

    // Build tracer provider with batch exporter (async, non-blocking)
    let tracer_provider = sdktrace::TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_config(
            sdktrace::Config::default()
                .with_sampler(Sampler::TraceIdRatioBased(sample_ratio))
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource),
        )
        .build();

    // Set as global provider (used by opentelemetry::global::tracer())
    let tracer = tracer_provider.tracer(service_name.clone());
    opentelemetry::global::set_tracer_provider(tracer_provider);

    // Set W3C TraceContext propagator (traceparent/tracestate headers)
    // This enables cross-service trace correlation with the EIAA runtime gRPC service
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    // Build tracing subscriber with OTel layer + stdout layer
    let otel_layer = OpenTelemetryLayer::new(tracer);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,api_server=debug,tower_http=debug".into());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();

    tracing::info!(
        service = %service_name,
        otlp_endpoint = %otlp_endpoint,
        sample_ratio = %sample_ratio,
        "OpenTelemetry tracing initialized (OTLP/gRPC)"
    );

    true
}

/// Initialize stdout-only tracing (fallback when OTel is disabled or fails)
fn init_stdout_only() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,api_server=debug".into());

    // Only init if not already initialized (idempotent)
    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}

/// Flush and shut down the global tracer provider.
///
/// Must be called on graceful shutdown to ensure all pending spans are exported.
/// Without this, the last batch of spans may be lost when the process exits.
pub fn shutdown_tracer_provider() {
    opentelemetry::global::shutdown_tracer_provider();
    tracing::info!("OpenTelemetry tracer provider shut down");
}

// Made with Bob
