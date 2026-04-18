// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Centralized telemetry initialization for all `PrintForge` services.
//!
//! Configures `tracing-subscriber` with structured JSON logging and an
//! optional OpenTelemetry OTLP exporter for distributed tracing.
//!
//! - If `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are exported via
//!   gRPC to the configured collector (e.g., Jaeger, Tempo).
//! - If not set, only local JSON logging is active — no OTLP traffic.
//!
//! **NIST 800-53 Rev 5:** AU-2 — Event Logging, AU-3 — Content of
//! Audit Records. Structured tracing ensures all auditable events are
//! captured with who, what, when, where, and outcome.

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::error::CommonError;

/// Initialize the global tracing subscriber for the given service.
///
/// When `OTEL_EXPORTER_OTLP_ENDPOINT` is present in the environment,
/// an OpenTelemetry tracing pipeline is configured to export spans via
/// OTLP/gRPC to the specified endpoint. Otherwise, only local JSON
/// structured logging is enabled.
///
/// The `RUST_LOG` environment variable controls the log filter level.
/// If unset, defaults to `info`.
///
/// # Errors
///
/// Returns [`CommonError::Config`] if the OpenTelemetry pipeline fails
/// to initialize (e.g., invalid endpoint).
pub fn init_telemetry(service_name: &str) -> Result<(), CommonError> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        init_with_otlp(service_name, env_filter)
    } else {
        init_local_only(env_filter);
        Ok(())
    }
}

/// Initialize tracing with an OTLP exporter layer.
fn init_with_otlp(service_name: &str, env_filter: EnvFilter) -> Result<(), CommonError> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::SpanExporter;

    let exporter = SpanExporter::builder()
        .with_tonic()
        .build()
        .map_err(|e| CommonError::Config {
            message: format!("failed to build OTLP exporter: {e}"),
        })?;

    let resource = opentelemetry_sdk::Resource::new(vec![
        KeyValue::new("service.name", service_name.to_owned()),
    ]);

    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer(service_name.to_owned());
    opentelemetry::global::set_tracer_provider(provider);

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().json())
        .with(otel_layer)
        .init();

    Ok(())
}

/// Initialize tracing with local JSON logging only (no OTLP export).
fn init_local_only(env_filter: EnvFilter) {
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().json())
        .init();
}

/// Flush and shut down the global OpenTelemetry tracer provider.
///
/// Call this during graceful shutdown to ensure all buffered spans are
/// exported before the process exits. Safe to call even when no OTLP
/// exporter was configured — it is a no-op in that case.
pub fn shutdown_telemetry() {
    opentelemetry::global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test that calls init_telemetry must run in isolation because
    // the global subscriber can only be set once per process. We use
    // serial test execution (cargo nextest runs each test in its own
    // process by default).

    #[test]
    fn init_telemetry_without_otel_env_does_not_panic() {
        // OTEL_EXPORTER_OTLP_ENDPOINT is not set in the test
        // environment, so this exercises the local-only path.
        assert!(std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_err());
        let result = init_telemetry("test-service");
        assert!(result.is_ok());
    }

    #[test]
    fn shutdown_telemetry_is_safe_without_provider() {
        // Calling shutdown when no provider was configured should not
        // panic or error.
        shutdown_telemetry();
    }
}
