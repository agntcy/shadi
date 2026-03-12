// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::Path;
use std::sync::{Once, OnceLock};

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{trace, Resource};
use tracing_subscriber::layer::SubscriberExt;

static INIT: Once = Once::new();
static PROVIDER: OnceLock<trace::TracerProvider> = OnceLock::new();
static FILE_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

pub fn init(service_name: &str) {
    INIT.call_once(|| {
        let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_default();
        let console = env::var("SHADI_OTEL_CONSOLE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let console_enabled = matches!(console.as_str(), "1" | "true" | "yes");

        let file_path = env::var("SHADI_OTEL_FILE")
            .ok()
            .filter(|value| !value.trim().is_empty());

        if otlp_endpoint.is_empty() && !console_enabled && file_path.is_none() {
            return;
        }

        let service_name = env::var("OTEL_SERVICE_NAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| service_name.to_string());

        let resource = Resource::new(vec![
            KeyValue::new("service.name", service_name),
            KeyValue::new("service.namespace", "shadi"),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("telemetry.sdk.language", "rust"),
        ]);

        let otel_layer = if !otlp_endpoint.is_empty() {
            let exporter = opentelemetry_otlp::new_exporter()
                .http()
                .with_endpoint(otlp_endpoint);
            let provider = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(exporter)
                .with_trace_config(trace::Config::default().with_resource(resource))
                .install_simple();

            provider.ok().map(|provider| {
                let _ = PROVIDER.set(provider);
                let tracer = PROVIDER
                    .get()
                    .expect("telemetry provider")
                    .tracer("shadi.telemetry");
                tracing_opentelemetry::layer().with_tracer(tracer)
            })
        } else {
            None
        };

        let file_layer = file_path.as_ref().and_then(|path| {
            let trace_path = Path::new(path);
            let dir = trace_path.parent().unwrap_or_else(|| Path::new("."));
            let file_name = trace_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("traces.jsonl");

            if std::fs::create_dir_all(dir).is_err() {
                return None;
            }

            let appender = tracing_appender::rolling::never(dir, file_name);
            let (non_blocking, guard) = tracing_appender::non_blocking(appender);
            let _ = FILE_GUARD.set(guard);

            Some(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(true)
                    .with_ansi(false)
                    .with_writer(non_blocking),
            )
        });

        let fmt_layer = console_enabled.then(|| tracing_subscriber::fmt::layer());

        let subscriber = tracing_subscriber::registry()
            .with(otel_layer)
            .with(fmt_layer)
            .with(file_layer);

        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}
