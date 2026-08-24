// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Once, OnceLock};

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{trace, Resource};
use tracing_subscriber::layer::SubscriberExt;

static INIT: Once = Once::new();
static PROVIDER: OnceLock<trace::SdkTracerProvider> = OnceLock::new();
static FILE_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

pub fn init(service_name: &str) {
    INIT.call_once(|| {
        let config = load_config(service_name);

        if !telemetry_enabled(
            &config.otlp_endpoint,
            config.console_enabled,
            config.file_path.as_deref(),
        ) {
            return;
        }

        let resource = Resource::builder()
            .with_attributes([
                KeyValue::new("service.name", config.service_name),
                KeyValue::new("service.namespace", "shadi"),
                KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                KeyValue::new("telemetry.sdk.language", "rust"),
            ])
            .build();

        let otel_layer = if !config.otlp_endpoint.is_empty() {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(traces_endpoint(&config.otlp_endpoint))
                .build();

            exporter.ok().map(|exporter| {
                // Batched, not simple: export runs on its own thread, so it
                // neither needs a reactor at startup nor blocks inside one when
                // a span ends in async code.
                let provider = trace::SdkTracerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(resource)
                    .build();
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

        let file_layer = config.file_path.as_ref().and_then(|path| {
            let (dir, file_name) = resolve_trace_path(path)?;
            if std::fs::create_dir_all(&dir).is_err() {
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

        let fmt_layer = config.console_enabled.then(|| tracing_subscriber::fmt::layer());

        let subscriber = tracing_subscriber::registry()
            .with(otel_layer)
            .with(fmt_layer)
            .with(file_layer);

        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// OTEL_EXPORTER_OTLP_ENDPOINT is a base URL per the OpenTelemetry spec, and
/// 0.24 appended the signal path itself. 0.32 takes the full URL, so a base
/// endpoint has to be completed here or spans go nowhere.
/// Flush and stop the exporter.
///
/// Batched export means spans still in the queue are lost if the process just
/// exits, so anything that calls [`init`] should call this on the way out.
pub fn shutdown() {
    if let Some(provider) = PROVIDER.get() {
        if let Err(err) = provider.shutdown() {
            tracing::debug!(%err, "telemetry shutdown failed");
        }
    }
}

fn traces_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if trimmed.ends_with("/v1/traces") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1/traces")
    }
}

fn parse_bool_env(key: &str) -> bool {
    let value = env::var(key).unwrap_or_default().trim().to_ascii_lowercase();
    matches!(value.as_str(), "1" | "true" | "yes")
}

fn normalize_file_path(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn resolve_trace_path(path: &str) -> Option<(PathBuf, String)> {
    let trace_path = Path::new(path);
    let dir = trace_path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
    let file_name = trace_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("traces.jsonl")
        .to_string();
    Some((dir, file_name))
}

#[derive(Debug, Clone)]
struct TelemetryConfig {
    otlp_endpoint: String,
    console_enabled: bool,
    file_path: Option<String>,
    service_name: String,
}

fn load_config(default_service_name: &str) -> TelemetryConfig {
    let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_default();
    let console_enabled = parse_bool_env("SHADI_OTEL_CONSOLE");
    let file_path = env::var("SHADI_OTEL_FILE")
        .ok()
        .and_then(|value| normalize_file_path(&value));
    let service_name = resolve_service_name(default_service_name);

    TelemetryConfig {
        otlp_endpoint,
        console_enabled,
        file_path,
        service_name,
    }
}

fn resolve_service_name(default_service_name: &str) -> String {
    env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_service_name.to_string())
}

fn telemetry_enabled(otlp_endpoint: &str, console_enabled: bool, file_path: Option<&str>) -> bool {
    !otlp_endpoint.is_empty() || console_enabled || file_path.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_bool_env_accepts_truthy_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SHADI_OTEL_CONSOLE", "1");
        assert!(parse_bool_env("SHADI_OTEL_CONSOLE"));
        std::env::set_var("SHADI_OTEL_CONSOLE", "true");
        assert!(parse_bool_env("SHADI_OTEL_CONSOLE"));
        std::env::set_var("SHADI_OTEL_CONSOLE", "yes");
        assert!(parse_bool_env("SHADI_OTEL_CONSOLE"));
        std::env::set_var("SHADI_OTEL_CONSOLE", "no");
        assert!(!parse_bool_env("SHADI_OTEL_CONSOLE"));
        std::env::remove_var("SHADI_OTEL_CONSOLE");
    }

    #[test]
    fn normalize_file_path_trims_and_rejects_empty() {
        assert_eq!(normalize_file_path(""), None);
        assert_eq!(normalize_file_path("   "), None);
        assert_eq!(normalize_file_path("/tmp/trace.jsonl"), Some("/tmp/trace.jsonl".to_string()));
        assert_eq!(normalize_file_path("  ./traces.jsonl "), Some("./traces.jsonl".to_string()));
    }

    #[test]
    fn resolve_trace_path_builds_dir_and_name() {
        let (dir, file) = resolve_trace_path("/tmp/trace.jsonl").expect("path");
        assert_eq!(dir, PathBuf::from("/tmp"));
        assert_eq!(file, "trace.jsonl");
    }

    #[test]
    fn resolve_trace_path_defaults_parent_for_bare_filename() {
        let (dir, file) = resolve_trace_path("trace.jsonl").expect("path");
        assert_eq!(dir, PathBuf::new());
        assert_eq!(file, "trace.jsonl");
    }

    #[test]
    fn load_config_reads_env_vars() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318");
        std::env::set_var("SHADI_OTEL_CONSOLE", "true");
        std::env::set_var("SHADI_OTEL_FILE", "./traces.jsonl");
        std::env::set_var("OTEL_SERVICE_NAME", "shadi-test");

        let config = load_config("default");
        assert_eq!(config.otlp_endpoint, "http://localhost:4318");
        assert!(config.console_enabled);
        assert_eq!(config.file_path, Some("./traces.jsonl".to_string()));
        assert_eq!(config.service_name, "shadi-test");

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("SHADI_OTEL_CONSOLE");
        std::env::remove_var("SHADI_OTEL_FILE");
        std::env::remove_var("OTEL_SERVICE_NAME");
    }

    #[test]
    fn resolve_service_name_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OTEL_SERVICE_NAME");
        let name = resolve_service_name("default-service");
        assert_eq!(name, "default-service");
    }

    #[test]
    fn telemetry_enabled_requires_any_sink() {
        assert!(!telemetry_enabled("", false, None));
        assert!(telemetry_enabled("http://localhost:4318", false, None));
        assert!(telemetry_enabled("", true, None));
        assert!(telemetry_enabled("", false, Some("/tmp/trace.jsonl")));
    }

    #[test]
    fn init_configures_console_and_file_layers() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let file_path = std::env::temp_dir().join(format!("shadi-traces-{nanos}.jsonl"));

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::set_var("SHADI_OTEL_CONSOLE", "true");
        std::env::set_var("SHADI_OTEL_FILE", file_path.to_string_lossy().to_string());
        std::env::set_var("OTEL_SERVICE_NAME", "shadi-telemetry-test");

        init("default-service");

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("SHADI_OTEL_CONSOLE");
        std::env::remove_var("SHADI_OTEL_FILE");
        std::env::remove_var("OTEL_SERVICE_NAME");
    }

    /// A base endpoint has to gain the signal path, or 0.32 exports nowhere.
    #[test]
    fn traces_endpoint_completes_a_base_url() {
        assert_eq!(
            traces_endpoint("http://localhost:4318"),
            "http://localhost:4318/v1/traces"
        );
        assert_eq!(
            traces_endpoint("http://localhost:4318/"),
            "http://localhost:4318/v1/traces"
        );
        // Already complete, including a trailing slash, is left as it is.
        assert_eq!(
            traces_endpoint("http://localhost:4318/v1/traces"),
            "http://localhost:4318/v1/traces"
        );
        assert_eq!(
            traces_endpoint("http://collector.example:4318/v1/traces/"),
            "http://collector.example:4318/v1/traces"
        );
    }
}
