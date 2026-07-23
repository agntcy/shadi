# Telemetry

SHADI uses OpenTelemetry spans to trace core runtime activity and SecOps workflows.
Telemetry is opt-in and only enabled when an exporter or console output is configured.

## Environment Variables

The core runtime (shadictl, shadi_py, and tools) and the SecOps agent respect the
standard OpenTelemetry variables below.

- `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP/HTTP endpoint for trace export.
  - Example: `http://localhost:4318`
- `OTEL_SERVICE_NAME`: Override the service name reported by SHADI components.
  - Defaults: `shadi-core` (shadictl) and `shadi-runtime` (shadi_py / tools).
- `SHADI_OTEL_CONSOLE`: Set to `1` to print spans to stdout when no OTLP endpoint is set.
- `SHADI_OTEL_FILE`: Write JSON trace logs to a local file (one JSON object per line).

## Local Collector Setup

You can run a local OpenTelemetry Collector and point SHADI to it.

Example `otelcol.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      http:

exporters:
  logging:

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [logging]
```

Run the collector:

```bash
otelcol --config otelcol.yaml
```

Then set the endpoint and launch SHADI:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_SERVICE_NAME=shadi-core
shadictl --policy ./policy.json -- echo "hello"
```

## Local Trace Files

To write trace logs directly to disk, set `SHADI_OTEL_FILE`:

```bash
export SHADI_OTEL_FILE=.shadi/traces.jsonl
shadictl --policy ./policy.json -- echo "hello"
```

You can inspect the logs with `shadictl`:

`--file` is a flag on `trace` itself, so it comes before the subcommand:

```bash
shadictl trace --file .shadi/traces.jsonl list --limit 50
shadictl trace --file .shadi/traces.jsonl list --name shadi.sandbox.run
shadictl trace --file .shadi/traces.jsonl summary
```

## Notes

- When `OTEL_EXPORTER_OTLP_ENDPOINT` is unset and `SHADI_OTEL_CONSOLE` is not enabled,
  tracing is a no-op.
- Service naming is standardized under the `service.namespace=shadi` resource attribute
  so core runtime and SecOps spans can be correlated.

## Next steps

- See the full `trace` command reference in the [CLI Reference](cli.md).
- Return to the operator workflow in [Operations](operations.md).
