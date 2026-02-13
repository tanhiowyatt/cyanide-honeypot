# Observability Guide 📊

Cyanide Honeypot supports modern observability standards including **OpenTelemetry** for distributed tracing and **Prometheus** for metrics.

## 📈 Prometheus Metrics

The honeypot exposes a metrics server (default port `9090`) with the following endpoints:

*   `/metrics`: Standard Prometheus metrics.
*   `/stats`: Human-readable JSON summary of honeypot activity.
*   `/health`: System health check.

### Key Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `cyanide_active_sessions` | Gauge | Current number of active SSH/Telnet sessions. |
| `cyanide_total_sessions_total` | Counter | Total connections received. |
| `cyanide_dns_cache_hits_total` | Counter | Number of successful DNS cache lookups. |
| `cyanide_dns_cache_misses_total` | Counter | Number of DNS lookups that required resolution. |
| `cyanide_malicious_files_total` | Counter | Number of files flagged as malicious by VirusTotal. |

---

## 🕵️ OpenTelemetry Tracing

Cyanide uses OpenTelemetry to trace internal operations such as command execution, filesystem access, and network requests.

### Jaeger Setup (Recommended)
The easiest way to view traces is using **Jaeger**.

1.  **Run Jaeger via Docker**:
    ```bash
    docker run --name jaeger \
      -e COLLECTOR_OTLP_ENABLED=true \
      -p 16686:16686 \
      -p 4317:4317 \
      -p 4318:4318 \
      jaegertracing/all-in-one:latest
    ```

2.  **Enable Tracing in `cyanide.cfg`**:
    Configure the OTLP exporter to point to your Jaeger instance:
    ```ini
    [otel]
    enabled = true
    exporter = otlp
    endpoint = http://localhost:4318/v1/traces
    ```

### Exporting Traces
Traces are automatically exported via OTLP over HTTP/wRPC. In a production Docker setup, ensure the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable is set.

---

## 🛠️ Debugging Observability

If metrics or traces are not appearing:
1.  Check that `[metrics] enabled = true` is set in the configuration.
2.  Verify connectivity to the Jaeger/Collector endpoint.
3.  Check the honeypot logs for `otel_error` or `metrics_error` events.
