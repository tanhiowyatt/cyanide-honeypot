# Observability Guide

Cyanide supports **Prometheus** for metrics and **OpenTelemetry** for distributed tracing.

## 1. Metrics (Prometheus)

Exposed on port `9090` by default.

### Endpoints
*   `/metrics`: Prometheus scraping endpoint.
*   `/stats`: Human-readable JSON summary.
*   `/health`: System health status.

### Key Metrics
*   `cyanide_active_sessions`: Current connections.
*   `cyanide_honeytoken_hits_total`: Alerts triggered.
*   `cyanide_ml_anomalies_total`: ML detection events.

### Configuration
Update `configs/app.yaml`:
```yaml
metrics:
  enabled: true
  port: 9090
```

---

## 2. Distributed Tracing (Jaeger)

Cyanide pushes traces via OTLP to a collector (e.g., Jaeger).

### Setup via Docker
The provided `docker-compose.yml` includes a reliable Jaeger setup.

1.  **Enable Tracing in `configs/app.yaml`**:
    ```yaml
    otel:
      enabled: true
      exporter: otlp
      endpoint: http://jaeger:4318/v1/traces
    ```

2.  **Start Stack**:
    ```bash
    docker-compose -f deployments/docker/docker-compose.yml up -d
    ```

3.  **View Traces**:
    Open `http://localhost:16686` in your browser.

---

## 3. Dashboards

Pre-built dashboards are located in `deployments/monitoring/`:
*   `grafana-dashboard.json`: Import this into Grafana to visualize `cyanide_*` metrics.
*   `prometheus-alerts.yml`: AlertManager rules for high-priority events.
