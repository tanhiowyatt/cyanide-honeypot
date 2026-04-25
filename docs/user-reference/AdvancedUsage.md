# Advanced Configuration Reference

Cyanide Honeypot is highly configurable. This document provides a complete map of all settings used to tune the behavior, security, and integration of your honeypot.

---

## Configuration Principle: Strict Mode

Cyanide uses a **Strict Mode** naming convention. For environment variables, prefix every key with `CYANIDE_`, convert YAML keys to uppercase, and use underscores for nesting.

> [!IMPORTANT]
> **Example**: To override `ssh.port`, use `CYANIDE_SSH_PORT`. For nested items like `logging.rotation.strategy`, use `CYANIDE_LOGGING_ROTATION_STRATEGY`.

---

## Environment Variables Reference

Click on a section below to expand the available settings.

<details>
<summary>01. Core & Server Settings</summary>

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CYANIDE_HONEYPOT_HOSTNAME` | `server01` | Hostname visible to attackers. |
| `CYANIDE_SERVER_OS_PROFILE` | `random` | OS persona to emulate (`ubuntu`, `debian`, `centos`). |
| `CYANIDE_SERVER_MAX_SESSIONS` | `100` | Global concurrent session limit. |
| `CYANIDE_SERVER_SESSION_TIMEOUT` | `300` | Inactivity timeout in seconds. |
| `CYANIDE_SERVER_VFS_ROOT` | `None` | Custom path to virtual filesystem root. |

</details>

<details>
<summary>02. SSH & Telnet Services</summary>

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CYANIDE_SSH_PORT` | `2222` | Listening port for SSH. |
| `CYANIDE_SSH_ENABLED` | `true` | Toggle the SSH service. |
| `CYANIDE_SSH_BACKEND_MODE` | `emulated` | Mode: `emulated`, `proxy`, or `pool`. |
| `CYANIDE_SSH_FORWARDING_ENABLED` | `false` | Enable SSH port tunneling (`-L`/`-R`). |
| `CYANIDE_SSH_MAX_UPLOAD_SIZE_MB` | `50` | Max size for a single file upload. |
| `CYANIDE_SSH_LOG_PASSWORDS` | `false` | Enable to record cleartext password attempts. |
| `CYANIDE_TELNET_PORT` | `2323` | Listening port for Telnet. |
| `CYANIDE_TELNET_ENABLED` | `false` | Toggle the Telnet service. |

</details>

<details>
<summary>03. Machine Learning & Detection</summary>

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CYANIDE_ML_ENABLED` | `true` | Toggle the LSTM behavioral analysis engine. |
| `CYANIDE_ML_THRESHOLD` | `0.8` | Anomaly score threshold for malicious flagging. |
| `CYANIDE_ML_ONLINE_LEARNING` | `false` | If true, the model updates based on live traffic. |
| `CYANIDE_ML_RETRAINING_INTERVAL_DAYS` | `7` | Days between automatic ML model retraining. |
| `CYANIDE_VIRUSTOTAL_ENABLED` | `false` | Toggle automated malware scanning via VT API. |
| `CYANIDE_IOC_REPORTING_ENABLED` | `true` | Enable automatic STIX 2.1 and MISP IOC reporting. |
| `CYANIDE_IOC_REPORTING_INTERVAL_HOURS` | `1` | Hours between IOC report generations. |
| `CYANIDE_IOC_REPORTING_OUTPUT_FORMAT` | `all` | Report format: `stix2.1`, `misp`, or `all`. |

</details>

<details>
<summary>04. Logging & Observability</summary>

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CYANIDE_LOGGING_DIRECTORY` | `var/log/cyanide`| Root path for all system and session logs. |
| `CYANIDE_LOGGING_LOGTYPE` | `plain` | Mode: `plain` or `rotating`. |
| `CYANIDE_METRICS_ENABLED` | `true` | Export Prometheus metrics on port 9090. |
| `CYANIDE_OTEL_ENABLED` | `false` | Enable OpenTelemetry tracing. |
| `CYANIDE_OTEL_ENDPOINT` | `http://localhost:4318/v1/traces` | OTLP collector endpoint. |

</details>

### HTTP API Endpoints
If the Metrics server is enabled (`CYANIDE_METRICS_ENABLED`), you can access real-time status and reports via:
*   `/metrics`: Prometheus-compatible metrics.
*   `/stats`: High-level JSON statistics summary.
*   `/health`: Health check probe (returns HTTP 200 if OK).
*   `/reports/stix`: Download the latest STIX 2.1 IOC bundle.
*   `/reports/misp`: Download the latest MISP JSON report.

> [!NOTE]
> All endpoints except `/health` require a Bearer Token if `CYANIDE_METRICS_TOKEN` is configured.

<details>
<summary>05. Integrations (Webhooks)</summary>

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CYANIDE_OUTPUT_SLACK_ENABLED` | `false` | Toggle Slack notification plugin. |
| `CYANIDE_OUTPUT_SLACK_WEBHOOK_URL` | `None` | Incoming Webhook URL for Slack. |
| `CYANIDE_OUTPUT_DISCORD_ENABLED` | `false` | Toggle Discord notification plugin. |
| `CYANIDE_OUTPUT_DISCORD_WEBHOOK_URL` | `None` | Webhook URL for Discord. |
| `CYANIDE_OUTPUT_TELEGRAM_ENABLED` | `false` | Toggle Telegram notification plugin. |
| `CYANIDE_OUTPUT_TELEGRAM_TOKEN` | `None` | Telegram Bot Token. |
| `CYANIDE_OUTPUT_TELEGRAM_CHAT_ID` | `None` | Target Chat ID for Telegram alerts. |

</details>

---

## Specialized Features

### Honeytoken Tripwires
Honeytokens are fake files that act as "sensor-mines." Any interaction with them is a 100% indicator of a human attacker searching for secrets.

*   **Setup**: Use `CYANIDE_HONEYTOKENS='["/etc/shadow", "/root/.ssh/id_rsa"]'`.
*   **Profiles**: You can also define them in `configs/profiles/<name>/base.yaml` under `honeytokens:`.
*   **Logic**: There are no hardcoded defaults; you must define them explicitly.

### VM Pool (Libvirt)
When `CYANIDE_SSH_BACKEND_MODE=pool` is used, Cyanide manages real KVM/QEMU VMs.
*   **`CYANIDE_POOL_ENABLED`**: Enable orchestration (Default: `false`).
*   **`CYANIDE_POOL_MAX_VMS`**: Concurrency limit for target VMs.
*   **`CYANIDE_POOL_LIBVIRT_URI`**: Connection URI (e.g., `qemu:///system`).

### Session Storage Architecture
Every session is written to `var/log/cyanide/tty/[IP]_[SESSION_ID]/`. 

| File | Content | Purpose |
| :--- | :--- | :--- |
| **`audit.json`** | Structured Events | Feeding SIEMs/Dashboards. |
| **`transcript.log`**| Plain Text | Quick human review of the session. |
| **`timing.time`** | Byte-offsets | Replaying the session with `scriptreplay`. |
| **`ml_analysis.json`**| Behavioral Verdict | Identifying the *intent* of the attacker. |

---

## Security Best Practices

1.  **Read-Only Root**: Run the Docker container with a read-only root whenever possible.
2.  **Network Isolation**: Use a dedicated bridge network in Docker to prevent "honeypot escape" to your host's local services.
3.  **Port Remapping**: Avoid running the honeypot on port 22 of the host machine. Instead, map host port `22` to container port `2222`.

## Scaling & Production
For larger deployments, Cyanide can be scaled horizontally or customized for high-fidelity research.

### Multiple Sensors
Cyanide is stateless per session. You can deploy multiple "Sensing Nodes" behind a Load Balancer (like HAProxy or Nginx).
- **Log Centralization**: Use the [Integrations Guide](Integrations.md) to stream events to a central ELK or Splunk instance.
- **Database Backend**: Configure a single PostgreSQL or MySQL instance for aggregated metrics across all nodes.

### Baremetal Installation (Development)
If you need absolute control over performance or are developing new features:
1.  **Virtual Environment**: `python3.11 -m venv venv && source venv/bin/activate`
2.  **Dependencies**: `pip install -e .` (Installs core + ML support).
3.  **Outputs**: For DB drivers, use `pip install .[outputs]`.

### Backend VM Pool
When using `backend_mode: pool`, ensure the host has sufficient RAM to support `max_vms`. We recommend using a dedicated virtualization server with **Libvirt/KVM** for the most realistic sandbox experience.

---
<p align="center">
  <i>Revision: 1.0  April 2026  Cyanide Honeypot</i>
</p>
