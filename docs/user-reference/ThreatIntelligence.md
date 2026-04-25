# Threat Intelligence & IOC Reporting

Cyanide Honeypot goes beyond simple logging by automatically extracting **Indicators of Compromise (IOCs)** from attacker interactions and aggregating them into standardized, actionable reports.

---

## Overview

The **IOC Reporter** module works in tandem with the ML behavioral analysis engine to identify and extract malicious artifacts. This allows security teams to feed high-fidelity threat data directly into their SIEM, TIP (Threat Intelligence Platform), or automated blocklists.

### Automatically Extracted IOCs
*   **Attacker IPs**: Source IPs of attackers who perform anomalous actions or use malicious tools.
*   **Credentials**: Malicious username/password combinations used during brute-force or credential stuffing attempts.
*   **IPv4 Addresses**: Extracted from anomalous commands (e.g., secondary payloads, C2 IPs).
*   **URLs**: Extracted from `wget`, `curl`, and other download attempts.
*   **File Hashes (SHA-256)**: Automatically calculated for anomalous file uploads quarantined by the honeypot.
*   **Domains**: Extracted from network-related commands.

---

## Standardization: STIX 2.1 & MISP

Cyanide supports exporting collected IOCs in both **STIX 2.1** and **MISP** formats. This ensures compatibility with modern security orchestration tools like MISP, OpenCTI, and various SOAR platforms.

### Report Generation
Reports are generated as snapshots containing all unique IOCs collected since the last reset.

#### STIX 2.1 (JSON Bundle)
*   **Identity Object**: Representing the honeypot sensor itself.
*   **Indicator Objects**: Each containing a STIX pattern (e.g., `[ipv4-addr:value = '1.2.3.4']`) and associated metadata like severity and session context.
*   **File Path**: `var/log/cyanide/cyanide_iocs.stix.json`

#### MISP (JSON Event)
*   **Event Object**: Aggregating all attributes under a single threat intelligence event.
*   **Attributes**: Mapped to MISP types (e.g., `ip-src`, `url`, `sha256`).
*   **File Path**: `var/log/cyanide/cyanide_iocs.misp.json`

---

## Remote Access via API

Collected IOCs can be retrieved remotely via the Cyanide Metrics API (if enabled). This is the recommended way to integrate with external platforms.

| Format | Endpoint | Description |
| :--- | :--- | :--- |
| **STIX 2.1** | `GET /logs/reports/stix` | Returns the latest STIX JSON Bundle. |
| **MISP** | `GET /logs/reports/misp` | Returns the latest MISP JSON Event. |

> [!IMPORTANT]
> Access to these endpoints requires the same Bearer Token as the `/metrics` endpoint (configured via `CYANIDE_METRICS_TOKEN`).

---

## Configuration

You can tune the reporting frequency and behavior using the following settings in `app.yaml` or via environment variables.

| YAML Key | Env Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `ioc_reporting.enabled` | `CYANIDE_IOC_REPORTING_ENABLED` | `true` | Enable/Disable the IOC reporter. |
| `ioc_reporting.report_interval_hours` | `CYANIDE_IOC_REPORTING_INTERVAL_HOURS` | `1` | Frequency of STIX report updates. |
| `ioc_reporting.output_format` | `CYANIDE_IOC_REPORTING_OUTPUT_FORMAT` | `stix2.1` | The format for generated reports. |

---

## How It Works (The Pipeline)

1.  **Interaction**: An attacker performs an anomalous action (e.g., runs a suspicious `wget` command).
2.  **ML Verdict**: The behavioral engine flags the command as an anomaly.
3.  **Extraction**: The `AnalyticsService` runs regex-based extraction to find IPs and URLs within the malicious string.
4.  **Aggregation**: The `IOCReporter` stores these indicators in memory.
5.  **Snapshot**: Periodically, the background loop triggers `generate_stix_report()`, which writes the STIX 2.1 Bundle to disk.

---
<p align="center">
  <i>Revision: 1.0  April 2026  Cyanide Honeypot</i>
</p>
