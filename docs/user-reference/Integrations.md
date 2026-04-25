# SIEM & External Integrations

Cyanide is designed to be a high-fidelity data sensor. Instead of drowning you in noise, it provides structured, actionable intelligence that integrates seamlessly with modern security stacks.

---

### Supported Output Backends

Cyanide currently includes a wide variety of native output plugins:

*   **Databases**: SQLite, MySQL, PostgreSQL, MongoDB, RethinkDB.
*   **Analytics & SIEM**: Elasticsearch, Splunk (HEC), Syslog.
*   **Specialized Alerting**: Slack (Webhooks), HPFeeds (Threat Intel).
*   **Threat Intelligence**: STIX 2.1 & MISP (Structured IOC reports).

---

## Technical Architecture

Every plugin operates in its own dedicated background thread with a thread-safe queue. This ensures that even if your Elasticsearch or Splunk server is slow, the honeypot session remains snappy for the attacker.

### Asynchronous Flow:
1.  **Queue**: A thread-safe queue with a default capacity of 10,000 events. If the queue fills up, events are dropped to prevent memory exhaustion.
2.  **Worker Loop**: A background loop pulls events from the queue and executes the-specific `write(event)` method.
3.  **Error Isolation**: If a database connection fails, the individual plugin thread will retry without impacting the main honeypot engine.

---

##  SIEM Data Schema

All exported events use a flat, searchable JSON structure.

| Field | Description | Example |
| :--- | :--- | :--- |
| `event_type` | Category of the event. | `honeytoken`, `cmd.input`, `login` |
| `src_ip` | The attacker's source IP. | `1.2.3.4` |
| `is_malicious` | ML Engine's verdict. | `true` |
| `session_id` | Unique session trace ID. | `dfa1-423b-88...` |

---

##  SIEM Alerting Manifest (Example Rules)

Use these logic blocks to build high-fidelity alerts in **Elasticsearch (Kibana)** or **Splunk**.

### 1. The "Red Phone" (Critical)
**Trigger**: Attacker touches a honeytoken.
*   **Logic**: `event_type: "honeytoken"`
*   **Action**: PagerDuty / Telegram. This indicates a human attacker exploring the system.

### 2. Payload Extraction (High)
**Trigger**: Attacker attempts to download a file or URL.
*   **Logic**: `event_type: "ioc"`
*   **Search**: Look for `wget`, `curl`, or `ftp` in `cmd.input`.

### 3. Successful Intrusion (Medium)
**Trigger**: Valid credentials guessed.
*   **Logic**: `event_type: "login" AND success: true`

---

##  Creating a Custom Plugin
For specialized needs (e.g., calling an internal API), you can write a custom plugin:
1.  **Code**: Create `src/cyanide/output/my_plugin.py` inheriting from `OutputPlugin`.
2.  **Logic**: Implement the `write(self, event)` method.
3.  **Enable**: Add `my_plugin: { enabled: true }` to your `outputs` config.

---

## Quick Integration: Webhooks (Slack / Discord / Telegram)

To get real-time alerts in your favorite chat platform, add these environment variables:

### Slack
```bash
CYANIDE_OUTPUT_SLACK_ENABLED=true
CYANIDE_OUTPUT_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"
```

### Discord
```bash
CYANIDE_OUTPUT_DISCORD_ENABLED=true
CYANIDE_OUTPUT_DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

### Telegram
```bash
CYANIDE_OUTPUT_TELEGRAM_ENABLED=true
CYANIDE_OUTPUT_TELEGRAM_TOKEN="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
CYANIDE_OUTPUT_TELEGRAM_CHAT_ID="987654321"
```

> [!TIP]
> Combine Webhooks with **Honeytokens** for a zero-noise alerting system. You will only get a notification when someone actually tries to read your "secrets."

---
<p align="center">
  <i>Revision: 1.0  April 2026  Cyanide Honeypot</i>
</p>
