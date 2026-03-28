# 🧩 Output Plugins Architecture

Cyanide is designed for seamless integration with external SIEMs, databases, and alerting platforms. This is achieved through a dynamic, asynchronous **Output Plugin** system located in `src/cyanide/output/`.

Instead of blocking the honeypot's execution for slow network or database operations, every plugin operates in its own dedicated background thread with a thread-safe queue.

## ⚙️ How Plugins are Loaded

The `CyanideLogger` (`src/cyanide/logger.py`) is responsible for the lifecycle of output plugins:
1. It reads the `outputs` dictionary from the global configuration (`app.yaml` or `CYANIDE_OUTPUT_*` environment variables).
2. For every entry where `enabled: true`, it attempts to dynamically import the corresponding module from the `cyanide.output` namespace.
3. It instantiates the `Plugin` class from that module, passing the specific configuration dictionary.
4. It calls `plugin.start()`, which spawns the background worker thread.

## 🏗️ The `OutputPlugin` Base Class

All plugins must inherit from the `OutputPlugin` abstract base class (`src/cyanide/output/base.py`). This class provides the core "plumbing" for asynchronous operation:

- **`queue.Queue`**: A thread-safe queue with a default capacity of 10,000 events. If the queue fills up (e.g., during a network partition), events are dropped to prevent memory exhaustion.
- **`emit(event)`**: The method called by the logger to enqueue a new JSON log entry.
- **`_worker_loop()`**: A background loop that pulls events from the queue and calls the implementation-specific `write(event)` method.
- **`write(event)`**: **[Abstract]** The method where the actual output logic resides (e.g., executing a SQL query or making an HTTP POST request).

## 🔌 Supported Output Backends

Cyanide currently includes a wide variety of native output plugins:

### Databases
- **SQLite**: Local, lightweight event storage (`sqlite.py`).
- **MySQL**: Remote RDBMS integration (`mysql.py`).
- **PostgreSQL**: Robust relational storage (`postgresql.py`).
- **MongoDB**: NoSQL document-based storage (`mongodb.py`).
- **RethinkDB**: Real-time push-based storage (`rethinkdb.py`).

### SIEM & Analytics
- **ElasticSearch**: High-performance indexing and search (`elasticsearch.py`).
- **Splunk / HEC**: HTTP Event Collector support (`splunk_hec.py`).
- **Graylog / GELF**: GELF-formatted logging over UDP/TCP (`graylog.py`).
- **Syslog**: Standard UNIX syslog or remote syslog forwarding (`syslog.py`).

### Specialized & Alerts
- **Slack**: Instant notifications via Incoming Webhooks (`slack.py`).
- **HPFeeds**: Shared threat intelligence feeds for the Honeynet project (`hpfeeds.py`).
- **DShield**: SANS ISC DShield threat reporting (`dshield.py`).

## ✍️ Creating a Custom Plugin

Creating a new plugin is straightforward:
1. Create a new file in `src/cyanide/output/my_plugin.py`.
2. Inherit from `OutputPlugin`:

```python
from .base import OutputPlugin

class Plugin(OutputPlugin):
    def write(self, event):
        # Your custom logic here
        # e.g., print(f"Hacking attempt from {event['src_ip']}")
        pass
```

3. Enable it in your configuration:
```yaml
outputs:
  my_plugin:
    enabled: true
    custom_setting: "value"
```

The system will automatically detect and load your new plugin on the next startup.
