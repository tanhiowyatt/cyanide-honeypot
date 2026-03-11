# Configuration Guide

Cyanide is highly customizable through YAML-based configuration files and environment variables.

## ⚙️ Global Configuration (`configs/app.yaml`)

The `app.yaml` file controls the core behavior of the honeypot.

### Networking & Services
- **`ssh.port`**: Port to listen for SSH (default: 2222).
- **`telnet.port`**: Port to listen for Telnet (default: 2223).
- **`backend_mode`**: Either `emulator` (simulated shell), `proxy` (forwarding to a real server), or `pool` (Libvirt VM orchestration).

### Logging & Rotation
Unified rotation policy for `cyanide-server.json`, `cyanide-fs.json`, `cyanide-ml.json` and `cyanide-stats.json`.
- **`logging.directory`**: Master log path (default: `var/log/cyanide`).
- **`logging.logtype`**: Mode to write (`plain` or `rotating`).
- **`logging.rotation.strategy`**: Method for triggering rotation (`time` or `size`).
- **`logging.rotation.when`**: Interval point for timing rotations (e.g `midnight`).
- **`logging.rotation.interval`**: Unit frequency before rotation if strategy=time (default: 1).
- **`logging.rotation.backup_count`**: Historical handlers retention (default: 14).
- **`logging.rotation.max_bytes`**: Maximum single-file scale before rotation if strategy=size (default: 10485760).

### VM Pool Orchestration (Libvirt)
When `backend_mode` is set to `pool`, Cyanide can automatically manage backend VMs.
- **`pool.enabled`**: Enable the orchestration pool (default: false).
- **`pool.mode`**: Set to `libvirt` for full lifecycle management.
- **`pool.max_vms`**: Maximum concurrently running VMs.
- **`pool.recycle_period`**: How often to recycle VMs (in seconds).
- **`pool.libvirt_uri`**: Connection URI (e.g., `qemu:///system`).

### SSH Fingerprinting & Forwarding
- **`ssh.ciphers`**: List of allowed encryption algorithms.
- **`ssh.macs`**: List of allowed MAC algorithms.
- **`ssh.kex_algs`**: List of allowed Key Exchange algorithms.
- **`ssh.forwarding_enabled`**: Enable or disable SSH port forwarding (`-L` / `-R`).
- **`ssh.forward_redirect_enabled`**: Enable rules-based redirection for forwarded traffic.
- **`ssh.forward_redirect_rules`**: Mapping of port -> target host:port.

### Detection Engine (ML)
- **`enabled`**: Toggle the hybrid detection engine.
- **`threshold`**: The anomaly score above which a command is flagged as malicious.
- **`model_path`**: Path to the pre-trained LSTM Autoencoder model.

### Services
- **`quarantine.enabled`**: Toggle automatic malware interception.
- **`stats.enabled`**: Toggle Prometheus metrics export.
- **`telemetry.enabled`**: Toggle Jaeger tracing.

---

## 🎭 OS Profiles (`configs/profiles/`)

Profiles allow Cyanide to masquerade as different Linux distributions. Each profile is a directory containing:

### 1. `base.yaml` (Metadata & Dynamics)
Defines the "Identity" of the OS.
```yaml
metadata:
  os_name: "Ubuntu"
  hostname: "web-server-01"
  kernel_version: "5.15.0-73-generic"
  arch: "x86_64"
  os_id: "ubuntu"
  version_id: "22.04"

dynamic_files:
  /proc/uptime: { provider: uptime_provider }
  /proc/cpuinfo: { provider: cpuinfo_provider }
```

### 2. `static.yaml` (Filesystem Manifest)
Maps virtual paths to content or source files.
- **`content`**: Inline string content (supports Jinja2 templating).
- **`source`**: Path to a file on the host (relative to the profile root).
- **`root/` mapping**: Uses glob patterns to mirror directories.
```yaml
static:
  /etc/issue:
    content: "Welcome to {{ os_name }} {{ version_id }}\n"
  /bin/**:
    source: "ubuntu/root/bin/"
```

---

## 🌍 Environment Variables

Environment variables defined in your `docker-compose.yml` or shell will override settings in `app.yaml`:

- `OS_PROFILE`: Force a specific profile (e.g., `debian`). Default is `random`.
- `ML_THRESHOLD`: Override the anomaly detection threshold.
- `SERVER_PORT`: Override the primary listening port.
