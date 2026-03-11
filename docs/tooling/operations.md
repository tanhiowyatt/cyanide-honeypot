# Operations & Forensics Guide

This guide covers running, monitoring, and analyzing data from the Cyanide Honeypot.

## 📊 Logging Infrastructure

Cyanide generates high-fidelity JSON logs in `var/log/cyanide/`.

### Log Types
- **`cyanide-server.json`**: System-level logs (startup, service status, errors).
- **`cyanide-fs.json`**: Filesystem audit logs (all file reads, writes, and deletions).
- **`cyanide-ml.json`**: Detection engine output (command anomaly scores and classifier results).
- **`cyanide-stats.json`**: Periodic metric aggregates.
- **`tty/`**: Session recordings compatible with `scriptreplay`.

### Log Rotation Policy (logtype)
Cyanide supports built-in rotation logic controlled by `app.yaml` (`logging.logtype`).
1. **`plain` (Default)**: Cyanide logs exclusively into persistent JSON files without rotating them. Recommended when you deploy standard infrastructure utilities such as `logrotate` via cron jobs to gzip your outputs.
2. **`rotating`**: Built-in Python logging mechanisms automatically trigger archival behavior avoiding external dependencies. Use variables like `logging.rotation.strategy` to configure split boundaries (`time` for midnight boundaries or `size` for maxBytes limitations).

---

## 🔍 Observability & Monitoring

Cyanide is instrumented for deep visibility using modern observability standards.

### Prometheus (Metrics)
Standard system and honeypot metrics are exposed on port `9090` at `/metrics`. 
- **Session Count**: Total active and historical attacker sessions.
- **VFS Activity**: Rate of file operations.
- **Detection Rates**: Distribution of anomaly scores.

### Jaeger (Tracing)
Distributed tracing for complex session flows (e.g., download -> ML analysis -> quarantine).
- **Endpoint**: `http://localhost:16686` (when using Docker Compose).

---

## 🛠️ Management Scripts

Located in `scripts/management/`:

### 1. Real-time Stats
View a dashboard of active sessions and top attacker IPs.
```bash
python3 scripts/management/stats.py
```

### 2. Session Replay
Replay TTY sessions exactly as they appeared to the attacker.
```bash
scriptreplay var/log/cyanide/tty/<session_id>/timing var/log/cyanide/tty/<session_id>/data
```

---

## 🛡️ Forensics & Malware Handling

### Libvirt VM Pool Operations
When using Cyanide in `pool` mode with `libvirt`:
1. Ensure `libvirt-python` is installed in your python environment or docker container.
2. The Honeypot must have privileges to reach the `qemu:///system` URI (e.g., matching groups or socket permissions).
3. Base XML configurations for guests (`configs/pool/default_guest.xml`) are used to provision new VMs dynamically.
4. If a guest hangs or receives heavy traffic, Cyanide automatically recycles it based on your configured `recycle_period` and unused timeout policies.

### Quarantine Service
Any file downloaded by an attacker (via `wget` or `curl`) is automatically:
1.  **Intercepted**: The actual file is moved to `var/quarantine/`.
2.  **Hashed**: MD5/SHA256 calculations for threat intelligence.
3.  **Analyzed**: Automatically submitted to VirusTotal if an API key is configured.
4.  **Emulated**: A fake, benign file of the same name and size is placed in the VFS to avoid suspicious behavior alerts.

### Biometric Analysis
Cyanide captures keystroke timing to build behavioral profiles of attackers, allowing you to distinguish between human operators and automated bots.
