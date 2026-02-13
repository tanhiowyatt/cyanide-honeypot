# Configuration Documentation

The main configuration file is located at `config/cyanide.cfg`.

## [honeypot]
General settings.
*   `hostname`: hostname of the fake server.
*   `log_path`: Directory for logs.
*   `data_path`: Directory for persistence.
*   `fs_yaml`: Primary YAML filesystem template (optional if using profiles).
*   `dns_cache_ttl`: TTL in seconds for DNS caching in URL validation (default 60).


## [server]
Connection handling settings.
*   `host`: Listen address (0.0.0.0).
*   `max_sessions`: Global connection limit.
*   `session_timeout`: Inactivity timeout in seconds.
*   `os_profile`: OS personality (`ubuntu_22_04`, `debian_11`, `centos_7`, or `random`).
    *   The honeypot selects a filesystem from `config/fs-config/` based on this profile name (e.g., `fs.ubuntu_22_04.yaml`).
    -   Metadata (banners, uname, etc.) is loaded directly from the `metadata:` section within the selected YAML.
    -   If the YAML lacks a `metadata:` section, hardcoded defaults from `src/cyanide/core/defaults.py` are used.

## [ssh]
SSH Service settings.
*   `enabled`: true/false.
*   `port`: Listening port (default 2222).
*   `version`: SSH Banner string (or handled by os_profile).
*   `backend_mode`:
    *   `emulated`: Use Fake Filesystem (default).
    *   `proxy`: Forward to a single target (`target_host`:`target_port`).
    *   `pool`: Forward to a target from the pool.

## [telnet]
Telnet Service settings.
*   `enabled`: true/false.
*   `port`: Listening port (default 2223).
*   `backend_mode`: `emulated` / `proxy` / `pool`.

## [smtp]
SMTP Proxy settings.
*   `enabled`: true/false.
*   `listen_port`: Port to accept connections (e.g., 2525).
*   `target_host`: Real honeypot/server (e.g., Mailoney).
*   `target_port`: Port of the target.

## [pool]
VM Pool configuration for `backend_mode = pool`.
*   `targets`: Comma-separated list of `host:port` (e.g., `192.168.1.10:22,192.168.1.11:22`).

## [users]
Allowed credentials for Emulated mode.
*   Format: `username = password`
*   Example: `root = 123456`

## [ml]
Machine Learning settings for anomaly detection.
*   `enabled`: true/false.
*   `ml_log`: Path to ML-specific logs.
*   `model_path`: Path to the pre-trained `cyanideML` model.
*   `online_learning`: If true, the model updates based on incoming traffic.

## [cleanup]
Auto-cleanup settings to prevent disk exhaustion.
*   `enabled`: true/false.
*   `interval`: Check interval in seconds (default 3600).
*   `retention_days`: Delete logs and files older than X days (default 7).
*   `paths`: Comma-separated list of directories to clean.

## [rate_limit]
Protection against aggressive bot scanning.
*   `max_connections_per_minute`: Number of connections allowed before banning an IP.
*   `ban_duration`: Duration of the ban in seconds (default 3600).

## [security]
*   `allow_local_network`: true/false (default false). Blocks `curl`/`wget` access to internal/loopback IPs to prevent SSRF.
    -   Cyanide resolves hostnames and checks all returned IP addresses.
    -   DNS resolution is cached and pinned for the duration of the request (see `dns_cache_ttl`) to prevent DNS rebinding attacks.

---

# Configuration Scenarios

## 1. Changing Listening Ports
If you want to run Cyanide on standard ports (22, 23), you must run it as root (not recommended) or use `authbind` / `iptables` redirection.

**Config:**
```ini
[ssh]
port = 2222  <-- Change to desired port
```

**Iptables Redirection (Preferred):**
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

## 2. Setting Up a VM Pool (Hybrid Mode)
To use real QEMU/KVM backends instead of the fake shell:

1.  Start your VMs and ensure you can SSH into them (e.g., at 192.168.122.10 and .11).
2.  Edit `config/cyanide.cfg`:
```ini
[ssh]
enabled = true
backend_mode = pool

[pool]
targets = 192.168.122.10:22, 192.168.122.11:22
```
3.  Restart Cyanide. Incoming SSH connections will be transparently proxied to one of the VMs.

## 3. Creating Custom Users
To catch attackers using specific credentials (like `oracle:oracle`):

Edit `config/cyanide.cfg`:
```ini
[users]
root = admin
oracle = oracle
test = 1234
```
*Note: In 'emulated' mode, any username not in this list will fail authentication.*

---

## 📊 Next Steps
For advanced monitoring, tracing, and metrics setup, see the **[Observability Guide](OBSERVABILITY.md)**.
