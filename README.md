# Cyanide Honeypot 2.0

**Cyanide** is a high-interaction SSH & Telnet honeypot designed to deceive attackers with a realistic fake filesystem, advanced command emulation, and deep anti-detection mechanisms. It captures detailed telemetry to analyze attacker behavior, tools, and techniques.

---

## 🌟 Key Features

### 🧠 Core Emulation
*   **Async Interface**: High-performance asynchronous handling of SSH (via `asyncssh`) and Telnet.
*   **Fake Filesystem**: A persistent, stateful filesystem that mimics a real Linux directory structure. Changes made by attackers (e.g., `touch`, `rm`) persist during the session.
*   **Advanced Shell**: Supports pipes (`|`), redirections (`>`, `>>`), and command chaining (`&&`, `||`, `;`).
*   **Network Commands**: Functional `wget` and `curl` for downloading malware payloads (non-blocking).

### �️ Anti-Detection Hardening (New!)
Designed to fool automated scanners and wary humans:
*   **Network Jitter**: Injects random delays (50ms - 300ms) to simulate realistic network latency.
*   **OS Consistency (Profiles)**: 
    *   Configurable personalities: **Ubuntu 22.04**, **Debian 11**, **CentOS 7**.
    *   Synchronizes SSH Banner, `uname -a`, `/etc/issue`, and `/proc/version` to match the chosen OS.
*   **Fake History**: Pre-populated `.bash_history` with realistic admin commands (`apt update`, `docker ps`).
*   **Realistic Process List**: `ps` shows system daemons (`systemd`, `kworker`, `sshd`) matching the profile.
*   **Network Artifacts**: Dynamic `/proc/net/tcp` generation to show open ports (SSH/MySQL) to rootkits.
*   **Package Manager State**: Adapts history (`apt` vs `yum`) based on the OS profile.

### 📊 Logging & Analytics
Captures rich forensic data (JSON format):
*   **Session Recording**: Full TTY logs replayable via `asciinema`.
*   **GeoIP Enrichment**: Automatically tags sessions with Country and ISP.
*   **SSH Fingerprinting**: Logs client KEX, Cipher, and MAC algorithms (HASSH-like).
*   **Keystroke Biometrics**: Calculates typing speed (inter-key latency) to distinguish bots from humans.
*   **Confusion Metrics**: Tracks `command_not_found` errors to measure emulation quality.
*   **Honeytokens**: Alerts on access to sensitive files like `/home/admin/secret.conf`.
*   **C2 Detection**: Automatically extracts IPs and URLs from executed commands.
*   **Traffic Volume**: Tracks bytes in/out to detect tunneling or heavy downloads.

### 🔒 Security
*   **Signed Filesystem**: `fs.pickle` is integrity-checked with HMAC-SHA256 to prevent tampering.
*   **Quarantine**: Files uploaded via `scp`, `sftp`, or `wget` are isolated in `var/quarantine` for analysis.
*   **VirusTotal Integration**: Automatically scans quarantined files and logs detection results.

---

## 🚀 Quick Start

### 1. Installation
Requires **Python 3.9+**.

```bash
# 1. Clone the repository
git clone https://github.com/tanhiowyatt/cyanide-honeypot.git
cd cyanide-honeypot

# 2. Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Edit `etc/cyanide.cfg` to customize the honeypot.

```ini
[server]
host = 0.0.0.0
# Choose personality: ubuntu_22_04, debian_11, centos_7, or random
os_profile = random

[ssh]
enabled = true
listen_port = 2222

[virustotal]
enabled = true
# API Key is read from environment variable CYANIDE_VT_KEY
```

**Set VirusTotal Key (Optional):**
```bash
export CYANIDE_VT_KEY="your_api_key_here"
```

### 3. Running
Use the control script to manage the background process.

```bash
# Start the server
./bin/cyanide start

# Stop the server
./bin/cyanide stop

# Restart
./bin/cyanide restart
```

### 4. Verify
Connect to it (password `root` or `admin`):
```bash
ssh -p 2222 root@localhost
```

### 5. Docker Support

You can also run Cyanide using Docker:

```bash
# Build and start in background
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop
docker-compose down
```


---

## 🛠️ Tools & Utilities

### Session Replay
Convert recorded TTY logs into a visual playback format.

```bash
# 1. Find a log file
ls var/log/cyanide/tty/

# 2. Convert to asciinema cast
./bin/cyanide-replay var/log/cyanide/tty/session_id.log > playback.cast

# 3. Play (requires asciinema installed)
asciinema play playback.cast
```

### Filesystem Snapshot
Create a new fake filesystem snapshot from a real directory.

```bash
# Snapshot a directory
./bin/cyanide-createfs /path/to/real/root --output share/cyanide/fs.pickle
```

### Cleanup
Manage disk usage by deleting old logs and artifacts.

```bash
# Dry run (see what would be deleted)
./bin/cyanide-clean --days 7 --dry-run

# Delete logs older than 7 days
./bin/cyanide-clean --days 7 --force
```

---

## 📂 Project Structure

| Path | Description |
|------|-------------|
| `bin/` | Control scripts (`cyanide`, `cyanide-replay`, etc.) |
| `etc/` | Configuration (`cyanide.cfg`) |
| `src/core/` | Engine logic (`server.py`, `shell_emulator.py`, `fake_filesystem.py`) |
| `src/commands/` | Emulated commands (`ls.py`, `grep.py`, `wget.py`) |
| `src/cyanide/` | Library code (probes, utils) |
| `var/log/cyanide/` | JSON event logs and TTY recordings |
| `var/quarantine/` | Isolated uploaded files |

---

## ⚠️ Disclaimer
This software is for **educational and research purposes only**. Running a honeypot involves risks. Ensure you isolate this system from your production network. The author is not responsible for any misuse or damage caused by this software.
