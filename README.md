# Cyanide Honeypot 2.1 🛡️

**Cyanide** is a high-interaction SSH & Telnet honeypot designed to deceive and analyze attacker behavior. It combines realistic Linux filesystem emulation, advanced command simulation, and deep anti-detection mechanisms.

---

### 🌐 Translations / Tłumaczenia / Переводы
*   🇷🇺 [Russian (Русский)](docs/README.RU.md)
*   🇵🇱 [Polish (Polski)](docs/README.PL.md)

---

## 🌟 Key Features

### 🧠 Realistic Emulation
*   **Multi-protocol**: Simultaneous support for SSH (via `asyncssh`) and Telnet on different ports.
*   **Dynamic FS**: Fully functional Linux filesystem. Changes (creating files, deleting) persist throughout the session.
*   **Advanced Shell**: Support for pipes (`|`), redirections (`>`, `>>`), and command chaining (`&&`, `||`, `;`).
*   **Anti-Fingerprinting**: 
    *   **Network Jitter**: Randomized response delays (50-300ms) to simulate a real network.
    *   **OS Profiles**: Masquerade as **Ubuntu**, **Debian**, or **CentOS** (banners, `uname`, `/proc/version`).

### 📊 Forensics & Logging
*   **TTY Recording**: Session recording in a format compatible with `scriptreplay`.
*   **Structured JSON**: Detailed event logs in JSON format for ELK/Splunk integration.
*   **Keystroke Biometrics**: Analysis of typing rhythm to distinguish bots from humans.
*   **Quarantine**: Automatic isolation of files downloaded via `wget`, `curl`, `scp`, or `sftp`.
*   **VirusTotal**: Automatic scanning of suspicious files in quarantine.

---

## 🏗️ Architecture & Structure

The project is built on a modular principle using modern Python patterns:
*   **Facade Pattern**: Core functions are available directly from package roots (e.g., `from core import HoneypotServer`).
*   **Command Registry**: Dynamic loading of emulated commands via a central registry in `src/commands`.

### Directory Structure
| Path | Description |
|------|-------------|
| `scripts/` | Management and control tools |
| `config/` | Configuration files (`cyanide.cfg`) and FS YAMLs |
| `src/cyanide/core/` | Server core, shell emulator, and FS logic |
| `src/cyanide/commands/` | Implementations of emulated Linux commands |
| `var/log/cyanide/` | JSON logs and TTY recordings |
| `var/lib/cyanide/` | Data persistence and quarantine |
| `docs/` | Comprehensive guides for **[Configuration](docs/configuration.md)** and **[Observability](docs/OBSERVABILITY.md)** |

---

## 🚀 Deployment & Operation

**Note: This project is designed to run exclusively within Docker.**

### 🐳 Docker Compose (Required)
The fastest and safest way to run.

```bash
# Build and start in background
docker compose -f docker/docker-compose.yml up --build -d

# View server logs in real-time
docker compose -f docker/docker-compose.yml logs -f

# Check status
docker compose -f docker/docker-compose.yml ps

# Stop
docker compose -f docker/docker-compose.yml down
```

---

## 🛠️ Tool Reference (`bin/`)

| Utility | Description |
|---------|-------------|
| `./bin/cyanide` | Main management script (start, stop, status, restart). |
| `./bin/cyanide-replay` | TTY log player. |
| `./bin/cyanide-clean` | Clean up old logs and quarantined files. |

---

## ⌨️ Emulated Commands

Cyanide supports over 25 standard Linux commands, including:
*   **Navigation**: `cd`, `ls`, `pwd`.
*   **File Ops**: `cat`, `touch`, `mkdir`, `rm`, `cp`, `mv`, `id`.
*   **Information**: `uname`, `ps`, `whoami`, `who`, `w`, `help`.
*   **Advanced**: `sudo`, `export`, `echo`.
*   **Network**: `curl`, `ping`, `wget` (with files saved to quarantine).
*   **Editors**: `vi`, `vim`, `nano` (simulation).

---

## 🕵️ Session Analysis (Scriptreplay)

All sessions are recorded in `var/log/cyanide/tty/`. Each session has its own folder with a data file (`.log`) and a timing file (`.timing`).

**How to play a session:**
1.  Find the desired session folder in `var/log/cyanide/tty/`.
2.  Execute the command:
```bash
./scripts/cyanide-replay var/log/cyanide/tty/<dir>/
```

---

## 💾 Filesystem Configuration (YAML)

The honeypot filesystem is defined in YAML templates located in `config/fs-config/`.

### 🌍 OS Profiles
Cyanide supports multiple OS personalities out of the box. Each profile has a corresponding YAML file containing both the filesystem structure and OS metadata:
-   `fs.ubuntu_22_04.yaml`: Ubuntu 22.04 LTS
-   `fs.debian_11.yaml`: Debian 11 (Bullseye)
-   `fs.centos_7.yaml`: CentOS 7

### 📝 Metadata Customization
Each YAML file starts with a `metadata:` section where you can customize the appearance of the OS:
```yaml
metadata:
  os_name: "Ubuntu 22.04 LTS"
  ssh_banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
  uname_r: "5.15.0-76-generic"
  uname_a: "Linux server 5.15.0-76-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux"
```

### 🎯 Manual Structuring
See `config/fs-config/fs.yaml.example` for a complete filesystem template. Simply edit the YAML file to add honey files or modify the structure, and restart the honeypot.

---

## 🧹 Maintenance

After long operation, it is recommended to clear logs:
```bash
# Delete logs older than 7 days
make clean
# or specifically:
./bin/cyanide-clean --days 7 --force
```

---

## 🤖 ML Anomaly Detection

Cyanide includes a built-in Machine Learning engine (`cyanideML`) to filter high-volume attacks (e.g., Mirai botnets) and identify novel threats.

### Features
*   **Algorithm**: MiniBatchKMeans Clustering (Online Learning).
*   **Input**: 537-dimensional feature vector (Command Hashing + Stats + Dynamic Ports).
*   **Performance**: Process >10k logs/sec with <10ms latency.
*   **Metrics**: Exports Prometheus metrics for latency and anomaly rates.

### Usage
The ML filter is available as a Python package in `ai-models/cyanideML`.

```python
from cyanideML import HoneypotFilter

# Initialize
model = HoneypotFilter()

# Analyze Log
is_anomaly, reason, distance = model.process_log(log_entry)

if is_anomaly:
    print(f"New Threat Detected! Reason: {reason}")
```

### Integration
The ML engine is integrated directly into the Cyanide core. If enabled, it processes every command in real-time.

**Metrics**: available on the main metrics port (default `:9090/metrics`), combined with standard statistics.

### Configuration
Enable it in `etc/cyanide.cfg`:
```ini
[ml]
enabled = true
```

### Real-time Monitoring CLI
To watch logs and detect anomalies in real-time as they appear:

```bash
python3 tools/watch_logs.py
```

---

## ⚠️ Disclaimer
This software is for **educational and research purposes only**. Running a honeypot involves risks. The author is not responsible for any damage.
