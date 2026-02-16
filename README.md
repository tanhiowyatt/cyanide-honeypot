# Cyanide

![alt text](assets/branding/logoreedme.png)

**Cyanide** is a high-interaction SSH & Telnet honeypot designed to deceive and analyze attacker behavior. It combines realistic Linux filesystem emulation, advanced command simulation (pipes, redirections), and deep anti-detection mechanisms with a hybrid ML-based anomaly detection engine.

---

### 🌐 Translations
*   🇷🇺 [Russian (Русский)](docs/README.RU.md)
*   🇵🇱 [Polish (Polski)](docs/README.PL.md)

---

## 🌟 Key Features

### 🧠 Realistic Emulation
*   **Multi-protocol**: SSH (`asyncssh`) and Telnet on customizable ports (default 2222/2223).
*   **Dynamic VFS**: Fully functional in-memory Linux filesystem loaded from YAML profiles. Changes persist per session.
*   **Advanced Shell**: Supports pipes (`|`), redirections (`>`, `>>`), logic (`&&`, `||`), and environment variables.
*   **Anti-Fingerprinting**: 
    *   **Network Jitter**: Randomized response delays (50-300ms).
    *   **OS Profiles**: Masquerade as **Ubuntu 22.04**, **Debian 11**, or **CentOS 7** (banners, `uname`, `/proc` matching).

### 🛡️ Hybrid Detection System
Cyanide employs a 3-layer detection engine to identify malicious intent:
1.  **ML Anomaly Detector**: Autoencoder neural network detects abnormal command structures (zero-day/obfuscation).
2.  **Security Rule Engine**: Regex-based signatures for known threats (`wget`, `curl | bash`, etc.).
3.  **Context Analyzer**: Semantic analysis of accessed files (`/etc/shadow`) and reputation checks (domains/IPs).

### 📊 Forensics & Logging
*   **TTY Recording**: Full session replay compatible with `scriptreplay` (timing + data).
*   **JSON Structured Logs**: Detailed events for ELK/Splunk integration.
*   **Keystroke Biometrics**: Typing rhythm analysis.
*   **Quarantine**: Automatic isolation of downloaded malware (`wget`, `scp`).
*   **VirusTotal Integration**: Automatic scanning of quarantined files.

---

## 🚀 Deployment

**Cyanide is designed to be run as a containerized service.**

### 🐳 Docker Compose (Recommended)

```bash
# 1. Start the full stack (Honeypot + MailHog + Jaeger)
docker-compose -f deployments/docker/docker-compose.yml up --build -d

# 2. Monitor logs
docker-compose -f deployments/docker/docker-compose.yml logs -f cyanide

# 3. Stop
docker-compose -f deployments/docker/docker-compose.yml down
```

### 🔧 Configuration

Configuration is managed via **YAML** files in `configs/`:

| File | Purpose |
|------|---------|
| `configs/app.yaml` | Main configuration (ports, timeouts, ML settings, enabling/disabling services). |
| `configs/profiles/*.yaml` | OS Personalities. Defines the fake filesystem structure, file contents, and system metadata. |
| `configs/fs.yaml` | (Optional) Custom filesystem template if you want to override the random profile selection. |

**Environment Variables** in `docker-compose.yml` override `app.yaml` settings.

---

## 🛠️ Management & Tools

Scripts located in `scripts/management/` help manage the honeypot:

| Script | Command | Description |
|--------|---------|-------------|
| **Stats** | `python3 scripts/management/stats.py` | View real-time uptime, session counts, and attacker IPs. |
| **Replay** | `scriptreplay <timing> <log>` | Replay a recorded TTY session (files in `var/log/cyanide/tty/`). |

---

## 🕵️ Data & Forensics

*   **Logs**: `var/log/cyanide/`
    *   `cyanide-log.json`: Main event log.
    *   `cyanideML-log.json`: ML detection details.
    *   `tty/<session_id>/`: Session recordings.
*   **Quarantine**: `var/lib/cyanide/quarantine/`
    *   Downloaded malware and uploaded files.

---

## ⚠️ Disclaimer
This software is for **educational and research purposes only**. Running a honeypot involves significant risks. The author is not responsible for any damage or misuse.
