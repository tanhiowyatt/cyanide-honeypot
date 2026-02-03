# Cyanide Honeypot 2.1 🛡️

**Cyanide** is a high-interaction SSH & Telnet honeypot designed to deceive and analyze attacker behavior. It combines realistic Linux filesystem emulation, advanced command simulation, and deep anti-detection mechanisms.

---

### 🌐 Translations / Tłumaczenia / Переводы
*   🇷🇺 [Russian (Русский)](README.RU.md)
*   🇵🇱 [Polish (Polski)](README.PL.md)

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
| `bin/` | Management and control tools |
| `etc/` | Configuration files (`cyanide.cfg`) |
| `src/core/` | Server core, shell emulator, and FS logic |
| `src/commands/` | Implementations of emulated Linux commands |
| `src/cyanide/` | Helper libraries and logging |
| `var/log/cyanide/` | JSON logs and TTY recordings |
| `var/quarantine/` | Isolated files |

---

## 🚀 Deployment & Operation

### 🐳 Option 1: Docker (Recommended)
The fastest and safest way to run.

```bash
# Build and start in background
docker-compose up -d --build

# View server logs in real-time
docker-compose logs -f

# Stop
docker-compose down
```

### 🐍 Option 2: Local Launch
Requires **Python 3.10+**.

```bash
# 1. Install dependencies
make install

# 2. Configure
# Edit etc/cyanide.cfg (ports, OS profile, passwords)

# 3. Start via control script
./bin/cyanide start

# Check status
./bin/cyanide status

# Stop
./bin/cyanide stop
```

---

## 🛠️ Tool Reference (`bin/`)

| Utility | Description |
|---------|-------------|
| `./bin/cyanide` | Main management script (start, stop, status, restart). |
| `./bin/cyanide-replay` | TTY log player. |
| `./bin/cyanide-createfs` | Create a new filesystem snapshot from a real directory. |
| `./bin/cyanide-clean` | Clean up old logs and quarantined files. |
| `./bin/cyanide-fsctl` | Manual management tool for `fs.pickle` database. |

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
scriptreplay --timing var/log/cyanide/tty/<dir>/<dir>.timing --typescript var/log/cyanide/tty/<dir>/<dir>.log
```

---

## 💾 Persistence & Snapshots (fs.pickle)

The Cyanide filesystem is stored in the `share/cyanide/fs.pickle` file. This is a binary snapshot protected by an HMAC signature.

**How to create your own snapshot:**
If you want the attacker to see the structure of your real server:
```bash
sudo ./bin/cyanide-createfs / --output share/cyanide/fs.pickle
```

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

## ⚠️ Disclaimer
This software is for **educational and research purposes only**. Running a honeypot involves risks. The author is not responsible for any damage.
