# Cyanide Honeypot

**Cyanide** is a high-interaction SSH/Telnet honeypot designed to deceive attackers with a realistic fake filesystem and command emulation. Built on top of `asyncssh` and Python 3.

## Features
- **AsyncSSH Proxy**: High-performance SSH handling.
- **FakeFilesystem**: Realistic, stateful filesystem (not just static responses).
- **Cyanide Tooling**: standard unix-like management tools (`etc/cyanide.cfg`, `bin/cyanide`).
- **JSON Logging**: Structured logs ready for analysis/ELK stack.

## Directory Structure

| Directory | Purpose |
|-----------|---------|
| `bin/` | Executable control scripts (`cyanide`, `createfs`) |
| `etc/` | Configuration files |
| `share/` | Data files (filesystems pickles, text commands) |
| `src/` | Source code (core logic, commands, proxy) |
| `var/` | Runtime data (logs, pids) |

## Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate Filesystem (Optional)**
   Create a honeypot filesystem snapshot from a real directory:
   ```bash
   ./bin/cyanide-createfs src/commands
   ```

3. **Configure**
   Edit `etc/cyanide.cfg` to set ports and options:
   ```ini
   [ssh]
   listen_port = 2222
   enabled = true
   ```

4. **Run**
   ```bash
   ./bin/cyanide start
   ```

5. **Stop**
   ```bash
   ./bin/cyanide stop
   ```

## Development

The project entry point is `main.py`, but it is best managed via `bin/cyanide`.
- **Core Logic**: `src/core/server.py`
- **Commands**: `src/commands/*.py` (Implement new shell commands here)
- **Logger**: `src/cyanide/logger.py`

## Logs
Logs are written to `var/log/cyanide/cyanide.json`.
```json
{"timestamp": "...", "eventid": "auth", "data": {"username": "root", ...}}
```
