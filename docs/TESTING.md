# Testing Guide

## 1. Prerequisites

Dependencies are managed via `pyproject.toml`.
For local testing, install the project in editable mode with dev dependencies:

```bash
pip install -e .[dev]
```

## 2. Running Tests

### Inside Docker (Recommended)
This ensures the environment matches production (Python version, OS libraries).

```bash
# Run all tests
docker exec -it cyanide pytest tests/

# Run specific test
docker exec -it cyanide pytest tests/integration/test_ssh_server.py
```

### Locally
```bash
pytest tests/
```

## 3. Test Structure

| Directory | Purpose |
|-----------|---------|
| `tests/unit/` | Isolated component tests (Shell, VFS, ML). |
| `tests/integration/` | End-to-end flows (SSH login, file download). |
| `tests/conftest.py` | Shared fixtures (`mock_fs`, `event_loop`). |

## 4. Continuous Integration
GitHub Actions workflows are defined in `.github/workflows/`:
- `tests.yml`: Runs `pytest` on push.
- `lint.yml`: Runs `ruff` linter.

## 5. Manual & Technical Testing Plan

For a granular breakdown of how to test every internal module (ML, VFS, Security), see the [Technical Test Plan](TECHNICAL_TEST_PLAN.md).

### 5.1 Connection & Environment
- **SSH Check**: `ssh -p 2222 root@127.0.0.1` (Verify banner and OS identity).
- **Telnet Check**: `telnet 127.0.0.1 2223` (Verify login prompt).

### 5.2 OS Fidelity & VFS
- **OS Identity**: `cat /etc/os-release` (Check for `ID`, `VERSION`, `PRETTY_NAME`).
- **Dynamic /proc**: `cat /proc/uptime` (Run twice to see changes) and `cat /proc/meminfo`.
- **Filesystem Aging**: `ls -la /etc` (Verify timestamps are in the past, not current date).
- **Process List**: `ps aux` (Ensure it shows processes from the YAML profile).

### 5.3 Command Emulation
- **Navigation**: `pwd`, `cd /var/log`, `ls -F`.
- **File Ops**: `mkdir test_dir`, `touch test.txt`, `rm test.txt`.
- **Logic**: `cat /etc/passwd | grep root` (Pipes) and `echo "test" > log.txt` (Redirection).

### 5.4 Network Simulation
- **Outbound**: `curl http://google.com` (Verify simulated external connectivity).
- **Downloads**: `wget http://example.com/exploit.sh` (Verify download animation).

### 5.5 Security & Forensics
- **Honeytokens**: `cat /etc/shadow` (Check `var/log/cyanide/cyanide.log` for critical alerts).
- **ML Detection**: Run an anomaly (e.g., base64 encoded strings) and verify the score in logs.
- **Quarantine**: `scp -P 2222 payload.exe root@127.0.0.1:/tmp/` (Verify file is moved to `var/lib/cyanide/quarantine/`).

### 5.6 Operational
- **Metrics**: Visit `http://localhost:9090/metrics`.
- **Health**: Visit `http://localhost:9090/health`.
