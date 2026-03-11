# 🧪 Comprehensive Testing Guide

Cyanide uses a multi-layered approach to ensure reliability, security mimicry, and performance. This guide covers everything from basic unit tests to advanced red-teaming scenarios.

---

## 🔝 Testing Hierarchy (Easiest to Hardest)

### 🟢 Level 1: Static Analysis & Linting
Fastest checks to ensure code quality and formatting.
- **Tools**: `ruff`, `black`, `mypy`.
- **Command**: `black --check src/ && ruff check src/ && mypy src/`

### 🟡 Level 2: Component Unit Tests
Verifies individual modules (VFS, Config, Utils) in isolation.
- **Location**: `tests/unit/`
- **Command**: `pytest tests/unit/`

### 🟠 Level 3: Integration & Protocol Tests
Verifies SSH/Telnet sessions, MiTM proxying, and Malware quarantine flows.
- **Location**: `tests/integration/`
- **Command**: `pytest tests/integration/`
- **Requirement**: May require `libvirt` if testing VM Pool modes.

### 🔴 Level 4: Manual "Gauntlet" Testing
Step-by-step verification of the end-user experience and mimicry.
- **Guide**: **[Manual Testing Checklist](manual.md)**
- **Focus**: UI/UX, shell realism, and "feel" of the honeypot.

### 🟣 Level 5: Red Teaming & Adversarial Ops
Attacking the honeypot with real toolkits (Metasploit, Nmap, custom botnets).
- **Focus**: Detection bypass, breakout attempts, and anti-fingerprinting effectiveness.

---

## 🛠️ Automated Testing Details

### Environment Setup
1. Use a virtual environment: `source .venv/bin/activate`
2. Install dev dependencies: `pip install -e ".[dev]"`
3. (Optional) Start `libvirtd` for VM Pool testing.

### Running Specific Tests
- **By Marker**: `pytest -m "not slow"`
- **With Coverage**: `pytest --cov=cyanide tests/`
- **Fail Fast**: `pytest -x`

---

## 🔬 Specialized Testing

### Load & Performance
Located in `tests/load/`. Used to verify how many concurrent sessions Cyanide can handle before the shell emulator or proxy layer degrades.

### ML Drift Testing
Verifies that the ML Anomaly Detection engine correctly flags new types of obfuscated commands.

---

## 🔗 Related Resources
* 🎭 **[OS Profiles Guide](../vfs/profiles_guide.md)**: How to test custom victim personas.
* 🔌 **[Plugins Architecture](../tooling/plugins.md)**: Testing output data integrity.
* 🆘 **[Troubleshooting](../core/troubleshooting.md)**: Common test failure causes (Libvirt/Auth).
