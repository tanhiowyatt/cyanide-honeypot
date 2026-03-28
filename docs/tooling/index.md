# 🔧 Project Tooling & Operations

This section is dedicated to the scripts in `scripts/management/` and the workflows employed by developers and maintainers of the Cyanide platform.

## 📄 Overview
Running a production honeypot requires robust monitoring and forensic toolsets. Cyanide provides built-in utilities for real-time traffic visualization and replaying attacker session data exactly as it was typed.

## 🛠️ How it Works
Cyanide's tools interact directly with the log files (`cyanide-fs.json`) and TTY capture files using Python-based parsers. The `cyanide stats` command provides immediate situational awareness, while `scriptreplay` is used for in-depth forensic investigation.

## ⚙️ Configuration
Diagnostic tools usually rely on default log paths (`var/log/cyanide/`). If you've modified these in `app.yaml`, make sure to pass the custom paths to the tools via CLI flags or by updating their internal constants.

## 📑 Detailed Documents

*   **[Operations Guide](operations.md)**: Comprehensive manual on system monitoring, logging, and TTY playback.
*   **[Plugins Architecture](plugins.md)**: Details on the asynchronous output system and how to integrate with external SIEMs/Databases.
*   **[Deployment Workflow](operations.md#deployment-setup)**: How to scale from individual local instances to high-availability Docker swarms.
*   **[Session Playback](operations.md#tty-log-replay)**: Utilizing `scriptreplay` for granular session investigation.
*   **[Asset Management](operations.md#system-maintenance)**: Handling the local file cache and quarantine directories.

## 🔗 See Also
*   🧪 **[Tests Documentation](../tests/index.md)**: Development-centric tests for each tool.
*   🏢 **[Management Architecture](../core/architecture.md)**: How core tools interface with the main server process.

---
*Last updated: 2026-03-10*
