# Cyanide Documentation Hub

Welcome to the official documentation for **Cyanide**, a high-interaction SSH & Telnet honeypot designed for deep behavioral analysis and threat intelligence gathering.

This documentation suite provides detailed insights into the system's architecture, configuration, and extensibility.

## Documentation Sections

| Section | Description |
|:---|:---|
| 🏛️ **[Core](core/index.md)** | System architecture, global configuration, and core engine mechanics. |
| 🚀 **[Deployment](core/deployment.md)** | Step-by-step setup (Docker vs Baremetal) and scaling. |
| 💎 **[Advanced](core/advanced_features.md)** | **New:** Honeytokens, HTTP Log Browser, and SMTP Capture. |
| 🔌 **[Plugins](tooling/plugins.md)** | Asynchronous output system for SIEMs, databases, and Slack. |
| 🧩 **[Extensibility](core/extensibility.md)** | Modular design: custom VFS providers, shell commands, and VM backends. |
| 📁 **[VFS](vfs/index.md)** | The Virtual Filesystem layer, OS profiles, and dynamic file providers. |
| 🎭 **[OS Profiles](vfs/profiles_guide.md)** | **New:** Tutorial on creating custom OS personas and file manifests. |
| 🛠️ **[Services](services/index.md)** | Technical details on individual honeypot services (SSH, Telnet, etc.). |
| 🌐 **[Networking](networking/index.md)** | Man-in-the-Middle proxying, traffic interception, and protocol handling. |
| 🧠 **[ML & Analytics](ml-analytics/index.md)** | Anomaly detection, security rule engine, and log analysis. |
| 🔧 **[Tooling](tooling/index.md)** | Operational scripts, management CLI, and deployment guides. |
| 🧪 **[Testing](tests/index.md)** | **Full Guide:** Automated suites, integration tests, and [Manual "Gauntlet"](tests/manual.md). |
| 🆘 **[Troubleshooting](core/troubleshooting.md)** | **New:** Solutions for common errors (Libvirt, ML, Logging). |

## Translations

We maintain a localized version of the main project overview in several languages:

*   🇷🇺 **[Русский (Russian)](translations/readme-ru.md)** — Перевод основного README.
*   🇵🇱 **[Polski (Polish)](translations/readme-pl.md)** — Tłumaczenie głównego pliku README.

---
*Last updated: 2026-03-10*
