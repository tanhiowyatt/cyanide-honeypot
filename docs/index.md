# Cyanide Documentation Hub

<p align="center">
  <img src="https://raw.githubusercontent.com/tanhiowyatt/cyanide-honeypot/main/src/cyanide/assets/branding/name.png" alt="Cyanide Logo" width="400">
</p>

Welcome to the central documentation hub for **Cyanide**a medium-interaction SSH and Telnet honeypot designed for high-fidelity threat intelligence and behavioral analysis.

---

## Choose Your Path

Whether you are looking to deploy Cyanide in your network or dive deep into its hybrid ML engine, we have you covered.

### For Operators (User Reference)
*Learn how to deploy, configure, and integrate Cyanide into your security stack.*

| Guide | Description |
| :--- | :--- |
| [**Quick Start**](user-reference/QuickStart.md) | Get Cyanide running in under 5 minutes using Docker. |
| [**Detailed Configuration**](user-reference/AdvancedUsage.md) | A complete reference for environment variables and honeypot tuning. |
| [**SIEM Integrations**](user-reference/Integrations.md) | Connecting to ELK, Splunk, Slack, and setting up alert rules. |
| [**Threat Intelligence**](user-reference/ThreatIntelligence.md) | Automatic IOC extraction and STIX 2.1 reporting. |

### For Architects (Technical Reference)
*Explore the internal mechanics, VFS logic, and machine learning components.*

| Section | Description |
| :--- | :--- |
| [**Core Architecture**](developer-reference/core/index.md) | High-level system design and execution flow. |
| [**VFS Internals**](developer-reference/vfs/index.md) | How Cyanide emulates a Linux filesystem using SQLite backends. |
| [**ML & Analytics**](developer-reference/ml-analytics/index.md) | Deep dive into LSTM anomaly detection and behavioral scores. |
| [**Testing Suite**](developer-reference/tests/index.md) | How we ensure stability via automated and manual testing. |

---

## Key Concepts

> **Why Medium-Interaction?**
> Cyanide offers more realism than "low-interaction" honeypots (which just log logins) by providing a simulated shell, but remains safer and easier to manage than "high-interaction" honeypots (which use real VMs).

### How It Works
1.  **Ingress**: Attacker connects via SSH or Telnet.
2.  **Masquerade**: Cyanide presents a dynamic OS profile (Ubuntu, CentOS, etc.).
3.  **Interaction**: Attacker executes commands in a sandboxed VFS.
4.  **Analysis**: The ML engine calculates an anomaly score for every keystroke.
5.  **Egress**: High-fidelity events are streamed to your SIEM via Output Plugins.

---

## Community & Support

*   **Translations**: Read the project overview in [Russian](translations/readme-ru.md) or [Polish](translations/readme-pl.md).
*   **Contributing**: Found a bug or want to add a feature? Check out our [Contributing Guide](https://github.com/tanhiowyatt/cyanide-honeypot/blob/main/CONTRIBUTING.md).

---
<p align="center">
  <i>Revision: 1.0  April 2026  Cyanide Honeypot</i>
</p>
