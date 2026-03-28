# 🛠️ Honeypot Services Overview

**Cyanide** provides several protocol-specific services. Each service is designed to be fully configurable via `app.yaml` or environment variables and integrates with the common VFS and detection engine.

## 📑 Service Details

*   **SSH Interaction**: A deep-interaction SSH server using `asyncssh`. Supports both emulated and proxied backend modes.
*   **Telnet Service**: Low-latency Telnet server implementing the Telnet protocol state machine and RFC-compliant shell sessions.
*   **Metrics Server**: Internal Prometheus-compatible exporter for real-time monitoring of sessions, traffic, and security alerts.
*   **VMPool Manager**: Dynamic backend pool for managing proxied sessions into isolated micro-VMs.

## 📄 Detailed Documents

*   **[SSH Service Architecture](ssh.md)**: Deep interactions around custom crypto mimicry, port forwarding interception, and standard PTY allocation.
*   **[Telnet Service Architecture](telnet.md)**: Details on the asynchronous raw TCP connection handler and `IAC` byte sanitization logic.

## 🔗 See Also
*   🌐 **[Networking Logic](../networking/index.md)**: Details on the MiTM proxying.
*   📁 **[VFS Layer](../vfs/index.md)**: The shared filesystem used by all honeypot protocols.

---
*Last updated: 2026-03-10*
