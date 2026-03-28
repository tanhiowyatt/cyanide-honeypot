# 🌐 Networking Documentation

This section explains Cyanide's networking stack, focusing on its protocol handling and protocol-specific proxying.

## 📄 Overview
Cyanide facilitates communication between attackers and the honeyport engine via a custom asynchronous networking layer. It supports both emulated direct interaction and specialized MiTM (Man-in-the-Middle) proxying to isolated backends.

## 🛠️ How it Works
Communication is handled via `asyncio` transport layers. For SSH, we utilize `asyncssh` for protocol negotiation, while the **Proxy Layer** intercepts the decrypted stream and allows for real-time traffic modification and credential harvesting.

## ⚙️ Configuration
Network settings (ports, host binding, os_profile) are managed in `configs/app.yaml` under the `server` and `ssh` blocks. For more info, see the **[Configuration Guide](../core/configuration.md)**.

## 📑 Detailed Documents

*   **[Network Stack Architecture](network.md)**: High-level overview of SSH, Telnet, and TCP proxying logic.
*   **[TCP Proxy Configuration](network.md#tcp-proxying)**: How Cyanide acts as a Man-in-the-Middle for arbitrary TCP traffic.
*   **[SSH Proxying Logic](network.md#ssh-man-in-the-middle)**: Details on the credential collection and traffic interception.
*   **[Anti-Fingerprinting](network.md#latency-and-jitter)**: Network jitter and response timing to deceive advanced scanners.

## 🔗 See Also
*   🛠️ **[Honeypot Services](../services/index.md)**: Individual protocol servers (SSH, Telnet).
*   🧪 **[Test Suite](../tests/index.md)**: Network failure and latency injection tests.

---
*Last updated: 2026-03-10*
