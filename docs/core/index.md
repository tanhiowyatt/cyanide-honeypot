# 🏛️ Core Service Documentation

The Core Engine of **Cyanide** is responsible for the overall lifecycle management of the honeypot, including configuration parsing, event orchestration, and the main server loop.

## 📄 Overview
Cyanide's core handles the transition between incoming network connections and the internal emulation logic. It acts as the "brain" that initializes services (SSH, Telnet), manages global security settings, and routes events to the analytics engine.

## 🛠️ How it Works
The core utilizes a central `CyanideServer` class built on top of `asyncio`. It starts multiple protocol-specific listeners and coordinates access to shared resources like the Virtual Filesystem (VFS) and the Statistics Manager.

## ⚙️ Configuration
The primary configuration for the core resides in `configs/app.yaml`. Session limits and listening IP are set under `server:`. Protocol settings such as `auth_tries` and `login_timeout` are located under `ssh:`. For detailed options, see the **[Configuration Guide](configuration.md)**.

## 📑 Detailed Documents

*   **[Core Overview](core.md)**: Introduction to the central `CyanideServer` and its event loop.
*   **[Architecture Guide](architecture.md)**: Deep dive into the internal mechanics and major system components.
*   **[Caching Engine](caching.md)**: Performance optimization tactics for static file profiles.

## 🔗 See Also
*   📁 **[VFS Documentation](../vfs/index.md)**: How the core interacts with the virtual filesystem.
*   🧠 **[ML & Analytics](../ml-analytics/index.md)**: Threat detection logic.

---
*Last updated: 2026-03-10*
