# 📁 Virtual Filesystem (VFS) Documentation

The **Virtual Filesystem** layer provides a convincing Linux environment for the attacker. It manages dynamic file generation, memory overlays, and per-session file state mutations.

## 📄 Overview
Instead of exposing the host system's disk, Cyanide uses a purely in-memory filesystem representation. This allows for total isolation while still providing the attacker with a rich, interactive environment (files, directories, pipes).

## 🛠️ How it Works
The VFS resolves all attacker requests to `Node` objects. Changes are stored in a session-specific **memory overlay**, meaning an attacker can "delete" `/bin/ls` or "create" a folder without affecting the base installation or other concurrent sessions.

## ⚙️ Configuration
FileSystem structure is defined via **OS Profiles** in `configs/profiles/`. These YAML files specify the base file list, permissions, and initial content. Dynamic files (like `/proc/cpuinfo`) use custom providers.

## 📑 Detailed Documents

*   **[VFS Architecture](vfs.md)**: Details on the engine, proxy nodes, and profile-based OS manifests.
*   **[Shell Emulator Architecture](shell_emulator.md)**: Details on the custom AST parser, logic gates, and command dispatching.
*   **[Caching Strategy](../core/caching.md)**: Performance optimizations for high-throughput I/O scenarios.
*   **[Dynamic Providers](vfs.md#3-dynamic-providers)**: How `/proc/uptime`, `/proc/cpuinfo`, and other system files are generated.
*   **[Commands](vfs.md#5-command-implementation)**: Native implementations of standard Linux command-line utilities.

## 🔗 See Also
*   🏛️ **[Core Architecture](../core/index.md#architecture-guide)**: The high-level service orchestration.
*   🛠️ **[Honeypot Services](../services/index.md)**: How SSH/Telnet sessions utilize the VFS.

---
*Last updated: 2026-03-10*
