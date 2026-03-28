# 🧩 System Extensibility & Modular Architecture

Beyond the [Output Plugins](../tooling/plugins.md), Cyanide is built on a modular "Everything is a Plugin" philosophy. This allows developers to extend the filesystem, terminal, and backend orchestration without modifying the core server engine.

## 1. VFS Dynamic Providers (`src/cyanide/vfs/dynamic.py`)

Cyanide can generate file content on-the-fly. This is essential for files like `/proc/uptime` or `/proc/cpuinfo` which must look real but cannot be static.

### How it Works:
1. **The Registry (`PROVIDERS`)**: A simple dictionary mapping provider names to Python functions.
2. **Implementation**: A provider is a standard Python function:
   ```python
   def my_provider(context, args=None):
       return "Dynamic content string\n"
   ```
3. **Usage in Profiles**: In any `base.yaml` or `static.yaml` OS profile, you can reference the provider:
   ```yaml
   dynamic_files:
     /proc/custom: { provider: my_provider }
   ```

## 2. Shell Command Handlers (`src/cyanide/vfs/commands/`)

In `emulated` mode, commands like `ls`, `cat`, and `mkdir` are not real binaries. They are Python classes that mimic the behavior of those binaries while operating on the in-memory VFS.

### How to Add a Command:
1. Create a file in `src/cyanide/vfs/commands/`.
2. Inherit from the base `Command` class.
3. Implement the `execute()` method.
4. The [Shell Emulator](../vfs/shell_emulator.md) will automatically resolve the command by name when an attacker types it.

## 3. VM Pool Backends (`src/cyanide/pool/`)

The `VMPool` is abstract. It doesn't care *how* a VM is started, only that it gets a target IP to proxy traffic to.

### Available Backends:
- **`SimplePool`**: A static pool of pre-populated IP addresses (e.g., a whitelist of old IoT devices).
- **`LibvirtPool`**: A full-lifecycle manager using KVM/QEMU to clone and destroy VMs on-demand for every attacker session.

This allows you to swap out the orchestration layer (e.g., adding a Proxmox or Docker backend) by simply implementing a new backend class.

## 4. SSH Interaction Profiles

The SSH server mimics specific `kex`, `macs`, and `ciphers` based on the [Security Profiling](../services/ssh.md) documentation. These are essentially plugins for the SSH handshake, allowing the honeypot to appear as an old Cisco router, a modern Ubuntu server, or a custom IoT firmware depending on your research goals.
