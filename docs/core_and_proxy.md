# Core Architecture & Network

This section covers the internal logic of Cyanide, split between `src/cyanide/core` (Orchestration & Emulation) and `src/cyanide/network` (Traffic Handling).

---

## 1. Core Logic (`src/cyanide/core`)

### `server.py`
**Class:** `HoneypotServer`
The central orchestrator that initializes services and manages lifecycle.
*   **Key Responsibilities:**
    *   Starting SSH (`asyncssh`), Telnet, and Metrics servers.
    *   Routing traffic based on `backend_mode` (Emulated vs. Proxy).
    *   Initialize sub-services: `SessionManager`, `QuarantineService`, `AnalyticsService`.
    *   Dispatching commands to the ML engine for analysis.

### `emulator.py`
**Class:** `ShellEmulator`
A state machine that simulates a Bash-like shell environment.
*   **Features:**
    *   **Parsing:** Handles complex command chains (`&&`, `||`, `;`), pipes (`|`), and redirections (`>`, `2>`).
    *   **Environment:** Manages variables (`export`, `$VAR`).
    *   **User Context:** Tracks current user (`root`, `admin`), CWD, and permissions.

---

## 2. Virtual Filesystem (`src/cyanide/vfs`)

Cyanide does not touch the host disk for emulation. It uses an in-memory VFS.

### `provider.py`
**Class:** `FakeFilesystem`
*   Loads the initial state from YAML profiles (`configs/profiles/`).
*   **Operations:** `mkfile`, `mkdir`, `remove`, `write`, `read`.
*   **Persistence:** Changes (e.g., `touch newfile`) persist for the duration of the session.
*   **Audit Hooks:** Any file read/write triggers an audit event log.

---

## 3. Network & Proxy (`src/cyanide/network`)

### `tcp_proxy.py`
**Class:** `TCPProxy`
A generic asyncio-based TCP forwarder used when `backend_mode` is set to `proxy` or for the SMTP service.
*   **Functionality:**
    *   Accepts connection on `listen_port`.
    *   Connects to `target_host:target_port`.
    *   Bidirectional data streaming.
    *   Logs traffic size and duration.

### `ssh_proxy.py` (Legacy/Specialized)
Used for advanced SSH Man-in-the-Middle scenarios where we need to decrypt traffic before forwarding to a real backend.
