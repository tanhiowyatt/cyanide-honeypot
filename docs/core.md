# Core Orchestration (`src/cyanide/core`)

This module forms the brain and the operational center of the Cyanide honeypot. It manages the server lifecycle, handles incoming connections, and maintains the isolated state of every active session.

## 1. HoneypotServer (`src/cyanide/core/server.py`)

The `HoneypotServer` is the main entry point and lifecycle manager of the application. 

### Responsibilities:
- **Service Initialization:** On startup, it initializes the asynchronous networking components (e.g., SSH listeners, Telnet listeners) and binds them to the configured host and ports.
- **Dependency Injection & Setup:** It sets up the backend services that all sessions will share, such as the ML detection models, stats aggregators, and the logging infrastructure.
- **Connection Dispatching:** When an attacker connects, the `HoneypotServer` evaluates the connection against proxy settings (e.g., whether to route the attacker to a real backend via the TCP proxy or to trap them in the emulator).
- **Session Finalization:** When a connection is dropped or closed, the server triggers cleanup routines and flushes final telemetry events.

## 2. Shell Emulator (`src/cyanide/core/emulator.py`)

The `ShellEmulator` represents the simulated Linux shell environment presented to the attacker. It does not spawn a real underlying process; instead, it provides a highly convincing mock interface.

### Mechanism:
- **State Machine:** For every session, a new `ShellEmulator` instance is created. It tracks the `cwd` (Current Working Directory), the active `username` (e.g., admin or root), and any session-specific variables or aliases.
- **Parser Pipeline:** The emulator implements a custom parser to handle complex command lines. It understands:
  - Sequences and logic gates: `;`, `&&`, `||`
  - Piping: `|` (passing string data seamlessly between command handlers)
  - Redirections: `>`, `>>` (writing output to the VFS rather than the screen)
- **Command Dispatch:** Tokens are resolved against `aliases`. If a command matches an internal VFS command handler (e.g., `ls`, `cat`), it is executed. If it does not exist, a realistic `command not found` error is returned.
- **Permission Boundary:** The emulator works intimately with the VFS to enforce permissions `check_permission()`. For instance, actions in `/root` will prompt for a password or deny access unless the active user is correctly authenticated.

## 3. Session Management

Sessions represent the isolated context bounds of a single attacker.
- Every SSH or Telnet connection spawns an independent session ID.
- The state (history, VFS memory overlay) is strictly bound to this session to prevent attackers from interfering with one another or seeing each other's files.
- Session events (key presses, commands, login attempts) are forwarded to the `cyanide.logger` with the specific `session` UUID tag to ensure forensic traceability.

## Interaction Flow
1. An attacker connects on port 2222. The `HoneypotServer` accepts the connection.
2. The server instantiates a `FakeFilesystem` tied to the profile config, and passes it to a newly created `ShellEmulator`.
3. The attacker requests a virtual terminal (PTY) and types `ls -la > out.txt`.
4. The SSH handler passes this string to the `ShellEmulator.execute()` method.
5. The emulator splits the string, redirects the output channel to point to `out.txt` inside the `FakeFilesystem`, and executes the `ls` command class.
6. The VFS handles the file creation, and the session remains isolated.
