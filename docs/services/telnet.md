# Telnet Service Architecture (`src/cyanide/services/telnet_handler.py`)

Cyanide implements a raw, highly optimized asynchronous TCP Telnet server built natively with `asyncio.start_server`. Unlike SSH, which relies on a specialized cryptographic library, Cyanide parses Telnet directly at the byte level to recreate an authentic legacy UNIX terminal experience.

## 1. Raw Protocol Execution & State Machine

The Telnet protocol (RFC 854) involves in-band signaling using `IAC` (Interpret As Command) bytes (0xFF).

### Key Iteration Handlers:
- **`handle_connection`:** The primary entry point. When a TCP connection is established on port 2223, a new handler loop spawns, reading up to 1024 bytes per tick.
- **IAC Sanitization:** Before the buffer is passed to the emulation layer or the proxy backend, Cyanide intercepts `IAC` sequences (like `WILL ECHO`, `DO LINEMODE`). It logs these negotiation attempts (helpful for identifying automated Telnet scanners like Mirai) and seamlessly strips the bytes to ensure clean string execution on the emulator.

## 2. Authentication Prompting

Telnet is unencrypted and plaintext. The `TelnetSession` initiates the connection by presenting a standard Linux login sequence:

1. Server writes: `Ubuntu 22.04 LTS\n` (Derived from the dynamic OS Profile module)
2. Server writes: `login: `
3. Attacker inputs username. (Visible in plaintext).
4. Server writes: `Password: ` (With local echo softly disabled to mimic real behavior, though clients often enforce their own echo loops).
5. Attacker inputs password.
6. Cyanide evaluates the credentials against `CYANIDE_USERS`.
7. **Authentication Delay:** A configurable 1-second delay (default) is applied after credential entry but before the session is established to enhance realism.

During this phase, Cyanide logs all failed and successful `telnet_auth` events to the core logger.

## 3. Emulation Bridging & Window Scaling

Because Telnet has no native concept of PTY allocation in the same rigid way as SSH (unless negotiated via `NAWS`), Cyanide treats the standard byte-stream as a persistent, single-channel terminal overlay.

- If the user types a command, Cyanide collects bytes until a carriage return (`\r\n`) is encountered, buffering incoming streams to reconstruct fragmented TCP packets.
- The reconstructed string is passed to `ShellEmulator.execute()`.
- The emulator's standard output is wrapped in Telnet formatting, returning carriage-return strings correctly aligned so they don't stair-step across the attacker's terminal screen.

## 4. Backend Routing

Like the SSH module, the Telnet service dynamically adapts to the `backend_mode`.
If the configuration instructs the honeypot to run as a `proxy`, the `CyanideServer` bypasses `handle_connection` entirely and forces the raw TCP stream through the `TCPProxy` into an underlying target, treating Telnet essentially as an unfiltered socket pipe.
