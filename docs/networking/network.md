# Network & Proxy (`src/cyanide/network` & `src/cyanide/core`)

This module brokers the physical connections between literal attacker IP addresses and the emulated services inside Cyanide. It acts as both the listener layer and the security proxy protecting backend systems.

## 1. Emulated Services

Attackers do not interact with native unshielded daemons (like `sshd` or `telnetd`). Instead, they communicate with entirely synthetic, asynchronous Python listeners constructed specifically for honeypot data extraction.

### SSH Handler (`src/cyanide/core/server.py`):
- Runs entirely in the asyncio event loop via `asyncssh`.
- **Key Collection:** Presents configurable host keys derived directly from the loaded profile manifest, making fingerprints identical to specific real-world Ubuntu/Debian releases.
- **PTY Handshaking:** Fully implements the PTY setup, window resizing, and VT100 control codes to support interactive usage (e.g., launching `nano`, updating passwords).
- **Authentication Hooks:** Allows Cyanide to capture usernames, password combinations, and pubkeys before optionally granting access into the `ShellEmulator`.

### Telnet Handler (`src/cyanide/services/telnet_handler.py`):
- An explicit, raw TCP socket parser tracking Telnet Negotiation protocols (DO, DONT, WILL, WONT).
- Simulates legacy login workflows common on old IoT devices, dropping the attacker into an identical `ShellEmulator` instance once standard text-based authentication criteria are met.

## 2. Proxy Dispatch (`src/cyanide/network/tcp_proxy.py`)

If the honeypot is configured in Proxy or Pool Mode, the Network layer conditionally routes attacker traffic directly at the TCP stream level rather than trapping it in an emulator.

### `TCPProxy` Implementation
The `TCPProxy` class sits invisibly between the attacker and the configured destination (a proxy target or a dynamic `VMPool` guest).

1. **Transparent Bridging:** Once the attacker connects, `TCPProxy` asynchronously opens a socket to the target backend (`target_host:target_port`). It reads raw bytes (`data_received`) from the attacker's transport, buffers them, and writes them immediately to the target backend's transport.
2. **Reverse Tunneling:** Simultaneously, it reads byte output back from the target and pipes it directly to the attacker.
3. **Forensic Logging & Observability:** While the stream acts like a pure pass-through, `TCPProxy` silently clones all transmitted payloads in real-time. It translates hexadecimal data into readable formats and routes it centrally through `CyanideLogger` as `proxy_traffic` events, ensuring an immutable audit trail of the man-in-the-middle session.
4. **VMPool Awareness:** If a `Lease` object is passed into the proxy, the `TCPProxy` takes ownership of the VM lifecycle for that session. Upon connection loss (`connection_lost`), the proxy automatically triggers the `VMPool` to release the lease, which destroys the attacker's sandbox VM.

## 3. Defensive Anti-Fingerprinting (Jitter)

Automated vulnerability scanners (like Nmap, ZMap) and sophisticated attackers often attempt to fingerprint honeypots by measuring exact protocol response times. Real operating systems have unpredictable process scheduler latency.

- **The Jitter Algorithm:** The network layer artificially injects highly randomized, imperceptible execution delays (e.g., `50-300ms`) into response streams.
- **Outcome:** This random variance defeats deterministic fingerprinting tools analyzing TCP acknowledgment deltas, forcing the attacker's scripts to conclude they are scanning a busy production host.
