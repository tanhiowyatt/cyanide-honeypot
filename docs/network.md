# Network & Proxy (`src/cyanide/network`)

This module brokers the physical connections between literal attacker IP addresses and the emulated services inside Cyanide. It acts as both the listener layer and the security proxy protecting backend systems.

## 1. Emulated Services

Attackers do not interact with native unshielded daemons (like `sshd` or `telnetd`). Instead, they communicate with entirely synthetic, asynchronous Python listeners constructed specifically for honeypot data extraction.

### SSH Handler (`ssh_handler.py`):
- Runs entirely in the asyncio event loop via `asyncssh`.
- **Key Collection:** Presents configurable host keys derived directly from the loaded profile manifest, making fingerprints identical to specific real-world Ubuntu/Debian releases.
- **PTY Handshaking:** Fully implements the PTY setup, window resizing, and VT100 control codes to support interactive usage (e.g., launching `nano`, updating passwords).
- **Authentication Hooks:** Allows Cyanide to capture usernames, password combinations, and pubkeys before optionally granting access into the `ShellEmulator`.

### Telnet Handler (`telnet_handler.py`):
- An explicit, raw TCP socket parser tracking Telnet Negotiation protocols (DO, DONT, WILL, WONT).
- Simulates legacy login workflows common on old IoT devices, dropping the attacker into an identical `ShellEmulator` instance once standard text-based authentication criteria are met.

## 2. Proxy Dispatch

If the honeypot is configured in Proxy Mode, the Network layer conditionally routes attacker traffic rather than trapping it in an emulator.

### `TCP Proxy`:
- Operates at Layer 4, forwarding raw bytes back and forth between the attacker and a legitimate internal testing server (e.g., forwarding an attacker probing port 25 to a real Postfix staging instance).
- Passively logs the stream for forensics via hexadecimal dumps and PCAP tracking.

### `SSH Proxy`:
- Serves as an advanced Man-in-the-Middle interceptor.
- If the target backend relies on SSH, this module negotiates the initial cryptography with the attacker, then transparently opens a corresponding SSH tunnel to the backend using the attacker's supplied credentials.
- All decrypted input/output is silently logged prior to being routed via the tunnel.

## 3. Defensive Anti-Fingerprinting (Jitter)

Automated vulnerability scanners (like Nmap, ZMap) and sophisticated attackers often attempt to fingerprint honeypots by measuring exact protocol response times. Real operating systems have unpredictable process scheduler latency.

- **The Jitter Algorithm:** The network layer artificially injects highly randomized, imperceptible execution delays (e.g., `50-300ms`) into response streams.
- **Outcome:** This random variance defeats deterministic fingerprinting tools analyzing TCP acknowledgment deltas, forcing the attacker's scripts to conclude they are scanning a busy production host.
