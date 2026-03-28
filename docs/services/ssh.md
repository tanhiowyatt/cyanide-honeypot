# SSH Service Architecture (`src/cyanide/services/ssh_handler.py`)

Cyanide provides a complete, high-interaction SSH server implementation built upon the asynchronous `asyncssh` library. The integration represents a fully functional OpenSSH-compatible endpoint engineered for forensics, session capturing, and connection interception.

## 1. The SSHServerFactory & Session Lifecycle

The `SSHServerFactory` class dictates how an incoming SSH connection is initially received and authenticated.

### Key Capabilities:
- **Authentication Handlers:** Cyanide supports both `password` and `publickey` authentication.
  - Unlike naive honeypots that blindly accept any credential, Cyanide can optionally parse a `CYANIDE_USERS` list to only permit specific credentials. This weeds out simplistic bots and encourages advanced human attackers to proceed.
  - **Authentication Delay:** To enhance realism and frustrate automated scanners, a configurable 1-second delay (default) is applied after credential entry but before the session is established.
  - If a public key is provided natively via the client, Cyanide records the key fingerprint and accepts the payload, allowing it to trace specific threat actors via their unique SSH keypairs across different servers.
- **Connection Logging:** The initial `connection_made` event is trapped. Cyanide extracts the remote client version (e.g. `SSH-2.0-OpenSSH_9.0`) and logs it, identifying the attacker's toolkit before authentication even completes.

## 2. PTY and Session Layer (`CyanideSSHServer`)

Once an attacker passes the `SSHServerFactory` layer, a `CyanideSSHServer` instance is provisioned for their session.

- **PTY (Pseudo-Terminal) Requests:** When the attacker requests a PTY, Cyanide checks the `backend_mode`.
  - In **Emulated** mode, it initializes the `ShellEmulator` bridging strings from the SSH channel into the VFS.
  - In **Proxy** and **Pool** modes, it transparently passes the stream directly to the underlying `TCPProxy` and returns the true remote output.
- **Environment Capturing:** Any `env` variables the attacker attempts to pass over SSH are silently captured and logged as `ssh_env_data`.

## 3. Cryptographic Mimicry & Security Profiling

Cyanide simulates high-security enterprise environments to encourage advanced malware drops.

Through configuration (`CYANIDE_SSH_MACS`, `CYANIDE_SSH_CIPHERS`, `CYANIDE_SSH_KEX_ALGS`), Cyanide limits exactly which cryptographic negotiation algorithms it broadcasts during the handshakes. By broadcasting highly-secure, modern ciphers (e.g., `curve25519-sha256`, `chacha20-poly1305@openssh.com`), Cyanide tricks reconnaissance tools into classifying the honeypot as an up-to-date, heavily fortified target.

This prevents older, noisy botnets from connecting, ensuring that only specialized or heavily motivated adversaries can establish a session.

## 4. Advanced Port Forwarding (Tunnels) Interception

A key differentiator for Cyanide is its rigorous capability to intercept SSH port-forwarding channels (`-L` Local Forwarding, `-R` Remote Forwarding, `-D` Dynamic SOCKS proxy).

When an attacker attempts to establish a tunnel through Cyanide, the `direct_tcpip_requested` and `connection_requested` handler hooks are triggered.

### The Interception Flow:
1. **Request Tracking:** Cyanide captures the `dest_host` and `dest_port` the attacker wishes to tunnel to through the honeypot.
2. **Policy Router Evaluation:** Cyanide evaluates `CYANIDE_SSH_FORWARD_REDIRECT_RULES`.
3. **Redirection (Optional):** If a rule exists (e.g., mapping port `80` to a safe internal sinkhole sandbox), Cyanide transparently alters the `dest_host` and routes the tunnel silently to the safe sandbox, making the attacker believe they successfully breached the internal network.
4. **Denial:** If `CYANIDE_SSH_FORWARDING_ENABLED` is false, Cyanide denies the channel softly, emulating a correct `Administratively Prohibited` firewall response.
## 5. File Transfer Capabilities (SFTP, SCP, rsync)

Cyanide supports advanced file transfer protocols to realistically simulate a target environment where attackers might attempt to drop malware or exfiltrate data.

### SFTP Subsystem
Cyanide implements a full SFTP subsystem that bridges directly to the Virtual Filesystem (VFS).
- **Realistic Metadata:** File permissions, owners (root/user), and timestamps are realistically simulated.
- **Quarantining:** Every file uploaded via SFTP is automatically captured and moved to the `quarantine` directory for deep forensics and malware analysis.
- **Audit Logging:** Every SFTP operation (listdir, open, mkdir, rename, delete) is logged as a structured event with the origin IP and session context.

### SCP Support
Secure Copy (SCP) is supported via the standard RCP-based wire protocol.
- **Interception:** Cyanide intercepts `scp` and `/usr/bin/scp` execution requests in the SSH session.
- **Recursive Transfers (`-r`):** Full support for recursive directory uploads. Captured directory structures are realistically mirrored in the VFS.
- **Realistic Sink Mode:** Implements the `sink` protocol (`-t`) to receive files. The honeypot performs the expected ACK-based handshake (`\0`) to realistically simulate a successful transfer.
- **VFS Integration:** Captured files and directories are automatically placed into the Virtual Filesystem (VFS) and forwarded to the quarantine service for analysis.

### rsync Monitoring & Intent Capture
Cyanide provides a high-fidelity rsync "Server Mode" monitor that performs active protocol analysis of incoming synchronization requests.

- **Binary Handshake (v31.x)**: Performs the native binary protocol handshake (4-byte LE integers) to prevent client-side "protocol version mismatch" errors.
- **Intent Capture (File List Parsing)**: Unlike simple simulators, Cyanide implements a minimal rsync 31.x file list parser. It actively reads the binary stream sent by the client to reconstruct:
    - **Filenames**: The exact names of files the attacker intends to upload/download.
    - **Metadata**: Reported file sizes and permission modes.
- **Intelligent Denial**: After extracting the file list (capturing the attacker's "inventory"), Cyanide realistically terminates the session with an `EACCES (13)` error and a standard `Permission denied` message on `stderr`. This emulates a Read-Only filesystem while providing maximum forensic data.
- **Audit Logging**: Captures `rsync_exec_detected`, `rsync_handshake`, and `rsync_filelist` events.

### Security Limits
To prevent the honeypot from being used as a storage drop:
- `CYANIDE_SSH_MAX_UPLOAD_SIZE_MB`: Limits the size of a single file.
- `CYANIDE_SSH_MAX_TOTAL_UPLOAD_MB_PER_SESSION`: Limits the total bytes an attacker can upload.
- `CYANIDE_SSH_ALLOW_DOWNLOAD`: Can be disabled to prevent "exfiltration" of the simulated target's sensitive files.
