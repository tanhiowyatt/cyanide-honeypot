"""
Advanced SSH/Telnet Honeypot Server Implementation.
"""
import asyncio
import asyncssh
import sys
import os
import signal
import uuid
import time
import random
import json
from pathlib import Path
from typing import Dict, Any, Optional

from .fake_filesystem import FakeFilesystem
from .shell_emulator import ShellEmulator
from cyanide import CyanideLogger
from cyanide.fs import load_fs
from .sftp import CyanideSFTPServer
from .vt_scanner import VTScanner
from .geoip import GeoIP
from .stats import StatsManager

class HoneypotServer:
    """Main honeypot server orchestrating SSH, Telnet, and MySQL services."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize honeypot server with configuration."""
        self.config = config
        
        # Setup Cyanide Logger
        log_path = os.getenv('TEST_LOG_DIR', config.get("log_path", "var/log/cyanide"))
        self.logger = CyanideLogger(log_path)
        
        # Setup Quarantine
        self.quarantine_path = Path(config.get("quarantine_path", "var/quarantine"))
        self.quarantine_path.mkdir(parents=True, exist_ok=True)
        
        self.users = self._load_users(config.get("users", []))
        self.active_sessions = 0
        self.max_sessions = config.get("max_sessions", 100)
        self.max_sessions_per_ip = config.get("max_sessions_per_ip", 5)
        self.sessions_per_ip = {} # Map of IP -> count
        self.session_timeout = config.get("session_timeout", 300)
        
        # Quarantine quota (in MB)
        self.quarantine_max_mb = config.get("quarantine_max_size_mb", 500)
        
        # Preload FS if pickled
        self.fs_pickle_path = config.get("fs_pickle")
        
        # VirusTotal
        vt_key = config.get("virustotal", {}).get("api_key", "")
        self.vt_scanner = VTScanner(vt_key)
        
        # GeoIP
        self.geoip = GeoIP()
        
        # OS Profile Selection
        from .system_profiles import PROFILES
        
        profile_key = config.get("os_profile", "random")
        if profile_key in PROFILES:
            self.profile = PROFILES[profile_key]
        else:
            if profile_key != "random":
                print(f"[!] Unknown profile '{profile_key}', falling back to random.")
            self.profile = random.choice(list(PROFILES.values()))
        
        print(f"[*] OS Profile: {self.profile['name']}")
        
        # Stats Manager
        self.stats = StatsManager()

    async def log_geoip(self, session_id, ip, protocol):
        """Async GeoIP enrichment logging."""
        geo_data = await self.geoip.lookup(ip)
        if geo_data:
            await self.logger.log_event_async({
                "event": "client_geo", "session_id": session_id,
                "protocol": protocol, "src_ip": ip,
                "geo": geo_data
            })


    def _load_users(self, config_users):
        """Load user credentials from configuration."""
        return config_users

    def is_valid_user(self, username, password):
        """Validate user credentials against configured users."""
        for user in self.users:
            if user["user"] == username and user["pass"] == password:
                return True
        return False
    
    def _fs_audit_hook(self, action, path, session_id="unknown", src_ip="unknown"):
        """Callback for filesystem auditing."""
        try:
            loop = asyncio.get_running_loop()
            
            # Honeytoken Tripwires
            HONEYTOKENS = [
                "/home/admin/secret.conf", 
                "/home/admin/flag.txt", 
                "/etc/shadow", 
                "/var/spool/cron/crontabs/root",
                "/root/flag.txt",
                "/root/secret.conf",
                "/root/.ssh/id_rsa"
            ]
            
            event_type = "fs_audit"
            if str(path) in HONEYTOKENS:
                event_type = "CRITICAL_ALERT"
                self.stats.on_honeytoken(str(path), src_ip)
            
            loop.create_task(self.logger.log_event_async({
                "event": event_type, 
                "action": action, 
                "path": str(path),
                "session_id": session_id,
                "src_ip": src_ip
            }))
        except RuntimeError:
            pass

    def get_filesystem(self, session_id="unknown", src_ip="unknown"):
        """Factory to get the filesystem instance."""
        audit_hook = lambda a, p: self._fs_audit_hook(a, p, session_id, src_ip)
        if self.fs_pickle_path and os.path.isfile(self.fs_pickle_path):
            try:
                root = load_fs(self.fs_pickle_path)
                fs = FakeFilesystem(audit_callback=audit_hook, profile=self.profile)
                fs.root = root # Hot-swap root
                return fs
            except Exception as e:
                print(f"Error loading pickle FS: {e}")
        return FakeFilesystem(audit_callback=audit_hook, profile=self.profile)

    async def _scan_and_log(self, filename: str, content: bytes, session_id="unknown", src_ip="unknown"):
        """Background task to scan file and log results."""
        try:
            result = await self.vt_scanner.scan(content, filename)
            if result:
                await self.logger.log_event_async({
                    "event": "malware_scan",
                    "session_id": session_id,
                    "src_ip": src_ip,
                    "filename": filename,
                    "sha256": result.get("sha256"),
                    "malicious": result.get("malicious"),
                    "label": result.get("label"),
                    "vt_link": result.get("link")
                })
                self.stats.on_malware(filename, result.get("malicious", False))
        except Exception as e:
            print(f"[!] Scan Error: {e}")

    def save_quarantine_file(self, filename: str, content: bytes, session_id="unknown", src_ip="unknown"):
        """Save a file to the quarantine directory with quota check."""
        try:
            # Check Disk Quota
            current_size = sum(f.stat().st_size for f in self.quarantine_path.glob('*') if f.is_file())
            content_size = len(content)
            
            if (current_size + content_size) > (self.quarantine_max_mb * 1024 * 1024):
                print(f"[!] Quarantine Quota Reached ({self.quarantine_max_mb}MB). Rejecting {filename}")
                return None

            timestamp = int(time.time())
            safe_name = f"{timestamp}_{Path(filename).name}"
            target_path = self.quarantine_path / safe_name
            
            with open(target_path, "wb") as f:
                f.write(content)
            
            # Trigger Async Analysis
            if self.vt_scanner.enabled:
                asyncio.create_task(self._scan_and_log(filename, content, session_id, src_ip))
                
            return str(target_path)
        except Exception as e:
            print(f"[!] Error saving quarantine file: {e}")
            return None
    def _log_tty(self, session_obj, direction: str, data: str):
        """Standard scriptreplay format: timing file + typescript file."""
        if direction != "OUT":
            return
            
        if hasattr(session_obj, 'tty_log_path') and hasattr(session_obj, 'tty_timing_path'):
            try:
                now = time.time()
                elapsed = now - session_obj.last_log_time
                session_obj.last_log_time = now
                
                # Convert to bytes if string
                if isinstance(data, str):
                    raw_bytes = data.encode('utf-8', 'ignore')
                else:
                    raw_bytes = data
                
                # Write timing: <interval> <bytes>
                with open(session_obj.tty_timing_path, "a") as f:
                    f.write(f"{elapsed:.6f} {len(raw_bytes)}\n")
                    f.flush()
                    
                # Write raw data
                with open(session_obj.tty_log_path, "ab", buffering=0) as f:
                    f.write(raw_bytes)
            except Exception as e:
                pass


    async def start_metrics_server(self):
        """Start a lightweight HTTP server for metrics and stats."""
        metrics_conf = self.config.get("metrics", {})
        if not metrics_conf.get("enabled", True):
            return
            
        port = metrics_conf.get("port", 9090)
        
        async def handle_request(reader, writer):
            try:
                # Read request line with timeout
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                except asyncio.TimeoutError:
                    writer.close()
                    return
                    
                if not line:
                    writer.close()
                    return
                    
                request_parts = line.decode().split()
                if len(request_parts) < 2:
                    writer.close()
                    return
                    
                path = request_parts[1]
                
                # Drain headers
                try:
                    while True:
                        header = await asyncio.wait_for(reader.readline(), timeout=1.0)
                        if header in (b'\r\n', b'\n', b''):
                            break
                except asyncio.TimeoutError:
                    pass

                if path == "/metrics":
                    content = self.stats.to_prometheus()
                    content_type = "text/plain; version=0.0.4; charset=utf-8"
                elif path == "/stats":
                    content = json.dumps(self.stats.get_stats(), indent=2)
                    content_type = "application/json"
                else:
                    content = "Cyanide Honeypot Metrics Server. Use /metrics or /stats."
                    content_type = "text/plain"
                    
                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(content)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{content}"
                ).encode()
                
                writer.write(response)
                await writer.drain()
            except Exception as e:
                print(f"[!] Metrics Handler Error: {e}")
            finally:
                writer.close()
                await writer.wait_closed()

        try:
            server = await asyncio.start_server(handle_request, "0.0.0.0", port)
            print(f"[*] Metrics Server listening on port {port}")
            async with server:
                await server.serve_forever()
        except Exception as e:
            print(f"[!] Metrics Server Error: {e}")

    async def start(self):
        """Start all honeypot services and enter main event loop."""
        # Generate SSH Host Key
        ssh_key = asyncssh.generate_private_key("ssh-rsa")
        
        # Helper to inject dependencies into SFTPServer
        def sftp_factory(channel):
            return CyanideSFTPServer(channel, self.get_filesystem(), self.save_quarantine_file)

        # Start SSH Server
        ssh_enabled = self.config.get("ssh", {}).get("enabled", True)
        if ssh_enabled:
            ssh_port = self.config["ssh"]["port"]
            
            # Anti-Fingerprinting
            # Use consistent banner from profile
            chosen_version = self.profile["ssh_banner"]
            print(f"[*] SSH Banner: {chosen_version}")
            
            ssh_server = await asyncssh.listen(
                "0.0.0.0", ssh_port,
                server_host_keys=[ssh_key],
                server_factory=lambda: SSHServerFactory(self),
                reuse_address=True,
                server_version=chosen_version
            )
            print(f"[*] SSH Server listening on port {ssh_port} (SFTP enabled via Factory)", flush=True)

        # Start Telnet Server
        telnet_enabled = self.config.get("telnet", {}).get("enabled", False)
        if telnet_enabled:
            telnet_port = self.config["telnet"]["port"]
            telnet_server = await asyncio.start_server(
                self.handle_telnet, "0.0.0.0", telnet_port, reuse_address=True
            )
            print(f"[*] Telnet Server listening on port {telnet_port}", flush=True)



        # Start Metrics Server
        asyncio.create_task(self.start_metrics_server())

        # Start Cleanup Task
        asyncio.create_task(self._cleanup_loop())
        
        # Keep running
        await asyncio.Future()

    async def _cleanup_loop(self):
        """Background task for automatic file cleanup."""
        # Initial delay to let things start
        await asyncio.sleep(60)
        
        from .cleanup import CleanupManager
        manager = CleanupManager(self.config)
        
        if not manager.enabled:
            print("[*] Cleanup: Disabled")
            return
            
        print(f"[*] Cleanup: Enabled (Every {manager.interval}s, older than {manager.retention_days}d)")
        
        while True:
            try:
                stats = manager.cleanup_files()
                if stats["deleted"] > 0:
                   await self.logger.log_event_async({
                       "event": "system_cleanup", 
                       "deleted": stats["deleted"], 
                       "bytes_freed": stats["bytes_freed"]
                   })
            except Exception as e:
                print(f"[!] Cleanup Error: {e}")
                
            await asyncio.sleep(manager.interval)

    async def handle_telnet(self, reader, writer):
        """Handle Telnet connections with interactive shell emulation."""
        src_ip, src_port = writer.get_extra_info("peername")
        
        # Global limit
        if self.active_sessions >= self.max_sessions:
            print(f"[!] Telnet: Global session limit reached ({self.max_sessions})")
            writer.close()
            return
            
        # Per-IP limit
        per_ip_count = self.sessions_per_ip.get(src_ip, 0)
        if per_ip_count >= self.max_sessions_per_ip:
            print(f"[!] Telnet: Per-IP limit reached for {src_ip} ({self.max_sessions_per_ip})")
            writer.close()
            return

        self.active_sessions += 1
        self.sessions_per_ip[src_ip] = per_ip_count + 1
        
        session_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        self.last_log_time = start_time # For TTY logging
        
        # Setup TTY logging for Telnet
        folder_name = f"telnet_{src_ip}_{session_id}"
        log_dir = Path("var/log/cyanide/tty") / folder_name
        log_dir.mkdir(parents=True, exist_ok=True)
        self.tty_log_path = log_dir / f"{folder_name}.log"
        self.tty_timing_path = log_dir / f"{folder_name}.timing"
        open(self.tty_log_path, "wb").close()
        open(self.tty_timing_path, "w").close()
        
        commands = []
        username = ""
        password = ""
        
        try:
            await self.logger.log_event_async({
                "event": "connect", "protocol": "telnet", 
                "src_ip": src_ip, "src_port": src_port, "session_id": session_id
            })
            
            # GeoIP Lookup
            asyncio.create_task(self.log_geoip(session_id, src_ip, "telnet"))
            self.stats.on_connect("telnet", src_ip)

            
            # Simple auth
            writer.write(b"login: ")
            await writer.drain()
            username = (await reader.readuntil(b"\n")).decode().strip()
            
            writer.write(b"Password: ")
            await writer.drain()
            password = (await reader.readuntil(b"\n")).decode().strip()
            
            success = self.is_valid_user(username, password)
            self.stats.on_auth("telnet", src_ip, username, password, success)
            await self.logger.log_event_async({
                "event": "auth", "protocol": "telnet", "session_id": session_id,
                "src_ip": src_ip, "username": username, "password": password, "success": success
            })
            
            if not success:
                 writer.write(b"\r\nLogin incorrect\r\n")
                 await writer.drain()
                 writer.close()
                 return

            # Shell loop
            # Removed artificial banner to mimic real system behavior (banner handled by issue usually)
            
            # Use Factory with session context
            fs = self.get_filesystem(session_id, src_ip)
            quarantine_hook = lambda f, c: self.save_quarantine_file(f, c, session_id, src_ip)
            shell = ShellEmulator(fs, username, quarantine_callback=quarantine_hook)
            
            # Session state for Telnet
            class TelnetState: pass
            session_state = TelnetState()
            session_state.tty_log_path = self.tty_log_path
            session_state.tty_timing_path = self.tty_timing_path
            session_state.last_log_time = self.last_log_time
            
            prompt = f"{username}@server:~$ "
            writer.write(prompt.encode())
            self._log_tty(session_state, "OUT", prompt)
            await writer.drain()
            
            while True:
                try:
                    line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=self.session_timeout)
                    cmd = line.decode().strip()
                    if not cmd:
                        writer.write(prompt.encode())
                        await writer.drain()
                        continue
                        
                    commands.append(cmd)
                    
                    if cmd in ("exit", "logout"):
                        break
                        
                    # Log command immediately
                    self.stats.on_command("telnet", src_ip, username, cmd)
                    await self.logger.log_command(session_id, "telnet", src_ip, username, cmd, client_version="Telnet")
                    
                    # Jitter
                    import random
                    await asyncio.sleep(random.uniform(0.05, 0.3))
                    
                    
                    stdout, stderr, rc = await shell.execute(cmd)
                    
                    # Confusion Metric
                    if rc == 127:
                         await self.logger.log_event_async({
                             "event": "command_not_found",
                             "session_id": session_id,
                             "cmd": cmd
                         })
                         
                    output = stdout + stderr
                    resp = output.replace("\n", "\r\n").encode()
                    writer.write(resp)
                    self._log_tty(session_state, "OUT", resp)
                    
                    # Update prompt
                    cwd = shell.cwd
                    if cwd.startswith(f"/home/{username}"):
                        cwd = cwd.replace(f"/home/{username}", "~", 1)
                    elif username == "root" and cwd.startswith("/root"):
                        cwd = cwd.replace("/root", "~", 1)
                        
                    prompt = f"{username}@server:{cwd}$ "
                    writer.write(prompt.encode())
                    await writer.drain()
                    
                except asyncio.TimeoutError:
                    writer.write(b"\r\nTimeout.\r\n")
                    break
        except Exception as e:
            print(f"[!] Telnet: Connection Error from {src_ip}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            duration = time.time() - start_time
            await self.logger.log_event_async({
                "event": "session_end", "protocol": "telnet", "session_id": session_id,
                "src_ip": src_ip, "username": username, "commands": commands, "duration": duration
            })
            self.active_sessions -= 1
            if src_ip in self.sessions_per_ip:
                self.sessions_per_ip[src_ip] = max(0, self.sessions_per_ip[src_ip] - 1)
                if self.sessions_per_ip[src_ip] == 0:
                    del self.sessions_per_ip[src_ip]
            self.stats.on_disconnect("telnet", src_ip)
            writer.close()

class SSHServerFactory(asyncssh.SSHServer):
    """SSH server factory."""
    
    def __init__(self, honeypot: HoneypotServer):
        self.honeypot = honeypot
        self.src_ip = "unknown"
        self.src_port = 0
        self.fs = None
        self.conn_id = str(uuid.uuid4())[:8]
    
    def connection_made(self, conn):
        self.src_ip = conn.get_extra_info("peername")[0]
        self.src_port = conn.get_extra_info("peername")[1]
        
        # Check limits early
        if self.honeypot.active_sessions >= self.honeypot.max_sessions:
             print(f"[!] SSH: Global limit reached")
             conn.close()
             return
             
        per_ip = self.honeypot.sessions_per_ip.get(self.src_ip, 0)
        if per_ip >= self.honeypot.max_sessions_per_ip:
             print(f"[!] SSH: Per-IP limit reached for {self.src_ip}")
             conn.close()
             return

        self.honeypot.active_sessions += 1
        self.honeypot.sessions_per_ip[self.src_ip] = per_ip + 1
        
        # Create a filesystem instance for this connection with IP context
        self.fs = self.honeypot.get_filesystem(session_id="conn_"+self.conn_id, src_ip=self.src_ip)
        
    def connection_lost(self, exc):
        # Transport level cleanup - handle leaks here
        self.honeypot.active_sessions -= 1
        if self.src_ip in self.honeypot.sessions_per_ip:
            self.honeypot.sessions_per_ip[self.src_ip] = max(0, self.honeypot.sessions_per_ip[self.src_ip] - 1)
            if self.honeypot.sessions_per_ip[self.src_ip] == 0:
                del self.honeypot.sessions_per_ip[self.src_ip]
        print(f"[*] SSH Connection Lost from {self.src_ip} (Active: {self.honeypot.active_sessions})")
        
    def password_auth_supported(self):
        return True
        
    def validate_password(self, username, password):
        success = self.honeypot.is_valid_user(username, password)
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "auth", "protocol": "ssh", "session_id": "conn_"+self.conn_id,
            "src_ip": self.src_ip, "username": username, "password": password, "success": success
        }))
        return success

    def sftp_factory(self, channel):
        """Create SFTP server instance sharing the connection's filesystem."""
        # Use conn_id for SFTP since it's pre-shell
        q_hook = lambda f, c: self.honeypot.save_quarantine_file(f, c, "sftp_"+self.conn_id, self.src_ip)
        return CyanideSFTPServer(channel, self.fs, q_hook)

    def session_requested(self):
        return SSHSession(self.honeypot, self.fs, self.src_ip, self.src_port)

class SSHSession(asyncssh.SSHServerSession):
    """SSH session handler."""
    
    def __init__(self, honeypot: HoneypotServer, fs: FakeFilesystem, src_ip, src_port):
        self.honeypot = honeypot
        self.fs = fs
        self.src_ip = src_ip
        self.src_port = src_port
        self.session_id = str(uuid.uuid4())[:8]
        self.commands = []
        self.start_time = time.time()
        self.client_version = "unknown"
        self.username = "root"
        self.buf = ""
        self.shell = None
        self.last_log_time = time.time()
        # Prompt is dynamic now 
        # Biometrics
        self.keystrokes = [] # List of timestamps
        # Traffic
        self.bytes_in = 0
        self.bytes_out = 0
        
    def connection_made(self, channel):
        self.channel = channel
        conn = channel.get_connection()
        self.username = conn.get_extra_info("username") or "root"
        self.client_version = conn.get_extra_info("client_version") or "unknown"
        
        self.honeypot.stats.on_connect("ssh", self.src_ip)
        
        # GeoIP Lookup
        asyncio.create_task(self.honeypot.log_geoip(self.session_id, self.src_ip, "ssh"))

        # SSH Fingerprinting
        # Extract negotiated algorithms (HASSH-like data)
        try:
             # asyncssh exposes these via get_extra_info on the connection
             cipher = conn.get_extra_info("cipher", "unknown")
             mac = conn.get_extra_info("mac", "unknown")
             compression = conn.get_extra_info("compression", "unknown")
             kex = conn.get_extra_info("kex", "unknown")
             key_algo = conn.get_extra_info("server_host_key", "unknown")
             
             fingerprint = {
                 "kex": kex,
                 "key_algo": key_algo,
                 "cipher": cipher,
                 "mac": mac,
                 "compression": compression
             }
             
             asyncio.create_task(self.honeypot.logger.log_event_async({
                 "event": "client_fingerprint", "session_id": self.session_id, "src_ip": self.src_ip,
                 "protocol": "ssh", "fingerprint": fingerprint,
                 "client_version": self.client_version
             }))
        except Exception as e:
             pass

    def connection_lost(self, exc):
        """Log session disconnect."""
        reason = "clean"
        if exc:
            reason = f"error: {exc}"
            
        self.honeypot.stats.on_disconnect("ssh", self.src_ip)
            
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "session_disconnect", 
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "reason": reason
        }))

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        """Log terminal resize events (SIGWINCH)."""
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "window_resize", 
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "width": width, "height": height
        }))
        if self.shell:
            # Propagate
            pass

    def shell_requested(self):
        # Use shared FS
        q_hook = lambda f, c: self.honeypot.save_quarantine_file(f, c, self.session_id, self.src_ip)
        self.shell = ShellEmulator(self.fs, self.username, quarantine_callback=q_hook)
        return True
    
    def _get_prompt(self):
        if not self.shell: return "$ "
        cwd = self.shell.cwd
        if cwd.startswith(f"/home/{self.username}"):
            cwd = cwd.replace(f"/home/{self.username}", "~", 1)
        elif self.username == "root" and cwd.startswith("/root"):
            cwd = cwd.replace("/root", "~", 1)
        return f"{self.username}@server:{cwd}$ "
    
    def session_started(self):
        self._ensure_tty_log()
        if self.shell:
            # self.channel.write(f"Welcome into {self.username} shell\r\n")
            self.channel.write(self._get_prompt())
    
    def _ensure_tty_log(self):
        # Setup TTY logging (scriptreplay compatible)
        folder_name = f"ssh_{self.src_ip}_{self.session_id}"
        log_dir = Path("var/log/cyanide/tty") / folder_name
        log_dir.mkdir(parents=True, exist_ok=True)
        
        self.tty_log_path = log_dir / f"{folder_name}.log"
        self.tty_timing_path = log_dir / f"{folder_name}.timing"
        open(self.tty_log_path, "wb").close()
        open(self.tty_timing_path, "w").close()
        self.last_log_time = time.time()
            
    def _log_tty(self, direction: str, data: str):
        self.honeypot._log_tty(self, direction, data)

    def env_received(self, name, value):
        """Log client environment variables."""
        # Convert bytes to str if needed
        if isinstance(name, bytes): name = name.decode('utf-8', 'ignore')
        if isinstance(value, bytes): value = value.decode('utf-8', 'ignore')
        
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "client_env", 
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "name": name,
            "value": value
        }))
        return True

    def data_received(self, data, datatype=None):
        asyncio.create_task(self._process_input(data))

    async def _process_input(self, data):
        try:
            # Enhanced Randomized Jitter
            # Use a mix of stable and spikey delays to mimic human behavior or network issues
            if random.random() < 0.1:
                # 10% chance of a "network spike"
                delay = random.uniform(0.5, 1.5)
            else:
                # Normal human-like typing jitter
                delay = random.uniform(0.02, 0.15)
                
            await asyncio.sleep(delay)

            # Record Keystroke Timing
            self.keystrokes.append(time.time())
            
            # Traffic
            self.bytes_in += len(data)
            
            if isinstance(data, bytes):
                data = data.decode('utf-8', errors='ignore')
            
            self._log_tty("IN", data)
            
            self.buf += data
            
            while "\n" in self.buf or "\r" in self.buf:
                if "\n" in self.buf:
                    line, self.buf = self.buf.split("\n", 1)
                elif "\r" in self.buf:
                    line, self.buf = self.buf.split("\r", 1)
                else:
                    break
                    
                cmd = line.strip()
                if not cmd:
                    self.channel.write("\r\n" + self._get_prompt())
                    self._log_tty("OUT", "\r\n" + self._get_prompt())
                    continue
                    
                self.commands.append(cmd)
                
                if cmd in ("exit", "logout"):
                    asyncio.create_task(self._close_session())
                    return
                
                # IOC/C2 Detection
                import re
                ipv4_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                urls_regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
                
                iocs = []
                iocs.extend(re.findall(ipv4_regex, cmd))
                iocs.extend(re.findall(urls_regex, cmd))
                
                if iocs:
                    asyncio.create_task(self.honeypot.logger.log_event_async({
                         "event": "ioc_detected",
                         "session_id": self.session_id,
                         "src_ip": self.src_ip,
                         "iocs": list(set(iocs)), # Deduplicate
                         "cmd": cmd
                     }))

                # Log command immediately
                self.honeypot.stats.on_command("ssh", self.src_ip, self.username, cmd)

                asyncio.create_task(self.honeypot.logger.log_command(
                    self.session_id, "ssh", self.src_ip, self.username, cmd,
                    client_version=self.client_version
                ))
                
                stdout, stderr, rc = await self.shell.execute(cmd)
                
                # Confusion Metric
                if rc == 127: # Command not found
                     asyncio.create_task(self.honeypot.logger.log_event_async({
                         "event": "command_not_found",
                         "session_id": self.session_id,
                         "src_ip": self.src_ip,
                         "cmd": cmd
                     }))
                
                response = stdout + stderr
                
                self.channel.write(response)
                self.bytes_out += len(response)
                self._log_tty("OUT", response)
                
                curr_prompt = self._get_prompt()
                self.channel.write(curr_prompt)
                self.bytes_out += len(curr_prompt)
                self._log_tty("OUT", curr_prompt)
                
        except Exception as e:
            print(f"[DEBUG] process_input error: {e}", flush=True)
    
    async def _close_session(self):
        await asyncio.sleep(0.01)
        self.channel.write_eof()
        self.channel.exit(0)
        self.channel.close()

    def exec_requested(self, command):
        print(f"[DEBUG] exec_requested: {command}", flush=True)
        self.commands.append(command)
        asyncio.create_task(self.honeypot.logger.log_command(
            self.session_id, "ssh", self.src_ip, self.username, command,
            client_version=self.client_version
        ))
        asyncio.create_task(self._async_exec(command))
        return True

    async def _async_exec(self, command):
        # Use Factory
        self._ensure_tty_log()
        fs = self.honeypot.get_filesystem()
        shell = ShellEmulator(fs, self.username, quarantine_callback=self.honeypot.save_quarantine_file)
        stdout, stderr, rc = await shell.execute(command)
        
        self.channel.write(stdout)
        self.honeypot._log_tty(self, "OUT", stdout)
        
        if stderr:
            self.channel.write_stderr(stderr)
            self.honeypot._log_tty(self, "OUT", stderr)
            
        self.channel.write_eof()
        await asyncio.sleep(0.01)
        self.channel.exit(rc)
        self.channel.close()
                
    def session_ended(self):
        duration = time.time() - self.start_time
        
        # Calculate Biometrics
        keystroke_stats = {}
        if len(self.keystrokes) > 1:
            diffs = []
            for i in range(1, len(self.keystrokes)):
                diffs.append(self.keystrokes[i] - self.keystrokes[i-1])
            
            avg = sum(diffs) / len(diffs)
            
            # Variance
            variance = sum((x - avg) ** 2 for x in diffs) / len(diffs)
            std_dev = variance ** 0.5
            
            keystroke_stats = {
                "count": len(self.keystrokes),
                "avg_latency": round(avg, 4),
                "std_dev": round(std_dev, 4)
            }
            
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "session_end", "protocol": "ssh", "session_id": self.session_id,
            "src_ip": self.src_ip, "username": self.username, "commands": self.commands, "duration": duration,
            "client_version": self.client_version,
            "keystroke_metrics": keystroke_stats,
            "traffic": {"bytes_in": self.bytes_in, "bytes_out": self.bytes_out}
        }))
