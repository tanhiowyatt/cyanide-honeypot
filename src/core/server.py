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
from .stats import StatsManager
from proxy.tcp_proxy import TCPProxy
from core.vm_pool import VMPool
from .geoip import GeoIP
from prometheus_client import generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST

# ML Integration - Moved to HoneypotServer.__init__ to avoid circular imports


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

        # ML Initialization
        self.ml_enabled = config.get("ml", {}).get("enabled", False)
        self.ml_online_learning = config.get("ml", {}).get("online_learning", False)
        self.ml_filter = None
        if self.ml_enabled:
            print("[*] Initializing ML Anomaly Detector...")
            try:
                try:
                    from ai_models.cyanideML import HoneypotFilter
                    model_file = config.get("ml", {}).get("model_path", "ai_models/cyanideML/cyanideML.pkl")
                    if os.path.exists(model_file):
                        print(f"[*] Loading pre-trained ML model from {model_file}...")
                        self.ml_filter = HoneypotFilter.load(model_file)
                        self.ml_filter.online_learning = self.ml_online_learning
                    else:
                        print("[!] Pre-trained model not found, starting fresh (WARMUP mode).")
                        self.ml_filter = HoneypotFilter(online_learning=self.ml_online_learning)
                except (ImportError, ModuleNotFoundError) as e:
                    print(f"[!] ML Module could not be loaded: {e}")
                    self.ml_enabled = False
                    return
                
                self.anomalies_log_path = config.get("ml", {}).get("anomalies_log", "var/log/cyanide/cyanideML-anomalies-log.json")
                self.ml_log_path = config.get("ml", {}).get("ml_log", "var/log/cyanide/cyanideML-log.json")
            except Exception as e:
                print(f"[!] Failed to init ML model: {e}")
                self.ml_enabled = False

    def _analyze_command(self, cmd, username, src_ip, session_id, protocol):
        """Run command through ML filter and alert if anomaly."""
        try:
            # Construct log entry format expected by filter
            log_entry = {
                "command": cmd,
                "username": username,
                "src_ip": src_ip,
                "dst_port": self.config.get(protocol, {}).get("port", 0), # Best effort
                "protocol": protocol
            }
            
            is_anomaly, reason, distance = self.ml_filter.process_log(log_entry)
            
            # Log ML 'thought' for every action
            ml_log_entry = {
                "timestamp": time.time(),
                "src_ip": src_ip,
                "session_id": session_id,
                "verdict": "anomaly" if is_anomaly else "clean",
                "reason": reason,
                "distance": float(distance),
                "command": cmd
            }
            with open(self.ml_log_path, "a") as f:
                f.write(json.dumps(ml_log_entry) + "\n")

            if is_anomaly:
                print(f"[!] ML ANOMALY: {reason} from {src_ip}")
                
                # Log to dedicated anomaly file
                with open(self.anomalies_log_path, "a") as f:
                    f.write(json.dumps(ml_log_entry) + "\n")
                    
                # Log to generic logger as well
                asyncio.create_task(self.logger.log_event_async({
                    "event": "ml_anomaly",
                    "reason": reason,
                    "distance": distance,
                    "cmd": cmd,
                    "src_ip": src_ip
                }))
                
        except Exception as e:
            print(f"[!] ML Error: {e}")

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
        """Dual format logging: JSONL for reading + Timing/TS for scriptreplay."""
        if direction != "OUT" and not hasattr(session_obj, 'tty_log_path_jsonl'):
            return
            
        # 1. JSONL Log
        if hasattr(session_obj, 'tty_log_path_jsonl'):
            try:
                now = time.time()
                # Convert to string if bytes
                if isinstance(data, bytes):
                    readable_data = data.decode('utf-8', 'ignore')
                else:
                    readable_data = data
                
                entry = {"timestamp": now, "direction": direction, "data": readable_data}
                with open(session_obj.tty_log_path_jsonl, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as e:
                print(f"[!] Error saving JSONL TTY: {e}")

        # 2. Timing + TypeScript Log (scriptreplay)
        if hasattr(session_obj, 'tty_log_path') and hasattr(session_obj, 'tty_timing_path'):
            try:
                now = time.time()
                elapsed = now - session_obj.last_log_time
                session_obj.last_log_time = now
                
                with open(session_obj.tty_timing_path, "a") as f_time:
                    f_time.write(f"{elapsed:.6f} {len(data)}\n")
                    
                with open(session_obj.tty_log_path, "ab") as f_log:
                    if isinstance(data, str):
                        f_log.write(data.encode())
                    else:
                        f_log.write(data)
            except Exception as e:
                print(f"[!] Error saving scriptreplay TTY: {e}")

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
                    
                    # Append ML metrics if available
                    if self.ml_enabled and self.ml_filter:
                         try:
                             ml_metrics = generate_latest().decode()
                             content += "\n" + ml_metrics
                         except Exception as e:
                             print(f"Error generating ML metrics: {e}")
                             
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
            
        # Initialize VM Pool if needed
        self.vm_pool = VMPool(self.config)

        # Start SSH Server
        ssh_conf = self.config.get("ssh", {})
        ssh_enabled = ssh_conf.get("enabled", True)
        if ssh_enabled:
            ssh_port = ssh_conf["port"]
            backend_mode = ssh_conf.get("backend_mode", "emulated") # emulated, proxy, pool
            
            if backend_mode == "emulated":
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
                print(f"[*] SSH Server (Emulated) listening on port {ssh_port}", flush=True)
            elif backend_mode == "proxy" or backend_mode == "pool":
                 # Use TCP Proxy for pure SSH monitoring (simplest approach for "Pure Proxy" request)
                 # Or use the specific SSH Proxy implementation if we want to dissect packets?
                 # The user asked for "pure telnet and ssh proxy with monitoring"
                 # Our TCPProxy monitors data.
                 # If pool, use selector.
                 selector = self.vm_pool.get_target if backend_mode == "pool" else None
                 t_host = ssh_conf.get("target_host", "127.0.0.1")
                 t_port = int(ssh_conf.get("target_port", 22222))
                 
                 ssh_proxy = TCPProxy(
                    "0.0.0.0", ssh_port,
                    target_host=t_host, target_port=t_port,
                    protocol_name="ssh_proxy",
                    target_selector=selector
                 )
                 await ssh_proxy.start()
            
        # Start Telnet Server
        telnet_conf = self.config.get("telnet", {})
        telnet_enabled = telnet_conf.get("enabled", False)
        if telnet_enabled:
            telnet_port = telnet_conf["port"]
            backend_mode = telnet_conf.get("backend_mode", "emulated")

            if backend_mode == "emulated":
                telnet_server = await asyncio.start_server(
                    self.handle_telnet, "0.0.0.0", telnet_port, reuse_address=True
                )
                print(f"[*] Telnet Server (Emulated) listening on port {telnet_port}", flush=True)
            elif backend_mode == "pool" or backend_mode == "proxy":
                 selector = self.vm_pool.get_target if backend_mode == "pool" else None
                 t_host = telnet_conf.get("target_host", "127.0.0.1")
                 t_port = int(telnet_conf.get("target_port", 2323))
                 
                 telnet_proxy = TCPProxy(
                    "0.0.0.0", telnet_port,
                    target_host=t_host, target_port=t_port,
                    protocol_name="telnet_proxy",
                    target_selector=selector
                 )
                 await telnet_proxy.start()

        # Start SMTP Proxy (Forwarding)
        smtp_conf = self.config.get("smtp", {})
        if smtp_conf.get("enabled", False):
            try:
                smtp_proxy = TCPProxy(
                    "0.0.0.0",
                    int(smtp_conf.get("listen_port", 25)),
                    smtp_conf.get("target_host", "127.0.0.1"),
                    int(smtp_conf.get("target_port", 2525)),
                    protocol_name="smtp"
                )
                await smtp_proxy.start()
            except Exception as e:
                print(f"[!] Failed to start SMTP Proxy: {e}")



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
        self.tty_log_path = log_dir / f"{folder_name}.jsonl"
        open(self.tty_log_path, "w").close()
        
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
            
            # Setup TTY logging (scriptreplay + JSONL)
            folder_name = f"telnet_{src_ip}_{session_id}"
            log_dir = Path("var/log/cyanide/tty") / folder_name
            log_dir.mkdir(parents=True, exist_ok=True)
            
            class TelnetState: pass
            session_state = TelnetState()
            session_state.tty_log_path_jsonl = log_dir / f"{folder_name}.jsonl"
            session_state.tty_log_path = log_dir / f"{folder_name}.log"
            session_state.tty_timing_path = log_dir / f"{folder_name}.time"
            session_state.last_log_time = time.time()
            
            # Touch files
            open(session_state.tty_log_path_jsonl, 'a').close()
            open(session_state.tty_log_path, 'a').close()
            open(session_state.tty_timing_path, 'a').close()
            
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
                    self._log_tty(session_state, "IN", cmd + "\n")
                    
                    if cmd in ("exit", "logout"):
                        break
                        
                    # Log command immediately
                    self.stats.on_command("telnet", src_ip, username, cmd)
                    self.stats.on_command("telnet", src_ip, username, cmd)
                    await self.logger.log_command(session_id, "telnet", src_ip, username, cmd, client_version="Telnet")
                    
                    # ML Analysis
                    if self.ml_enabled and self.ml_filter:
                         self._analyze_command(cmd, username, src_ip, session_id, "telnet")
                    
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
             # Helper for extraction
             def get_val(key, internal_attr=None, decode=False):
                 val = conn.get_extra_info(key)
                 if val is not None: return val
                 if internal_attr:
                     val = getattr(conn, internal_attr, None)
                     if val is not None:
                         if decode and isinstance(val, bytes):
                             return val.decode("utf-8", "ignore")
                         return val
                 return "unknown"

             # KEX
             kex = get_val("kex")
             
             # Key Algo
             key_algo = get_val("server_host_key")
             if key_algo == "unknown":
                 hk = getattr(conn, "_server_host_key", None)
                 if hk and hasattr(hk, "algorithm"):
                     key_algo = hk.algorithm.decode() if isinstance(hk.algorithm, bytes) else str(hk.algorithm)

             # Cipher
             cipher = get_val("cipher", "_enc_alg_cs", decode=True)
             if cipher == "unknown":
                 # Chacha20 poly1305 often stored in mac field in local implementations
                 mac_raw = getattr(conn, "_mac_alg_cs", None)
                 if mac_raw and b"chacha" in mac_raw:
                     cipher = mac_raw.decode()
             
             # MAC
             mac = get_val("mac", "_mac_alg_cs", decode=True)
             
             # Compression
             compression = get_val("compression", "_compress_alg_cs", decode=True)
             if compression == "unknown":
                 if getattr(conn, "_compress_after_auth", False):
                     compression = "zlib@openssh.com"
                 else:
                     compression = "none"

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
        # Setup TTY logging (scriptreplay + JSONL)
        folder_name = f"ssh_{self.src_ip}_{self.session_id}"
        log_dir = Path("var/log/cyanide/tty") / folder_name
        log_dir.mkdir(parents=True, exist_ok=True)
        
        self.tty_log_path_jsonl = log_dir / f"{folder_name}.jsonl"
        self.tty_log_path = log_dir / f"{folder_name}.log"
        self.tty_timing_path = log_dir / f"{folder_name}.time"
        self.last_log_time = time.time()
        
        # Touch files
        open(self.tty_log_path_jsonl, 'a').close()
        open(self.tty_log_path, 'a').close()
        open(self.tty_timing_path, 'a').close()
            
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
                
                # ML Analysis
                if self.honeypot.ml_enabled and self.honeypot.ml_filter:
                    self.honeypot._analyze_command(cmd, self.username, self.src_ip, self.session_id, "ssh")
                
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
                self._log_tty("IN", cmd + "\n")
                
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
        
        # ML Analysis
        if self.honeypot.ml_enabled and self.honeypot.ml_filter:
            self.honeypot._analyze_command(command, self.username, self.src_ip, self.session_id, "ssh")
            
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
