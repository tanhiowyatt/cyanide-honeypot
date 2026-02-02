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
from pathlib import Path
from typing import Dict, Any, Optional

from src.core.fake_filesystem import FakeFilesystem
from src.core.shell_emulator import ShellEmulator
# from src.utils.logging_system import HoneypotLogger # Deprecated
from src.cyanide.logger import CyanideLogger
from src.cyanide.fs.pickle import load_fs
from src.core.sftp import CyanideSFTPServer
from src.core.vt_scanner import VTScanner
from src.core.geoip import GeoIP

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
        self.session_timeout = config.get("session_timeout", 300)
        
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
    
    def _fs_audit_hook(self, action, path):
        """Callback for filesystem auditing."""
        try:
            loop = asyncio.get_running_loop()
            
            # Honeytoken Tripwires
            HONEYTOKENS = [
                "/home/admin/secret.conf", 
                "/home/admin/flag.txt", 
                "/etc/shadow", 
                "/var/spool/cron/crontabs/root"
            ]
            
            event_type = "fs_audit"
            if str(path) in HONEYTOKENS:
                event_type = "CRITICAL_ALERT"
            
            loop.create_task(self.logger.log_event_async({
                "event": event_type, 
                "action": action, 
                "path": path,
                # "session_id": "unknown" 
            }))
        except RuntimeError:
            pass

    def get_filesystem(self):
        """Factory to get the filesystem instance."""
        if self.fs_pickle_path and os.path.exists(self.fs_pickle_path):
            try:
                root = load_fs(self.fs_pickle_path)
                fs = FakeFilesystem(audit_callback=self._fs_audit_hook, profile=self.profile)
                fs.root = root # Hot-swap root
                return fs
            except Exception as e:
                print(f"Error loading pickle FS: {e}")
        return FakeFilesystem(audit_callback=self._fs_audit_hook, profile=self.profile)

    def save_quarantine_file(self, filename: str, content: bytes):
        """Save a file to the quarantine directory."""
        try:
            timestamp = int(time.time())
            safe_name = f"{timestamp}_{Path(filename).name}"
            target_path = self.quarantine_path / safe_name
            
            with open(target_path, "wb") as f:
                f.write(content)
            
            # Trigger Async Analysis
            if self.vt_scanner.enabled:
                asyncio.create_task(self._scan_and_log(filename, content))
                
            return str(target_path)
        except Exception as e:
            print(f"[!] Error saving quarantine file: {e}")
            return None

    async def _scan_and_log(self, filename: str, content: bytes):
        """Background task to scan file and log results."""
        try:
            result = await self.vt_scanner.scan(content, filename)
            if result:
                await self.logger.log_event_async({
                    "event": "malware_scan",
                    "filename": filename,
                    "sha256": result.get("sha256"),
                    "malicious": result.get("malicious"),
                    "label": result.get("label"),
                    "vt_link": result.get("link")
                })
        except Exception as e:
            print(f"[!] Scan Error: {e}")

    async def handle_mysql(self, reader, writer):
        """Handle basic MySQL handshake to capture auth."""
        try:
            ip, port = writer.get_extra_info("peername")
            session_id = str(uuid.uuid4())[:8]
            
            await self.logger.log_event_async({
                "event": "connect", "protocol": "mysql", 
                "src_ip": ip, "src_port": port, "session_id": session_id
            })
            asyncio.create_task(self.log_geoip(session_id, ip, "mysql"))
            
            # Send MySQL Handshake Packet (Mock)
            # Proto: 10, Version: 5.7.33, Thread: 1, Salt...
            handshake = b'\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x33\x00\x01\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00'
            writer.write(handshake)
            await writer.drain()
            
            # Read Login Packet
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            if len(data) > 0:
                 # Extract username (trivial parsing)
                 # Usually starts after capability flags
                 try:
                     # Very heuristic parsing for demo
                     clean_data = data.replace(b'\x00', b' ').decode('ascii', 'ignore')
                     parts = clean_data.split()
                     user_hint = parts[3] if len(parts) > 3 else "unknown"
                     
                     await self.logger.log_event_async({
                         "event": "auth_attempt", "protocol": "mysql", 
                         "session_id": session_id,
                         "raw_packet_len": len(data),
                         "user_hint": user_hint
                     })
                 except:
                     pass

            # Error: Access Denied
            error_packet = b'\x17\x00\x00\x01\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64'
            writer.write(error_packet)
            await writer.drain()
            
        except Exception:
            pass
        finally:
            writer.close()

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



        # Start Vulnerable Services (MySQL)
        mysql_conf = self.config.get("services", {}).get("mysql", {})
        if mysql_conf.get("enabled", False):
            mysql_port = mysql_conf.get("port", 3306)
            try:
                 await asyncio.start_server(self.handle_mysql, "0.0.0.0", mysql_port, reuse_address=True)
                 print(f"[*] MySQL Emulation listening on port {mysql_port}")
            except Exception as e:
                 print(f"[!] MySQL Bind Error: {e}")
        
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
        if self.active_sessions >= self.max_sessions:
            writer.close()
            return
            
        self.active_sessions += 1
        session_id = str(uuid.uuid4())[:8]
        src_ip, src_port = writer.get_extra_info("peername")
        start_time = time.time()
        
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

            
            # Simple auth
            writer.write(b"login: ")
            await writer.drain()
            username = (await reader.readuntil(b"\n")).decode().strip()
            
            writer.write(b"Password: ")
            await writer.drain()
            password = (await reader.readuntil(b"\n")).decode().strip()
            
            success = self.is_valid_user(username, password)
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
            
            # Use Factory
            fs = self.get_filesystem()
            shell = ShellEmulator(fs, username, quarantine_callback=self.save_quarantine_file)
            
            prompt = f"{username}@server:~$ "
            writer.write(prompt.encode())
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
                    writer.write(output.replace("\n", "\r\n").encode())
                    
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
            pass
        finally:
            duration = time.time() - start_time
            await self.logger.log_event_async({
                "event": "session_end", "protocol": "telnet", "session_id": session_id,
                "src_ip": src_ip, "username": username, "commands": commands, "duration": duration
            })
            self.active_sessions -= 1
            writer.close()

class SSHServerFactory(asyncssh.SSHServer):
    """SSH server factory."""
    
    def __init__(self, honeypot: HoneypotServer):
        self.honeypot = honeypot
        self.src_ip = None
        self.src_port = None
        # Create a filesystem instance for this connection
        self.fs = self.honeypot.get_filesystem()
    
    def connection_made(self, conn):
        self.src_ip = conn.get_extra_info("peername")[0]
        self.src_port = conn.get_extra_info("peername")[1]
        
    def password_auth_supported(self):
        return True
        
    def validate_password(self, username, password):
        success = self.honeypot.is_valid_user(username, password)
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "auth", "protocol": "ssh", 
            "src_ip": self.src_ip, "username": username, "password": password, "success": success
        }))
        return success

    def sftp_factory(self, channel):
        """Create SFTP server instance sharing the connection's filesystem."""
        return CyanideSFTPServer(channel, self.fs, self.honeypot.save_quarantine_file)

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
        self.client_version = "unknown"
        self.username = "root"
        self.buf = ""
        self.shell = None
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
                 "event": "client_fingerprint", "session_id": self.session_id,
                 "protocol": "ssh", "fingerprint": fingerprint,
                 "client_version": self.client_version
             }))
        except Exception as e:
             pass

    def connection_lost(self, exc):
        """Log connection loss reason."""
        reason = "clean"
        if exc:
            reason = f"error: {exc}"
            
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "session_disconnect", 
            "session_id": self.session_id,
            "reason": reason
        }))

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        """Log terminal resize events (SIGWINCH)."""
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "window_resize", 
            "session_id": self.session_id,
            "width": width, "height": height
        }))
        if self.shell:
            # Propagate
            pass

    def shell_requested(self):
        # Use shared FS
        self.shell = ShellEmulator(self.fs, self.username, quarantine_callback=self.honeypot.save_quarantine_file)
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
        # Setup TTY logging
        # User requested: var/log/cyanide/tty (implied inside logs dir)
        log_dir = Path("var/log/cyanide/tty")
        log_dir.mkdir(parents=True, exist_ok=True)
        self.tty_log_path = log_dir / f"{self.session_id}.log"
        # Create empty or start 
        with open(self.tty_log_path, "w") as f:
            f.write(f"Session {self.session_id} started at {time.time()}\n")
            
    def _log_tty(self, direction: str, data: str):
        # Simple line-oriented log
        if hasattr(self, 'tty_log_path'):
            try:
                enc_data = repr(data)
                with open(self.tty_log_path, "a") as f:
                    f.write(f"{time.time()} [{direction}] {enc_data}\n")
            except:
                pass

    def env_received(self, name, value):
        """Log client environment variables."""
        # Convert bytes to str if needed
        if isinstance(name, bytes): name = name.decode('utf-8', 'ignore')
        if isinstance(value, bytes): value = value.decode('utf-8', 'ignore')
        
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "client_env", 
            "session_id": self.session_id,
            "name": name,
            "value": value
        }))
        return True

    def data_received(self, data, datatype=None):
        asyncio.create_task(self._process_input(data))

    async def _process_input(self, data):
        try:
            # Jitter (Network Latency Simulation)
            # Default 50ms - 300ms
            import random
            delay = random.uniform(0.05, 0.3)
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
                         "iocs": list(set(iocs)), # Deduplicate
                         "cmd": cmd
                     }))

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
        fs = self.honeypot.get_filesystem()
        shell = ShellEmulator(fs, self.username, quarantine_callback=self.honeypot.save_quarantine_file)
        stdout, stderr, rc = await shell.execute(command)
        self.channel.write(stdout)
        self.channel.write_stderr(stderr)
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
