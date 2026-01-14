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
from pathlib import Path
from typing import Dict, Any, Optional

from src.core.fake_filesystem import FakeFilesystem
from src.core.shell_emulator import ShellEmulator
# from src.utils.logging_system import HoneypotLogger # Deprecated
from src.cyanide.logger import CyanideLogger
from src.cyanide.fs.pickle import load_fs

class HoneypotServer:
    """Main honeypot server orchestrating SSH, Telnet, and MySQL services."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize honeypot server with configuration."""
        self.config = config
        
        # Setup Cyanide Logger
        log_path = os.getenv('TEST_LOG_DIR', config.get("log_path", "var/log/cyanide"))
        self.logger = CyanideLogger(log_path)
        
        self.users = self._load_users(config.get("users", []))
        self.active_sessions = 0
        self.max_sessions = config.get("max_sessions", 100)
        self.session_timeout = config.get("session_timeout", 300)
        
        # Preload FS if pickled, or just cache the path for per-session loading?
        # Cowrie typically works on a fresh copy per session or a shared one.
        # We will load fresh per session for now to avoid state pollution, 
        # or implement Copy-On-Write later.
        self.fs_pickle_path = config.get("fs_pickle")

    def _load_users(self, config_users):
        """Load user credentials from configuration."""
        return config_users

    def is_valid_user(self, username, password):
        """Validate user credentials against configured users."""
        for user in self.users:
            if user["user"] == username and user["pass"] == password:
                return True
        return False
    
    def get_filesystem(self):
        """Factory to get the filesystem instance."""
        if self.fs_pickle_path and os.path.exists(self.fs_pickle_path):
            try:
                root = load_fs(self.fs_pickle_path)
                fs = FakeFilesystem()
                fs.root = root # Hot-swap root
                return fs
            except Exception as e:
                print(f"Error loading pickle FS: {e}")
        return FakeFilesystem()
        
    async def start(self):
        """Start all honeypot services and enter main event loop."""
        # Generate SSH Host Key
        ssh_key = asyncssh.generate_private_key("ssh-rsa")
        
        # Start SSH Server
        ssh_enabled = self.config.get("ssh", {}).get("enabled", True)
        if ssh_enabled:
            ssh_port = self.config["ssh"]["port"]
            ssh_server = await asyncssh.listen(
                "0.0.0.0", ssh_port,
                server_host_keys=[ssh_key],
                server_factory=lambda: SSHServerFactory(self),
                reuse_address=True
            )
            print(f"[*] SSH Server listening on port {ssh_port}", flush=True)

        # Start Telnet Server
        telnet_enabled = self.config.get("telnet", {}).get("enabled", False)
        if telnet_enabled:
            telnet_port = self.config["telnet"]["port"]
            telnet_server = await asyncio.start_server(
                self.handle_telnet, "0.0.0.0", telnet_port, reuse_address=True
            )
            print(f"[*] Telnet Server listening on port {telnet_port}", flush=True)

        # Start Vulnerable Services (MySQL)
        # Simplified for brevity/Cyanide focus
        
        # Keep running
        await asyncio.Future()

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
            
            # Shell loop
            writer.write(b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n\r\n")
            
            # Use Factory
            fs = self.get_filesystem()
            shell = ShellEmulator(fs, username if success else "user")
            
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
                    
                    stdout, stderr, rc = shell.execute(cmd)
                    output = stdout + stderr
                    writer.write(output.replace("\n", "\r\n").encode())
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
        return True

    def session_requested(self):
        return SSHSession(self.honeypot, self.src_ip, self.src_port)

class SSHSession(asyncssh.SSHServerSession):
    """SSH session handler."""
    
    def __init__(self, honeypot: HoneypotServer, src_ip, src_port):
        self.honeypot = honeypot
        self.src_ip = src_ip
        self.src_port = src_port
        self.session_id = str(uuid.uuid4())[:8]
        self.commands = []
        self.start_time = time.time()
        self.client_version = "unknown"
        self.username = "root"
        self.buf = ""
        self.fs = None
        self.shell = None
        self.prompt = None 
        
    def connection_made(self, channel):
        self.channel = channel
        self.username = channel.get_connection().get_extra_info("username") or "root"
        self.client_version = channel.get_connection().get_extra_info("client_version") or "unknown"

    def shell_requested(self):
        # Use Factory
        self.fs = self.honeypot.get_filesystem()
        self.shell = ShellEmulator(self.fs, self.username)
        self.prompt = f"{self.username}@server:~$ "
        return True
    
    def session_started(self):
        if self.shell:
            self.channel.write(f"Welcome into {self.username} shell\r\n")
            self.channel.write(self.prompt)
    
    def data_received(self, data, datatype=None):
        try:
            if isinstance(data, bytes):
                data = data.decode('utf-8', errors='ignore')
            
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
                    self.channel.write("\r\n" + self.prompt)
                    continue
                    
                self.commands.append(cmd)
                
                if cmd in ("exit", "logout"):
                    asyncio.create_task(self._close_session())
                    return
                
                asyncio.create_task(self.honeypot.logger.log_command(
                    self.session_id, "ssh", self.src_ip, self.username, cmd,
                    client_version=self.client_version
                ))
                
                stdout, stderr, rc = self.shell.execute(cmd)
                self.channel.write(stdout + stderr)
                self.channel.write(self.prompt)
                
        except Exception as e:
            print(f"[DEBUG] data_received error: {e}", flush=True)
    
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
        shell = ShellEmulator(fs, self.username)
        stdout, stderr, rc = shell.execute(command)
        self.channel.write(stdout)
        self.channel.write_stderr(stderr)
        self.channel.write_eof()
        await asyncio.sleep(0.01)
        self.channel.exit(rc)
        self.channel.close()
                
    def session_ended(self):
        duration = time.time() - self.start_time
        asyncio.create_task(self.honeypot.logger.log_event_async({
            "event": "session_end", "protocol": "ssh", "session_id": self.session_id,
            "src_ip": self.src_ip, "username": self.username, "commands": self.commands, "duration": duration,
            "client_version": self.client_version
        }))
