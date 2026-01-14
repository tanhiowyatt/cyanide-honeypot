"""
SSH Proxy Module.

Implements a Man-in-the-Middle SSH proxy using asyncssh.
Intercepts traffic between an attacker and a backend honeypot (or simulated backend),
logging all session activity including commands and data transfer.
"""
import asyncssh
import asyncio
import logging
import uuid
import datetime
import json
import sys
import os

sys.path.append(os.getcwd())

from typing import Optional, List
from src.core.fake_filesystem import FakeFilesystem

# Configure logging to stdout as json
logging.basicConfig(level=logging.INFO, format='%(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("ssh_proxy")

class HoneypotSSHClientConnection(asyncssh.SSHClientConnection):
    """Connection from Proxy to Backend.
    
    Manages the SSH connection between the proxy and the backend honeypot/server.
    """
    def __init__(self, server_channel_factory, session_id, src_ip):
        """Initialize backend connection.
        
        Args:
            server_channel_factory: Factory function for server-side channel.
            session_id: Unique session ID.
            src_ip: Attacker's source IP.
        """
        # server_channel_factory: function to create the Server-side proxy channel
        self.server_channel_factory = server_channel_factory
        self.session_id = session_id
        self.src_ip = src_ip
        super().__init__()

    def connection_made(self, conn):
        """Called when connection to backend is established."""
        pass

    def session_started(self):
        """Called when session is started on backend."""
        pass

class HoneypotSSHServer(asyncssh.SSHServer):
    """SSH Proxy Server implementation.
    
    Accepts connections from attackers and bridges them to the backend 
    via ProxyServerSession.
    """
    def __init__(self, dst_host, dst_port, fs):
        """Initialize SSH Proxy Server.
        
        Args:
            dst_host: Backend host to forward to.
            dst_port: Backend port to forward to.
            fs: FakeFilesystem instance.
        """
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.fs = fs

    def connection_made(self, conn):
        """Handle new incoming connection from attacker."""
        self._conn = conn
        self.session_id = str(uuid.uuid4())
        peername = conn.get_extra_info('peername')
        self.src_ip = peername[0] if peername else "unknown"
        logger.info(json.dumps({"event": "connection_new", "src_ip": self.src_ip, "session_id": self.session_id}))

    def password_auth_supported(self): 
        """Allow password auth."""
        return True
    
    def validate_password(self, username, password): 
        """Validate password (always accept)."""
        return True
    
    def public_key_auth_supported(self): 
        """Allow public key auth."""
        return True
    
    def validate_public_key(self, username, key): 
        """Validate public key (always accept)."""
        return True

    async def session_requested(self):
        """Bridge a new session to the backend.
        
        Returns:
            ProxyServerSession: New session handler for this connection.
        """
        try:
           pass
        except Exception as e:
           logger.error(f"Error bridging session: {e}")
           return False
        
        # We return the Session object directly
        return ProxyServerSession(self.dst_host, self.dst_port, self.session_id, self.src_ip, self.fs)

class ProxyServerSession(asyncssh.SSHServerSession):
    """Handles the session from the Attacker -> Proxy.
    
    Acts as the server for the attacker's client. Responsible for 
    initiating connection to the backend and forwarding requests.
    """
    def __init__(self, dst_host, dst_port, session_id, src_ip, fs):
        """Initialize proxy server session.
        
        Args:
            dst_host: Backend host.
            dst_port: Backend port.
            session_id: Unique session ID.
            src_ip: Attacker's source IP.
            fs: FakeFilesystem instance.
        """
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.session_id = session_id
        self.src_ip = src_ip
        self.fs = fs
        self.backend_conn = None
        self.backend_channel = None
        self.buffer = []
        self.send_task = None
        self._chan = None
        self.request_event = asyncio.Event()

    def connection_made(self, chan):
        """Called when attacker channel is open."""
        self._chan = chan
        # Start connection to backend
        asyncio.create_task(self._connect_backend())

    async def _connect_backend(self):
        """Establish connection to backend server and bridge channels."""
        try:
            self.backend_conn = await asyncssh.connect(
                self.dst_host, self.dst_port,
                username="root", password="password", known_hosts=None
            )
            
            # Wait for shell or exec request
            await self.request_event.wait()
            
            req_type, args = self.pending_request
            command = args if req_type == 'exec' else None
            
            # Create session on backend
            # We pass a callback that creates the Client-Side Proxy Channel
            self.backend_channel, _ = await self.backend_conn.create_session(
                lambda: ProxyClientChannel(self.session_id, self.src_ip, self._chan),
                command=command,
                term_type=self._chan.get_terminal_type(),
                term_size=self._chan.get_terminal_size()
            )
            
            # Start flush loop for our side (Attacker -> Backend)
            self.send_task = asyncio.create_task(self._send_loop())
            
        except Exception as e:
            logger.error(f"Backend connect failed: {e}")
            self._chan.close()

    def data_received(self, data, datatype):
        """Handle data from attacker."""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "direction": "out", # Attacker -> Proxy -> Backend
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "data_hex": data.hex() if isinstance(data, bytes) else data.encode().hex(),
            "data_len": len(data)
        }
        logger.info(json.dumps(log_entry))
        self.buffer.append(data)

    def shell_requested(self): 
        """Handle shell request."""
        self.pending_request = ('shell', None)
        self.request_event.set()
        return True
        
    def exec_requested(self, command): 
        """Handle exec request."""
        self.pending_request = ('exec', command)
        self.request_event.set()
        return True
        
    def pty_requested(self, term_type, term_size, term_modes): 
        """Handle PTY request."""
        # Handled by get_terminal_type in _connect_backend
        return True 

    def terminal_window_resized(self, width, height, pixwidth, pixheight): 
        """Handle window resize."""
        if self.backend_channel: self.backend_channel.change_terminal_size(width, height, pixwidth, pixheight)
    def break_received(self, msec): 
        """Handle break signal."""
        if self.backend_channel: self.backend_channel.send_break(msec)
    def signal_received(self, signal): 
        """Handle POSIX signal."""
        if self.backend_channel: self.backend_channel.send_signal(signal)
    def eof_received(self):
        """Handle EOF from attacker."""
        if self.backend_channel: self.backend_channel.write_eof()
    def connection_lost(self, exc):
        """Handle connection loss."""
        if self.send_task: self.send_task.cancel()
        if self.backend_conn: self.backend_conn.close()

    async def _send_loop(self):
        """Buffered send loop to backend."""
        try:
            while True:
                if self.buffer and self.backend_channel:
                    await asyncio.sleep(0.5)
                    chunk = b"".join(self.buffer) if isinstance(self.buffer[0], bytes) else "".join(self.buffer)
                    self.buffer = []
                    self.backend_channel.write(chunk)
                else:
                    await asyncio.sleep(0.1)
        except Exception: pass

class ProxyClientChannel(asyncssh.SSHClientSession):
    """Handles the session from Proxy -> Backend.
    
    Acts as a client to the backend server. Forwards responses back 
    to the attacker's channel (peer_channel).
    """
    def __init__(self, session_id, src_ip, peer_channel):
        """Initialize proxy client session.
        
        Args:
            session_id: Unique session ID.
            src_ip: Attacker's source IP.
            peer_channel: The ServerSession channel connected to attacker.
        """
        self.session_id = session_id
        self.src_ip = src_ip
        self.peer_channel = peer_channel 
        self.buffer = []
        self.send_task = None

    def connection_made(self, chan):
        """Called when backend channel is open."""
        self.send_task = asyncio.create_task(self._send_loop())

    def data_received(self, data, datatype):
        """Handle data from backend."""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "direction": "in", # Backend -> Proxy -> Attacker
            "session_id": self.session_id,
            "data_hex": data.hex() if isinstance(data, bytes) else data.encode().hex(),
            "data_len": len(data)
        }
        logger.info(json.dumps(log_entry))
        self.buffer.append(data)

    def eof_received(self):
        """Handle EOF from backend."""
        if self.peer_channel: self.peer_channel.write_eof()

    def connection_lost(self, exc):
        """Handle backend connection loss."""
        if self.send_task: self.send_task.cancel()
        if self.peer_channel: self.peer_channel.close()

    async def _send_loop(self):
        """Buffered send loop to attacker."""
        try:
            while True:
                if self.buffer and self.peer_channel:
                    await asyncio.sleep(0.5)
                    # If data is str, join as str. If bytes, as bytes.
                    if self.buffer:
                         chunk = self.buffer[0]
                         for b in self.buffer[1:]: chunk += b
                         self.buffer = []
                         self.peer_channel.write(chunk)
                else:
                    await asyncio.sleep(0.1)
        except Exception: pass

async def main():
    """Main entry point for proxy server."""
    dst_host = '127.0.0.1'
    dst_port = 2222
    listen_port = 2220
    
    # Generate host key if not exists
    if not os.path.exists("ssh_host_key"):
         # Create a dummy key for testing efficiently without shell command
         from asyncssh import generate_private_key
         key = generate_private_key("ssh-rsa")
         with open("ssh_host_key", "w") as f:
             f.write(key.export_private_key().decode())

    print(f"Starting SSH Proxy on 0.0.0.0:{listen_port} -> {dst_host}:{dst_port}...")
    
    fs = FakeFilesystem()
    
    stop_event = asyncio.Event()
    
    def factory():
        return HoneypotSSHServer(dst_host, dst_port, fs)

    await asyncssh.create_server(factory, '0.0.0.0', listen_port, server_host_keys=['ssh_host_key'])
    
    await stop_event.wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
