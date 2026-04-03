"""
SSH Proxy Module.

Implements a Man-in-the-Middle SSH proxy using asyncssh.
Intercepts traffic between an attacker and a backend honeypot (or simulated backend),
logging all session activity including commands and data transfer.
"""

import asyncio
import datetime
import json
import logging
import os
import sys
import uuid

import asyncssh

sys.path.append(os.getcwd())

from cyanide.vfs.engine import FakeFilesystem

logging.basicConfig(
    level=logging.INFO, format="%(message)s", handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ssh_proxy")


class CyanideSSHClientConnection(asyncssh.SSHClientConnection):
    """Connection from Proxy to Backend.

    Manages the SSH connection between the proxy and the backend honeypot/server.
    """

    def __init__(self, server_channel_factory, session_id, src_ip, *args, **kwargs):
        """Initialize backend connection.

        Args:
            server_channel_factory: Factory function for server-side channel.
            session_id: Unique session ID.
            src_ip: Attacker's source IP.
        """
        self.server_channel_factory = server_channel_factory
        self.session_id = session_id
        self.src_ip = src_ip
        super().__init__(*args, **kwargs)

    def connection_made(self, conn):
        """Called when connection to backend is established."""
        pass

    def session_started(self):
        """Called when session is started on backend."""
        pass


class CyanideSSHServer(asyncssh.SSHServer):
    """SSH Proxy Server implementation.

    Accepts connections from attackers and bridges them to the backend
    via ProxyServerSession.
    """

    def __init__(self, pool, target_host, target_port, fs):
        """Initialize SSH Proxy Server.

        Args:
            pool: VMPool instance (optional).
            target_host: Backend host to forward to (used if pool is None).
            target_port: Backend port to forward to.
            fs: FakeFilesystem instance.
        """
        self.pool = pool
        self.target_host = target_host
        self.target_port = target_port
        self.fs = fs

    def connection_made(self, conn):
        """Handle new incoming connection from attacker."""
        self._conn = conn
        self.session_id = str(uuid.uuid4())
        peername = conn.get_extra_info("peername")
        self.src_ip = peername[0] if peername else "unknown"
        logger.info(
            json.dumps(
                {"event": "connection_new", "src_ip": self.src_ip, "session_id": self.session_id}
            )
        )

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
        """Bridge a new session to the backend."""
        session = ProxyServerSession(
            self.pool, self.target_host, self.target_port, self.session_id, self.src_ip, self.fs
        )

        if hasattr(self, "logger") and getattr(self, "logger"):
            getattr(self, "logger").log_event(
                self.session_id,
                "session_created",
                {"backend": self.pool.__class__.__name__, "src_ip": self.src_ip},
            )
        return session


class ProxyServerSession(asyncssh.SSHServerSession):
    """Handles the session from the Attacker -> Proxy.

    Acts as the server for the attacker's client. Responsible for
    initiating connection to the backend and forwarding requests.
    """

    def __init__(self, pool, target_host, target_port, session_id, src_ip, fs):
        """Initialize proxy server session.

        Args:
            pool: VMPool instance.
            target_host: Backend host.
            target_port: Backend port.
            session_id: Unique session ID.
            src_ip: Attacker's source IP.
            fs: FakeFilesystem instance.
        """
        self.pool = pool
        self.target_host = target_host
        self.target_port = target_port
        self.session_id = session_id
        self.src_ip = src_ip
        self.fs = fs
        self.backend_conn = None
        self.backend_channel = None
        self.buffer = []
        self.lease = None
        self.send_task = None
        self._chan = None
        self.request_event = asyncio.Event()
        self._background_tasks = set()

    def connection_made(self, chan):
        """Called when attacker channel is open."""
        self._chan = chan
        task = asyncio.create_task(self._connect_backend())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _connect_backend(self):
        """Establish connection to backend server and bridge channels."""
        target = await self._get_target()
        if not target:
            return

        tgt_host, tgt_port = target

        try:
            self.backend_conn = await asyncssh.connect(
                tgt_host, tgt_port, username="root", password="password", known_hosts=None
            )

            if not self._chan:
                logger.error("Channel not available during backend connect")
                return

            await self.request_event.wait()
            req_type, args = self.pending_request
            command = args if req_type == "exec" else None

            await self._setup_backend_session(tgt_host, tgt_port, command)

            self.send_task = asyncio.create_task(self._send_loop())

        except Exception as e:
            logger.error(f"Backend connect failed: {e}")
            if self._chan:
                self._chan.close()

    async def _get_target(self):
        """Get target host and port from pool or config."""
        if not self.pool:
            return self.target_host, self.target_port

        self.lease = await self.pool.reserve_target(self.session_id, "ssh")
        if not self.lease:
            logger.error("No target available from pool")
            if self._chan:
                self._chan.close()
            return None

        if hasattr(self.lease, "host"):
            return self.lease.host, self.lease.port

        return self.lease[0], self.lease[1]

    async def _setup_backend_session(self, host, port, command):
        """Initialize the backend SSH session."""
        if not self.backend_conn or not self._chan:
            return

        self.backend_channel, _ = await self.backend_conn.create_session(
            lambda: ProxyClientChannel(self.session_id, self.src_ip, self._chan),
            command=command,
            term_type=self._chan.get_terminal_type(),
            term_size=self._chan.get_terminal_size(),
        )

    def data_received(self, data, datatype):
        """Handle data from attacker."""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "direction": "out",
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "data_hex": data.hex() if isinstance(data, bytes) else data.encode().hex(),
            "data_len": len(data),
        }
        logger.info(json.dumps(log_entry))
        self.buffer.append(data)

    def shell_requested(self):
        """Handle shell request."""
        self.pending_request = ("shell", None)
        self.request_event.set()
        return True

    def exec_requested(self, command):
        """Handle exec request."""
        self.pending_request = ("exec", command)
        self.request_event.set()
        return True

    def pty_requested(self, term_type, term_size, term_modes):
        """Handle PTY request."""
        return True

    def terminal_window_resized(self, width, height, pixwidth, pixheight):
        """Handle window resize."""
        if self.backend_channel:
            self.backend_channel.change_terminal_size(width, height, pixwidth, pixheight)

    def break_received(self, msec):
        """Handle break signal."""
        if self.backend_channel:
            self.backend_channel.send_break(msec)

    def signal_received(self, signal):
        """Handle POSIX signal."""
        if self.backend_channel:
            self.backend_channel.send_signal(signal)

    def eof_received(self):
        """Handle EOF from attacker."""
        if self.backend_channel:
            self.backend_channel.write_eof()

    def connection_lost(self, exc):
        """Handle connection loss."""
        if self.send_task:
            self.send_task.cancel()
        if self.backend_conn:
            self.backend_conn.close()

        if self.pool and self.lease:
            task = asyncio.create_task(self.pool.release_target(self.lease))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

    async def _send_loop(self):
        """Buffered send loop to backend."""
        try:
            while True:
                if self.buffer and self.backend_channel:
                    await asyncio.sleep(0.5)
                    chunk = (
                        b"".join(self.buffer)
                        if isinstance(self.buffer[0], bytes)
                        else "".join(self.buffer)
                    )
                    self.buffer = []
                    self.backend_channel.write(chunk)
                else:
                    await asyncio.sleep(0.1)
        except Exception:
            pass


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
            "direction": "in",
            "session_id": self.session_id,
            "data_hex": data.hex() if isinstance(data, bytes) else data.encode().hex(),
            "data_len": len(data),
        }
        logger.info(json.dumps(log_entry))
        self.buffer.append(data)

    def eof_received(self):
        """Handle EOF from backend."""
        if self.peer_channel:
            self.peer_channel.write_eof()

    def connection_lost(self, exc):
        """Handle backend connection loss."""
        if self.send_task:
            self.send_task.cancel()
        if self.peer_channel:
            self.peer_channel.close()

    async def _send_loop(self):
        """Buffered send loop to attacker."""
        try:
            while True:
                if self.buffer and self.peer_channel:
                    await asyncio.sleep(0.5)
                    if self.buffer:
                        chunk = self.buffer[0]
                        for b in self.buffer[1:]:
                            chunk += b
                        self.buffer = []
                        self.peer_channel.write(chunk)
                else:
                    await asyncio.sleep(0.1)
        except Exception:
            pass


async def main():
    """Main entry point for proxy server."""
    dst_host = "127.0.0.1"
    dst_port = 2222
    listen_port = 2220

    from asyncssh import generate_private_key

    key = generate_private_key("ssh-rsa")

    logger.info(f"Starting SSH Proxy on 0.0.0.0:{listen_port} -> {dst_host}:{dst_port}...")

    fs = FakeFilesystem()

    stop_event = asyncio.Event()

    def factory():
        return CyanideSSHServer(pool=None, target_host=dst_host, target_port=dst_port, fs=fs)

    await asyncssh.create_server(factory, "0.0.0.0", listen_port, server_host_keys=[key])

    await stop_event.wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("\nSSH Proxy stopped.")
        raise
