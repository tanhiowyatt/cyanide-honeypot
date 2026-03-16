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

    # Function 146: Initializes the class instance and its attributes.
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

    # Function 147: Performs operations related to connection made.
    def connection_made(self, conn):
        """Called when connection to backend is established."""
        pass

    # Function 148: Performs operations related to session started.
    def session_started(self):
        """Called when session is started on backend."""
        pass


class CyanideSSHServer(asyncssh.SSHServer):
    """SSH Proxy Server implementation.

    Accepts connections from attackers and bridges them to the backend
    via ProxyServerSession.
    """

    # Function 149: Initializes the class instance and its attributes.
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

    # Function 150: Performs operations related to connection made.
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

    # Function 151: Performs operations related to password auth supported.
    def password_auth_supported(self):
        """Allow password auth."""
        return True

    # Function 152: Performs operations related to validate password.
    def validate_password(self, username, password):
        """Validate password (always accept)."""
        return True

    # Function 153: Performs operations related to public key auth supported.
    def public_key_auth_supported(self):
        """Allow public key auth."""
        return True

    # Function 154: Performs operations related to validate public key.
    def validate_public_key(self, username, key):
        """Validate public key (always accept)."""
        return True

    # Function 155: Performs operations related to session requested.
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

        return ProxyServerSession(
            self.pool, self.target_host, self.target_port, self.session_id, self.src_ip, self.fs
        )


class ProxyServerSession(asyncssh.SSHServerSession):
    """Handles the session from the Attacker -> Proxy.

    Acts as the server for the attacker's client. Responsible for
    initiating connection to the backend and forwarding requests.
    """

    # Function 156: Initializes the class instance and its attributes.
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

    # Function 157: Performs operations related to connection made.
    def connection_made(self, chan):
        """Called when attacker channel is open."""
        self._chan = chan
        asyncio.create_task(self._connect_backend())

    # Function 158: Performs operations related to connect backend.
    async def _connect_backend(self):
        """Establish connection to backend server and bridge channels."""
        if self.pool:
            self.lease = await self.pool.reserve_target(self.session_id, "ssh")
            if self.lease:
                if hasattr(self.lease, "host"):
                    tgt_host, tgt_port = self.lease.host, self.lease.port
                else:
                    tgt_host, tgt_port = self.lease[0], self.lease[1]
            else:
                logger.error("No target available from pool")
                if self._chan:
                    self._chan.close()
                return
        else:
            tgt_host, tgt_port = self.target_host, self.target_port

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

            self.backend_channel, _ = await self.backend_conn.create_session(
                lambda: ProxyClientChannel(self.session_id, self.src_ip, self._chan),
                command=command,
                term_type=self._chan.get_terminal_type(),
                term_size=self._chan.get_terminal_size(),
            )

            self.send_task = asyncio.create_task(self._send_loop())

        except Exception as e:
            logger.error(f"Backend connect failed: {e}")
            if self._chan:
                self._chan.close()

    # Function 159: Performs operations related to data received.
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

    # Function 160: Performs operations related to shell requested.
    def shell_requested(self):
        """Handle shell request."""
        self.pending_request = ("shell", None)
        self.request_event.set()
        return True

    # Function 161: Performs operations related to exec requested.
    def exec_requested(self, command):
        """Handle exec request."""
        self.pending_request = ("exec", command)
        self.request_event.set()
        return True

    # Function 162: Performs operations related to pty requested.
    def pty_requested(self, term_type, term_size, term_modes):
        """Handle PTY request."""
        return True

    # Function 163: Performs operations related to terminal window resized.
    def terminal_window_resized(self, width, height, pixwidth, pixheight):
        """Handle window resize."""
        if self.backend_channel:
            self.backend_channel.change_terminal_size(width, height, pixwidth, pixheight)

    # Function 164: Performs operations related to break received.
    def break_received(self, msec):
        """Handle break signal."""
        if self.backend_channel:
            self.backend_channel.send_break(msec)

    # Function 165: Performs operations related to signal received.
    def signal_received(self, signal):
        """Handle POSIX signal."""
        if self.backend_channel:
            self.backend_channel.send_signal(signal)

    # Function 166: Performs operations related to eof received.
    def eof_received(self):
        """Handle EOF from attacker."""
        if self.backend_channel:
            self.backend_channel.write_eof()

    # Function 167: Performs operations related to connection lost.
    def connection_lost(self, exc):
        """Handle connection loss."""
        if self.send_task:
            self.send_task.cancel()
        if self.backend_conn:
            self.backend_conn.close()

        if self.pool and self.lease:
            asyncio.create_task(self.pool.release_target(self.lease))

    # Function 168: Performs operations related to send loop.
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

    # Function 169: Initializes the class instance and its attributes.
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

    # Function 170: Performs operations related to connection made.
    def connection_made(self, chan):
        """Called when backend channel is open."""
        self.send_task = asyncio.create_task(self._send_loop())

    # Function 171: Performs operations related to data received.
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

    # Function 172: Performs operations related to eof received.
    def eof_received(self):
        """Handle EOF from backend."""
        if self.peer_channel:
            self.peer_channel.write_eof()

    # Function 173: Performs operations related to connection lost.
    def connection_lost(self, exc):
        """Handle backend connection loss."""
        if self.send_task:
            self.send_task.cancel()
        if self.peer_channel:
            self.peer_channel.close()

    # Function 174: Performs operations related to send loop.
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


# Function 175: Main entry point for the application execution.
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

    # Function 176: Performs operations related to factory.
    def factory():
        return CyanideSSHServer(pool=None, target_host=dst_host, target_port=dst_port, fs=fs)

    await asyncssh.create_server(factory, "0.0.0.0", listen_port, server_host_keys=[key])

    await stop_event.wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
