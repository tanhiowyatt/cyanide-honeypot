import asyncio
import traceback
from typing import Any, Dict, Optional


class RsyncHandler:
    """
    Handler for rsync requests (rsync --server).
    Provides realistic logging and minimal handshake.
    Works with both legacy SSHSession.channel and new process_factory SSHServerProcess.
    """

    def __init__(self, session: Any, process=None):
        self.session = session
        self.process = process  # SSHServerProcess (from process_factory)
        self.honeypot = session.honeypot
        self.src_ip = session.src_ip
        self.username = session.username
        self.session_id = (
            "conn_" + session.conn_id
            if hasattr(session, "conn_id")
            else getattr(session, "session_id", "unknown")
        )
        self.logger = self.honeypot.logger

    def _write(self, data: bytes):
        """Write bytes to the correct output stream."""
        if self.process is not None:
            # process_factory: stdout is a StreamWriter, write bytes directly via channel
            self.process.channel.write(data)
        else:
            self.session.channel.write(data)

    async def _read(self, n: int, timeout: float = 5.0) -> bytes:
        """Read bytes from the correct input stream."""
        if self.process is not None:
            try:
                data = await asyncio.wait_for(self.process.stdin.read(n), timeout=timeout)
                return data if data else b""
            except asyncio.TimeoutError:
                return b""
        else:
            try:
                data = await asyncio.wait_for(self.session.channel.read(n), timeout=timeout)
                return data if data else b""
            except asyncio.TimeoutError:
                return b""

    def _log_op(self, op: str, command: str, success: bool = True, extra: Optional[Dict] = None):
        log_data = {
            "protocol": "rsync",
            "src_ip": self.src_ip,
            "username": self.username,
            "op": op,
            "command": command,
            "success": success,
        }
        if extra:
            log_data.update(extra)
        self.logger.log_event(self.session_id, "rsync_op", log_data)

    async def handle(self, command: str) -> int:
        """
        Detects and logs rsync server attempts.
        Returns the exit code.
        """
        is_sender = "--sender" in command

        self._log_op("server_mode_request", command, extra={"is_sender": is_sender})

        try:
            # Send rsync protocol version greeting: "@RSYNCD: 31.0\n"
            # Real rsync sends a text greeting first
            self._write(b"@RSYNCD: 31.0\n")

            # Read client greeting
            try:
                client_hello = await self._read(64, timeout=5.0)
                client_version = client_hello.decode("utf-8", "ignore").strip()
            except Exception:
                client_version = "unknown"

            self._log_op("handshake", command, extra={"client_hello": client_version})

            await asyncio.sleep(0.3)

            # Send a realistic rsync error to terminate gracefully
            # "@ERROR: access denied to root from ..." is a realistic honeypot response
            error_msg = f"@ERROR: access denied to root from {self.src_ip} (Permission denied)\n"
            self._write(error_msg.encode())

            return 1

        except Exception as e:
            traceback.print_exc()
            self._log_op("error", command, success=False, extra={"error": str(e)})
            return 1
