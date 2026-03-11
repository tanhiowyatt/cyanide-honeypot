import asyncio
import re
import os
import traceback
from typing import Any, Dict, Optional

import asyncssh


class SCPHandler:
    """
    Handler for SCP requests (scp -t, scp -f).
    Implements the basic SCP protocol over a channel.
    Works with both legacy SSHSession.channel and new process_factory SSHServerProcess.
    """

    def __init__(self, session: Any, process=None):
        self.session = session  # SSHServerFactory or SSHSession instance
        self.process = process  # SSHServerProcess (from process_factory)
        self.honeypot = session.honeypot
        self.fs = session.fs
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
            self.process.channel.write(data)
        else:
            self.session.channel.write(data)

    def _write_stderr(self, data: bytes):
        """Write bytes to the stderr stream."""
        if self.process is not None:
            self.process.channel.write_stderr(data)
        else:
            self.session.channel.write_stderr(data)

    async def _read(self, n: int, timeout: float = 10.0) -> bytes:
        """Read bytes from the correct input stream."""
        if self.process is not None:
            try:
                data = await asyncio.wait_for(self.process.stdin.read(n), timeout=timeout)
                return data if isinstance(data, bytes) else data.encode() if data else b""
            except asyncio.TimeoutError:
                return b""
        else:
            try:
                data = await asyncio.wait_for(self.session.channel.read(n), timeout=timeout)
                return data if isinstance(data, bytes) else data.encode() if data else b""
            except asyncio.TimeoutError:
                return b""

    async def _readuntil(self, sep: bytes, timeout: float = 10.0) -> bytes:
        """Read until sep from the correct input stream."""
        if self.process is not None:
            # process.stdin is an AsyncIterator, no readuntil — read byte by byte
            buf = b""
            try:
                deadline = asyncio.get_event_loop().time() + timeout
                while sep not in buf:
                    remaining = deadline - asyncio.get_event_loop().time()
                    if remaining <= 0:
                        break
                    chunk = await asyncio.wait_for(self.process.stdin.read(1), timeout=remaining)
                    if not chunk:
                        break
                    if isinstance(chunk, str):
                        chunk = chunk.encode()
                    buf += chunk
            except (asyncio.TimeoutError, Exception):
                pass
            return buf
        else:
            try:
                data = await asyncio.wait_for(
                    self.session.channel.readuntil(sep), timeout=timeout
                )
                return data if isinstance(data, bytes) else data.encode() if data else b""
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncssh.misc.ConnectionLost):
                return b""

    def _log_op(self, op: str, path: str, success: bool = True, extra: Optional[Dict] = None):
        log_data = {
            "protocol": "scp",
            "src_ip": self.src_ip,
            "username": self.username,
            "op": op,
            "path": path,
            "success": success,
        }
        if extra:
            log_data.update(extra)
        self.logger.log_event(self.session_id, "scp_op", log_data)

    async def handle(self, command: str) -> int:
        """
        Main entry point for handling an SCP command.
        Returns the exit code.
        """
        # Parse scp command line
        sink_mode = "-t" in command
        source_mode = "-f" in command

        # Simple extraction of the path
        # Typical: scp [-v] [-p] [-d] -t /path
        parts = command.split()
        try:
            args = [p for p in parts if not p.startswith("-") and p != "scp"]
            if not args:
                path = "."
            else:
                path = args[-1]
        except Exception:
            path = "."

        if sink_mode:
            self._log_op("sink_mode_request", path)
            return await self._handle_sink(path)
        elif source_mode:
            self._log_op("source_mode_request", path)
            return await self._handle_source(path)
        else:
            self._log_op("unknown_scp_request", command, success=False)
            self._write_stderr(b"scp: invalid command\n")
            return 1

    async def _handle_sink(self, dest_path: str) -> int:
        """Attacker -> Honeypot (Upload)"""
        # Ack start
        self._write(b"\0")

        try:
            while True:
                line_bytes = await self._readuntil(b"\n", timeout=30.0)
                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", "ignore").strip()
                if not line:
                    continue

                # SCP command types:
                # C modes size name (File)
                # D modes 0 name (Directory)
                # E (End directory)

                if line.startswith("C"):
                    match = re.match(r"C(\d+) (\d+) (.+)", line)
                    if match:
                        modes, size, name = match.groups()
                        size = int(size)
                        full_path = os.path.join(dest_path, name)

                        # Check upload limits
                        ssh_conf = self.honeypot.config.get("ssh", {})
                        max_size = ssh_conf.get("max_upload_size_mb", 50) * 1024 * 1024
                        if size > max_size:
                            self._write(b"\x01SCP upload size limit exceeded\n")
                            self._log_op(
                                "upload_rejected",
                                full_path,
                                extra={"reason": "size_limit", "size": size},
                            )
                            return 1

                        # Ack line
                        self._write(b"\0")

                        # Read file data
                        content = await self._read_fixed(size)

                        # Ack data
                        self._write(b"\0")

                        # Wait for terminating null from client (optional)
                        try:
                            await asyncio.wait_for(self._read(1), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass

                        # Save to VFS
                        try:
                            self.fs.mkfile(full_path, content=content.decode("utf-8", "ignore"))
                        except Exception:
                            pass

                        # Quarantine
                        try:
                            self.honeypot.save_quarantine_file(
                                name, content, self.session_id, self.src_ip
                            )
                        except Exception:
                            pass

                        self._log_op("upload_complete", full_path, extra={"size": size})
                    else:
                        self._write(b"\x01SCP protocol error: invalid C line\n")
                        return 1

                elif line.startswith("D"):
                    match = re.match(r"D(\d+) 0 (.+)", line)
                    if match:
                        modes, name = match.groups()
                        new_dir = os.path.join(dest_path, name)
                        try:
                            self.fs.mkdir_p(new_dir)
                        except Exception:
                            pass
                        self._write(b"\0")
                        dest_path = new_dir  # Descend
                        self._log_op("mkdir", new_dir)
                elif line.startswith("E"):
                    self._write(b"\0")
                    dest_path = os.path.dirname(dest_path)  # Ascend
                else:
                    # Unknown line, ack and continue
                    self._write(b"\0")

            return 0
        except Exception as e:
            traceback.print_exc()
            self._log_op("error", dest_path, success=False, extra={"error": str(e)})
            return 1

    async def _handle_source(self, src_path: str) -> int:
        """Honeypot -> Attacker (Download)"""
        ssh_conf = self.honeypot.config.get("ssh", {})
        if not ssh_conf.get("allow_download", True):
            self._write(b"\x01SCP downloads disabled\n")
            self._log_op("download_rejected", src_path, extra={"reason": "disabled"})
            return 1

        try:
            # Wait for initial null ack from client
            await self._read(1, timeout=2.0)

            if not self.fs.exists(src_path):
                self._write(b"\x01SCP no such file\n")
                return 1

            if self.fs.is_file(src_path):
                raw_content = self.fs.get_content(src_path)
                content = (
                    raw_content.encode("utf-8", "ignore")
                    if isinstance(raw_content, str)
                    else (raw_content or b"")
                )
                size = len(content)
                name = os.path.basename(src_path)

                # Send C command
                header = f"C0644 {size} {name}\n".encode()
                self._write(header)

                # Wait for ack
                await self._read(1)

                # Send data
                self._write(content)
                self._write(b"\0")  # Terminator

                # Wait for ack
                await self._read(1)

                self._log_op("download_complete", src_path, extra={"size": size})
            else:
                self._write(b"\x01SCP directory downloads not yet implemented\n")
                return 1

            return 0
        except Exception as e:
            traceback.print_exc()
            self._log_op("error", src_path, success=False, extra={"error": str(e)})
            return 1

    async def _read_fixed(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = await self._read(size - len(data))
            if not chunk:
                break
            data += chunk
        return data
