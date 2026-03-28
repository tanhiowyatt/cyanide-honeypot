import asyncio
import logging
import shlex
import struct
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyanide.vfs.rsync")


class RsyncHandler:
    """
    Enhanced rsync-over-SSH server protocol implementation.
    Parses the initial file list during 'push' (upload) to log attacker intentions
    before realistically denying the transfer.
    """

    def __init__(self, session: Any, process=None):
        self.session = session
        self.process = process
        self.honeypot = session.honeypot
        self.fs = getattr(session, "fs", None)
        if not self.fs:
            self.fs = self.honeypot.get_filesystem(session.src_ip)

        self.src_ip = session.src_ip
        self.username = session.username
        self.session_id = (
            "conn_" + session.conn_id
            if hasattr(session, "conn_id")
            else getattr(session, "session_id", "unknown")
        )
        self.logger = self.honeypot.logger
        self.protocol_version = 31

        self.bytes_read = 0
        self.bytes_written = 0

    def _write(self, data: bytes):
        if self.process is not None:
            # If encoding is set, write() expects a string
            self.process.channel.write(data.decode("latin-1"))
        else:
            self.session.channel.write(data.decode("latin-1"))
        self.bytes_written += len(data)

    async def _read(self, n: int) -> bytes:
        if n <= 0:
            return b""

        try:
            async with asyncio.timeout(10.0):  # type: ignore[attr-defined]
                if self.process is not None:
                    data = await self.process.stdin.read(n)
                else:
                    data = await self.session.channel.read(n)

                if not data:
                    return b""

                if isinstance(data, str):
                    data = data.encode("latin-1")

                self.bytes_read += len(data)
                return bytes(data)

        except asyncio.TimeoutError:
            logger.debug("Read timeout after 10s - normal for honeypot")
            return b""
        except Exception as e:
            logger.error(f"Read error: {e}")
            return b""

    async def _read_int(self) -> int:
        """Read a 4-byte little-endian integer."""
        data = await self._read(4)
        if len(data) < 4:
            return -1
        return int(struct.unpack("<i", data)[0])

    async def _read_byte(self) -> int:
        data = await self._read(1)
        return data[0] if data else -1

    async def _read_varint(self) -> int:
        """Read rsync-style variable length integer."""
        b = await self._read_byte()
        if b == -1:
            return -1
        if b != 0xFF:
            return b

        data = await self._read(4)
        if len(data) < 4:
            return -1
        return int(struct.unpack("<I", data)[0])

    def _log_event(self, eventid: str, extra: Optional[Dict] = None):
        log_data = {
            "protocol": "rsync",
            "src_ip": self.src_ip,
            "username": self.username,
            "session_id": self.session_id,
        }
        if extra:
            log_data.update(extra)
        self.logger.log_event(self.session_id, eventid, log_data)

    async def handle(self, command: str) -> int:
        """Main rsync loop."""
        is_sender = "--sender" in command
        try:
            parts = shlex.split(command)
            dest_path = parts[-1] if parts else "."
        except Exception:
            dest_path = "."

        self._log_event(
            "rsync_exec_detected",
            {
                "command": command,
                "direction": "download" if is_sender else "upload",
                "path": dest_path,
            },
        )

        ssh_cfg = self.honeypot.config.get("ssh", {})
        rsync_cfg = ssh_cfg.get("rsync", {})
        if not rsync_cfg.get("enabled", True):
            self._log_event("rsync_denied", {"reason": "disabled"})
            return 1

        try:
            self._write(struct.pack("<i", self.protocol_version))
            client_version = await self._read_int()
            if client_version == -1:
                return 1

            self._write(struct.pack("<i", 12345678))
            self._log_event(
                "rsync_handshake",
                {"client_version": client_version, "server_version": self.protocol_version},
            )

            if is_sender:
                return self._handle_pull(dest_path)
            else:
                return await self._handle_push(dest_path)

        except Exception as e:
            self._log_event("rsync_error", {"error": str(e)})
            return 1

    async def _handle_push(self, dest_path: str) -> int:
        """Attacker pushed files TO honeypot. Parse file list for intelligence."""
        ssh_cfg = self.honeypot.config.get("ssh", {})
        rsync_cfg = ssh_cfg.get("rsync", {})

        files = []
        try:
            files = await self._read_file_list()
            if files:
                self._log_event(
                    "rsync_filelist",
                    {
                        "count": len(files),
                        "files": files[:50],
                        "path": dest_path,
                    },
                )
        except Exception as e:
            self._log_event("rsync_error", {"op": "file_list_parsing", "error": str(e)})

        if not rsync_cfg.get("allow_upload", True):
            self._log_event("rsync_denied", {"direction": "upload", "reason": "upload_disabled"})
        else:
            await asyncio.sleep(0.5)
            self._log_event("rsync_denied", {"direction": "upload", "reason": "target_readonly"})

        err_msg = f"rsync: [receiver] push to {dest_path} failed: Permission denied (13)\n"
        if self.process:
            self.process.channel.write_stderr(err_msg.encode())
        else:
            self.session.channel.write_stderr(err_msg.encode())

        return 13

    async def _read_file_list(self) -> List[Dict[str, Any]]:
        """
        Minimal rsync 31.x file list parser.
        Structure (simplified): flags(byte), [l1(byte), l2(byte)], name, size, mtime, mode...
        """
        files = []
        last_name = ""

        while True:
            flags = await self._read_byte()
            if flags <= 0:
                break

            l1 = 0
            if flags & 0x04:
                l1 = await self._read_byte()

            l2 = await self._read_byte()
            if l2 == -1:
                break

            name_suffix_bytes = await self._read(l2)
            name_suffix = name_suffix_bytes.decode("utf-8", "ignore")
            name = last_name[:l1] + name_suffix
            last_name = name

            size = await self._read_varint()

            mtime = 0
            if not (flags & 0x08):
                mtime = await self._read_int()

            mode = 0
            if not (flags & 0x10):
                mode = await self._read_int()

            files.append({"name": name, "size": size, "mode": mode, "mtime": mtime})

            if len(files) > 1000:
                break

        return files

    def _handle_pull(self, src_path: str) -> int:
        """Attacker pulls files FROM honeypot."""
        self._log_event(
            "rsync_denied",
            {"direction": "download", "path": src_path, "reason": "download_disabled"},
        )

        err_msg = f"rsync: [sender] slice of {src_path} failed: Permission denied (13)\n"
        if self.process:
            self.process.channel.write_stderr(err_msg.encode())
        else:
            self.session.channel.write_stderr(err_msg.encode())
        return 13
