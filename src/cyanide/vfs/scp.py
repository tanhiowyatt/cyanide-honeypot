import logging
import os
import re
import shlex
from typing import Any, List, Tuple

logger = logging.getLogger("cyanide.vfs.scp")


class ScpHandler:
    """
    Simplified SCP protocol handler for honeypot file capture.
    Handles 'sink' mode (-t) which is used for uploading files to the server.
    """

    def __init__(self, session: Any, process: Any = None):
        self.session = session
        self.process = process
        self.honeypot = session.honeypot
        self.fs = getattr(session, "fs", None)
        if not self.fs:
            # Fallback if fs is not directly attached
            self.fs = self.honeypot.get_filesystem(
                session_id=getattr(session, "session_id", "unknown"),
                src_ip=getattr(session, "src_ip", "unknown"),
            )

        self.src_ip = getattr(session, "src_ip", "unknown")
        self.session_id = (
            "conn_" + session.conn_id
            if hasattr(session, "conn_id")
            else getattr(session, "session_id", "unknown")
        )
        self.logger = self.honeypot.logger
        self.dir_stack: List[str] = []

    async def _read(self, n: int) -> bytes:
        """Read n bytes from the appropriate input stream."""
        try:
            if self.process is not None:
                # In process_factory mode, use stdin
                data = await self.process.stdin.read(n)
            else:
                # In direct session mode, use channel
                data = await self.session.channel.read(n)

            if isinstance(data, str):
                return data.encode("latin-1")
            return bytes(data)
        except Exception as e:
            logger.error(f"SCP Read Error: {e}")
            return b""

    def _write(self, data: bytes):
        """Write data to the appropriate output stream."""
        try:
            if self.process is not None:
                # If encoding is set, write() expects a string
                self.process.channel.write(data.decode("latin-1"))
            else:
                self.session.channel.write(data.decode("latin-1"))
        except Exception as e:
            logger.error(f"SCP Write Error: {e}")

    def _send_ack(self):
        """Send SCP success acknowledgement (a null byte)."""
        self._write(b"\0")

    async def _read_header(self) -> str:
        """Read SCP protocol header (e.g. C0644 123 filename\n)."""
        header = b""
        while not header.endswith(b"\n"):
            char = await self._read(1)
            if not char:
                return ""
            header += char
        return header.decode("utf-8", "ignore").strip()

    async def _read_file_data(self, size: int) -> bytes:
        """Read exactly size bytes from the input."""
        content = b""
        remaining = size
        while remaining > 0:
            chunk = await self._read(min(remaining, 8192))
            if not chunk:
                break
            content += chunk
            remaining -= len(chunk)
        return content

    def _save_to_vfs(self, target_path: str, content: bytes):
        """Helper to save file content to the virtual filesystem."""
        if not self.fs:
            return
        try:
            self.fs.mkfile(
                target_path,
                content=content.decode("utf-8", "ignore"),
                owner=getattr(self.session, "username", "root"),
                group=getattr(self.session, "username", "root"),
            )
        except Exception as e:
            logger.error(f"Failed to save SCP file to VFS: {e}")

    async def _handle_copy_command(self, header_str: str, dest_dir: str) -> int:
        """Handle the 'C' (Copy) protocol command."""
        match = re.match(r"C(\d{4}) (\d+) (.+)", header_str)
        if not match:
            self._write(b"\x01SCP Protocol Error: Invalid header\n")
            return 1

        mode_str, size_str, filename = match.groups()
        size = int(size_str)

        # ACK metadata
        self._send_ack()

        # Read the actual file content
        content = await self._read_file_data(size)

        # Consume the trailing null byte from the client
        await self._read(1)

        # Save to Virtual Filesystem
        target_path = os.path.join(dest_dir, filename)
        self._save_to_vfs(target_path, content)

        # Save to Quarantine and Log
        self.honeypot.save_quarantine_file(filename, content, self.session_id, self.src_ip)

        self.logger.log_event(
            self.session_id,
            "scp_upload_complete",
            {"filename": filename, "path": target_path, "size": size, "mode": mode_str},
        )

        # Final ACK for the file
        self._send_ack()
        return 0

    async def _handle_dir_command(self, header_str: str, current_base: str) -> str:
        """Handle the 'D' (Directory) protocol command."""
        match = re.match(r"D(\d{4}) 0 (.+)", header_str)
        if not match:
            self._write(b"\x01SCP Protocol Error: Invalid directory header\n")
            return current_base

        mode_str, dirname = match.groups()
        new_dir = os.path.join(current_base, dirname)

        if self.fs:
            try:
                self.fs.mkdir_p(new_dir)
            except Exception as e:
                logger.error(f"Failed to create SCP directory in VFS: {e}")

        self.logger.log_event(
            self.session_id,
            "scp_directory_created",
            {"path": new_dir, "mode": mode_str},
        )

        self._send_ack()
        return new_dir

    async def _handle_end_dir_command(self):
        """Handle the 'E' (End of Directory) protocol command."""
        self._send_ack()

    def _parse_scp_metadata(self, command: str) -> Tuple[bool, str]:
        """Extract is_sink and dest_dir from SCP command."""
        is_sink = "-t" in command
        try:
            parts = shlex.split(command)
            dest_dir = parts[-1] if parts else "."
        except Exception:
            dest_dir = "."

        self.logger.log_event(
            self.session_id,
            "scp_exec_detected",
            {
                "command": command,
                "direction": "upload" if is_sink else "download",
                "target_path": dest_dir,
            },
        )
        return is_sink, dest_dir

    async def _handle_end_dir(self, current_base: str) -> Tuple[str, bool]:
        """Pop directory stack and check if protocol should end."""
        if self.dir_stack:
            current_base = self.dir_stack.pop()
        await self._handle_end_dir_command()
        return current_base, not self.dir_stack

    async def handle(self, command: str) -> int:
        """
        Main SCP loop.
        Expects a command like 'scp -t /path/to/target'
        """
        is_sink, dest_dir = self._parse_scp_metadata(command)
        if not is_sink:
            return 0

        # Initial ACK to start the protocol
        self._send_ack()

        current_base = dest_dir
        self.dir_stack = [dest_dir]

        while True:
            header_str = await self._read_header()
            if not header_str:
                break

            if header_str.startswith("C"):
                rc = await self._handle_copy_command(header_str, current_base)
                if rc != 0:
                    return rc
            elif header_str.startswith("D"):
                self.dir_stack.append(current_base)
                current_base = await self._handle_dir_command(header_str, current_base)
            elif header_str.startswith("E"):
                current_base, should_break = await self._handle_end_dir(current_base)
                if should_break:
                    break
            else:
                self._send_ack()

        return 0
