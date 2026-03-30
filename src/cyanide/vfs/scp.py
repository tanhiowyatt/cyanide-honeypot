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
            # Save raw bytes to VFS
            self.fs.mkfile(
                target_path,
                content=content,
                owner=getattr(self.session, "username", "root"),
                group=getattr(self.session, "username", "root"),
            )
        except Exception as e:
            logger.error(f"Failed to save SCP file to VFS: {e}")
            raise

    async def _handle_copy_command(self, header_str: str, dest_base: str) -> int:
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

        # In sink mode, common SCP clients send a null byte after file data.
        # This is essentially an EOF marker for the file transfer.
        await self._read(1)

        # Determine target path
        if self.fs and self.fs.is_dir(dest_base):
            target_path = os.path.join(dest_base, filename)
        else:
            target_path = dest_base

        try:
            # Save to Virtual Filesystem
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
        except Exception as e:
            logger.error(f"SCP Upload Error for {filename}: {e}")
            self._write(f"\x01SCP: Internal error saving file {filename}: {e}\n".encode("utf-8"))
            return 1

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

    def _parse_scp_metadata(self, command: str) -> Tuple[bool, bool, str]:
        """Extract is_sink, is_source and dest_dir from SCP command."""
        try:
            parts = shlex.split(command)
            # Protocol hardening: SCP requires either -t (sink) or -f (source)
            is_sink = "-t" in parts
            is_source = "-f" in parts

            if not is_sink and not is_source:
                return False, False, "."

            # Find the path (usually the last argument that isn't a flag)
            path = "."
            for part in reversed(parts):
                if not part.startswith("-"):
                    path = part
                    break
        except Exception:
            return False, False, "."

        self.logger.log_event(
            self.session_id,
            "scp_exec_detected",
            {
                "command": command,
                "direction": "upload" if is_sink else ("download" if is_source else "unknown"),
                "target_path": path,
            },
        )
        return is_sink, is_source, path

    async def _handle_end_dir(self, current_base: str) -> Tuple[str, bool]:
        """Pop directory stack and check if protocol should end."""
        if self.dir_stack:
            current_base = self.dir_stack.pop()
        await self._handle_end_dir_command()
        return current_base, not self.dir_stack

    async def _handle_source_mode(self, path: str) -> int:
        """Handle 'source' mode (-f) - sending files/dirs to the client."""
        if not self.fs:
            return 1

        node = self.fs.get_node(path)
        if not node:
            self._write(b"\x01SCP: No such file or directory\n")
            return 1

        self.logger.log_event(
            self.session_id,
            "scp_download_started",
            {"path": path, "type": "dir" if node.is_dir() else "file", "direction": "download"},
        )
        logger.debug(f"SCP Source Mode: Waiting for initial ACK for {path}...")

        # Wait for initial ACK from client
        initial_ack = await self._read(1)
        logger.debug(f"SCP Source Mode: Initial ACK received: {initial_ack!r}")
        if initial_ack != b"\0":
            self.logger.log_event(
                self.session_id, "scp_protocol_error", {"msg": "Missing initial ACK"}
            )
            return 1

        if node.is_dir():
            await self._send_directory(path, node)
        else:
            await self._send_file(path, node)

        # Final ACK after all files are sent (optional but often expected)
        # However, for ScpSource, it's usually the client that ACKs E or C.
        return 0

    def _perm_to_mode(self, perm: str) -> int:
        """Convert 'drwxr-xr-x' or '-rw-r--r--' to octal mode."""
        if not perm or len(perm) < 10:
            return 0o644
        mode = 0
        mapping = {"r": 4, "w": 2, "x": 1}
        for i, char in enumerate(perm[1:10]):
            if char in mapping:
                mode |= mapping[char] << (3 * (2 - i // 3))
        return mode

    async def _send_file(self, path: str, node: Any):
        """Send a single file in SCP protocol."""
        filename = os.path.basename(path)
        try:
            content = node.content
        except Exception:
            content = b""

        if isinstance(content, str):
            content = content.encode("utf-8")

        size = len(content)
        mode = self._perm_to_mode(getattr(node, "perm", "-rw-r--r--"))
        header = f"C{mode:04o} {size} {filename}\n".encode("utf-8")

        logger.debug(f"SCP _send_file: Sending header: {header!r}")
        self._write(header)

        ack = await self._read(1)
        logger.debug(f"SCP _send_file: Received header ACK: {ack!r}")
        if ack != b"\0":
            self.logger.log_event(
                self.session_id, "scp_protocol_error", {"msg": f"Missing header ACK, got {ack!r}"}
            )
            return

        logger.debug(f"SCP _send_file: Sending content ({size} bytes)...")
        self._write(content)
        self._write(b"\0")  # End of file marker (null byte)

        # Some clients send an ACK here, some don't.
        # We'll use a short timeout to try reading it without blocking forever.
        try:
            import asyncio

            logger.debug("SCP _send_file: Waiting for final ACK (0.1s timeout)...")
            final_ack = await asyncio.wait_for(self._read(1), timeout=0.1)
            logger.debug(f"SCP _send_file: Final ACK received: {final_ack!r}")
        except Exception as e:
            logger.debug(f"SCP _send_file: Final ACK wait error/timeout: {e}")
            pass

        self.logger.log_event(
            self.session_id,
            "scp_download_complete",
            {"filename": filename, "path": path, "size": size},
        )

    async def _send_directory(self, path: str, node: Any):
        """Send a directory and its contents in SCP protocol (recursive)."""
        dirname = os.path.basename(path)
        mode = self._perm_to_mode(getattr(node, "perm", "drwxr-xr-x"))
        header = f"D{mode:04o} 0 {dirname}\n".encode("utf-8")

        self._write(header)
        if await self._read(1) != b"\0":
            return

        # Send contents
        try:
            if self.fs is None:
                return
            for item in self.fs.list_dir(path):
                child_path = os.path.join(path, item)
                child_node = self.fs.get_node(child_path)
                if child_node:
                    if child_node.is_dir():
                        await self._send_directory(child_path, child_node)
                    else:
                        await self._send_file(child_path, child_node)
        except Exception as e:
            logger.error(f"Error sending SCP directory content: {e}")

        # End of directory
        self._write(b"E\n")
        await self._read(1)

    async def handle(self, command: str) -> int:
        """
        Main SCP loop.
        Handles both sink mode (-t) and source mode (-f).
        """
        is_sink, is_source, path = self._parse_scp_metadata(command)

        if is_source:
            return await self._handle_source_mode(path)

        if not is_sink:
            # Send standard SCP usage error for malformed/non-protocol commands
            self._write(b"\x01usage: scp [-f | -t] [-d] [-p] [-r] [-v] [path]\n")
            return 1

        # Initial ACK to start the protocol
        self._send_ack()

        current_base = path
        self.dir_stack = [path]

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
            elif header_str.startswith("T"):
                # Protocol hardening (T is for timestamps, ignore it with an ACK)
                self._send_ack()
            else:
                # Unknown command: send a NACK
                self._write(f"\x01SCP: Unknown protocol command: {header_str}\n".encode("utf-8"))
                return 1

        return 0
