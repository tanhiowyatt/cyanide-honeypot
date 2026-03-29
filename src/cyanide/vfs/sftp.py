import asyncio
import os
from typing import Any, AsyncIterator, Dict, Optional, Union

import asyncssh


class CyanideSFTPFile:
    """
    SFTP file object implementing the asyncssh SFTP file protocol.
    """

    def __init__(self, handler: "CyanideSFTPHandler", path: str, buffer: bytearray, is_write: bool):
        self.handler = handler
        self.path = path
        self.buffer = buffer
        self.is_write = is_write
        self.pos = 0

    def read(self, size: int) -> bytes:
        if self.pos >= len(self.buffer):
            return b""
        end = min(self.pos + size, len(self.buffer))
        data = bytes(self.buffer[self.pos:end])
        self.pos = end
        return data

    def write(self, data: bytes) -> int:
        try:
            if not self.is_write:
                raise asyncssh.SFTPPermissionDenied("File not open for writing")

            ssh_conf = self.handler.honeypot.config.get("ssh", {})
            session_limit = ssh_conf.get("max_total_upload_mb_per_session", 200) * 1024 * 1024
            if len(self.buffer) + len(data) > session_limit:
                raise asyncssh.SFTPPermissionDenied("Session upload limit exceeded")

            end = self.pos + len(data)
            if end > len(self.buffer):
                self.buffer.extend(b"\0" * (end - len(self.buffer)))

            # If data is somehow a string, convert it
            if isinstance(data, str):
                data = data.encode("utf-8", "ignore")

            self.buffer[self.pos:end] = data
            self.pos = end
            return len(data)
        except Exception as e:
            self.handler._log_op("write_error", self.path, success=False, extra={"error": str(e), "type": str(type(e))})
            raise

    def seek(self, offset: int, whence: int = 0):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = len(self.buffer) + offset
        else:
            raise asyncssh.SFTPBadMessage("Invalid seek whence")

    def tell(self) -> int:
        return self.pos

    def fstat(self) -> asyncssh.SFTPAttrs:
        node = self.handler.fs.get_node(self.path)
        return self.handler._get_attrs(node) if node else asyncssh.SFTPAttrs()

    def fsetstat(self, attrs: asyncssh.SFTPAttrs) -> None:
        self.handler._log_op("fsetstat", self.path, extra={"attrs": str(attrs)})
        return None

    def close(self):
        if self.is_write:
            content = bytes(self.buffer)
            # Save raw bytes to VFS
            self.handler.fs.mkfile(self.path, content=content)

            # Save to quarantine
            self.handler.honeypot.save_quarantine_file(
                os.path.basename(self.path), content, self.handler.session_id, self.handler.src_ip
            )

            self.handler._log_op("upload_complete", self.path, extra={"size": len(content)})
        else:
            self.handler._log_op("close", self.path)


class CyanideSFTPHandler(asyncssh.SFTPServer):
    """
    SFTP server implementation for Cyanide honeypot.
    Bridges asyncssh SFTP requests to the FakeFilesystem (VFS).
    """

    ERR_NO_SUCH_FILE = "No such file"

    def __init__(self, chan: asyncssh.SSHServerChannel):
        super().__init__(chan)
        self.chan = chan
        self.conn = chan.get_connection()
        self.server_factory = getattr(self.conn, "cyanide_factory", None)

        if self.server_factory:
            self.honeypot = self.server_factory.honeypot
            self.fs = self.server_factory.fs
            self.session_id = "conn_" + self.server_factory.conn_id
            self.src_ip = self.server_factory.src_ip
        else:
            self.honeypot = getattr(chan, "honeypot", None)
            self.fs = getattr(chan, "fs", None)
            self.session_id = getattr(chan, "session_id", "unknown")
            self.src_ip = getattr(chan, "src_ip", "unknown")

        if not self.honeypot:
            raise RuntimeError("CyanideSFTPHandler requires honeypot context")

        self.username = self.conn.get_extra_info("username") or "root"
        self.cyanide_logger = self.honeypot.logger

    def _decode_path(self, path: Union[str, bytes]) -> str:
        if isinstance(path, bytes):
            return path.decode("utf-8", "ignore")
        return path

    def _log_op(self, op: str, path: str, success: bool = True, extra: Optional[Dict] = None):
        log_data = {
            "protocol": "sftp",
            "src_ip": self.src_ip,
            "username": self.username,
            "op": op,
            "path": path,
            "success": success,
        }
        if extra:
            log_data.update(extra)

        self.cyanide_logger.log_event(self.session_id, "sftp_op", log_data)

    def realpath(self, path: Union[str, bytes]) -> Union[str, bytes]:
        p = self._decode_path(path)
        if not p or p == ".":
            p = "/"
        if not p.startswith("/"):
            p = "/" + p
        res = posixpath.normpath(p)
        if isinstance(path, bytes):
            return res.encode("utf-8")
        return res

    async def scandir(self, path: Union[str, bytes]) -> AsyncIterator[asyncssh.SFTPName]:
        p = self._decode_path(path)
        try:
            names = self.fs.list_dir(p)
            for name in names:
                full_path = os.path.join(p, name)
                node = self.fs.get_node(full_path)
                attrs = self._get_attrs(node) if node else asyncssh.SFTPAttrs()

                if isinstance(path, bytes):
                    yield asyncssh.SFTPName(name.encode("utf-8"), attrs=attrs)
                else:
                    yield asyncssh.SFTPName(name, attrs=attrs)

            self._log_op("scandir", p)
        except Exception as e:
            self._log_op("scandir", p, success=False, extra={"error": str(e)})
            raise asyncssh.SFTPNoSuchFile(str(e))

    async def stat(self, path: Union[str, bytes]) -> asyncssh.SFTPAttrs:
        await asyncio.sleep(0)
        p = self._decode_path(path)
        node = self.fs.get_node(p)
        if not node:
            self._log_op("stat", p, success=False, extra={"error": "no such file"})
            raise asyncssh.SFTPNoSuchFile(self.ERR_NO_SUCH_FILE)

        self._log_op("stat", p)
        return self._get_attrs(node)

    async def lstat(self, path: Union[str, bytes]) -> asyncssh.SFTPAttrs:
        return await self.stat(path)

    async def setstat(self, path: Union[str, bytes], attrs: asyncssh.SFTPAttrs):
        await asyncio.sleep(0)
        p = self._decode_path(path)
        self._log_op("setstat", p, extra={"attrs": str(attrs)})

    def fstat(self, file_obj: object) -> asyncssh.SFTPAttrs:
        return file_obj.fstat()

    def fsetstat(self, file_obj: object, attrs: asyncssh.SFTPAttrs) -> None:
        file_obj.fsetstat(attrs)
        return None

    async def open(
        self, path: Union[str, bytes], flags: int, attrs: asyncssh.SFTPAttrs
    ) -> CyanideSFTPFile:
        p = self._decode_path(path)
        self._log_op("open", p, extra={"flags": flags})

        is_write = bool(flags & (asyncssh.FXF_WRITE | asyncssh.FXF_CREAT | asyncssh.FXF_TRUNC))
        self._check_sftp_permissions(is_write)

        if is_write and self.fs.is_dir(p):
            raise asyncssh.SFTPPermissionDenied("Is a directory")

        if is_write:
            content = b""
            if not (flags & asyncssh.FXF_TRUNC) and self.fs.exists(p):
                content = self._get_node_content(p)
            return CyanideSFTPFile(self, p, bytearray(content), True)

        if not self.fs.exists(p):
            raise asyncssh.SFTPNoSuchFile(self.ERR_NO_SUCH_FILE)

        return CyanideSFTPFile(self, p, bytearray(self._get_node_content(p)), False)

    def _check_sftp_permissions(self, is_write: bool) -> None:
        """Check if SFTP operation is allowed by configuration."""
        ssh_conf = self.honeypot.config.get("ssh", {})
        if is_write and not ssh_conf.get("allow_upload", True):
            raise asyncssh.SFTPPermissionDenied("Uploads disabled")
        if not is_write and not ssh_conf.get("allow_download", True):
            raise asyncssh.SFTPPermissionDenied("Downloads disabled")

    def _get_node_content(self, path: str) -> bytes:
        """Retrieve and format node content from the filesystem."""
        raw = self.fs.get_content(path)
        if isinstance(raw, str):
            return raw.encode("utf-8", "ignore")
        return raw or b""

    async def mkdir(self, path: Union[str, bytes], attrs: asyncssh.SFTPAttrs):
        await asyncio.sleep(0)
        p = self._decode_path(path)
        self.fs.mkdir_p(p)
        self._log_op("mkdir", p)

    async def remove(self, path: Union[str, bytes]):
        await asyncio.sleep(0)
        p = self._decode_path(path)
        if self.fs.remove(p):
            self._log_op("remove", p)
        else:
            self._log_op("remove", p, success=False)
            raise asyncssh.SFTPNoSuchFile(self.ERR_NO_SUCH_FILE)

    async def rmdir(self, path: Union[str, bytes]):
        await self.remove(path)

    async def rename(self, oldpath: Union[str, bytes], newpath: Union[str, bytes], flags: int = 0):
        op = self._decode_path(oldpath)
        np = self._decode_path(newpath)
        if self.fs.move(op, np):
            self._log_op("rename", op, extra={"new_path": np})
        else:
            self._log_op("rename", op, success=False, extra={"new_path": np})
            raise asyncssh.SFTPNoSuchFile(self.ERR_NO_SUCH_FILE)

    def _get_attrs(self, node: Any) -> asyncssh.SFTPAttrs:
        attrs = asyncssh.SFTPAttrs()
        attrs.size = node.size if hasattr(node, "size") else 0

        is_directory = False
        if hasattr(node, "is_dir"):
            is_directory = node.is_dir()
        elif hasattr(node, "perm") and str(node.perm).startswith("d"):
            is_directory = True

        attrs.permissions = self._parse_mode(node.perm, is_directory)

        if hasattr(node, "mtime"):
            if isinstance(node.mtime, (int, float)):
                attrs.atime = attrs.mtime = int(node.mtime)
            elif hasattr(node.mtime, "timestamp"):
                attrs.atime = attrs.mtime = int(node.mtime.timestamp())

        attrs.uid = 0 if node.owner == "root" else 1000
        attrs.gid = 0 if node.group == "root" else 1000
        return attrs

    def _parse_mode(self, perm_str: str, is_dir: bool = False) -> int:
        mode = 0o40000 if is_dir else 0o100000
        perm_str = str(perm_str)

        if perm_str.isdigit() or (perm_str.startswith("0") and len(perm_str) > 1):
            try:
                return mode | int(perm_str, 8)
            except ValueError:
                pass

        mapping = {"r": 4, "w": 2, "x": 1, "-": 0}
        start = 1 if perm_str and perm_str[0] in "d-" else 0
        p_bits = perm_str[start : start + 9]

        res = 0
        for i in range(0, len(p_bits), 3):
            chunk = p_bits[i : i + 3]
            val = sum(mapping.get(c, 0) for c in chunk)
            res = (res << 3) | val

        return mode | res
