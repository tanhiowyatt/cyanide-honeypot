import time
import asyncssh
from pathlib import PurePosixPath
from cyanide.vfs.nodes import Directory

class CyanideSFTPServer(asyncssh.SFTPServer):
    """
    SFTP Server implementation backed by FakeFilesystem.
    Intercepts uploads to Quarantine.
    """
    def __init__(self, channel, fs, quarantine_callback=None):
        # We process 'fs' and 'quarantine_callback' via the channel/server if possible,
        # but SFTPServer is initialized by asyncssh. 
        # We need to pass these context data.
        # AsyncSSH allows passing `sftp_factory` as a class or callable.
        # We will use a closure or partial to inject fs.
        self.fs = fs
        self.quarantine = quarantine_callback
        self.username = channel.get_server().username
        # Handle open files handles
        self.open_files = {} # handle_id -> {node, mode, buffer}
        self.next_handle = 0
        
        super().__init__(channel)

    def _get_node(self, path):
        # paths are absolute or relative to chroot. 
        # For us, all paths are absolute virtual paths
        if not path.startswith("/"):
            # Assume root relative if not absolute (ssh usually sends absolute)
            path = "/" + path
        return self.fs.get_node(path)

    def _resolve_path(self, path):
        # Simplistic resolution
        if path == ".":
            return "/root" # Should depend on cwd
        return path

    def stat(self, path):
        node = self._get_node(path)
        if not node:
            raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, path)
        
        # Construct attrs
        is_dir = isinstance(node, Directory)
        mode = 0o40755 if is_dir else 0o100644
        # We could parse node.perm, but lazy defaults are fine for now
        
        attrs = asyncssh.SFTPName(
            filename=node.name,
            longname=f"-rw-r--r-- 1 root root {node.size} Jan 1 12:00 {node.name}", # Dummy longname
            attrs=asyncssh.SFTPAttributes(
                size=node.size,
                uid=0,
                gid=0,
                permissions=mode,
                atime=int(node.mtime.timestamp()),
                mtime=int(node.mtime.timestamp()),
            )
        )
        return attrs.attrs

    def lstat(self, path):
        return self.stat(path)

    def opendir(self, path):
        node = self._get_node(path)
        if not node or not isinstance(node, Directory):
             raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, path)
        
        handle = f"dir_{self.next_handle}"
        self.next_handle += 1
        self.open_files[handle] = {"node": node, "type": "dir", "iter": iter(node.children.values())}
        return handle

    def readdir(self, handle):
        if handle not in self.open_files:
             raise asyncssh.SFTPError(asyncssh.FX_INVALID_HANDLE, "")
        
        handle_obj = self.open_files[handle]
        if handle_obj["type"] != "dir":
             raise asyncssh.SFTPError(asyncssh.FX_INVALID_HANDLE, "")

        entries = []
        try:
            # Return batches? 
            # For simplicity, return one by one or all?
            # asyncssh calls readdir repeatedly until EOF
            node = next(handle_obj["iter"])
            
            is_dir = isinstance(node, Directory)
            mode = 0o40755 if is_dir else 0o100644
            
            attrs = asyncssh.SFTPAttributes(
                size=node.size,
                uid=0, 
                gid=0,
                permissions=mode,
                mtime=int(node.mtime.timestamp())
            )
            entries.append(asyncssh.SFTPName(node.name, longname=f"{node.name}", attrs=attrs))
            return entries
        except StopIteration:
            return asyncssh.SFTP_EOF

    def open(self, path, pflags, attrs):
        path = self._resolve_path(path)
        
        handle = f"file_{self.next_handle}"
        self.next_handle += 1
        
        mode = "r"
        if (pflags & asyncssh.FXF_WRITE) or (pflags & asyncssh.FXF_CREAT) or (pflags & asyncssh.FXF_TRUNC):
            mode = "w"
            
        # Logic for read
        node = self._get_node(path)
        content = b""
        
        if mode == "r":
            if not node or isinstance(node, Directory):
                raise asyncssh.SFTPError(asyncssh.FX_NO_SUCH_FILE, path)
            # content = node.content.encode('utf-8') # Old text logic
            # Handle bytes if node.content is bytes
            if isinstance(node.content, str):
                content = node.content.encode('utf-8', errors='ignore')
            else:
                content = node.content
        elif mode == "w":
             # Prepare buffer
             pass
             
        self.open_files[handle] = {
            "path": path,
            "type": "file", 
            "mode": mode,
            "buffer": bytearray() if mode == "w" else content,
            "offset": 0
        }
        return handle

    def read(self, handle, offset, length):
        if handle not in self.open_files:
            raise asyncssh.SFTPError(asyncssh.FX_INVALID_HANDLE, "")
        obj = self.open_files[handle]
        if obj["mode"] != "r":
            raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, "")
        
        input_data = obj["buffer"]
        if offset >= len(input_data):
            raise asyncssh.SFTPError(asyncssh.FX_EOF, "")
            
        return input_data[offset:offset+length]

    def write(self, handle, offset, data):
        if handle not in self.open_files:
            raise asyncssh.SFTPError(asyncssh.FX_INVALID_HANDLE, "")
        obj = self.open_files[handle]
        if obj["mode"] != "w":
            raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, "")
        
        # Simple APPEND logic (ignoring offset for now, usually sequential)
        # Proper implementation should handle seek/offset
        if offset > len(obj["buffer"]):
            # fill hole?
            obj["buffer"].extend(b'\0' * (offset - len(obj["buffer"])))
        
        # If overwrite middle?
        # Simplified: just append
        obj["buffer"].extend(data)
        return asyncssh.SFTP_OK

    def close(self, handle):
        if handle in self.open_files:
            obj = self.open_files[handle]
            if obj["type"] == "file" and obj["mode"] == "w":
                # Commit clean file to system
                content = bytes(obj["buffer"])
                path = obj["path"]
                
                # 1. Quarantine
                if self.quarantine:
                    self.quarantine(path, content)
                    
                # 2. FakeFS
                parent_dir = str(PurePosixPath(path).parent)
                filename = PurePosixPath(path).name
                
                parent = self.fs.get_node(parent_dir)
                if parent and isinstance(parent, Directory):
                    # Try to decode for text files, keep bytes for binary
                    # But our Node definition currently usually expects text?
                    # Let's save as bytes in content regardless, but Node might default to text methods.

                    
                    # Check overwrite
                    existing = parent.get_child(filename)
                    if existing:
                        existing.content = content # Assign bytes
                        existing.size = len(content)
                        existing.mtime = time.time() # This fails type check if mtime is datetime, wait Node uses datetime.
                        import datetime
                        existing.mtime = datetime.datetime.now()
                    else:
                        from cyanide.vfs.nodes import File
                        new_file = File(filename, parent=parent, content=content, owner=self.username, group=self.username)
                        parent.add_child(new_file)
            
            del self.open_files[handle]
