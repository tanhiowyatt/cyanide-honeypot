from pathlib import PurePosixPath
import posixpath
import datetime
import random
import time
from .nodes import Directory, File, Node, DynamicFile
# print(f"DEBUG: Loading FakeFilesystem from {__file__}")

class FakeFilesystem:
    """Simulated Linux filesystem for honeypot.
    
    Provides a fake directory structure with pre-populated files and directories
    that mimic a realistic Linux system. Used by ShellEmulator for file operations.
    """
    
    def __init__(self, root=None, audit_callback=None, profile=None):
        """Initialize fake filesystem with realistic directory structure and files."""
        self.root = root or Directory("/") 
        self.audit_callback = audit_callback
        self.profile = profile
        self._init_fs()

    def _init_fs(self):
        """Populate filesystem with dynamic/metadata files.
        
        Injects magic files like /proc/version and /etc/issue if they are defined 
        in the profile metadata but missing from the loaded YAML structure.
        """
        if not self.profile:
            return

        # --- 1. /proc/version ---
        if "proc_version" in self.profile:
            if not self.exists("/proc/version"):
                self.mkdir_p("/proc")
                self.mkfile("/proc/version", content=self.profile["proc_version"])

        # --- 2. /etc/issue ---
        if "etc_issue" in self.profile:
            if not self.exists("/etc/issue"):
                self.mkdir_p("/etc")
                self.mkfile("/etc/issue", content=self.profile["etc_issue"])
        elif "os_name" in self.profile and not self.exists("/etc/issue"):
             self.mkdir_p("/etc")
             self.mkfile("/etc/issue", content=f"{self.profile['os_name']} \\n \\l\n")

        # --- 3. /etc/os-release (enriched generation) ---
        if "os_id" in self.profile or "os_name" in self.profile:
            self.mkdir_p("/etc")
            lines = []
            
            # Use os_pretty_name or fall back to os_name
            pretty_name = self.profile.get("os_pretty_name", self.profile.get("os_name", "Linux"))
            lines.append(f'PRETTY_NAME="{pretty_name}"')
            
            # Name
            name = self.profile.get("os_name", "Linux")
            lines.append(f'NAME="{name}"')
            
            # ID
            os_id = self.profile.get("os_id", name.lower().split()[0])
            lines.append(f'ID={os_id}')
            
            # ID_LIKE
            if "os_id_like" in self.profile:
                lines.append(f'ID_LIKE="{self.profile["os_id_like"]}"')
                
            # VERSION_ID
            if "os_version_id" in self.profile:
                lines.append(f'VERSION_ID="{self.profile["os_version_id"]}"')
                
            # VERSION
            if "os_version" in self.profile:
                lines.append(f'VERSION="{self.profile["os_version"]}"')
                
            # ANSI_COLOR
            if "os_ansi_color" in self.profile:
                lines.append(f'ANSI_COLOR="{self.profile["os_ansi_color"]}"')
            
            content = "\n".join(lines) + "\n"
            self.mkfile("/etc/os-release", content=content)

        # --- 4. /proc dynamic files ---
        self._init_proc_files()

        # --- 5. Set historical timestamps if install_date is present (at the end to cover dynamic files) ---
        install_date_str = self.profile.get("install_date")
        if install_date_str:
            try:
                # Support ISO format
                base_time = datetime.datetime.fromisoformat(install_date_str.replace("Z", "+00:00"))
                self._apply_historical_timestamps(self.root, base_time)
            except Exception:
                pass

    def _apply_historical_timestamps(self, node: Node, base_time: datetime.datetime):
        """Recursively apply historical timestamps to nodes."""
        # Random offset to look realistic (e.g., +/- 30 days around install date for system files)
        # But directories and core files should be close to base_time.
        offset_seconds = random.randint(-86400 * 5, 86400 * 30) # Mostly after install
        node.mtime = base_time + datetime.timedelta(seconds=offset_seconds)
        
        if isinstance(node, Directory):
            for child in node.children.values():
                self._apply_historical_timestamps(child, base_time)

    def _init_proc_files(self):
        """Initialize dynamic /proc files."""
        self.mkdir_p("/proc")
        
        # /proc/uptime
        start_time = time.time() - random.randint(3600, 86400 * 30) # Random uptime 1h to 30d
        
        def gen_uptime():
            uptime_sec = time.time() - start_time
            idle_sec = uptime_sec * 0.9 # Fake idle time
            return f"{uptime_sec:.2f} {idle_sec:.2f}\n"

        # /proc/meminfo (Simplified)
        total_mem = random.choice([4096, 8192, 16384]) * 1024 # KB
        
        def gen_meminfo():
            free_mem = int(total_mem * random.uniform(0.1, 0.6))
            buffers = int(total_mem * 0.05)
            cached = int(total_mem * 0.2)
            return (
                f"MemTotal:       {total_mem} kB\n"
                f"MemFree:        {free_mem} kB\n"
                f"MemAvailable:   {free_mem + cached} kB\n"
                f"Buffers:        {buffers} kB\n"
                f"Cached:         {cached} kB\n"
            )

        self.root.get_child("proc").add_child(DynamicFile("uptime", gen_uptime))
        self.root.get_child("proc").add_child(DynamicFile("meminfo", gen_meminfo))

    def mkdir_p(self, path: str, owner="root", group="root", perm="drwxr-xr-x"):
        """Create a directory and all its parents (public)."""
        parts = [p for p in path.split("/") if p]
        current = self.root
        for part in parts:
            child = current.get_child(part)
            if not child:
                child = Directory(part, parent=current, perm=perm, owner=owner, group=group)
                current.add_child(child)
            current = child
        return current

    def mkfile(self, path: str, content="", owner="root", group="root", perm="-rw-r--r--"):
        """Create a file at the specified path (public)."""
        parent_path = str(PurePosixPath(path).parent)
        filename = PurePosixPath(path).name
        parent = self.get_node(parent_path)
        if parent and isinstance(parent, Directory):
            f = File(filename, parent=parent, content=content, owner=owner, group=group, perm=perm)
            parent.add_child(f)
            return f
        return None

    def remove(self, path: str) -> bool:
        """Remove a file or directory.
        
        Args:
            path: Path to remove.
            
        Returns:
            bool: True if successful, False if not found or permissions error (mocked).
        """
        resolved = self.resolve(path)
        if resolved == "/":
            return False # Cannot remove root

        parent_path = str(PurePosixPath(resolved).parent)
        name = PurePosixPath(resolved).name
        
        parent = self.get_node(parent_path)
        if isinstance(parent, Directory):
            # Check if it exists first
            if parent.get_child(name):
                # Audit
                if self.audit_callback:
                    self.audit_callback("delete", resolved)
                return parent.remove_child(name)
        return False



    def get_node(self, path: str) -> Node:
        """Retrieve a node from the filesystem tree."""
        resolved = self.resolve(path)
        if resolved == "/":
            return self.root
        
        parts = [p for p in resolved.split("/") if p]
        current = self.root
        for part in parts:
            if isinstance(current, Directory):
                child = current.get_child(part)
                if child:
                    current = child
                else:
                    return None
            else:
                return None
        return current

    def exists(self, path: str) -> bool:
        """Check if a path exists.
        
        Args:
            path: Path to check.
            
        Returns:
            bool: True if path exists, False otherwise.
        """
        return self.get_node(path) is not None

    def is_dir(self, path: str) -> bool:
        """Check if path is a directory.
        
        Args:
            path: Path to check.
            
        Returns:
            bool: True if path refers to a directory.
        """
        node = self.get_node(path)
        return isinstance(node, Directory)

    def is_file(self, path: str) -> bool:
        """Check if path is a file.
        
        Args:
            path: Path to check.
            
        Returns:
            bool: True if path refers to a file.
        """
        node = self.get_node(path)
        return isinstance(node, File)

    def list_dir(self, path: str) -> list:
        """List contents of a directory.
        
        Args:
            path: Absolute path to directory.
            
        Returns:
            list: List of filenames/directory names in the directory.
        """
        node = self.get_node(path)
        if isinstance(node, Directory):
            return sorted(node.children.keys())
        return []

    def get_content(self, path: str) -> str:
        """Get file content.
        
        Args:
            path: Path to file.
            
        Returns:
            str: Content of the file, or empty string if not a file/not found.
        """
        node = self.get_node(path)
        if isinstance(node, File):
            if self.audit_callback:
                self.audit_callback("read", path)
            return node.content
        return ""

    def resolve(self, path: str) -> str:
        """Normalize and resolve filesystem path.
        
        Args:
            path: Path to resolve (may contain .., ., //).
            
        Returns:
            str: Normalized absolute path.
            
        Note:
            Handles parent directory (..) and current directory (.) references.
            Removes duplicate slashes and ensures proper path formatting.
        """
        # This is a simplified resolver
        if not path:
             return "/"
        res = posixpath.normpath(str(PurePosixPath(path)))
        if res.startswith("//") and not res.startswith("///"):
            res = res[1:]
        return res
