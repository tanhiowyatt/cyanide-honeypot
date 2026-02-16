from pathlib import PurePosixPath
import posixpath
from .nodes import Directory, File, Node
# print(f"DEBUG: Loading FakeFilesystem from {__file__}")

class FakeFilesystem:
    """Simulated Linux filesystem for honeypot.
    
    Provides a fake directory structure with pre-populated files and directories
    that mimic a realistic Linux system. Used by ShellEmulator for file operations.
    """
    
    def __init__(self, audit_callback=None, profile=None):
        """Initialize fake filesystem with realistic directory structure and files."""
        self.root = Directory("/") 
        self.audit_callback = audit_callback
        self.profile = profile
        self._init_fs()

    def _init_fs(self):
        """Populate filesystem with default structure.
        
        NOTE: Filesystem is now loaded entirely from YAML configuration in config/fs-config/.
        This method is kept empty to avoid breaking legacy logic, avoiding hardcoded paths.
        """
        pass

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
