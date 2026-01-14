from pathlib import PurePosixPath
import datetime
from .filesystem_nodes import Directory, File, Node

class FakeFilesystem:
    """Simulated Linux filesystem for honeypot.
    
    Provides a fake directory structure with pre-populated files and directories
    that mimic a realistic Linux system. Used by ShellEmulator for file operations.
    """
    
    def __init__(self):
        """Initialize fake filesystem with realistic directory structure and files."""
        self.root = Directory(name="") # Root is nameless in path logic usually, but handled carefully
        self._init_fs()

    def _init_fs(self):
        """Populate filesystem with default structure."""
        # Helper to create dirs
        def mkdir_p(path, owner="root", group="root", perm="drwxr-xr-x"):
            parts = [p for p in path.split("/") if p]
            current = self.root
            for part in parts:
                child = current.get_child(part)
                if not child:
                    child = Directory(part, parent=current, perm=perm, owner=owner, group=group)
                    current.add_child(child)
                current = child
            return current

        # Create directories
        mkdir_p("/bin")
        mkdir_p("/etc")
        mkdir_p("/home")
        mkdir_p("/home/admin", owner="admin", group="admin", perm="drwxr-x---")
        mkdir_p("/proc", perm="dr-xr-xr-x")
        mkdir_p("/tmp", perm="drwxrwxrwt")
        mkdir_p("/var")
        mkdir_p("/var/log")
        mkdir_p("/var/www")
        mkdir_p("/var/www/html")
        mkdir_p("/var/lib/mysql", owner="mysql", group="mysql", perm="drwxr-x---")
        mkdir_p("/var/spool/cron")
        mkdir_p("/var/spool/cron/crontabs", group="crontab", perm="drwx-wx--T")
        mkdir_p("/var/run")
        mkdir_p("/usr/local/bin")

        # Create files helper
        def mkfile(path, content="", owner="root", group="root", perm="-rw-r--r--"):
            parent_path = str(PurePosixPath(path).parent)
            filename = PurePosixPath(path).name
            parent = self.get_node(parent_path)
            if parent and isinstance(parent, Directory):
                f = File(filename, parent=parent, content=content, owner=owner, group=group, perm=perm)
                parent.add_child(f)

        # /etc files
        mkfile("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n")
        mkfile("/etc/shadow", "root:$6$...\n", perm="-rw-r-----", group="shadow")
        mkfile("/etc/hostname", "ubuntu-server\n")
        mkfile("/etc/issue", "Ubuntu 22.04.3 LTS \\n \\l\n")

        # /home/admin files
        mkfile("/home/admin/file1.txt", "Just a boring file.\n", owner="admin", group="admin")
        mkfile("/home/admin/secret.conf", "db_password=supersecret123\napi_key=XYZ-999-000\n", owner="admin", group="admin", perm="-rw-------")
        mkfile("/home/admin/flag.txt", "flag{r3al_fl46_f0r_h0n3yp0t}\n", owner="admin", group="admin", perm="-r--------")

        # /proc files
        mkfile("/proc/cpuinfo", "processor       : 0\nvendor_id       : GenuineIntel\ncpu family      : 6\nmodel           : 142\nmodel name      : Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz\n", perm="-r--r--r--")
        mkfile("/proc/meminfo", "MemTotal:        8123456 kB\nMemFree:         123456 kB\nBuffers:          23456 kB\nCached:          456789 kB\n", perm="-r--r--r--")
        mkfile("/proc/version", "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-015) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n", perm="-r--r--r--")

        # /var/www
        mkfile("/var/www/html/index.html", "<html><body><h1>It works!</h1><p>Apache Server at 127.0.0.1 Port 80</p></body></html>\n", owner="www-data", group="www-data")

        # Cron
        mkfile("/var/spool/cron/crontabs/root", "# m h  dom mon dow   command\n*/5 * * * * /usr/local/bin/backup_secrets.sh\n", perm="-rw-------", group="crontab")
        mkfile("/usr/local/bin/backup_secrets.sh", "#!/bin/bash\ntar -czf /tmp/backup.tar.gz /home/admin/secret.conf\n", perm="-rwxr-xr-x")
        
        # /var/run
        mkfile("/var/run/utmp", "", perm="-rw-rw-r--", group="utmp")


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
        return str(PurePosixPath(path))
