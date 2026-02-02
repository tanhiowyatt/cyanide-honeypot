from pathlib import PurePosixPath
import posixpath
import datetime
from .filesystem_nodes import Directory, File, Node

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
        mkdir_p("/boot", perm="drwxr-xr-x")
        mkdir_p("/dev", perm="drwxr-xr-x")
        mkdir_p("/lib", perm="drwxr-xr-x")
        mkdir_p("/lib64", perm="drwxr-xr-x")
        mkdir_p("/media", perm="drwxr-xr-x")
        mkdir_p("/mnt", perm="drwxr-xr-x")
        mkdir_p("/opt", perm="drwxr-xr-x")
        mkdir_p("/run", perm="drwxr-xr-x")
        mkdir_p("/sbin", perm="drwxr-xr-x")
        mkdir_p("/srv", perm="drwxr-xr-x")
        mkdir_p("/sys", perm="dr-xr-xr-x")
        mkdir_p("/usr/bin", perm="drwxr-xr-x")
        mkdir_p("/usr/sbin", perm="drwxr-xr-x")
        mkdir_p("/usr/lib", perm="drwxr-xr-x")
        mkdir_p("/usr/share", perm="drwxr-xr-x")
        mkdir_p("/root", owner="root", group="root", perm="drwx------")

        # Create files helper
        def mkfile(path, content="", owner="root", group="root", perm="-rw-r--r--"):
            parent_path = str(PurePosixPath(path).parent)
            filename = PurePosixPath(path).name
            parent = self.get_node(parent_path)
            if parent and isinstance(parent, Directory):
                f = File(filename, parent=parent, content=content, owner=owner, group=group, perm=perm)
                parent.add_child(f)

        # Populate /bin and /usr/bin with common binaries (placeholders)
        bin_files = ["ls", "cd", "pwd", "cp", "mv", "rm", "cat", "more", "less", "grep", "awk", "sed", "bash", "sh", "dash", "ps", "kill", "chmod", "chown", "mkdir", "rmdir", "touch", "date", "tar", "gzip", "ping", "netstat", "vi", "nano", "su", "logname"]
        sbin_files = ["ip", "ifconfig", "iptables", "reboot", "shutdown", "fdisk", "mkfs", "useradd", "userdel", "usermod", "sshd"]
        
        for b in bin_files:
            mkfile(f"/bin/{b}", content="\x7fELF...", perm="-rwxr-xr-x")
            
        mkfile("/usr/bin/python3", content="\x7fELF...", perm="-rwxr-xr-x")
        mkfile("/usr/bin/wget", content="\x7fELF...", perm="-rwxr-xr-x")
        mkfile("/usr/bin/curl", content="\x7fELF...", perm="-rwxr-xr-x")
        mkfile("/usr/bin/sudo", content="\x7fELF...", perm="-rwsr-xr-x")

        for s in sbin_files:
             mkfile(f"/sbin/{s}", content="\x7fELF...", perm="-rwxr-xr-x")
             mkfile(f"/usr/sbin/{s}", content="\x7fELF...", perm="-rwxr-xr-x")

        # /etc files
        mkfile("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n")
        mkfile("/etc/shadow", "root:$6$...\n", perm="-rw-r-----", group="shadow")
        
        if self.profile:
             issue_content = self.profile.get("etc_issue", "Ubuntu 22.04.3 LTS \\n \\l\n\n")
             proc_version = self.profile.get("proc_version", "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-015) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n")
        else:
             issue_content = "Ubuntu 22.04.3 LTS \\n \\l\n\n"
             proc_version = "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-015) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n"

        mkfile("/etc/issue", issue_content, perm="-r--r--r--")
        mkfile("/etc/issue.net", issue_content, perm="-r--r--r--")
        mkfile("/etc/hostname", "server\n", perm="-r--r--r--")

        # Fake History
        history_cmds = [
            "systemctl status ssh",
            "ufw status",
            "docker ps",
            "ls -la /var/www/html",
            "cd /var/log",
            "tail -f syslog",
            "netstat -tulnp",
            "free -m",
            "df -h",
            "vim /etc/nginx/sites-available/default",
            "exit"
        ]
        
        # Package Manager Consistency
        pkg_manager = "apt"
        if self.profile and "centos" in self.profile.get("name", "").lower():
            pkg_manager = "yum"
            history_cmds.insert(0, "yum update -y")
            history_cmds.insert(1, "yum install -y net-tools")
        else:
            history_cmds.insert(0, "apt update")
            history_cmds.insert(1, "apt upgrade -y")
            
        history_content = "\n".join(history_cmds) + "\n"
        mkfile("/root/.bash_history", history_content, owner="root", group="root", perm="-rw-------")
        mkfile("/home/admin/.bash_history", history_content, owner="admin", group="admin", perm="-rw-------")
        
        # /home/admin files
        mkfile("/home/admin/file1.txt", "Just a boring file.\n", owner="admin", group="admin")
        mkfile("/home/admin/secret.conf", "db_password=supersecret123\napi_key=XYZ-999-000\n", owner="admin", group="admin", perm="-rw-------")
        mkfile("/home/admin/flag.txt", "flag{r3al_fl46_f0r_h0n3yp0t}\n", owner="admin", group="admin", perm="-r--------")

        from .filesystem_nodes import DynamicFile
        import random

        # /proc generators
        def gen_cpuinfo():
            models = [
                "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz",
                "AMD Ryzen 7 5800X 8-Core Processor",
                "Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz"
            ]
            model = random.choice(models)
            return f"processor       : 0\nvendor_id       : GenuineIntel\ncpu family      : 6\nmodel           : 142\nmodel name      : {model}\n"

        def gen_meminfo():
            total = random.randint(2000000, 16000000)
            free = random.randint(100000, total // 2)
            return f"MemTotal:        {total} kB\nMemFree:         {free} kB\nBuffers:          {random.randint(10000, 50000)} kB\n"

        def gen_uptime():
             uptime = random.randint(1000, 5000000)
             return f"{uptime}.{random.randint(10,99)} {uptime*4}.{random.randint(10,99)}\n"

        def gen_net_tcp():
            # Mimic /proc/net/tcp
            # sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
            header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     \n"
            # Hex ports: 22 -> 0016, 3306 -> 0CEA
            # We map our current profile ports (22, 3306) to look real
            # SSH (0016), MySQL (0CEA)
            lines = [
                "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 35843 1 0000000000000000 100 0 0 10 0",
                "   1: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   106        0 19451 1 0000000000000000 100 0 0 10 0"
            ]
            return header + "\n".join(lines) + "\n"

        # Explicitly add dynamic files
        proc = self.get_node("/proc")
        if isinstance(proc, Directory):
             proc.add_child(DynamicFile("cpuinfo", gen_cpuinfo, parent=proc))
             proc.add_child(DynamicFile("meminfo", gen_meminfo, parent=proc))
             proc.add_child(DynamicFile("uptime", gen_uptime, parent=proc))
             proc.add_child(File("version", parent=proc, content=proc_version, perm="-r--r--r--"))
             
             # /proc/net
             net = Directory("net", parent=proc, perm="dr-xr-xr-x")
             proc.add_child(net)
             net.add_child(DynamicFile("tcp", gen_net_tcp, parent=net))

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
            if self.audit:
                self.audit("read", path)
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
        return posixpath.normpath(str(PurePosixPath(path)))
