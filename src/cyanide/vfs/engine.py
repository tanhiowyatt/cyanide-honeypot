import datetime
import os
import posixpath
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from jinja2.sandbox import SandboxedEnvironment

from ..core.paths import get_profiles_dir
from .context import Context
from .dynamic import PROVIDERS
from .nodes import Directory, File, Node


class VFSBackend(ABC):
    @abstractmethod
    def get_config(self, path: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_dir(self, path: str) -> List[str]:
        pass

    @abstractmethod
    def exists(self, path: str) -> bool:
        pass

    @abstractmethod
    def is_dir(self, path: str) -> bool:
        pass

    def close(self):
        """Optional cleanup for the backend."""
        pass


class SqliteBackend(VFSBackend):
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        from opentelemetry import trace

        self.tracer = trace.get_tracer(__name__)

    def get_config(self, path: str) -> Optional[Dict[str, Any]]:
        with self.tracer.start_as_current_span("vfs.get_config") as span:
            span.set_attribute("vfs.path", path)
            cursor = self._conn.execute(
                "SELECT type, content, owner, group_name as 'group', perm, size, mtime FROM vfs WHERE path = ?",
                (path,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_dir(self, path: str) -> List[str]:
        with self.tracer.start_as_current_span("vfs.list_dir") as span:
            span.set_attribute("vfs.path", path)
            cursor = self._conn.execute("SELECT name FROM vfs WHERE parent_path = ?", (path,))
            return [row["name"] for row in cursor.fetchall()]

    def exists(self, path: str) -> bool:
        cursor = self._conn.execute("SELECT 1 FROM vfs WHERE path = ?", (path,))
        if cursor.fetchone():
            return True
        cursor = self._conn.execute("SELECT 1 FROM vfs WHERE parent_path = ? LIMIT 1", (path,))
        return cursor.fetchone() is not None

    def is_dir(self, path: str) -> bool:
        cursor = self._conn.execute("SELECT type FROM vfs WHERE path = ?", (path,))
        row = cursor.fetchone()
        if row:
            return str(row["type"]) == "dir"
        return self.exists(path)

    def close(self):
        if hasattr(self, "_conn") and self._conn:
            self._conn.close()

    def __del__(self):
        self.close()


class VirtualFile(File):
    """Proxy for a file node."""

    def __init__(
        self, name: str, path: str, fs: "FakeFilesystem", config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(name, **(config or {}))
        self.path = path
        self.fs = fs

    @property
    def content(self) -> Union[str, bytes]:
        return self.fs.get_content(self.path)


class VirtualDirectory(Directory):
    """Proxy for a directory node."""

    def __init__(
        self, name: str, path: str, fs: "FakeFilesystem", config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(name, children_getter=lambda: self._lazy_children(), **(config or {}))
        self.path = path
        self.fs = fs

    def _lazy_children(self) -> Dict[str, Node]:
        """Lazy-load children as needed by ls."""
        names = self.fs.list_dir(self.path)
        result = {}
        for name in names:
            child_path = posixpath.join(self.path, name)
            node = self.fs.get_node(child_path)
            if node:
                result[name] = node
        return result

    def get_child(self, name: str) -> Optional[Node]:
        return self.children.get(name)


class FakeFilesystem:
    """Modern Simulated Linux filesystem using Template + Context model."""

    def __init__(
        self,
        os_profile: Optional[str] = None,
        root_dir: Optional[Union[str, Path]] = None,
        audit_callback=None,
        stats=None,
        users: Optional[List[Dict[str, Any]]] = None,
        src_ip: str = "unknown",
        session_id: str = "unknown",
        session_mgr=None,
    ):
        self.root_dir = Path(root_dir) if root_dir else get_profiles_dir()
        self.audit_callback = audit_callback
        self.stats = stats
        self.users = users or []
        self.src_ip = src_ip
        self.session_id = session_id
        self.session_mgr = session_mgr

        self.os_profile = str(os_profile or os.getenv("OS_PROFILE", "ubuntu"))
        self.profile_path = self.root_dir / self.os_profile

        self.context: Optional[Context] = None
        self.dynamic_files: Dict[str, Any] = {}
        self.backend: Optional[VFSBackend] = None

        self.memory_overlay: Dict[str, Dict[str, Any]] = {}
        self.honeytokens: List[str] = []
        self.deleted_paths: Set[str] = set()
        self.processes: List[Dict[str, Any]] = [
            {"pid": 1, "tty": "?", "time": "00:00:15", "cmd": "/sbin/init", "user": "root"},
            {"pid": 2, "tty": "?", "time": "00:00:00", "cmd": "[kthreadd]", "user": "root"},
        ]
        self.jinja_env = SandboxedEnvironment()

        self._load_profile()
        self._generate_system_files()
        self._load_ip_history()
        self._initialize_user_homes()

    def close(self):
        if self.backend:
            self.backend.close()

    def __del__(self):
        self.close()

    def _generate_system_files(self):
        """Generate /etc/passwd and /etc/group based on self.users."""
        passwd_lines = [
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
        ]
        group_lines = [
            "root:x:0:",
            "daemon:x:1:",
            "bin:x:2:",
            "sys:x:3:",
            "adm:x:4:",
            "tty:x:5:",
            "disk:x:6:",
            "lp:x:7:",
            "mail:x:8:",
            "news:x:9:",
            "uucp:x:10:",
        ]

        uid = 1000
        for user_entry in self.users:
            username = user_entry.get("user")
            if not username or username == "root":
                continue

            home = f"/home/{username}"
            passwd_lines.append(f"{username}:x:{uid}:{uid}:{username}:{home}:/bin/bash")
            group_lines.append(f"{username}:x:{uid}:")
            uid += 1

        self.memory_overlay["/etc/passwd"] = {
            "type": "file",
            "content": "\n".join(passwd_lines) + "\n",
            "owner": "root",
            "group": "root",
            "perm": "-rw-r--r--",
        }
        self.memory_overlay["/etc/group"] = {
            "type": "file",
            "content": "\n".join(group_lines) + "\n",
            "owner": "root",
            "group": "root",
            "perm": "-rw-r--r--",
        }

    def _load_ip_history(self):
        """Load persistent history for the source IP."""
        if self.src_ip == "unknown":
            return

        history_base = Path("var/lib/cyanide/history") / self.src_ip
        history_file = history_base / ".bash_history"

        if history_file.exists():
            try:
                content = history_file.read_text()
                self.memory_overlay["/root/.bash_history"] = {
                    "type": "file",
                    "content": content,
                    "owner": "root",
                    "group": "root",
                    "perm": "-rw-------",
                    "size": len(content),
                    "mtime": datetime.datetime.fromtimestamp(history_file.stat().st_mtime),
                }
            except Exception as e:
                import logging

                logging.debug(f"Failed to load history for {self.src_ip}: {e}")

    def save_ip_history(self):
        """Save current session history to persistent storage."""
        if self.src_ip == "unknown":
            return

        history_path = "/root/.bash_history"
        if history_path not in self.memory_overlay:
            return

        content = self.memory_overlay[history_path].get("content", "")
        if not content:
            return

        history_base = Path("var/lib/cyanide/history") / self.src_ip
        try:
            history_base.mkdir(parents=True, exist_ok=True)
            (history_base / ".bash_history").write_text(content)
        except Exception as e:
            import logging

            logging.error(f"Failed to save history for {self.src_ip}: {e}")

    def _initialize_user_homes(self):
        """Automatically create /home/[user] for all configured users."""
        self.mkdir_p("/home")

        for user_entry in self.users:
            username = user_entry.get("user")
            if not username:
                continue

            if username == "root":
                self.mkdir_p("/root")
            else:
                self.mkdir_p(f"/home/{username}")

    def _load_profile(self):
        """Load profile configuration using SQLite backend."""
        from .profile_loader import load as load_profile

        if (
            not (self.profile_path / "base.yaml").exists()
            and not (self.profile_path / ".compiled.db").exists()
            and not self.profile_path.exists()
        ):
            self.profile_path = get_profiles_dir() / self.os_profile

        data = load_profile(self.os_profile, self.profile_path.parent)

        self.context = Context(**data.get("metadata", {}))
        self.dynamic_files = data.get("dynamic_files", {})
        self.honeytokens = data.get("honeytokens", [])

        db_path = data.get("backend_path")
        if db_path:
            self.backend = SqliteBackend(db_path)

    def get_node(self, path: str) -> Optional[Node]:
        """Resolve a path to a VirtualFile or VirtualDirectory node."""
        path = self.resolve(path)
        if path in self.deleted_paths:
            return None

        if path in self.memory_overlay:
            config = self.memory_overlay[path]
            return (
                VirtualDirectory(os.path.basename(path), path, self, config)
                if config.get("type") == "dir"
                else VirtualFile(os.path.basename(path), path, self, config)
            )

        if path in self.dynamic_files:
            return VirtualFile(os.path.basename(path), path, self, self.dynamic_files[path])

        if self.backend:
            backend_config = self.backend.get_config(path)
            if backend_config:
                if backend_config.get("type") == "dir":
                    return VirtualDirectory(
                        posixpath.basename(path) or "/", path, self, backend_config
                    )
                return VirtualFile(posixpath.basename(path), path, self, backend_config)

        if self.is_dir(path):
            return VirtualDirectory(os.path.basename(path) or "/", path, self)

        if self.exists(path):
            return VirtualFile(os.path.basename(path), path, self)

        return None

    def exists(self, path: str) -> bool:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return False
        if (
            path == "/"
            or path in self.memory_overlay
            or path in self.dynamic_files
            or (self.backend and self.backend.exists(path))
        ):
            return True
        return False

    def is_dir(self, path: str) -> bool:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return False
        if path == "/":
            return True

        if path in self.memory_overlay:
            return self.memory_overlay[path].get("type") == "dir"

        if path in self.dynamic_files:
            return str(self.dynamic_files[path].get("type")) == "dir"

        if self.backend and self.backend.is_dir(path):
            return True

        return False

    def is_file(self, path: str) -> bool:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return False
        if path in self.memory_overlay:
            return self.memory_overlay[path].get("type") == "file"
        if path in self.dynamic_files:
            return str(self.dynamic_files[path].get("type", "file")) == "file"

        if self.backend:
            config = self.backend.get_config(path)
            if config:
                return str(config.get("type", "file")) == "file"

        if not self.exists(path):
            return False
        return not self.is_dir(path)

    def list_dir(self, path: str) -> List[str]:
        path = self.resolve(path)
        if path in self.deleted_paths or not self.is_dir(path):
            return []

        contents = set()

        if self.backend:
            for item in self.backend.list_dir(path):
                contents.add(item)

        prefix = path.rstrip("/") + "/"
        for p in self.dynamic_files:
            if p.startswith(prefix):
                rel = p[len(prefix) :].split("/")[0]
                contents.add(rel)

        for p in self.memory_overlay:
            if p.startswith(prefix):
                rel = p[len(prefix) :].split("/")[0]
                contents.add(rel)

        return sorted([c for c in contents if posixpath.join(path, c) not in self.deleted_paths])

    def get_content(self, path: str, args: Optional[Dict[str, Any]] = None) -> Union[str, bytes]:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return ""

        if self.audit_callback:
            self.audit_callback("read", path, self)
        if self.stats:
            self.stats.on_file_op("read", path)
        if self.session_mgr:
            self.session_mgr.record_file_op(self.session_id)

        if path in self.memory_overlay:
            content = self.memory_overlay[path].get("content", "")
            if isinstance(content, (str, bytes)):
                return content
            return str(content)

        if path in self.dynamic_files:
            config = self.dynamic_files[path]
            provider = PROVIDERS.get(config.get("provider"))
            if provider:
                combined_args = {**config.get("args", {}), **(args or {})}
                return provider(self.context, combined_args)
            if "content" in config:
                res = self._render(config["content"])
                return res
            return ""

        if self.backend:
            config = self.backend.get_config(path)
            if config:
                res = self._render(config.get("content", ""))
                return res

        return ""

    def mkfile(
        self,
        path: str,
        content: Union[str, bytes] = "",
        owner="root",
        group="root",
        perm="-rw-r--r--",
    ):
        path = self.resolve(path)
        parent_path = posixpath.dirname(path)
        if parent_path != path:
            if not self.exists(parent_path) or not self.is_dir(parent_path):
                return None

        self.memory_overlay[path] = {
            "type": "file",
            "content": content,
            "owner": owner,
            "group": group,
            "perm": perm,
            "size": len(content) if isinstance(content, (str, bytes)) else 0,
            "mtime": datetime.datetime.now(),
        }
        if path in self.deleted_paths:
            self.deleted_paths.remove(path)
        if self.stats:
            self.stats.on_file_op("write", path)
        if self.session_mgr:
            self.session_mgr.record_file_op(self.session_id)
        return VirtualFile(posixpath.basename(path), path, self)

    def mkdir_p(self, path: str, owner="root", group="root", perm="drwxr-xr-x"):
        path = self.resolve(path)
        parts = [p for p in path.split("/") if p]
        current = "/"
        for part in parts:
            current = posixpath.join(current, part)
            if not self.exists(current) or self.is_file(current):
                self.memory_overlay[current] = {
                    "type": "dir",
                    "owner": owner,
                    "group": group,
                    "perm": perm,
                    "mtime": datetime.datetime.now(),
                }
                if current in self.deleted_paths:
                    self.deleted_paths.remove(current)
        return True

    def remove(self, path: str) -> bool:
        path = self.resolve(path)
        if path == "/" or not self.exists(path):
            return False

        self.deleted_paths.add(path)
        if path in self.memory_overlay:
            del self.memory_overlay[path]

        if self.audit_callback:
            self.audit_callback("delete", path, self)
        if self.stats:
            self.stats.on_file_op("delete", path)
        if self.session_mgr:
            self.session_mgr.record_file_op(self.session_id)
        return True

    def get_owner(self, path: str) -> str:
        """Get the owner of a file or directory."""
        node = self.get_node(path)
        res = getattr(node, "owner", "root")
        return str(res)

    def resolve(self, path: str) -> str:
        if not path:
            return "/"
        res = posixpath.normpath(path)
        if res.startswith("//") and not res.startswith("///"):
            res = "/" + res.lstrip("/")
        return res

    def copy(self, src: str, dst: str, recursive: bool = False) -> bool:
        src = self.resolve(src)
        dst = self.resolve(dst)

        if not self.exists(src):
            return False

        if self.is_dir(src):
            if not recursive:
                return False

            if not self.exists(dst):
                self.mkdir_p(dst)
            elif self.is_file(dst):
                return False

            for item in self.list_dir(src):
                self.copy(posixpath.join(src, item), posixpath.join(dst, item), recursive=True)
            return True
        else:
            content = self.get_content(src)
            if self.exists(dst) and self.is_dir(dst):
                dst = posixpath.join(dst, posixpath.basename(src))

            self.mkfile(dst, content=content)
            return True

    def move(self, src: str, dst: str) -> bool:
        src = self.resolve(src)
        dst = self.resolve(dst)

        if not self.exists(src):
            return False

        if self.copy(src, dst, recursive=True):
            return self.remove(src)
        return False

    def _render(self, content: Any) -> Union[str, bytes]:
        if not content:
            return ""

        if isinstance(content, bytes):
            return content

        if not self.context or not isinstance(content, str):
            return str(content)

        try:
            rendered = self.jinja_env.from_string(content).render(**self.context.to_dict())
            return str(rendered)
        except Exception:
            return str(content)
