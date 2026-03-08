import datetime
import os
import posixpath
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml
from jinja2 import Template

from .context import Context
from .dynamic import PROVIDERS
from .nodes import Directory, File, Node


class VirtualFile(File):
    """Proxy for a file node."""

    def __init__(self, name: str, path: str, fs: "FakeFilesystem", config: Optional[Dict[str, Any]] = None):
        super().__init__(name, **(config or {}))
        self.path = path
        self.fs = fs

    @property
    def content(self) -> str:
        return self.fs.get_content(self.path)


class VirtualDirectory(Directory):
    """Proxy for a directory node."""

    def __init__(self, name: str, path: str, fs: "FakeFilesystem", config: Optional[Dict[str, Any]] = None):
        # Pass a lambda to nodes.Directory to lazy-load children
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
        root_dir: str = "/app/configs/profiles",
        audit_callback=None,
        stats=None,
        users: Optional[List[Dict[str, Any]]] = None,
    ):
        self.root_dir = Path(root_dir)
        self.audit_callback = audit_callback
        self.stats = stats
        self.users = users or []

        self.os_profile = str(os_profile or os.getenv("OS_PROFILE", "ubuntu"))
        self.profile_path = self.root_dir / self.os_profile

        self.context: Optional[Context] = None
        self.dynamic_files: Dict[str, Any] = {}
        self.static_manifest: Dict[str, Any] = {}

        # Memory Layer (Writes during session)
        self.memory_overlay: Dict[str, Dict[str, Any]] = {}
        self.deleted_paths: Set[str] = set()

        self._load_profile()
        self._generate_system_files()
        self._initialize_user_homes()

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

        # Add configured users
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

    def _initialize_user_homes(self):
        """Automatically create /home/[user] for all configured users."""
        # First, ensure /home exists
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
        """Load profile configuration."""
        base_file = self.profile_path / "base.yaml"
        if not base_file.exists():
            # Fallback to current directory for local tests/dev
            self.profile_path = Path("configs/profiles") / self.os_profile
            base_file = self.profile_path / "base.yaml"

        if not base_file.exists():
            raise FileNotFoundError(f"Base config not found for profile: {self.os_profile}")

        with open(base_file, "r") as f:
            base_data = yaml.safe_load(f)

        meta = base_data.get("metadata", {})
        self.context = Context(**meta)
        self.dynamic_files = base_data.get("dynamic_files", {})

        static_file = self.profile_path / "static.yaml"
        if static_file.exists():
            with open(static_file, "r") as f:
                static_data = yaml.safe_load(f) or {}
                raw_static = static_data.get("static", {})
                for path, config in raw_static.items():
                    self.static_manifest[self.resolve(path)] = config

    def get_node(self, path: str) -> Optional[Node]:
        """Backward compatible node retrieval."""
        path = self.resolve(path)
        if path in self.deleted_paths:
            return None

        # 1. Check Memory Overlay
        if path in self.memory_overlay:
            config = self.memory_overlay[path]
            return (
                VirtualDirectory(os.path.basename(path), path, self, config)
                if config.get("type") == "dir"
                else VirtualFile(os.path.basename(path), path, self, config)
            )

        # 2. Check Static/Dynamic Manifests
        if path in self.dynamic_files:
            return VirtualFile(os.path.basename(path), path, self, self.dynamic_files[path])
        if path in self.static_manifest:
            config = self.static_manifest[path]
            return VirtualFile(os.path.basename(path), path, self, config)

        # 3. Check Patterns & Directory structure
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
            or path in self.static_manifest
        ):
            return True

        # Parent directories of any defined file
        all_paths = (
            list(self.dynamic_files.keys())
            + list(self.static_manifest.keys())
            + list(self.memory_overlay.keys())
        )
        prefix = path.rstrip("/") + "/"
        for p in all_paths:
            if p.startswith(prefix):
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

        # If it's a parent of any file, it's a dir
        all_paths = (
            list(self.dynamic_files.keys())
            + list(self.static_manifest.keys())
            + list(self.memory_overlay.keys())
        )
        prefix = path.rstrip("/") + "/"
        for p in all_paths:
            if p.startswith(prefix):
                return True
        return False

    def is_file(self, path: str) -> bool:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return False
        if path in self.memory_overlay:
            return self.memory_overlay[path].get("type") == "file"
        if path in self.dynamic_files or path in self.static_manifest:
            return True

        # Pattern check - must exist and not be a dir
        if not self.exists(path):
            return False
        return not self.is_dir(path)

    def list_dir(self, path: str) -> List[str]:
        path = self.resolve(path)
        if path in self.deleted_paths or not self.is_dir(path):
            return []

        contents = set()
        prefix = path.rstrip("/") + "/"

        # 1. Memory and Manifest
        all_paths = (
            list(self.dynamic_files.keys())
            + list(self.static_manifest.keys())
            + list(self.memory_overlay.keys())
        )
        for p in all_paths:
            if p.startswith(prefix) and p not in self.deleted_paths:
                rel = p[len(prefix) :].split("/")[0]
                contents.add(rel)

        # Remove deleted items that might have been added by parent logic
        return sorted([c for c in contents if posixpath.join(path, c) not in self.deleted_paths])

    def get_content(self, path: str) -> str:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return ""

        if self.audit_callback:
            self.audit_callback("read", path)
        if self.stats:
            self.stats.on_file_op("read", path)

        # 1. Memory Overlay
        if path in self.memory_overlay:
            return str(self.memory_overlay[path].get("content", ""))

        # 2. Dynamic Files
        if path in self.dynamic_files:
            config = self.dynamic_files[path]
            provider = PROVIDERS.get(config.get("provider"))
            if provider:
                return provider(self.context, config.get("args", {}))
            if "content" in config:
                return self._render(config["content"])
            return ""

        # 3. Static Manifest
        if path in self.static_manifest:
            config = self.static_manifest[path]
            return self._render(config.get("content", ""))

        return ""

    def mkfile(self, path: str, content="", owner="root", group="root", perm="-rw-r--r--"):
        path = self.resolve(path)
        parent_path = posixpath.dirname(path)
        if parent_path != path:  # Not root
            if not self.exists(parent_path) or not self.is_dir(parent_path):
                return None

        self.memory_overlay[path] = {
            "type": "file",
            "content": content,
            "owner": owner,
            "group": group,
            "perm": perm,
            "mtime": datetime.datetime.now(),
        }
        if path in self.deleted_paths:
            self.deleted_paths.remove(path)
        if self.stats:
            self.stats.on_file_op("write", path)
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
            self.audit_callback("delete", path)
        if self.stats:
            self.stats.on_file_op("delete", path)
        return True

    def resolve(self, path: str) -> str:
        if not path:
            return "/"
        res = posixpath.normpath(path)
        # posixpath.normpath might preserve // on some platforms
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

            # Recursive copy of a directory
            if not self.exists(dst):
                self.mkdir_p(dst)
            elif self.is_file(dst):
                return False  # Cannot copy dir over file

            for item in self.list_dir(src):
                self.copy(posixpath.join(src, item), posixpath.join(dst, item), recursive=True)
            return True
        else:
            # File copy
            content = self.get_content(src)
            # If dst is a dir, copy INTO it
            if self.exists(dst) and self.is_dir(dst):
                dst = posixpath.join(dst, posixpath.basename(src))

            self.mkfile(dst, content=content)
            return True

    def move(self, src: str, dst: str) -> bool:
        src = self.resolve(src)
        dst = self.resolve(dst)

        if not self.exists(src):
            return False

        # Implementation: copy then remove
        if self.copy(src, dst, recursive=True):
            return self.remove(src)
        return False

    def _render(self, content: str) -> str:
        if not self.context:
            return content
        try:
            return Template(content).render(**self.context.to_dict())
        except Exception:
            return content
