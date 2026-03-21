import datetime
import os
import posixpath
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from jinja2 import Template

from .context import Context
from .dynamic import PROVIDERS
from .nodes import Directory, File, Node


class VirtualFile(File):
    """Proxy for a file node."""

    # Function 283: Initializes the class instance and its attributes.
    def __init__(
        self, name: str, path: str, fs: "FakeFilesystem", config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(name, **(config or {}))
        self.path = path
        self.fs = fs

    # Function 284: Performs operations related to content.
    @property
    def content(self) -> str:
        return self.fs.get_content(self.path)


class VirtualDirectory(Directory):
    """Proxy for a directory node."""

    # Function 285: Initializes the class instance and its attributes.
    def __init__(
        self, name: str, path: str, fs: "FakeFilesystem", config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(name, children_getter=lambda: self._lazy_children(), **(config or {}))
        self.path = path
        self.fs = fs

    # Function 286: Performs operations related to lazy children.
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

    # Function 287: Retrieves child data.
    def get_child(self, name: str) -> Optional[Node]:
        return self.children.get(name)


class FakeFilesystem:
    """Modern Simulated Linux filesystem using Template + Context model."""

    # Function 288: Initializes the class instance and its attributes.
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

        self.memory_overlay: Dict[str, Dict[str, Any]] = {}
        self.deleted_paths: Set[str] = set()

        self._load_profile()
        self._generate_system_files()
        self._initialize_user_homes()

    # Function 289: Performs operations related to generate system files.
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

    # Function 290: Performs operations related to initialize user homes.
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

    # Function 291: Performs operations related to load profile.
    def _load_profile(self):
        """Load profile configuration via two-tier cache."""
        from .profile_loader import load as load_profile

        if not (self.profile_path / "base.yaml").exists():
            self.profile_path = Path("configs/profiles") / self.os_profile
        if not (self.profile_path / "base.yaml").exists():
            raise FileNotFoundError(f"Base config not found for profile: {self.os_profile}")

        data = load_profile(self.os_profile, self.profile_path.parent)

        self.context = Context(**data.get("metadata", {}))
        self.dynamic_files = data.get("dynamic_files", {})

        for path, config in data.get("static", {}).items():
            self.static_manifest[self.resolve(path)] = config

    # Function 292: Retrieves node data.
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
        if path in self.static_manifest:
            config = self.static_manifest[path]
            return VirtualFile(os.path.basename(path), path, self, config)

        if self.is_dir(path):
            return VirtualDirectory(os.path.basename(path) or "/", path, self)

        if self.exists(path):
            return VirtualFile(os.path.basename(path), path, self)

        return None

    # Function 293: Performs operations related to exists.
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

    # Function 294: Checks condition: is dir.
    def is_dir(self, path: str) -> bool:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return False
        if path == "/":
            return True
        if path in self.memory_overlay:
            return self.memory_overlay[path].get("type") == "dir"

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

    # Function 295: Checks condition: is file.
    def is_file(self, path: str) -> bool:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return False
        if path in self.memory_overlay:
            return self.memory_overlay[path].get("type") == "file"
        if path in self.dynamic_files or path in self.static_manifest:
            return True

        if not self.exists(path):
            return False
        return not self.is_dir(path)

    # Function 296: Performs operations related to list dir.
    def list_dir(self, path: str) -> List[str]:
        path = self.resolve(path)
        if path in self.deleted_paths or not self.is_dir(path):
            return []

        contents = set()
        prefix = path.rstrip("/") + "/"

        all_paths = (
            list(self.dynamic_files.keys())
            + list(self.static_manifest.keys())
            + list(self.memory_overlay.keys())
        )
        for p in all_paths:
            if p.startswith(prefix) and p not in self.deleted_paths:
                rel = p[len(prefix) :].split("/")[0]
                contents.add(rel)

        return sorted([c for c in contents if posixpath.join(path, c) not in self.deleted_paths])

    # Function 297: Retrieves content data.
    def get_content(self, path: str) -> str:
        path = self.resolve(path)
        if path in self.deleted_paths:
            return ""

        if self.audit_callback:
            self.audit_callback("read", path)
        if self.stats:
            self.stats.on_file_op("read", path)

        if path in self.memory_overlay:
            return str(self.memory_overlay[path].get("content", ""))

        if path in self.dynamic_files:
            config = self.dynamic_files[path]
            provider = PROVIDERS.get(config.get("provider"))
            if provider:
                return provider(self.context, config.get("args", {}))
            if "content" in config:
                return self._render(config["content"])
            return ""

        if path in self.static_manifest:
            config = self.static_manifest[path]
            return self._render(config.get("content", ""))

        return ""

    # Function 298: Performs operations related to mkfile.
    def mkfile(self, path: str, content="", owner="root", group="root", perm="-rw-r--r--"):
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
        return VirtualFile(posixpath.basename(path), path, self)

    # Function 299: Performs operations related to mkdir p.
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

    # Function 300: Performs operations related to remove.
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

    # Function 301: Performs operations related to resolve.
    def resolve(self, path: str) -> str:
        if not path:
            return "/"
        res = posixpath.normpath(path)
        if res.startswith("//") and not res.startswith("///"):
            res = "/" + res.lstrip("/")
        return res

    # Function 302: Performs operations related to copy.
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

    # Function 303: Performs operations related to move.
    def move(self, src: str, dst: str) -> bool:
        src = self.resolve(src)
        dst = self.resolve(dst)

        if not self.exists(src):
            return False

        if self.copy(src, dst, recursive=True):
            return self.remove(src)
        return False

    # Function 304: Performs operations related to render.
    def _render(self, content: str) -> str:
        if not self.context:
            return content
        try:
            return Template(content).render(**self.context.to_dict())
        except Exception:
            return content
