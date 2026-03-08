import datetime
from typing import Dict


class Node:
    """Base class/Interface for all VFS nodes."""

    def __init__(self, name: str, parent=None, **kwargs):
        self.name = name
        self._parent = parent
        self.perm = kwargs.get("perm", "drwxr-xr-x")
        self.owner = kwargs.get("owner", "root")
        self.group = kwargs.get("group", "root")
        self.size = kwargs.get("size", 4096)
        self.mtime = kwargs.get("mtime", datetime.datetime.now())

    @property
    def parent(self):
        return self._parent

    def is_dir(self) -> bool:
        return isinstance(self, Directory)

    def is_file(self) -> bool:
        return isinstance(self, File)


class File(Node):
    """File node for the shell emulator."""

    def __init__(self, name: str, parent=None, **kwargs):
        super().__init__(name, parent, **kwargs)
        if "perm" not in kwargs:
            self.perm = "-rw-r--r--"
        if "size" not in kwargs:
            self.size = 0


class Directory(Node):
    """Directory node for the shell emulator."""

    def __init__(self, name: str, parent=None, **kwargs):
        super().__init__(name, parent, **kwargs)
        self._children_getter = kwargs.get("children_getter", lambda: {})

    @property
    def children(self) -> Dict[str, Node]:
        return self._children_getter()  # type: ignore
