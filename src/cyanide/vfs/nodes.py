import datetime
from typing import Dict


class Node:
    """Base class/Interface for all VFS nodes."""

    # Function 305: Initializes the class instance and its attributes.
    def __init__(self, name: str, parent=None, **kwargs):
        self.name = name
        self._parent = parent
        self.perm = kwargs.get("perm", "drwxr-xr-x")
        self.owner = kwargs.get("owner", "root")
        self.group = kwargs.get("group", "root")
        self.size = kwargs.get("size", 4096)
        self.mtime = kwargs.get("mtime", datetime.datetime.now())

    # Function 306: Performs operations related to parent.
    @property
    def parent(self):
        return self._parent

    # Function 307: Checks condition: is dir.
    def is_dir(self) -> bool:
        return isinstance(self, Directory)

    # Function 308: Checks condition: is file.
    def is_file(self) -> bool:
        return isinstance(self, File)


class File(Node):
    """File node for the shell emulator."""

    # Function 309: Initializes the class instance and its attributes.
    def __init__(self, name: str, parent=None, **kwargs):
        super().__init__(name, parent, **kwargs)
        if "perm" not in kwargs:
            self.perm = "-rw-r--r--"
        if "size" not in kwargs:
            self.size = 0


class Directory(Node):
    """Directory node for the shell emulator."""

    # Function 310: Initializes the class instance and its attributes.
    def __init__(self, name: str, parent=None, **kwargs):
        super().__init__(name, parent, **kwargs)
        self._children_getter = kwargs.get("children_getter", lambda: {})

    # Function 311: Performs operations related to children.
    @property
    def children(self) -> Dict[str, Node]:
        return self._children_getter()
