import datetime

class Node:
    """Base class for filesystem nodes.
    
    Attributes:
        name (str): Name of the node.
        parent (Node): Parent directory node.
        perm (str): File permissions string (e.g., 'drwxr-xr-x').
        owner (str): Owner username.
        group (str): Group name.
        size (int): Size in bytes.
        mtime (datetime): Modification time.
    """
    def __init__(self, name: str, parent=None, perm: str = "drwxr-xr-x", owner: str = "root", group: str = "root", size: int = 4096):
        self.name = name
        self.parent = parent
        self.perm = perm
        self.owner = owner
        self.group = group
        self.size = size
        self.mtime = datetime.datetime.now()

    @property
    def path(self) -> str:
        """Calculate the absolute path of this node.
        
        Returns:
            str: Absolute path string.
        """
        if self.parent is None:
            return "/"
        if self.parent.path == "/":
            return f"/{self.name}"
        return f"{self.parent.path}/{self.name}"

    def to_dict(self) -> dict:
        """Serialize node to dictionary (safe primitive)."""
        return {
            "name": self.name,
            "type": "node",
            "perm": self.perm,
            "owner": self.owner,
            "group": self.group,
            "size": self.size,
            "mtime": self.mtime.timestamp()
        }

    @staticmethod
    def from_dict(data: dict) -> 'Node':
        """Reconstruct node from dictionary."""
        # This base method is rarely used directly, seeing as we usually instantiate File or Directory
        name = data.get("name", "")
        node = Node(name)
        node.perm = data.get("perm", "drwxr-xr-x")
        node.owner = data.get("owner", "root")
        node.group = data.get("group", "root")
        node.size = data.get("size", 4096)
        if "mtime" in data:
            node.mtime = datetime.datetime.fromtimestamp(data["mtime"])
        return node
    
class File(Node):
    """Represents a file in the filesystem."""
    def __init__(self, name: str, parent=None, content: str = "", perm: str = "-rw-r--r--", owner: str = "root", group: str = "root"):
        """Initialize a file node."""
        super().__init__(name, parent, perm, owner, group, len(content))
        self.content = content

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["type"] = "file"
        d["content"] = self.content
        return d

    @staticmethod
    def from_dict(data: dict) -> 'File':
        name = data.get("name", "unknown")
        content = data.get("content", "")
        f = File(name, content=content)
        f.perm = data.get("perm", "-rw-r--r--")
        f.owner = data.get("owner", "root")
        f.group = data.get("group", "root")
        if "mtime" in data:
            f.mtime = datetime.datetime.fromtimestamp(data["mtime"])
        return f

class DynamicFile(File):
    """File with dynamically generated content."""
    def __init__(self, name: str, generator, parent=None, perm: str = "-r--r--r--", owner: str = "root", group: str = "root"):
        super().__init__(name, parent, "", perm, owner, group)
        self.generator = generator

    @property
    def content(self) -> str:
        """Generate content on read."""
        try:
            return self.generator()
        except Exception:
            return ""

    @content.setter
    def content(self, value):
        pass # Read-only generator

class Directory(Node):
    """Represents a directory in the filesystem."""
    def __init__(self, name: str, parent=None, perm: str = "drwxr-xr-x", owner: str = "root", group: str = "root"):
        """Initialize a directory node."""
        super().__init__(name, parent, perm, owner, group, 4096)
        self.children = {}

    def add_child(self, node: Node) -> Node:
        """Add a child node to this directory."""
        node.parent = self
        self.children[node.name] = node
        return node
        
    def get_child(self, name: str) -> Node:
        """Retrieve a direct child node by name."""
        return self.children.get(name)

    def remove_child(self, name: str) -> bool:
        """Remove a child node by name.
        
        Args:
            name: Name of the child to remove.
            
        Returns:
            bool: True if removed, False if not found.
        """
        if name in self.children:
            del self.children[name]
            return True
        return False

    def to_dict(self) -> dict:
        d = super().to_dict()
        d["type"] = "dir"
        d["children"] = [child.to_dict() for child in self.children.values()]
        return d

    @staticmethod
    def from_dict(data: dict) -> 'Directory':
        name = data.get("name", "unknown")
        d = Directory(name)
        d.perm = data.get("perm", "drwxr-xr-x")
        d.owner = data.get("owner", "root")
        d.group = data.get("group", "root")
        if "mtime" in data:
            d.mtime = datetime.datetime.fromtimestamp(data["mtime"])
            
        for child_data in data.get("children", []):
            ctype = child_data.get("type")
            if ctype == "file":
                child_node = File.from_dict(child_data)
            elif ctype == "dir":
                child_node = Directory.from_dict(child_data)
            else:
                continue
            d.add_child(child_node)
            
        return d
