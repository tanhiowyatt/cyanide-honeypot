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

class File(Node):
    """Represents a file in the filesystem."""
    def __init__(self, name: str, parent=None, content: str = "", perm: str = "-rw-r--r--", owner: str = "root", group: str = "root"):
        """Initialize a file node.
        
        Args:
            content: File content as string.
        """
        super().__init__(name, parent, perm, owner, group, len(content))
        self.content = content

class Directory(Node):
    """Represents a directory in the filesystem."""
    def __init__(self, name: str, parent=None, perm: str = "drwxr-xr-x", owner: str = "root", group: str = "root"):
        """Initialize a directory node."""
        super().__init__(name, parent, perm, owner, group, 4096)
        self.children = {}

    def add_child(self, node: Node) -> Node:
        """Add a child node to this directory.
        
        Args:
            node: Node instance (File or Directory).
            
        Returns:
            Node: The added node.
        """
        node.parent = self
        self.children[node.name] = node
        return node
        
    def get_child(self, name: str) -> Node:
        """Retrieve a direct child node by name.
        
        Args:
            name: Name of the child.
            
        Returns:
            Node: The child node if found, else None.
        """
        return self.children.get(name)
