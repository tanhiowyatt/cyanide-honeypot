import pickle
from core.filesystem_nodes import Node

def save_fs(root_node: Node, path: str):
    """Serialize the filesystem tree to a pickle file."""
    with open(path, 'wb') as f:
        pickle.dump(root_node, f)

def load_fs(path: str) -> Node:
    """Load the filesystem tree from a pickle file.
    
    Returns:
        Node: The root node of the filesystem.
    """
    with open(path, 'rb') as f:
        return pickle.load(f)
