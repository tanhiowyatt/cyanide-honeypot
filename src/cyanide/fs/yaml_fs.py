#!/usr/bin/env python3
import os
from typing import Any, Dict

import yaml

from cyanide.core.defaults import DEFAULT_METADATA
from cyanide.vfs.nodes import Directory, File


def dict_to_node(data: Dict[str, Any], parent=None):
    """Reconstructs filesystem node from dictionary."""
    if data["type"] == "file":
        return File(
            name=data["name"],
            parent=parent,
            content=data.get("content", ""),
            perm=data.get("perm", "-rw-r--r--"),
            owner=data.get("owner", "root"),
            group=data.get("group", "root"),
        )
    elif data["type"] == "directory":
        dir_node = Directory(
            name=data["name"],
            parent=parent,
            perm=data.get("perm", "drwxr-xr-x"),
            owner=data.get("owner", "root"),
            group=data.get("group", "root"),
        )
        for child_data in data.get("children", []):
            child_node = dict_to_node(child_data, parent=dir_node)
            dir_node.add_child(child_node)
        return dir_node

    raise ValueError(f"Unknown node type: {data.get('type')}")


def load_fs(path: str):
    """Loads filesystem and metadata from YAML.

    Returns:
        tuple: (Directory, dict) containing root node and metadata.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Filesystem file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    metadata = DEFAULT_METADATA.copy()
    if "metadata" in data:
        metadata.update(data.pop("metadata"))

    print(f"DEBUG: load_fs loaded YAML from {path}. Metadata: {list(metadata.keys())}")

    return dict_to_node(data), metadata
