import datetime
import hashlib
import logging
import os
import posixpath
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Optional, cast

import yaml

logger = logging.getLogger("cyanide.vfs.profile_loader")

_MEMORY_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_LOCK = threading.RLock()

CACHE_FORMAT_VERSION = 3  # Increment version for SQLite migration
COMPILED_DB_NAME = ".compiled.db"


# Function 312: Performs operations related to compute hash.
def _compute_hash(base_file: Path, static_file: Path, rootfs_dir: Optional[Path] = None) -> str:
    """Compute SHA-256 hash of base.yaml, static.yaml, and optionally rootfs/ contents."""
    h = hashlib.sha256()

    if base_file.exists():
        with open(base_file, "rb") as f:
            h.update(f.read())

    if static_file.exists():
        with open(static_file, "rb") as f:
            h.update(f.read())

    if rootfs_dir and rootfs_dir.exists():
        # For large directories, we only hash the mtime of the directory
        # to detect changes quickly without a full scan
        h.update(str(rootfs_dir.stat().st_mtime).encode())

    return h.hexdigest()


def _scan_filesystem(rootfs_dir: Path) -> Dict[str, Any]:
    """Recursively scan a directory to build a VFS manifest."""
    manifest = {}

    for root, dirs, files in os.walk(rootfs_dir):
        # Create directories
        for d in dirs:
            abs_path = Path(root) / d
            rel_path = "/" + str(abs_path.relative_to(rootfs_dir))
            stat = abs_path.stat()
            manifest[rel_path] = {
                "type": "dir",
                "owner": "root",
                "group": "root",
                "perm": "drwxr-xr-x",
                "size": stat.st_size,
                "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }

        # Create files
        for f in files:
            abs_path = Path(root) / f
            rel_path = "/" + str(abs_path.relative_to(rootfs_dir))
            stat = abs_path.stat()

            content = b""
            try:
                if stat.st_size < 10 * 1024 * 1024:  # 10MB limit for direct inclusion
                    with open(abs_path, "rb") as f_in:
                        content = f_in.read()
            except Exception as e:
                logger.warning(f"Failed to read {abs_path}: {e}")

            manifest[rel_path] = {
                "type": "file",
                "content": content,
                "owner": "root",
                "group": "root",
                "perm": "-rw-r--r--",
                "size": stat.st_size,
                "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }

    return manifest


def _compile_to_sqlite(manifest: Dict[str, Any], db_path: Path, target_hash: str):
    """Compile a manifest into a SQLite database."""
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE vfs (
                path TEXT PRIMARY KEY,
                parent_path TEXT,
                name TEXT,
                type TEXT,
                content BLOB,
                owner TEXT,
                group_name TEXT,
                perm TEXT,
                size INTEGER,
                mtime TEXT
            )
        """)
        conn.execute("CREATE INDEX idx_parent ON vfs(parent_path)")
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO metadata (key, value) VALUES ('hash', ?)", (target_hash,))
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES ('v', ?)", (str(CACHE_FORMAT_VERSION),)
        )

        for path, config in manifest.items():
            name = posixpath.basename(path) or "/"
            parent = posixpath.dirname(path)

            content = config.get("content", b"")
            if isinstance(content, str):
                content = content.encode("utf-8")

            conn.execute(
                """
                INSERT INTO vfs (path, parent_path, name, type, content, owner, group_name, perm, size, mtime)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    path,
                    parent,
                    name,
                    config.get("type", "file"),
                    content,
                    config.get("owner", "root"),
                    config.get("group", "root"),
                    config.get("perm", "-rw-r--r--"),
                    config.get("size", len(content)),
                    config.get("mtime", datetime.datetime.now().isoformat()),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _handle_list_node(flat_map: Dict[str, Any], path: str, items: list):
    """Handle a list of names as empty files in a directory."""
    flat_map[path] = {"type": "dir", "content": ""}
    for item in items:
        item_path = f"{path}/{item}".replace("//", "/")
        flat_map[item_path] = {"content": "", "type": "file"}


def _handle_dict_node(flat_map: Dict[str, Any], path: str, value: Dict[str, Any]):
    """Handle a dictionary node (either a file with config or a subdirectory)."""
    if "content" in value or "provider" in value:
        if "type" not in value:
            value["type"] = "file"
        flat_map[path] = value
    else:
        flat_map[path] = {"type": "dir", "content": ""}
        flat_map.update(_flatten_nodes(value, path))


# Function 312.1: Recursively flattens a nested dictionary of VFS nodes into a flat path map.
def _flatten_nodes(nodes: Dict[str, Any], current_path: str = "") -> Dict[str, Any]:
    """
    Converts: { "etc": { "passwd": "..." } }
    Into: { "/etc/passwd": { "content": "..." } }
    """
    flat_map: Dict[str, Any] = {}
    for name, value in nodes.items():
        path = f"{current_path}/{name.lstrip('/')}".replace("//", "/")

        if isinstance(value, str):
            flat_map[path] = {"content": value, "type": "file"}
        elif isinstance(value, list):
            _handle_list_node(flat_map, path, value)
        elif isinstance(value, dict):
            _handle_dict_node(flat_map, path, value)
        else:
            logger.warning(f"Unexpected value type for node '{path}': {type(value)}")

    return flat_map


def _parse_tree_folders(static_manifest: Dict[str, Any], tree_folders: Any):
    """Update manifest with directories from tree_folders string."""
    if isinstance(tree_folders, str) and tree_folders:
        for folder in tree_folders.split():
            if folder != "/":
                static_manifest[folder] = {"content": "", "type": "dir"}


def _parse_static_content(static_manifest: Dict[str, Any], raw_static: Dict[str, Any]):
    """Update manifest with explicit static file entries."""
    for path, config in raw_static.items():
        if isinstance(config, str):
            static_manifest[path] = {"content": config, "type": "file"}
        else:
            if "type" not in config:
                config["type"] = "file"
            static_manifest[path] = config


def _parse_generators(static_manifest: Dict[str, Any], generators: list):
    """Update manifest with generated file sequences."""
    for gen in generators:
        path_tmpl = gen.get("path", "")
        name_tmpl = gen.get("template", gen.get("pattern", ""))
        count = gen.get("count", 0)
        content = gen.get("content", "")

        if path_tmpl and name_tmpl and count > 0:
            static_manifest[path_tmpl] = {"type": "dir", "content": ""}
            for i in range(count):
                full_path = f"{path_tmpl}/{name_tmpl}".format(i=i).replace("//", "/")
                static_manifest[full_path] = {
                    "content": content.format(i=i) if content else "",
                    "type": "file",
                }


# Function 313: Performs operations related to parse yaml profile.
def _parse_yaml_profile(base_file: Path, static_file: Path) -> Dict[str, Any]:
    """Parse profile from YAML files with support for hierarchical and flat formats."""
    if not base_file.exists():
        raise FileNotFoundError(f"Base config not found: {base_file}")

    with open(base_file, "r", encoding="utf-8") as f:
        base_data = yaml.safe_load(f) or {}

    metadata = base_data.get("metadata", {})
    dynamic_files = base_data.get("dynamic_files", {})
    static_manifest: Dict[str, Any] = {}

    # 1. Base tree folders
    _parse_tree_folders(static_manifest, base_data.get("static_files", {}).get("tree_folders"))

    # 2. Static data from static.yaml
    if static_file.exists():
        with open(static_file, "r", encoding="utf-8") as f:
            static_data = yaml.safe_load(f) or {}

            # Explicit static map
            _parse_static_content(static_manifest, static_data.get("static", {}))

            # Helper tree folders
            sh_data = static_data.get("static_files", {})
            _parse_tree_folders(static_manifest, sh_data.get("tree_folders"))

            # Hierarchical nodes
            nodes = sh_data.get("nodes", static_data.get("nodes", {}))
            if nodes:
                static_manifest.update(_flatten_nodes(nodes))

            # Template generators
            _parse_generators(
                static_manifest, sh_data.get("generators", static_data.get("generators", []))
            )

    return {
        "metadata": metadata,
        "dynamic_files": dynamic_files,
        "static": static_manifest,
    }


def _check_memory_cache(profile_name: str, target_hash: str) -> Optional[Dict[str, Any]]:
    """Return memory-cached profile if valid."""
    if profile_name in _MEMORY_CACHE:
        cached_data = _MEMORY_CACHE[profile_name]
        if cached_data.get("hash") == target_hash and cached_data.get("v") == CACHE_FORMAT_VERSION:
            return cached_data
    return None


def _check_disk_cache(
    profile_name: str, compiled_db: Path, target_hash: str, base_file: Path
) -> Optional[Dict[str, Any]]:
    """Return disk-cached profile metadata if valid."""
    if not compiled_db.exists():
        return None

    try:
        conn = sqlite3.connect(compiled_db)
        try:
            cursor = conn.execute("SELECT value FROM metadata WHERE key = 'hash'")
            db_hash = cursor.fetchone()
            cursor = conn.execute("SELECT value FROM metadata WHERE key = 'v'")
            db_v = cursor.fetchone()

            if (
                db_hash
                and db_hash[0] == target_hash
                and db_v
                and db_v[0] == str(CACHE_FORMAT_VERSION)
            ):
                logger.info(f"Profile '{profile_name}' loaded from SQLite cache.")

                metadata, dynamic_files = {}, {}
                if base_file.exists():
                    with open(base_file, "r") as f:
                        base_data = yaml.safe_load(f) or {}
                        metadata = base_data.get("metadata", {})
                        dynamic_files = base_data.get("dynamic_files", {})

                return {
                    "v": CACHE_FORMAT_VERSION,
                    "hash": target_hash,
                    "backend_path": str(compiled_db),
                    "metadata": metadata,
                    "dynamic_files": dynamic_files,
                }
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"Failed to check SQLite cache for '{profile_name}': {e}")
    return None


def _build_manifest(
    profile_name: str, rootfs_dir: Path, base_file: Path, static_file: Path, profiles_dir: Path
) -> Dict[str, Any]:
    """Import rootfs or compile YAML into a VFS manifest."""
    if rootfs_dir.exists():
        logger.info(f"Importing rootfs snapshot for '{profile_name}'...")
        return _scan_filesystem(rootfs_dir)

    if base_file.exists():
        logger.info(f"Compiling YAML manifest to SQLite for '{profile_name}'...")
        return cast(Dict[str, Any], _parse_yaml_profile(base_file, static_file)["static"])

    raise FileNotFoundError(f"No valid profile source found for '{profile_name}' in {profiles_dir}")


# Function 314: Performs operations related to load.
def load(profile_name: str, profiles_dir: Path) -> Dict[str, Any]:
    """
    Load profile data using SQLite backend.
    Order: 1. Memory cache, 2. Disk cache, 3. Rebuild (from rootfs/ or YAML)
    """
    profile_path = profiles_dir / profile_name
    base_file, static_file = profile_path / "base.yaml", profile_path / "static.yaml"
    rootfs_dir, compiled_db = profile_path / "rootfs", profile_path / COMPILED_DB_NAME

    target_hash = _compute_hash(base_file, static_file, rootfs_dir)

    with _CACHE_LOCK:
        # 1. & 2. Cache Checks
        res = _check_memory_cache(profile_name, target_hash) or _check_disk_cache(
            profile_name, compiled_db, target_hash, base_file
        )
        if res:
            _MEMORY_CACHE[profile_name] = res
            return res

        # 3. Rebuild Cache
        logger.info(f"Rebuilding SQLite VFS cache for profile '{profile_name}'...")
        manifest = _build_manifest(profile_name, rootfs_dir, base_file, static_file, profiles_dir)
        _compile_to_sqlite(manifest, compiled_db, target_hash)

        return load(profile_name, profiles_dir)


# Function 315: Invalidates data or cache.
def invalidate(profile_name: Optional[str] = None) -> None:
    """Clear memory cache. Disk cache is self-invalidating via hash."""
    with _CACHE_LOCK:
        if profile_name:
            if profile_name in _MEMORY_CACHE:
                del _MEMORY_CACHE[profile_name]
                logger.debug(f"Invalidated memory cache for profile '{profile_name}'.")
        else:
            _MEMORY_CACHE.clear()
            logger.debug("Invalidated all memory caches.")
