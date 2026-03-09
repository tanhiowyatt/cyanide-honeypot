import hashlib
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import msgpack
import yaml

logger = logging.getLogger("cyanide.vfs.profile_loader")

# In-memory thread-safe cache
_MEMORY_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_LOCK = threading.Lock()

CACHE_FORMAT_VERSION = 2
COMPILED_FILE_NAME = ".compiled.msgpack"


def _compute_hash(base_file: Path, static_file: Path) -> str:
    """Compute SHA-256 hash of base.yaml and static.yaml contents."""
    h = hashlib.sha256()

    if base_file.exists():
        with open(base_file, "rb") as f:
            h.update(f.read())

    if static_file.exists():
        with open(static_file, "rb") as f:
            h.update(f.read())

    return h.hexdigest()


def _parse_yaml_profile(base_file: Path, static_file: Path) -> Dict[str, Any]:
    """Parse profile from YAML files."""
    if not base_file.exists():
        raise FileNotFoundError(f"Base config not found: {base_file}")

    with open(base_file, "r", encoding="utf-8") as f:
        base_data = yaml.safe_load(f) or {}

    metadata = base_data.get("metadata", {})
    dynamic_files = base_data.get("dynamic_files", {})
    static_manifest = {}

    if static_file.exists():
        with open(static_file, "r", encoding="utf-8") as f:
            static_data = yaml.safe_load(f) or {}
            raw_static = static_data.get("static", {})
            for path, config in raw_static.items():
                static_manifest[path] = config

    return {
        "metadata": metadata,
        "dynamic_files": dynamic_files,
        "static": static_manifest,
    }


def load(profile_name: str, profiles_dir: Path) -> Dict[str, Any]:
    """
    Load profile data with two-tier caching.
    Order:
      1. Memory cache
      2. Disk cache (.compiled.msgpack)
      3. YAML parse
    """
    base_file = profiles_dir / profile_name / "base.yaml"
    static_file = profiles_dir / profile_name / "static.yaml"
    compiled_file = profiles_dir / profile_name / COMPILED_FILE_NAME

    # Always compute target hash to check against cache validity
    # This ensures auto-invalidation if file is modified during dev
    target_hash = _compute_hash(base_file, static_file)

    with _CACHE_LOCK:
        # 1. Try Memory Cache
        if profile_name in _MEMORY_CACHE:
            cached_data = _MEMORY_CACHE[profile_name]
            if (
                cached_data.get("hash") == target_hash
                and cached_data.get("v") == CACHE_FORMAT_VERSION
            ):
                logger.debug(f"Profile '{profile_name}' loaded from memory cache.")
                return cached_data

        # 2. Try Disk Cache
        if compiled_file.exists():
            try:
                with open(compiled_file, "rb") as f:
                    disk_data = msgpack.unpack(f, raw=False)

                if isinstance(disk_data, dict):
                    if (
                        disk_data.get("hash") == target_hash
                        and disk_data.get("v") == CACHE_FORMAT_VERSION
                    ):
                        logger.debug(f"Profile '{profile_name}' loaded from disk cache.")
                        _MEMORY_CACHE[profile_name] = disk_data
                        return disk_data
            except Exception as e:
                logger.warning(
                    f"Failed to load disk cache for '{profile_name}': {e}. Rebuilding..."
                )

        # 3. Cache Miss (Parse YAML)
        logger.info(f"Parsing YAML for profile '{profile_name}'...")
        parsed_data = _parse_yaml_profile(base_file, static_file)

        cache_entry = {
            "v": CACHE_FORMAT_VERSION,
            "hash": target_hash,
            "ts": time.time(),
            "metadata": parsed_data["metadata"],
            "dynamic_files": parsed_data["dynamic_files"],
            "static": parsed_data["static"],
        }

        # Save to Memory
        _MEMORY_CACHE[profile_name] = cache_entry

        # Save to Disk
        try:
            compiled_file.parent.mkdir(parents=True, exist_ok=True)
            with open(compiled_file, "wb") as f:
                msgpack.pack(cache_entry, f, use_bin_type=True)
            logger.debug(f"Saved disk cache for profile '{profile_name}'.")
        except Exception as e:
            logger.error(f"Failed to write disk cache for '{profile_name}': {e}")

        return cache_entry


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
