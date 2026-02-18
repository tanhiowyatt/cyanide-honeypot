import random
from pathlib import Path
from typing import Tuple

import yaml

# Built-in profiles that ship with the project
BUILTIN_PROFILES = {
    "ubuntu_22_04": "fs.ubuntu_22_04.yaml",
    "debian_11": "fs.debian_11.yaml",
    "centos_7": "fs.centos_7.yaml",
}


def get_fs_config_dir() -> Path:
    """Return the absolute path to the config/fs-config directory."""
    # current file is src/cyanide/core/fs_utils.py
    # we need project_root/configs/profiles
    current_dir = Path(__file__).parent
    # Go up 3 levels: core -> cyanide -> src -> root
    root_dir = current_dir.parent.parent.parent
    return root_dir / "configs" / "profiles"


def validate_fs_config(path: Path) -> Tuple[bool, str]:
    """
    Validate that a filesystem YAML file is correct.
    Returns (is_valid, error_message).
    """
    if not path.exists():
        return False, f"File not found: {path}"

    if not path.is_file():
        return False, f"Not a file: {path}"

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            return False, "Root element must be a dictionary (YAML object)"

        # Basic schema check (root node must have type)
        if "type" not in data:
            return False, "Missing required field: 'type' (must be 'directory' for root)"

        if data.get("type") != "directory":
            return False, "Root node must be of type 'directory'"

        return True, ""
    except yaml.YAMLError as e:
        return False, f"YAML syntax error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"


def resolve_fs_path(profile_name: str) -> str:
    """
    Resolve the path to the filesystem YAML based on profile name.

    Logic:
    1. If profile matches a built-in, use the built-in file.
    2. If profile is 'random', pick a random available FS (built-ins + custom).
    3. Otherwise, treat profile as a filename (with or without extension).
    """
    fs_dir = get_fs_config_dir()

    # 1. Built-in Profile
    if profile_name in BUILTIN_PROFILES:
        return str(fs_dir / BUILTIN_PROFILES[profile_name])

    # 2. Random Selection
    if profile_name == "random":
        # Gather all valid YAMLs
        candidates = []

        # Add built-ins if they exist
        for builtin_file in BUILTIN_PROFILES.values():
            p = fs_dir / builtin_file
            if p.exists():
                candidates.append(str(p))

        # Add custom ones (any other .yaml file in directory)
        # Requirement: "When OS_PROFILE=random... randomly select from ALL... built-in AND custom"
        if fs_dir.exists():
            for f in fs_dir.glob("*.yaml"):
                if f.name not in BUILTIN_PROFILES.values():
                    candidates.append(str(f))

        if not candidates:
            # Fallback to default if absolutely nothing found
            return str(fs_dir / "fs.ubuntu_22_04.yaml")

        return random.choice(candidates)

    # 3. Custom Profile / Filename
    # Try as exact filename in fs-config
    p = fs_dir / profile_name
    if p.exists():
        return str(p)

    # Try with .yaml extension if missing
    if not profile_name.endswith(".yaml"):
        p = fs_dir / f"{profile_name}.yaml"
        if p.exists():
            return str(p)

        # Try with fs. prefix and .yaml
        p = fs_dir / f"fs.{profile_name}.yaml"
        if p.exists():
            return str(p)

    # Try as absolute path
    p = Path(profile_name)
    if p.is_absolute() and p.exists():
        return str(p)

    # Failed to resolve
    # Return a fallback but also maybe we should assume the caller will handle file-not-found
    # Returning the attempted path "as is" allows the caller to try opening it and fail with standard error
    return str(fs_dir / f"fs.{profile_name}.yaml")
