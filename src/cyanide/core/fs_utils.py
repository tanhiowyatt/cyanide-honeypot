import random
from pathlib import Path
from typing import List


# Function 29: Retrieves fs config dir data.
def get_fs_config_dir() -> Path:
    """Return the absolute path to the configs/profiles directory."""
    current_file = Path(__file__).resolve()
    root_dir = current_file.parents[3]

    candidates = [root_dir / "configs", Path.cwd() / "configs", Path("/app/configs")]
    for cand in candidates:
        if cand.exists():
            return cand / "profiles"

    return root_dir / "configs" / "profiles"


# Function 30: Performs operations related to list profiles.
def list_profiles() -> List[str]:
    """List all available OS profiles (subdirectories in configs/profiles)."""
    fs_dir = get_fs_config_dir()
    if not fs_dir.exists():
        return ["ubuntu"]

    profiles = []
    for item in fs_dir.iterdir():
        if item.is_dir() and (item / "base.yaml").exists():
            profiles.append(item.name)

    return profiles or ["ubuntu"]


# Function 31: Performs operations related to resolve os profile.
def resolve_os_profile(profile_name: str) -> str:
    """
    Resolve the OS profile name.

    If profile is 'random', pick a random available profile.
    Otherwise, return the profile name if it exists.
    """
    profiles = list_profiles()

    if profile_name == "random":
        return random.choice(profiles)

    if profile_name in profiles:
        return profile_name

    return "ubuntu"
