from pathlib import Path


def get_package_root() -> Path:
    """Return the absolute path to the cyanide package root."""
    return Path(__file__).resolve().parent.parent


def get_default_config_path() -> Path:
    """
    Search for app.yaml in:
    1. Current working directory (./configs/app.yaml)
    2. Home directory (~/.cyanide/app.yaml)
    3. Package internal (cyanide/configs/app.yaml)
    """
    # 1. Local Dev / Docker / CWD
    search_paths = [Path("src/cyanide/configs/app.yaml"), Path("configs/app.yaml")]
    for p in search_paths:
        if p.exists():
            return p

    # 2. User Home
    home_path = Path.home() / ".cyanide" / "app.yaml"
    if home_path.exists():
        return home_path

    # 3. Package Data (Fallback)
    pkg_path = get_package_root() / "configs" / "app.yaml"
    if pkg_path.exists():
        return pkg_path

    # Special case: return example if nothing found
    example_path = get_package_root() / "configs" / "app.yaml.example"
    return example_path if example_path.exists() else Path("configs/app.yaml")


def get_profiles_dir() -> Path:
    """
    Search for profiles in:
    1. Current working directory (./configs/profiles)
    2. Home directory (~/.cyanide/profiles)
    3. Package internal (cyanide/configs/profiles)
    """
    # 1. Local Dev / Docker / CWD
    search_paths = [Path("src/cyanide/configs/profiles"), Path("configs/profiles")]
    for p in search_paths:
        if p.is_dir():
            return p

    # 2. User Home
    home_path = Path.home() / ".cyanide" / "profiles"
    if home_path.is_dir():
        return home_path

    # 3. Package Data
    pkg_path = get_package_root() / "configs" / "profiles"
    return pkg_path
