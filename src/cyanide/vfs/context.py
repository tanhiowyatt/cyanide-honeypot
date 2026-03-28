from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass
class Context:
    """Global system metadata context for VFS templates and providers."""

    os_name: str
    kernel_version: str
    hostname: str
    arch: str
    ssh_banner: str = "SSH-2.0-OpenSSH_8.0"
    version_id: str = ""
    os_id: str = ""
    install_date: str = ""

    # Function 280: Performs operations related to to dict.
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for Jinja2 rendering."""
        return asdict(self)
