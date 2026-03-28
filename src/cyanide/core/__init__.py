"""
Cyanide Core Engine
-------------------
Heart of the honeypot, containing the server, shell emulator, and filesystem logic.
"""

from .config import load_config

__all__ = ["load_config"]
