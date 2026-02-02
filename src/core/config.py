import configparser
import os
import sys
from pathlib import Path

def load_config(path: Path = Path("etc/cyanide.cfg")):
    """Load and normalized configuration from INI file."""
    if not path.exists():
        # Allow caller to handle missing file or print here?
        # main.py printed and exited. We should probably accept that behavior or just return None.
        # But for bin/cyanide it's better to know. 
        # Failure is handled by the caller or we can raise FileNotFoundError.
        # For now, let's keep the print logic but let caller decide to exit if needed?
        # Actually main.py was doing:
        # if not path.exists(): print; sys.exit(1)
        # I'll keep it simple for now and duplicate the print/exit here or just return available defaults?
        # The user wants to see info. If config is missing, defaults apply?
        # But the original code exited. I will stick to original behavior for now.
        print(f"Config file not found at {path}")
        sys.exit(1)
        
    cfg = configparser.ConfigParser()
    cfg.read(path)
    
    # Convert to dictionary structure expected by HoneypotServer
    config = {
        "log_path": cfg.get("honeypot", "log_path", fallback="var/log/cyanide"),
        "fs_pickle": cfg.get("honeypot", "fs_pickle", fallback=None),
        "quarantine_path": cfg.get("honeypot", "quarantine_path", fallback="var/quarantine"),
        "ssh": {
            "port": cfg.getint("ssh", "listen_port", fallback=2222),
            "enabled": cfg.getboolean("ssh", "enabled", fallback=True)
        },
        "telnet": {
            "port": cfg.getint("telnet", "listen_port", fallback=2223),
            "enabled": cfg.getboolean("telnet", "enabled", fallback=False)
        },
        "services": {
            "mysql": {
                "enabled": cfg.getboolean("services", "mysql_enabled", fallback=True),
                "port": cfg.getint("services", "mysql_port", fallback=3306)
            }
        },
        # Default users if not handling auth backend yet
        "users": [{"user": "root", "pass": "password"}, {"user": "admin", "pass": "admin"}] 
    }
    return config
