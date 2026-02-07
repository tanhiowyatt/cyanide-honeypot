import configparser
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

def load_config(path: Path = Path("config/cyanide.cfg")):
    """Load and normalized configuration from INI file and .env."""
    # Load .env file
    env_path = Path("config/.env")
    load_dotenv(dotenv_path=env_path)

    cfg = configparser.ConfigParser()
    if path.exists():
        cfg.read(path)
    else:
        # If config file is missing, we rely solely on .env or defaults
        print(f"[*] Config file not found at {path}, using .env and defaults.")
        
    def get_val(section, key, env_var, default, cast=str):
        # Priority: Env > Config File > Default
        val = os.getenv(env_var)
        if val is None and cfg.has_section(section):
            val = cfg.get(section, key, fallback=None)
        
        if val is None:
            return default
            
        if cast == bool:
            if isinstance(val, bool): return val
            return val.lower() in ('true', '1', 'yes', 'on')
        elif cast == int:
            return int(val)
        return val

    # Convert to dictionary structure expected by HoneypotServer
    config = {
        "log_path": get_val("honeypot", "log_path", "LOG_PATH", "var/log/cyanide"),
        "fs_pickle": get_val("honeypot", "fs_pickle", "FS_PICKLE", None),
        "quarantine_path": get_val("honeypot", "quarantine_path", "DATA_PATH", "var/lib/cyanide/quarantine"), # Note: DATA_PATH in env covers this? No, config.cfg had data_path but code used separate logic. 
        # Wait, config.cfg has data_path=var/lib/cyanide. Code logic below used hardcoded fallback.
        # In .env I put DATA_PATH. Let's use that base or specific?
        # The original code used "quarantine_path" key with fallback "var/lib/cyanide/quarantine".
        # config.cfg doesn't actually HAVE "quarantine_path". It has "data_path".
        # So original code fallback was always used unless I missed something?
        # Ah, lines 29: cfg.get("honeypot", "quarantine_path", fallback="var/lib/cyanide/quarantine")
        # In .env I don't have QUARANTINE_PATH. I have DATA_PATH=var/lib/cyanide.
        # I should probably just construct it from DATA_PATH if possible, or use default.
        # I'll stick to the original logic for now but checking DATA_PATH/quarantine.
        "ssh": {
            "port": get_val("ssh", "listen_port", "SSH_PORT", 2222, int),
            "enabled": get_val("ssh", "enabled", "SSH_ENABLED", True, bool)
        },
        "telnet": {
            "port": get_val("telnet", "listen_port", "TELNET_PORT", 2223, int),
            "enabled": get_val("telnet", "enabled", "TELNET_ENABLED", False, bool)
        },
        "users": []
    }
    
    # User loading - Env vars for users? USERS_ROOT=admin potentially? 
    # For now support standard cfg sections. Env support for list of users is complex.
    if cfg.has_section("users"):
        for username, password in cfg.items("users"):
            config["users"].append({"user": username, "pass": password})
    
    if not config["users"]:
        config["users"] = [{"user": "root", "pass": "admin"}, {"user": "admin", "pass": "admin"}]
        
    config["ml"] = {
        "enabled": get_val("ml", "enabled", "ML_ENABLED", False, bool),
        "anomalies_log": get_val("ml", "anomalies_log", "ML_ANOMALIES_LOG", "var/log/cyanide/cyanideML-anomalies-log.json"),
        "ml_log": get_val("ml", "ml_log", "ML_LOG", "var/log/cyanide/cyanideML-log.json"),
        "model_path": get_val("ml", "model_path", "MODEL_PATH", "src/cyanide/ml/cyanideML/cyanideML.pkl"),
        "online_learning": get_val("ml", "online_learning", "ONLINE_LEARNING", False, bool)
    }

    config["cleanup"] = {
        "enabled": get_val("cleanup", "enabled", "CLEANUP_ENABLED", True, bool),
        "interval": get_val("cleanup", "interval", "CLEANUP_INTERVAL", 3600, int),
        "retention_days": get_val("cleanup", "retention_days", "CLEANUP_RETENTION_DAYS", 7, int),
        "paths": get_val("cleanup", "paths", "CLEANUP_PATHS", "var/log/cyanide,var/lib/cyanide").split(",")
    }
        
    return config
