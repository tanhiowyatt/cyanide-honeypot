import yaml
import os
import sys
import json
from pathlib import Path
from dotenv import load_dotenv
from .config_schema import CyanideConfig
from pydantic import ValidationError

def load_config(path: Path = Path("configs/app.yaml")):
    """Load and normalized configuration from YAML file and .env."""
    # Load .env file
    env_path = Path("configs/.env")
    if not env_path.exists():
         env_path = Path(".env") # Fallback to root .env
    load_dotenv(dotenv_path=env_path)

    config_data = {}
    if path.exists():
        try:
            with open(path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
                if not isinstance(config_data, dict):
                    print(f"[!] Config file {path} is not a valid YAML dictionary.")
                    config_data = {}
        except Exception as e:
            print(f"[!] Error loading config {path}: {e}")
    else:
        # Check for example file as fallback if main doesn't exist? 
        # Or just warn.
        print(f"[*] Config file not found at {path}, using .env and defaults.")
        
    def get_val(section, key, env_var, default, cast=str):
        # Priority: Env > Config File (Nested) > Default
        val = os.getenv(env_var)
        
        # Deep lookup in config_data
        if val is None:
            if section in config_data and isinstance(config_data[section], dict):
                 val = config_data[section].get(key)
        
        if val is None:
            return default
            
        if cast is bool:
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ('true', '1', 'yes', 'on')
            return bool(val)
        elif cast is int:
            try:
                return int(val)
            except (ValueError, TypeError):
                return default
        return val

    # Convert to dictionary structure expected by HoneypotServer
    config = {
        "hostname": get_val("honeypot", "hostname", "HOSTNAME", "server01"),
        "log_path": get_val("honeypot", "log_path", "LOG_PATH", "var/log/cyanide"),
        "listen_ip": get_val("server", "host", "HOST", "0.0.0.0"),
        "quarantine_path": get_val("honeypot", "quarantine_path", "DATA_PATH", "var/lib/cyanide/quarantine"),
        "os_profile": get_val("server", "os_profile", "OS_PROFILE", "random"),
        "max_sessions": get_val("server", "max_sessions", "MAX_SESSIONS", 100, int),
        "max_sessions_per_ip": get_val("server", "max_sessions_per_ip", "MAX_SESSIONS_PER_IP", 5, int),
        "session_timeout": get_val("server", "session_timeout", "SESSION_TIMEOUT", 300, int),
        "quarantine_max_size_mb": get_val("server", "quarantine_max_size_mb", "QUARANTINE_MAX_SIZE_MB", 500, int),
        "ssh": {
            "port": get_val("ssh", "listen_port", "SSH_PORT", 2222, int),
            "enabled": get_val("ssh", "enabled", "SSH_ENABLED", True, bool),
            "backend_mode": get_val("ssh", "backend_mode", "SSH_BACKEND", "emulated"),
            "target_host": get_val("ssh", "target_host", "SSH_TARGET_HOST", "127.0.0.1"),
            "target_port": get_val("ssh", "target_port", "SSH_TARGET_PORT", 22222, int)
        },
        "telnet": {
            "port": get_val("telnet", "listen_port", "TELNET_PORT", 2323, int),
            "enabled": get_val("telnet", "enabled", "TELNET_ENABLED", False, bool),
            "backend_mode": get_val("telnet", "backend_mode", "TELNET_BACKEND", "emulated"),
            "target_host": get_val("telnet", "target_host", "TELNET_TARGET_HOST", "127.0.0.1"),
            "target_port": get_val("telnet", "target_port", "TELNET_TARGET_PORT", 23, int),
            "banner": get_val("telnet", "banner", "TELNET_BANNER", None)
        },
        "metrics": {
            "enabled": get_val("metrics", "enabled", "METRICS_ENABLED", True, bool),
            "port": get_val("metrics", "port", "METRICS_PORT", 9090, int)
        },
        "smtp": {
            "enabled": get_val("smtp", "enabled", "SMTP_ENABLED", False, bool),
            "listen_port": get_val("smtp", "listen_port", "SMTP_PORT", 25, int),
            "target_host": get_val("smtp", "target_host", "SMTP_TARGET_HOST", "127.0.0.1"),
            "target_port": get_val("smtp", "target_port", "SMTP_TARGET_PORT", 2525, int)
        },
        "users": []
    }
    
    # User loading
    users_env = os.getenv("CYANIDE_USERS")
    if users_env:
        try:
            env_users = json.loads(users_env)
            if isinstance(env_users, list):
                config["users"].extend(env_users)
        except json.JSONDecodeError:
            print("[!] Failed to parse CYANIDE_USERS env var.")

    # Load users from YAML
    yaml_users = config_data.get("users", [])
    if isinstance(yaml_users, list):
        for user_obj in yaml_users:
             if isinstance(user_obj, dict) and "user" in user_obj and "pass" in user_obj:
                 config["users"].append(user_obj)
    
    if not config["users"]:
        config["users"] = [{"user": "root", "pass": "admin"}, {"user": "admin", "pass": "admin"}]
        
    config["ml"] = {
        "enabled": get_val("ml", "enabled", "ML_ENABLED", False, bool),
        "ml_log": get_val("ml", "ml_log", "ML_LOG", "var/log/cyanide/cyanideML-log.json"),
        "model_path": get_val("ml", "model_path", "MODEL_PATH", "assets/models/cyanideML.pkl"),
        "online_learning": get_val("ml", "online_learning", "ONLINE_LEARNING", False, bool),
        "retraining_interval_days": get_val("ml", "retraining_interval_days", "ML_RETRAINING_INTERVAL_DAYS", 7, int),
        "training_data": {
            "hacker_methods": Path(config_data.get("ml", {}).get("training_data", {}).get("hacker_methods", "data/raw")),
            "mitre_cve": Path(config_data.get("ml", {}).get("training_data", {}).get("mitre_cve", "data/processed/kb_ready"))
        }
    }

    config["cleanup"] = {
        "enabled": get_val("cleanup", "enabled", "CLEANUP_ENABLED", True, bool),
        "interval": get_val("cleanup", "interval", "CLEANUP_INTERVAL", 3600, int),
        "retention_days": get_val("cleanup", "retention_days", "CLEANUP_RETENTION_DAYS", 7, int),
        "paths": get_val("cleanup", "paths", "CLEANUP_PATHS", "var/log/cyanide,var/lib/cyanide").split(",")
    }

    # Load Custom Profile metadata
    config["custom_profile"] = config_data.get("custom_profile", {})
            
    # Rate Limit
    config["rate_limit"] = {
        "max_connections_per_minute": get_val("rate_limit", "max_connections_per_minute", "RATE_LIMIT_MAX", 60, int),
        "ban_duration": get_val("rate_limit", "ban_duration", "RATE_LIMIT_BAN", 3600, int)
    }

    # OpenTelemetry
    config["otel"] = {
        "enabled": get_val("otel", "enabled", "OTEL_ENABLED", False, bool),
        "exporter": get_val("otel", "exporter", "OTEL_EXPORTER", "otlp"),
        "endpoint": get_val("otel", "endpoint", "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces")
    }

    # VirusTotal
    config["virustotal"] = {
        "enabled": get_val("virustotal", "enabled", "VIRUSTOTAL_ENABLED", False, bool),
        "api_key": get_val("virustotal", "api_key", "VIRUSTOTAL_API_KEY", None)
    }
        
    try:
        model = CyanideConfig(**config)
        return model.model_dump()
    except ValidationError as e:
        print(f"[!] Configuration Error:\n{e}")
        sys.exit(1)
