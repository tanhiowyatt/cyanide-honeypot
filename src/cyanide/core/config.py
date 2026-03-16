import json
import logging
import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import ValidationError

from .config_schema import CyanideConfig

logger = logging.getLogger("cyanide.config")


_CONFIG_EVENTS: list[dict[str, Any]] = []


# Function 16: Loads config from storage or configuration.
def load_config(path: Path = Path("configs/app.yaml")):
    """Load and normalized configuration from YAML file and .env."""
    _CONFIG_EVENTS.clear()

    env_path = Path("configs/.env")
    if not env_path.exists():
        env_path = Path(".env")

    _CONFIG_EVENTS.append(
        {
            "action": "config_load_start",
            "data": {
                "path": str(path),
                "env_file_used": str(env_path) if env_path.exists() else None,
            },
        }
    )

    load_dotenv(dotenv_path=env_path)

    config_data: dict[str, Any] = {}
    if path.exists():
        try:
            with open(path, "r") as f:
                config_data = yaml.safe_load(f) or {}
                if not isinstance(config_data, dict):
                    logger.error(f"Config file {path} is not a valid YAML dictionary.")
                    config_data = {}
        except Exception as e:
            logger.error(f"Error loading config {path}: {e}")
    else:
        logger.warning(f"Config file not found at {path}, using .env and defaults.")

    def apply_env_overrides(data: dict, prefix: str = "CYANIDE_") -> dict:
        """Deeply override configuration dictionary using single-underscore environment variables."""
        import json

        override_count = 0
        override_keys = []

        def parse_val(v):
            vl = str(v).lower()
            if vl in ("true", "1", "yes", "on"):
                return True
            if vl in ("false", "0", "no", "off"):
                return False
            if str(v).isdigit():
                return int(v)
            if str(v).startswith("[") or str(v).startswith("{"):
                try:
                    return json.loads(v)
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass
            return v

        for env_key, env_val in os.environ.items():
            if not env_key.startswith(prefix):
                continue

            remainder = env_key[len(prefix) :].lower()

            if remainder in data:
                data[remainder] = parse_val(env_val)
                override_count += 1
                override_keys.append(remainder)
                continue

            mapped = False
            for top_key, top_val in data.items():
                if remainder.startswith(top_key + "_"):
                    if not isinstance(top_val, dict):
                        continue

                    sub_remainder = remainder[len(top_key) + 1 :]

                    if sub_remainder in top_val:
                        top_val[sub_remainder] = parse_val(env_val)
                        override_count += 1
                        override_keys.append(f"{top_key}.{sub_remainder}")
                        mapped = True
                        break

                    for sub_key, sub_val in top_val.items():
                        if sub_remainder.startswith(sub_key + "_"):
                            if isinstance(sub_val, dict):
                                final_key = sub_remainder[len(sub_key) + 1 :]
                                sub_val[final_key] = parse_val(env_val)
                                override_count += 1
                                override_keys.append(f"{top_key}.{sub_key}.{final_key}")
                                mapped = True
                                break
                    if mapped:
                        break

        if override_count > 0:
            _CONFIG_EVENTS.append(
                {
                    "action": "config_env_override_applied",
                    "data": {"count": override_count, "keys": override_keys},
                }
            )

        return data

    config_data = apply_env_overrides(config_data)

    def get_val(section, key, env_var, default, cast=str):
        full_env_var = f"CYANIDE_{section.upper()}__" + (
            env_var if env_var not in (key.upper(), key) else key.upper()
        )
        val = os.getenv(full_env_var)
        if val is None:
            val = os.getenv(env_var)

        if val is None:
            if section in config_data and isinstance(config_data[section], dict):
                val = config_data[section].get(key)

        if val is None:
            return default

        if cast is bool:
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ("true", "1", "yes", "on")
            return bool(val)
        elif cast is int:
            try:
                return int(val)
            except (ValueError, TypeError):
                return default
        return val

    config = {
        "hostname": (
            os.getenv("CYANIDE_HONEYPOT__HOSTNAME")
            or os.getenv("CYANIDE_CORE__HOSTNAME")
            or (config_data.get("honeypot") or {}).get("hostname")
            or os.getenv("HOSTNAME", "server01")
        ),
        "log_path": get_val(
            "logging", "directory", "LOG_PATH", "var/log/cyanide"
        ),
        "logging": {
            "directory": get_val("logging", "directory", "LOGGING_DIRECTORY", "var/log/cyanide"),
            "logtype": get_val("logging", "logtype", "LOGGING_LOGTYPE", "plain"),
            "rotation": {
                "strategy": get_val(
                    "logging",
                    "rotation_strategy",
                    "LOGGING_ROTATION_STRATEGY",
                    get_val(
                        "rotation",
                        "strategy",
                        "LOGGING_ROTATION_STRATEGY",
                        (
                            config_data.get("logging", {})
                            .get("rotation", {})
                            .get("strategy", "time")
                        ),
                    ),
                ),
                "when": get_val(
                    "logging",
                    "rotation_when",
                    "LOGGING_ROTATION_WHEN",
                    get_val(
                        "rotation",
                        "when",
                        "LOGGING_ROTATION_WHEN",
                        (
                            config_data.get("logging", {})
                            .get("rotation", {})
                            .get("when", "midnight")
                        ),
                    ),
                ),
                "interval": get_val(
                    "logging",
                    "rotation_interval",
                    "LOGGING_ROTATION_INTERVAL",
                    get_val(
                        "rotation",
                        "interval",
                        "LOGGING_ROTATION_INTERVAL",
                        (config_data.get("logging", {}).get("rotation", {}).get("interval", 1)),
                        int,
                    ),
                    int,
                ),
                "backup_count": get_val(
                    "logging",
                    "rotation_backup_count",
                    "LOGGING_ROTATION_BACKUP_COUNT",
                    get_val(
                        "rotation",
                        "backup_count",
                        "LOGGING_ROTATION_BACKUP_COUNT",
                        (
                            config_data.get("logging", {})
                            .get("rotation", {})
                            .get("backup_count", 14)
                        ),
                        int,
                    ),
                    int,
                ),
                "max_bytes": get_val(
                    "logging",
                    "rotation_max_bytes",
                    "LOGGING_ROTATION_MAX_BYTES",
                    get_val(
                        "rotation",
                        "max_bytes",
                        "LOGGING_ROTATION_MAX_BYTES",
                        (
                            config_data.get("logging", {})
                            .get("rotation", {})
                            .get("max_bytes", 10485760)
                        ),
                        int,
                    ),
                    int,
                ),
            },
        },
        "listen_ip": get_val("server", "host", "HOST", "0.0.0.0"),
        "quarantine_path": "var/quarantine",
        "os_profile": get_val("server", "os_profile", "OS_PROFILE", None)
        or get_val("vfs", "profile", "VFS_PROFILE", None)
        or os.getenv("CYANIDE_VFS__PROFILE")
        or "random",
        "max_sessions": get_val("server", "max_sessions", "MAX_SESSIONS", 100, int),
        "max_sessions_per_ip": get_val(
            "server", "max_sessions_per_ip", "MAX_SESSIONS_PER_IP", 5, int
        ),
        "session_timeout": get_val("server", "session_timeout", "SESSION_TIMEOUT", 300, int),
        "quarantine_max_size_mb": get_val(
            "honeypot", "quarantine_max_size_mb", "QUARANTINE_MAX_SIZE_MB", 500, int
        ),
        "dns_cache_ttl": get_val("honeypot", "dns_cache_ttl", "DNS_CACHE_TTL", 60, int),
        "allow_local_network": get_val(
            "honeypot", "allow_local_network", "ALLOW_LOCAL", False, bool
        ),
        "fs_yaml": get_val("honeypot", "fs_yaml", "FS_YAML", None),
        "ssh": {
            "port": get_val(
                "ssh", "port", "SSH_PORT", get_val("ssh", "listen_port", "SSH_PORT", 2222, int), int
            ),
            "enabled": get_val("ssh", "enabled", "SSH_ENABLED", True, bool),
            "backend_mode": get_val("ssh", "backend_mode", "SSH_BACKEND", "emulated"),
            "target_host": get_val("ssh", "target_host", "SSH_TARGET_HOST", "127.0.0.1"),
            "target_port": get_val("ssh", "target_port", "SSH_TARGET_PORT", 22222, int),
            "rsa_keying": get_val("ssh", "rsa_keying", "SSH_RSA_KEYING", True, bool),
            "version": get_val("ssh", "version", "SSH_VERSION", None),
            "ciphers": get_val(
                "ssh",
                "ciphers",
                "SSH_CIPHERS",
                [
                    "aes256-gcm@openssh.com",
                    "aes128-gcm@openssh.com",
                    "chacha20-poly1305@openssh.com",
                ],
            ),
            "macs": get_val(
                "ssh",
                "macs",
                "SSH_MACS",
                ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"],
            ),
            "compression": get_val(
                "ssh", "compression", "SSH_COMPRESSION", ["none", "zlib@openssh.com"]
            ),
            "kex_algs": get_val("ssh", "kex_algs", "SSH_KEX_ALGS", ["curve25519-sha256"]),
            "host_key_algs": get_val(
                "ssh",
                "host_key_algs",
                "SSH_HOST_KEY_ALGS",
                ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"],
            ),
            "public_key_algs": get_val(
                "ssh",
                "public_key_algs",
                "SSH_PUBLIC_KEY_ALGS",
                ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"],
            ),
            "data_path": get_val("ssh", "data_path", "SSH_DATA_PATH", "var/lib/cyanide/keys"),
            "auth_tries": get_val("ssh", "auth_tries", "SSH_AUTH_TRIES", 3, int),
            "login_timeout": get_val("ssh", "login_timeout", "SSH_LOGIN_TIMEOUT", 60, int),
            "idle_timeout": get_val("ssh", "idle_timeout", "SSH_IDLE_TIMEOUT", 3600, int),
            "rekey_limit": get_val("ssh", "rekey_limit", "SSH_REKEY_LIMIT", "1G"),
            "forwarding_enabled": get_val(
                "ssh", "forwarding_enabled", "SSH_FORWARDING_ENABLED", False, bool
            ),
            "forward_redirect_enabled": get_val(
                "ssh", "forward_redirect_enabled", "SSH_FORWARD_REDIRECT_ENABLED", False, bool
            ),
            "forward_redirect_rules": get_val(
                "ssh", "forward_redirect_rules", "SSH_FORWARD_REDIRECT_RULES", {}
            ),
            "forward_tunnel_enabled": get_val(
                "ssh", "forward_tunnel_enabled", "SSH_FORWARD_TUNNEL_ENABLED", False, bool
            ),
            "forward_tunnel_rules": get_val(
                "ssh", "forward_tunnel_rules", "SSH_FORWARD_TUNNEL_RULES", {}
            ),
        },
        "telnet": {
            "port": get_val(
                "telnet",
                "port",
                "TELNET_PORT",
                get_val("telnet", "listen_port", "TELNET_PORT", 2323, int),
                int,
            ),
            "enabled": get_val("telnet", "enabled", "TELNET_ENABLED", False, bool),
            "backend_mode": get_val("telnet", "backend_mode", "TELNET_BACKEND", "emulated"),
            "target_host": get_val("telnet", "target_host", "TELNET_TARGET_HOST", "127.0.0.1"),
            "target_port": get_val("telnet", "target_port", "TELNET_TARGET_PORT", 23, int),
            "banner": get_val("telnet", "banner", "TELNET_BANNER", None),
        },
        "metrics": {
            "enabled": get_val("metrics", "enabled", "METRICS_ENABLED", True, bool),
            "port": get_val("metrics", "port", "METRICS_PORT", 9090, int),
        },
        "smtp": {
            "enabled": get_val("smtp", "enabled", "SMTP_ENABLED", False, bool),
            "port": get_val(
                "smtp",
                "port",
                "SMTP_PORT",
                get_val("smtp", "listen_port", "SMTP_PORT", 2525, int),
                int,
            ),
            "backend_mode": get_val("smtp", "backend_mode", "SMTP_BACKEND", "emulated"),
            "target_host": get_val("smtp", "target_host", "SMTP_TARGET_HOST", "127.0.0.1"),
            "target_port": get_val("smtp", "target_port", "SMTP_TARGET_PORT", 25255, int),
        },
        "pool": {
            "enabled": get_val("pool", "enabled", "POOL_ENABLED", False, bool),
            "mode": get_val("pool", "mode", "POOL_MODE", "libvirt"),
            "max_vms": get_val("pool", "max_vms", "POOL_MAX_VMS", 5, int),
            "recycle_period": get_val("pool", "recycle_period", "POOL_RECYCLE_PERIOD", 1500, int),
            "vm_unused_timeout": get_val(
                "pool", "vm_unused_timeout", "POOL_VM_UNUSED_TIMEOUT", 600, int
            ),
            "share_guests": get_val("pool", "share_guests", "POOL_SHARE_GUESTS", True, bool),
            "libvirt_uri": get_val("pool", "libvirt_uri", "POOL_LIBVIRT_URI", "qemu:///system"),
            "guest_config": get_val(
                "pool", "guest_config", "POOL_GUEST_CONFIG", "configs/pool/default_guest.xml"
            ),
            "guest_tag": get_val("pool", "guest_tag", "POOL_GUEST_TAG", "ubuntu18.04"),
            "guest_ssh_port": get_val("pool", "guest_ssh_port", "POOL_GUEST_SSH_PORT", 22, int),
            "guest_telnet_port": get_val(
                "pool", "guest_telnet_port", "POOL_GUEST_TELNET_PORT", 23, int
            ),
            "use_nat": get_val("pool", "use_nat", "POOL_USE_NAT", True, bool),
            "nat_public_ip": get_val("pool", "nat_public_ip", "POOL_NAT_PUBLIC_IP", "192.168.1.40"),
            "save_snapshots": get_val("pool", "save_snapshots", "POOL_SAVE_SNAPSHOTS", False, bool),
            "snapshot_path": get_val(
                "pool", "snapshot_path", "POOL_SNAPSHOT_PATH", "var/lib/cyanide/snapshots"
            ),
            "targets": get_val("pool", "targets", "POOL_TARGETS", ""),
        },
        "users": [],
    }

    users_env = os.getenv("CYANIDE_AUTH__USERS") or os.getenv("CYANIDE_USERS")
    env_users_loaded = False
    if users_env:
        try:
            env_users = json.loads(users_env)
            if isinstance(env_users, list):
                config["users"].extend(env_users)
                env_users_loaded = True
        except json.JSONDecodeError:
            logger.error(f"Failed to parse users env var: {users_env}")

    if not env_users_loaded:
        yaml_users = config_data.get("users", [])
        if isinstance(yaml_users, list):
            for user_obj in yaml_users:
                if isinstance(user_obj, dict) and "user" in user_obj and "pass" in user_obj:
                    config["users"].append(user_obj)

    if not config["users"]:
        config["users"] = [{"user": "root", "pass": "admin"}, {"user": "admin", "pass": "admin"}]

    config["ml"] = {
        "enabled": get_val("ml", "enabled", "ML_ENABLED", False, bool),
        "ml_log": get_val("ml", "ml_log", "ML_LOG", "var/log/cyanide/ml.json"),
        "model_path": get_val("ml", "model_path", "ML_MODEL_PATH", "assets/models/cyanideML.pkl"),
        "online_learning": get_val("ml", "online_learning", "ONLINE_LEARNING", False, bool),
        "retraining_interval_days": get_val(
            "ml", "retraining_interval_days", "ML_RETRAINING_INTERVAL_DAYS", 7, int
        ),
        "training_data": {
            "hacker_methods": Path("var/log/cyanide"),
        },
    }

    config["cleanup"] = {
        "enabled": get_val("cleanup", "enabled", "CLEANUP_ENABLED", True, bool),
        "interval": get_val("cleanup", "interval", "CLEANUP_INTERVAL", 3600, int),
        "retention_days": get_val("cleanup", "retention_days", "CLEANUP_RETENTION_DAYS", 7, int),
        "paths": ["var/log/cyanide", "var/lib/cyanide", "var/quarantine"],
    }

    config["custom_profile"] = config_data.get("custom_profile", {})

    config["rate_limit"] = {
        "max_connections_per_minute": get_val(
            "rate_limit", "max_connections_per_minute", "RATE_LIMIT_MAX", 60, int
        ),
        "ban_duration": get_val("rate_limit", "ban_duration", "RATE_LIMIT_BAN", 3600, int),
    }

    config["otel"] = {
        "enabled": get_val("otel", "enabled", "OTEL_ENABLED", False, bool),
        "exporter": get_val("otel", "exporter", "OTEL_EXPORTER", "otlp"),
        "endpoint": get_val(
            "otel", "endpoint", "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces"
        ),
    }

    config["virustotal"] = {
        "enabled": get_val("virustotal", "enabled", "VIRUSTOTAL_ENABLED", False, bool),
        "api_key": get_val("virustotal", "api_key", "VIRUSTOTAL_API_KEY", None),
    }

    config["output"] = config_data.get("output", {})

    try:
        model = CyanideConfig(**config)

        _CONFIG_EVENTS.append({"action": "config_schema_validated", "data": {"ok": True}})

        return model.model_dump()
    except ValidationError as e:
        _CONFIG_EVENTS.append({"action": "config_schema_error", "data": {"error": str(e)}})
        raise
