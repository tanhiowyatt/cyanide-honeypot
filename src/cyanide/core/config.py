import json
import logging
import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import ValidationError

from .config_schema import CyanideConfig
from .paths import get_default_config_path, get_package_root

logger = logging.getLogger("cyanide.config")

DEFAULT_LOG_PATH = "var/log/cyanide"

_CONFIG_EVENTS: list[dict[str, Any]] = []


def _parse_val(v):
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
        except (ValueError, TypeError):
            pass
    return v


def _try_map_env_to_dict(remainder: str, env_val: Any, data: dict, override_keys: list) -> bool:
    for top_key, top_val in data.items():
        if not remainder.startswith(top_key + "_") or not isinstance(top_val, dict):
            continue

        sub_remainder = remainder[len(top_key) + 1 :]
        if sub_remainder in top_val:
            top_val[sub_remainder] = _parse_val(env_val)
            override_keys.append(f"{top_key}.{sub_remainder}")
            return True

        for sub_key, sub_val in top_val.items():
            if sub_remainder.startswith(sub_key + "_") and isinstance(sub_val, dict):
                final_key = sub_remainder[len(sub_key) + 1 :]
                sub_val[final_key] = _parse_val(env_val)
                override_keys.append(f"{top_key}.{sub_key}.{final_key}")
                return True
    return False


def _apply_env_overrides(data: dict, prefix: str = "CYANIDE_") -> dict:
    override_count = 0
    override_keys = []

    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue

        remainder = env_key[len(prefix) :].lower()
        if remainder in data:
            data[remainder] = _parse_val(env_val)
            override_count += 1
            override_keys.append(remainder)
            continue

        if _try_map_env_to_dict(remainder, env_val, data, override_keys):
            override_count += 1

    if override_count > 0:
        _CONFIG_EVENTS.append(
            {
                "action": "config_env_override_applied",
                "data": {"count": override_count, "keys": override_keys},
            }
        )

    return data


def _get_val(config_data, section, key, default=None, cast=str):
    """
    Standardize value retrieval with the following priority:
    1. CYANIDE_{SECTION}_{KEY} environment variable.
    2. YAML config_data.
    3. Default value.
    """
    primary_env = f"CYANIDE_{section.upper()}_{key.upper()}"

    val = os.getenv(primary_env)

    if val is None:
        if section in config_data and isinstance(config_data[section], dict):
            val = config_data[section].get(key)

    if val is None:
        return default

    # Casting Logic
    if cast is bool:
        if isinstance(val, bool):
            return val
        return str(val).lower() in ("true", "1", "yes", "on")

    if cast is int:
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    if cast in ("json", "list", "dict") or cast is list or cast is dict:
        if isinstance(val, (list, dict)):
            return val
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return default

    return val


# Users parsing is now handled by _get_val using cast="json"


# Function 16: Loads config from storage or configuration.
def load_config(path: Any = None):
    """Load and normalized configuration from YAML file and .env."""
    if path is None:
        path = get_default_config_path()
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

    config_data = _apply_env_overrides(config_data)

    def get_val(section, key, default=None, cast=str):
        return _get_val(config_data, section, key, default, cast)

    config = {
        "hostname": get_val("honeypot", "hostname", "server01"),
        "log_path": get_val("logging", "directory", DEFAULT_LOG_PATH),
        "logging": {
            "directory": get_val("logging", "directory", DEFAULT_LOG_PATH),
            "logtype": get_val("logging", "logtype", "plain"),
            "rotation": {
                "strategy": get_val("logging", "rotation_strategy", "time"),
                "when": get_val("logging", "rotation_when", "midnight"),
                "interval": get_val("logging", "rotation_interval", 1, int),
                "backup_count": get_val("logging", "rotation_backup_count", 14, int),
                "max_bytes": get_val("logging", "rotation_max_bytes", 10485760, int),
            },
        },
        "listen_ip": get_val("server", "host", "0.0.0.0"),
        "quarantine_path": get_val("honeypot", "quarantine_path", "var/quarantine"),
        "vfs_root": get_val("server", "vfs_root") or get_val("vfs", "root_dir"),
        "os_profile": get_val("server", "os_profile", "random")
        or get_val("vfs", "profile", "random"),
        "max_sessions": get_val("server", "max_sessions", 100, int),
        "max_sessions_per_ip": get_val("server", "max_sessions_per_ip", 5, int),
        "session_timeout": get_val("server", "session_timeout", 300, int),
        "quarantine_max_size_mb": get_val("honeypot", "quarantine_max_size_mb", 500, int),
        "dns_cache_ttl": get_val("honeypot", "dns_cache_ttl", 60, int),
        "allow_local_network": get_val("honeypot", "allow_local_network", False, bool),
        "fs_yaml": get_val("honeypot", "fs_yaml", None),
        "ssh": {
            "port": get_val("ssh", "port", 2222, int),
            "enabled": get_val("ssh", "enabled", True, bool),
            "backend_mode": get_val("ssh", "backend_mode", "emulated"),
            "target_host": get_val("ssh", "target_host", "127.0.0.1"),
            "target_port": get_val("ssh", "target_port", 22222, int),
            "rsa_keying": get_val("ssh", "rsa_keying", True, bool),
            "vfs_persistence": get_val("ssh", "vfs_persistence", True, bool),
            "version": get_val("ssh", "version", None),
            "ciphers": get_val(
                "ssh",
                "ciphers",
                [
                    "aes256-gcm@openssh.com",
                    "aes128-gcm@openssh.com",
                    "chacha20-poly1305@openssh.com",
                ],
                cast="json",
            ),
            "macs": get_val(
                "ssh",
                "macs",
                ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"],
                cast="json",
            ),
            "compression": get_val("ssh", "compression", ["none", "zlib@openssh.com"], cast="json"),
            "kex_algs": get_val("ssh", "kex_algs", ["curve25519-sha256"], cast="json"),
            "host_key_algs": get_val(
                "ssh", "host_key_algs", ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"], cast="json"
            ),
            "public_key_algs": get_val(
                "ssh",
                "public_key_algs",
                ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"],
                cast="json",
            ),
            "data_path": get_val("ssh", "data_path", "var/lib/cyanide/keys"),
            "auth_tries": get_val("ssh", "auth_tries", 3, int),
            "login_timeout": get_val("ssh", "login_timeout", 60, int),
            "idle_timeout": get_val("ssh", "idle_timeout", 3600, int),
            "rekey_limit": get_val("ssh", "rekey_limit", "1G"),
            "forwarding_enabled": get_val("ssh", "forwarding_enabled", False, bool),
            "forwarding_strict_mode": get_val("ssh", "forwarding_strict_mode", True, bool),
            "log_passwords": get_val("ssh", "log_passwords", False, bool),
            "forward_redirect_enabled": get_val("ssh", "forward_redirect_enabled", False, bool),
            "forward_redirect_rules": get_val("ssh", "forward_redirect_rules", {}, cast="json"),
            "forward_tunnel_enabled": get_val("ssh", "forward_tunnel_enabled", False, bool),
            "forward_tunnel_rules": get_val("ssh", "forward_tunnel_rules", {}, cast="json"),
        },
        "telnet": {
            "enabled": get_val("telnet", "enabled", False, bool),
            "log_passwords": get_val("telnet", "log_passwords", False, bool),
            "port": get_val("telnet", "port", 2323, int),
            "backend_mode": get_val("telnet", "backend_mode", "emulated"),
            "target_host": get_val("telnet", "target_host", "127.0.0.1"),
            "target_port": get_val("telnet", "target_port", 23, int),
            "banner": get_val("telnet", "banner", None),
        },
        "metrics": {
            "enabled": get_val("metrics", "enabled", True, bool),
            "port": get_val("metrics", "port", 9090, int),
            "host": get_val("metrics", "host", "127.0.0.1"),
            "token": get_val("metrics", "token", None),
            "allow_remote": get_val("metrics", "allow_remote", False, bool),
        },
        "smtp": {
            "enabled": get_val("smtp", "enabled", False, bool),
            "port": get_val("smtp", "port", 2525, int),
            "backend_mode": get_val("smtp", "backend_mode", "emulated"),
            "target_host": get_val("smtp", "target_host", "127.0.0.1"),
            "target_port": get_val("smtp", "target_port", 25255, int),
        },
        "ml": {
            "enabled": get_val("ml", "enabled", True, bool),
            "ml_log": get_val("ml", "ml_log", f"{DEFAULT_LOG_PATH}/cyanide-ml.json"),
            "model_path": get_val(
                "ml", "model_path", str(get_package_root() / "assets" / "models" / "cyanideML.pkl")
            ),
            "online_learning": get_val("ml", "online_learning", False, bool),
            "retraining_interval_days": get_val("ml", "retraining_interval_days", 7, int),
            "training_data": {"hacker_methods": Path(DEFAULT_LOG_PATH)},
        },
        "cleanup": {
            "enabled": get_val("cleanup", "enabled", True, bool),
            "interval": get_val("cleanup", "interval", 3600, int),
            "retention_days": get_val("cleanup", "retention_days", 7, int),
            "paths": get_val(
                "cleanup",
                "paths",
                [DEFAULT_LOG_PATH, "var/lib/cyanide", "var/quarantine"],
                cast="json",
            ),
        },
        "pool": {
            "enabled": get_val("pool", "enabled", False, bool),
            "mode": get_val("pool", "mode", "libvirt"),
            "max_vms": get_val("pool", "max_vms", 5, int),
            "recycle_period": get_val("pool", "recycle_period", 1500, int),
            "vm_unused_timeout": get_val("pool", "vm_unused_timeout", 600, int),
            "share_guests": get_val("pool", "share_guests", True, bool),
            "libvirt_uri": get_val("pool", "libvirt_uri", "qemu:///system"),
            "guest_config": get_val("pool", "guest_config", "configs/pool/default_guest.xml"),
            "guest_tag": get_val("pool", "guest_tag", "ubuntu18.04"),
            "guest_ssh_port": get_val("pool", "guest_ssh_port", 22, int),
            "guest_telnet_port": get_val("pool", "guest_telnet_port", 23, int),
            "use_nat": get_val("pool", "use_nat", True, bool),
            "nat_public_ip": get_val("pool", "nat_public_ip", "192.168.1.40"),
            "save_snapshots": get_val("pool", "save_snapshots", False, bool),
            "snapshot_path": get_val("pool", "snapshot_path", "var/lib/cyanide/snapshots"),
            "targets": get_val("pool", "targets", ""),
        },
        "rate_limit": {
            "max_connections_per_minute": get_val(
                "rate_limit", "max_connections_per_minute", 60, int
            ),
            "ban_duration": get_val("rate_limit", "ban_duration", 3600, int),
        },
        "otel": {
            "enabled": get_val("otel", "enabled", False, bool),
            "exporter": get_val("otel", "exporter", "otlp"),
            "endpoint": get_val("otel", "endpoint", "http://localhost:4318/v1/traces"),
        },
        "virustotal": {
            "enabled": get_val("virustotal", "enabled", False, bool),
            "api_key": get_val("virustotal", "api_key", None),
        },
        "output": config_data.get("output", {}),
        "custom_profile": config_data.get("custom_profile", {}),
        "users": get_val("auth", "users", [{"user": "root", "pass": "admin"}], cast="json"),
    }

    # Ensure all Path objects in the returned dictionary are converted to strings for JSON serializability
    def stringify_paths(d):
        if isinstance(d, dict):
            return {k: stringify_paths(v) for k, v in d.items()}
        if isinstance(d, list):
            return [stringify_paths(v) for v in d]
        if isinstance(d, Path):
            return str(d)
        return d

    try:
        model = CyanideConfig(**config)
        _CONFIG_EVENTS.append({"action": "config_schema_validated", "data": {"ok": True}})
        final_config = model.model_dump()
        return stringify_paths(final_config)
    except ValidationError as e:
        _CONFIG_EVENTS.append({"action": "config_schema_error", "data": {"error": str(e)}})
        raise
