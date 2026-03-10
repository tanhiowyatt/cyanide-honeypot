from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SSHConfig(BaseModel):
    enabled: bool = True
    port: int = 2222
    backend_mode: str = Field(default="emulated", pattern="^(emulated|proxy|pool)$")
    target_host: Optional[str] = "127.0.0.1"
    target_port: Optional[int] = 22222


class TelnetConfig(BaseModel):
    enabled: bool = False
    port: int = 2323
    backend_mode: str = Field(default="emulated", pattern="^(emulated|proxy|pool)$")
    target_host: Optional[str] = "127.0.0.1"
    target_port: Optional[int] = 23
    banner: Optional[str] = None


class MetricsConfig(BaseModel):
    enabled: bool = True
    port: int = 9090


class SMTPConfig(BaseModel):
    enabled: bool = False
    listen_port: int = 25
    target_host: str = "127.0.0.1"
    target_port: int = 2525


class TelemetryConfig(BaseModel):
    enabled: bool = False
    exporter: str = "otlp"
    endpoint: Optional[str] = "http://localhost:4318/v1/traces"


class RateLimitConfig(BaseModel):
    max_connections_per_minute: int = 60
    ban_duration: int = 3600


class VirusTotalConfig(BaseModel):
    enabled: bool = False
    api_key: Optional[str] = None


class UserConfig(BaseModel):
    user: str
    password: str = Field(alias="pass")


class CyanideConfig(BaseModel):
    # ML
    ml: Dict[str, Any] = Field(default_factory=dict)

    # Cleanup
    cleanup: Dict[str, Any] = Field(default_factory=dict)

    # Output Plugins
    output: Dict[str, Any] = Field(default_factory=dict)

    # Paths & Core
    hostname: str = "server01"
    log_path: str = "var/log/cyanide"
    fs_yaml: Optional[str] = None
    quarantine_path: str = "var/quarantine"
    quarantine_max_size_mb: int = 500
    os_profile: str = "random"
    dns_cache_ttl: int = 60
    custom_profile: Dict[str, str] = Field(default_factory=dict)

    # Core (Session Manager)
    listen_ip: str = "0.0.0.0"
    max_sessions: int = 100
    max_sessions_per_ip: int = 5
    session_timeout: int = 300

    # Services
    ssh: SSHConfig = Field(default_factory=lambda: SSHConfig())
    telnet: TelnetConfig = Field(default_factory=lambda: TelnetConfig())
    metrics: MetricsConfig = Field(default_factory=lambda: MetricsConfig())
    smtp: SMTPConfig = Field(default_factory=lambda: SMTPConfig())
    otel: TelemetryConfig = Field(default_factory=lambda: TelemetryConfig())
    virustotal: VirusTotalConfig = Field(default_factory=lambda: VirusTotalConfig())
    rate_limit: RateLimitConfig = Field(default_factory=lambda: RateLimitConfig())
    allow_local_network: bool = False

    # Auth
    users: List[Dict[str, str]] = Field(
        default_factory=list
    )  # simplified from UserConfig for now as config.py uses dicts

    model_config = ConfigDict(extra="ignore")
