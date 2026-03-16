from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SSHConfig(BaseModel):
    enabled: bool = True
    port: int = 2222
    version: Optional[str] = None
    rsa_keying: bool = True
    backend_mode: str = Field(default="emulated", pattern="^(emulated|proxy|pool)$")
    target_host: Optional[str] = "127.0.0.1"
    target_port: Optional[int] = 22222
    pool_protocol: str = "ssh"

    ciphers: List[str] = Field(
        default_factory=lambda: [
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
            "chacha20-poly1305@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
        ]
    )
    macs: List[str] = Field(
        default_factory=lambda: [
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-256",
            "umac-128@openssh.com",
        ]
    )
    compression: List[str] = Field(default_factory=lambda: ["none", "zlib@openssh.com"])
    kex_algs: List[str] = Field(
        default_factory=lambda: [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
        ]
    )
    host_key_algs: List[str] = Field(
        default_factory=lambda: [
            "ssh-ed25519",
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ecdsa-sha2-nistp256",
        ]
    )
    public_key_algs: List[str] = Field(
        default_factory=lambda: [
            "ssh-ed25519",
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ecdsa-sha2-nistp256",
        ]
    )

    data_path: str = "var/lib/cyanide/keys"
    auth_tries: int = 3
    login_timeout: int = 60
    idle_timeout: int = 3600
    rekey_limit: str = "1G"

    sftp_enabled: bool = True
    scp_enabled: bool = True
    rsync_enabled: bool = True
    max_upload_size_mb: int = 50
    max_total_upload_mb_per_session: int = 200
    allow_download: bool = True
    allow_upload: bool = True

    rsync: Dict[str, Any] = Field(
        default_factory=lambda: {
            "enabled": True,
            "allow_upload": True,
            "allow_download": True,
            "max_file_size_mb": 50,
            "max_total_mb_per_session": 200,
        }
    )

    forwarding_enabled: bool = False
    forward_redirect_enabled: bool = False
    forward_redirect_rules: Dict[str, str] = Field(default_factory=dict)
    forward_tunnel_enabled: bool = False
    forward_tunnel_rules: Dict[str, str] = Field(default_factory=dict)


class TelnetConfig(BaseModel):
    enabled: bool = False
    port: int = 2323
    backend_mode: str = Field(default="emulated", pattern="^(emulated|proxy|pool)$")
    target_host: Optional[str] = "127.0.0.1"
    target_port: Optional[int] = 23
    pool_protocol: str = "telnet"
    banner: Optional[str] = None


class MetricsConfig(BaseModel):
    enabled: bool = True
    port: int = 9090


class SMTPConfig(BaseModel):
    enabled: bool = False
    port: int = 2525
    backend_mode: str = Field(default="emulated", pattern="^(emulated|proxy)$")
    target_host: str = "127.0.0.1"
    target_port: int = 25255


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


class PoolConfig(BaseModel):
    enabled: bool = False
    mode: str = Field(default="libvirt", pattern="^(simple|libvirt)$")
    max_vms: int = 5
    recycle_period: int = 1500
    vm_unused_timeout: int = 600
    share_guests: bool = True
    libvirt_uri: str = "qemu:///system"
    guest_config: str = "configs/pool/default_guest.xml"
    guest_tag: str = "ubuntu18.04"
    guest_ssh_port: int = 22
    guest_telnet_port: int = 23
    use_nat: bool = True
    nat_public_ip: str = "192.168.1.40"
    save_snapshots: bool = False
    snapshot_path: str = "var/lib/cyanide/snapshots"
    targets: str = ""


class LoggingRotationConfig(BaseModel):
    strategy: str = Field(default="time", pattern="^(time|size)$")
    when: str = "midnight"
    interval: int = 1
    backup_count: int = 14
    max_bytes: int = 10485760


class LoggingConfig(BaseModel):
    directory: str = "var/log/cyanide"
    logtype: str = Field(default="plain", pattern="^(plain|rotating)$")
    rotation: LoggingRotationConfig = Field(default_factory=LoggingRotationConfig)


class CyanideConfig(BaseModel):
    ml: Dict[str, Any] = Field(default_factory=dict)

    cleanup: Dict[str, Any] = Field(default_factory=dict)

    output: Dict[str, Any] = Field(default_factory=dict)

    hostname: str = "server01"
    log_path: str = "var/log/cyanide"
    fs_yaml: Optional[str] = None
    quarantine_path: str = "var/quarantine"
    quarantine_max_size_mb: int = 500
    os_profile: str = "random"
    dns_cache_ttl: int = 60
    custom_profile: Dict[str, str] = Field(default_factory=dict)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    listen_ip: str = "0.0.0.0"
    max_sessions: int = 100
    max_sessions_per_ip: int = 5
    session_timeout: int = 300

    ssh: SSHConfig = Field(default_factory=lambda: SSHConfig())
    telnet: TelnetConfig = Field(default_factory=lambda: TelnetConfig())
    metrics: MetricsConfig = Field(default_factory=lambda: MetricsConfig())
    pool: PoolConfig = Field(default_factory=lambda: PoolConfig())
    smtp: SMTPConfig = Field(default_factory=lambda: SMTPConfig())
    otel: TelemetryConfig = Field(default_factory=lambda: TelemetryConfig())
    virustotal: VirusTotalConfig = Field(default_factory=lambda: VirusTotalConfig())
    rate_limit: RateLimitConfig = Field(default_factory=lambda: RateLimitConfig())
    allow_local_network: bool = False

    users: List[Dict[str, str]] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")
