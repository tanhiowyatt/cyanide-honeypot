from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any

class SSHConfig(BaseModel):
    enabled: bool = True
    port: int = 2222
    backend_mode: str = Field("emulated", pattern="^(emulated|proxy|pool)$")
    target_host: Optional[str] = "127.0.0.1"
    target_port: Optional[int] = 22222
    version: Optional[str] = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

class TelnetConfig(BaseModel):
    enabled: bool = False
    port: int = 2323
    backend_mode: str = Field("emulated", pattern="^(emulated|proxy|pool)$")
    target_host: Optional[str] = "127.0.0.1"
    target_port: Optional[int] = 23
    banner: Optional[str] = None

class MetricsConfig(BaseModel):
    enabled: bool = True
    port: int = 9090

class RateLimitConfig(BaseModel):
    max_connections_per_minute: int = 60
    ban_duration: int = 3600

class UserConfig(BaseModel):
    user: str
    password: str = Field(alias="pass")
    
class CyanideConfig(BaseModel):
    # ML
    ml: Dict[str, Any] = Field(default_factory=dict)
    
    # Cleanup
    cleanup: Dict[str, Any] = Field(default_factory=dict)
    
    # Paths & Core
    log_path: str = "var/log/cyanide"
    fs_yaml: Optional[str] = None
    quarantine_path: str = "var/lib/cyanide/quarantine"
    os_profile: str = "random"
    dns_cache_ttl: int = 60
    custom_profile: Dict[str, str] = Field(default_factory=dict)
    
    # Core (Session Manager)
    listen_ip: str = "0.0.0.0"
    max_sessions: int = 100
    max_sessions_per_ip: int = 5
    session_timeout: int = 300
    
    # Services
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    telnet: TelnetConfig = Field(default_factory=TelnetConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    
    # Security
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    allow_local_network: bool = False
    
    # Auth
    users: List[Dict[str, str]] = Field(default_factory=list) # simplified from UserConfig for now as config.py uses dicts
    
    class Config:
        extra = "ignore"
