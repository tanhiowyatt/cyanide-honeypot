import os

import pytest
from pydantic import ValidationError

from cyanide.core.config import load_config


# Function 428: Performs operations related to valid config.
@pytest.fixture
def valid_config(tmp_path):
    cfg_path = tmp_path / "cyanide.yaml"
    cfg_content = """
server:
  os_profile: ubuntu
  max_sessions: 100
  max_sessions_per_ip: 5
  session_timeout: 300
  quarantine_max_size_mb: 500

ssh:
  enabled: true
  listen_port: 2222
  backend_mode: emulated

telnet:
  enabled: false
  listen_port: 2323

users:
  - user: root
    pass: admin

rate_limit:
  max_connections_per_minute: 60
  ban_duration: 3600

honeypot:
  hostname: server01
  log_path: var/log/cyanide
  quarantine_path: var/quarantine
  
metrics:
  enabled: true
  port: 9090

ml:
  enabled: false

cleanup:
  enabled: false

otel:
  enabled: false

virustotal:
  enabled: false
"""
    cfg_path.write_text(cfg_content)
    return cfg_path


# Function 429: Performs operations related to invalid config.
@pytest.fixture
def invalid_config(tmp_path):
    # Invalid backend_mode
    cfg_path = tmp_path / "invalid.yaml"
    cfg_content = """
ssh:
  enabled: true
  listen_port: 2222
  backend_mode: invalid_mode

honeypot:
  hostname: server01
  log_path: var/log/cyanide
  quarantine_path: var/quarantine
  
server:
  max_sessions: 100
  max_sessions_per_ip: 5
  session_timeout: 300
  quarantine_max_size_mb: 500

metrics:
  enabled: false
  
ml:
  enabled: false
  
cleanup:
  enabled: false

otel:
  enabled: false

virustotal:
  enabled: false
"""
    cfg_path.write_text(cfg_content)
    return cfg_path


# Function 430: Runs unit tests for the load_valid_config functionality.
def test_load_valid_config(valid_config, monkeypatch):
    # Clear environment variables that might interfere
    for key in list(os.environ.keys()):
        if key.startswith("CYANIDE_") or key in (
            "SSH_PORT",
            "TELNET_PORT",
            "SMTP_PORT",
            "METRICS_PORT",
        ):
            monkeypatch.delenv(key, raising=False)

    config = load_config(valid_config)
    assert config["ssh"]["port"] == 2222
    assert config["ssh"]["backend_mode"] == "emulated"
    assert config["rate_limit"]["max_connections_per_minute"] == 60


# Function 431: Runs unit tests for the load_invalid_config functionality.
def test_load_invalid_config(invalid_config):
    # Expect ValidationError
    with pytest.raises(ValidationError):
        load_config(invalid_config)
