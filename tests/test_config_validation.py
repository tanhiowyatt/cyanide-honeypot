import pytest

from cyanide.core.config import load_config


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
  quarantine_path: var/lib/cyanide/quarantine
  
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
  quarantine_path: var/lib/cyanide/quarantine
  
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


def test_load_valid_config(valid_config):
    config = load_config(valid_config)
    assert config["ssh"]["port"] == 2222
    assert config["ssh"]["backend_mode"] == "emulated"
    assert config["rate_limit"]["max_connections_per_minute"] == 60


def test_load_invalid_config(invalid_config):
    # Expect sys.exit(1)
    with pytest.raises(SystemExit) as e:
        load_config(invalid_config)
    assert e.value.code == 1
