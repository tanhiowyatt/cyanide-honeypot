import os
from unittest.mock import patch

import yaml

from cyanide.core.config import _apply_env_overrides, _get_val, _parse_val, load_config


def test_parse_val():
    assert _parse_val("true") is True
    assert _parse_val("FALSE") is False
    assert _parse_val("123") == 123
    assert _parse_val('{"a": 1}') == {"a": 1}
    assert _parse_val("random") == "random"


def test_apply_env_overrides():
    with patch.dict(os.environ, {"CYANIDE_DEBUG": "true", "CYANIDE_SSH_PORT": "2222"}):
        data = {"debug": False, "ssh": {"port": 22}}
        overridden = _apply_env_overrides(data)
        assert overridden["debug"] is True
        assert overridden["ssh"]["port"] == 2222


def test_get_val():
    config_data = {"server": {"host": "1.2.3.4"}}
    # env var take precedence
    with patch.dict(os.environ, {"CYANIDE_SERVER__HOST": "5.6.7.8"}):
        val = _get_val(config_data, "server", "host", "HOST", "0.0.0.0")
        assert val == "5.6.7.8"

    # from config_data
    val = _get_val(config_data, "server", "host", "HOST", "0.0.0.0")
    assert val == "1.2.3.4"

    # default
    val = _get_val(config_data, "nonexistent", "key", "ENV", "default")
    assert val == "default"


def test_load_config_minimal(tmp_path):
    conf_file = tmp_path / "app.yaml"
    conf_file.write_text(yaml.dump({"honeypot": {"hostname": "testhost"}}))

    with patch("cyanide.core.config.load_dotenv"):
        config = load_config(conf_file)
        assert config["hostname"] == "testhost"
        assert config["ssh"]["port"] == 2222  # default


def test_load_config_no_file(tmp_path):
    non_existent = tmp_path / "missing.yaml"
    with patch("cyanide.core.config.load_dotenv"):
        config = load_config(non_existent)
        assert config["hostname"] == "server01"  # default


def test_user_config_alias():
    from cyanide.core.config_schema import UserConfig

    # Test that 'pass' field is correctly aliased to 'password'
    u = UserConfig(**{"user": "admin", "pass": "secret"})
    assert u.user == "admin"
    assert u.password == "secret"
