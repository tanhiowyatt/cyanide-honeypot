from cyanide.core.config_schema import CyanideConfig


def test_ssh_file_transfer_config():
    config = CyanideConfig(users=[{"user": "root", "pass": "admin"}])
    assert config.ssh.sftp_enabled is True
    assert config.ssh.scp_enabled is True
    assert config.ssh.rsync_enabled is True
    assert config.ssh.max_upload_size_mb == 50
    assert config.ssh.allow_upload is True


def test_ssh_config_overrides():
    raw_config = {
        "ssh": {
            "sftp_enabled": False,
            "scp_enabled": False,
            "rsync_enabled": False,
            "max_upload_size_mb": 100,
            "allow_upload": False,
        },
        "users": [{"user": "root", "pass": "admin"}],
    }
    config = CyanideConfig(**raw_config)
    assert config.ssh.sftp_enabled is False
    assert config.ssh.max_upload_size_mb == 100
    assert config.ssh.allow_upload is False
