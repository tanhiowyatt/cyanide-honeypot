import pytest
import warnings
from unittest.mock import AsyncMock
from cyanide.vfs.provider import FakeFilesystem

# Suppress noise from asyncssh/cryptography
warnings.filterwarnings("ignore", message=".*ARC4 has been moved.*")
warnings.filterwarnings("ignore", message=".*TripleDES has been moved.*")

@pytest.fixture
def mock_config():
    """Return a standard test configuration dictionary."""
    return {
        "logging": {
            "directory": "var/log/cyanide_test"
        },
        "quarantine_path": "var/lib/cyanide/quarantine_test",
        "quarantine_max_size_mb": 100,
        "os_profile": "custom",
        "custom_profile": {
            "name": "TestOS",
            "ssh_banner": "SSH-2.0-Test",
            "uname_r": "5.4.0-test",
            "uname_a": "Linux test 5.4.0",
            "etc_issue": "Test OS 1.0",
            "proc_version": "Test Version"
        },
        "ssh": {
            "port": 2222,
            "enabled": True,
            "backend_mode": "emulated"
        },
        "telnet": {
            "port": 2223,
            "enabled": True,
            "backend_mode": "emulated"
        },
        "users": [{"user": "root", "pass": "admin"}],
        "ml": {
            "enabled": False,
            "ml_log": "var/log/ml_test.json",
            "model_path": "model_test.pkl",
            "online_learning": False
        },
        "cleanup": {
            "enabled": True,
            "interval": 3600,
            "retention_days": 1,
            "paths": []
        },
        "virustotal": {"api_key": "test_key"},
        "metrics": {"enabled": False}
    }

@pytest.fixture
def mock_fs():
    """Return a fresh FakeFilesystem instance."""
    fs = FakeFilesystem(profile={"name": "TestProfile"})
    # Create standard directories to prevent CWD fallback to /
    fs.mkdir_p("/home/testuser")
    fs.mkdir_p("/home/admin")
    fs.mkdir_p("/root")
    fs.mkdir_p("/tmp")
    fs.mkdir_p("/etc")
    return fs

@pytest.fixture
def mock_logger(mocker):
    """Return a mocked CyanideLogger."""
    logger = mocker.MagicMock()
    logger.log_event = mocker.MagicMock()
    logger.log_event_async = mocker.AsyncMock()
    logger.log_command = mocker.AsyncMock()
    return logger

@pytest.fixture
def mock_server(mock_config, mock_logger, mocker):
    """Return a mocked HoneypotServer instance."""
    # Mock external dependencies
    mocker.patch("cyanide.core.server.CyanideLogger", return_value=mock_logger)
    mocker.patch("cyanide.core.server.VTScanner")
    # mocker.patch("cyanide.core.server.GeoIP") # Not present in server.py
    mocker.patch("cyanide.core.server.VMPool")
    mocker.patch("cyanide.core.server.StatsManager")
    
    # Mock socket and network calls to prevent actual binding
    mocker.patch("asyncssh.listen", new_callable=AsyncMock)
    mocker.patch("asyncio.start_server", new_callable=AsyncMock)
    
    from cyanide.core.server import HoneypotServer
    server = HoneypotServer(mock_config)
    server.logger = mock_logger # Ensure mocked logger is used
    
    # Clean up any created directories during tests
    yield server
    # Teardown if needed


