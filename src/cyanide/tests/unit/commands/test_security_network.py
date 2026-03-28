from unittest.mock import MagicMock, patch

import pytest

from cyanide.vfs.commands.curl import CurlCommand
from cyanide.vfs.commands.wget import WgetCommand


# Function 402: Performs operations related to mock emulator.
@pytest.fixture
def mock_emulator(mock_fs):
    emulator = MagicMock()
    emulator.fs = mock_fs
    emulator.username = "root"
    emulator.config = {}  # Default config
    emulator.resolve_path.side_effect = lambda p: p  # Simple pass-through
    return emulator


# Function 403: Runs unit tests for the curl_validate_url_scheme functionality.
@pytest.mark.asyncio
async def test_curl_validate_url_scheme(mock_emulator):
    cmd = CurlCommand(mock_emulator)

    # Test file:// scheme
    stdout, stderr, rc = await cmd.execute(["file:///etc/passwd"])
    assert rc == 1
    assert "Protocol 'file' not supported" in stderr

    # Test valid scheme
    with patch("socket.getaddrinfo") as mock_dns:
        # Mock DNS to return public IP
        mock_dns.return_value = [(0, 0, 0, "", ("8.8.8.8", 80))]

        # We expect a network error (since we don't mock aiohttp here fully), but Validation should PASS
        # If validation passed, it tries to connect and fails with code 6 or 1 depending on mock
        # We just want to ensure it didn't fail with validation error

        # Actually, let's just test the validate_url method directly since we added it to base
        is_valid, error, ip = cmd.validate_url("http://google.com")
        assert is_valid
        assert error == ""


# Function 404: Runs unit tests for the curl_validate_private_ip functionality.
@pytest.mark.asyncio
async def test_curl_validate_private_ip(mock_emulator):
    cmd = CurlCommand(mock_emulator)

    with patch("socket.getaddrinfo") as mock_dns:
        # Mock DNS to return private IP
        mock_dns.return_value = [(0, 0, 0, "", ("192.168.1.1", 80))]

        is_valid, error, ip = cmd.validate_url("http://internal-service")
        assert not is_valid
        assert "Access to private/local resource" in error


# Function 405: Runs unit tests for the wget_security functionality.
@pytest.mark.asyncio
async def test_wget_security(mock_emulator):
    cmd = WgetCommand(mock_emulator)

    # Test direct IP
    stdout, stderr, rc = await cmd.execute(["http://127.0.0.1/secret"])
    assert rc == 1
    assert "Access to private/local resource" in stderr


# Function 406: Runs unit tests for the curl_allow_local_network functionality.
@pytest.mark.asyncio
async def test_curl_allow_local_network(mock_emulator):
    # Enable allow_local_network
    mock_emulator.config = {"allow_local_network": True}
    cmd = CurlCommand(mock_emulator)

    with patch("socket.getaddrinfo") as mock_dns:
        # Mock DNS to return private IP
        mock_dns.return_value = [(0, 0, 0, "", ("192.168.1.1", 80))]

        is_valid, error, ip = cmd.validate_url("http://internal-service")
        # Should be valid now
        assert is_valid
        assert error == ""
