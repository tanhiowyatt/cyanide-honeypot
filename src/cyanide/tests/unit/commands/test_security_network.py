from unittest.mock import MagicMock, patch

import pytest

from cyanide.vfs.commands.curl import CurlCommand
from cyanide.vfs.commands.wget import WgetCommand


@pytest.fixture
def mock_emulator(mock_fs):
    emulator = MagicMock()
    emulator.fs = mock_fs
    emulator.username = "root"
    emulator.config = {}
    emulator.resolve_path.side_effect = lambda p: p
    return emulator


@pytest.mark.asyncio
async def test_curl_validate_url_scheme(mock_emulator):
    cmd = CurlCommand(mock_emulator)

    stdout, stderr, rc = await cmd.execute(["file:///etc/passwd"])
    assert rc == 1
    assert "Protocol 'file' not supported" in stderr

    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(0, 0, 0, "", ("8.8.8.8", 80))]

        is_valid, error, ip = cmd.validate_url("http://google.com")
        assert is_valid
        assert error == ""


@pytest.mark.asyncio
async def test_curl_validate_private_ip(mock_emulator):
    cmd = CurlCommand(mock_emulator)

    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(0, 0, 0, "", ("192.168.1.1", 80))]

        is_valid, error, ip = cmd.validate_url("http://internal-service")
        assert not is_valid
        assert "Access to private/local resource" in error


@pytest.mark.asyncio
async def test_wget_security(mock_emulator):
    cmd = WgetCommand(mock_emulator)

    stdout, stderr, rc = await cmd.execute(["http://127.0.0.1/secret"])
    assert rc == 1
    assert "Access to private/local resource" in stderr


@pytest.mark.asyncio
async def test_curl_allow_local_network(mock_emulator):
    mock_emulator.config = {"allow_local_network": True}
    cmd = CurlCommand(mock_emulator)

    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(0, 0, 0, "", ("192.168.1.1", 80))]

        is_valid, error, ip = cmd.validate_url("http://internal-service")
        assert is_valid
        assert error == ""
