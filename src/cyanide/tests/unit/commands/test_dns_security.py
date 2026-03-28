from unittest.mock import MagicMock, patch

import pytest

from cyanide.vfs.commands.curl import CurlCommand


# Function 358: Performs operations related to mock emulator.
@pytest.fixture
def mock_emulator():
    emulator = MagicMock()
    emulator.fs = MagicMock()
    emulator.username = "root"
    emulator.config = {}
    emulator.dns_cache = {}  # Real dict for caching
    return emulator


# Function 359: Runs unit tests for the validate_url_checks_all_ips functionality.
@pytest.mark.asyncio
async def test_validate_url_checks_all_ips(mock_emulator):
    cmd = CurlCommand(mock_emulator)

    with patch("socket.getaddrinfo") as mock_dns:
        # One valid, one private
        mock_dns.return_value = [(0, 0, 0, "", ("8.8.8.8", 80)), (0, 0, 0, "", ("127.0.0.1", 80))]

        is_valid, error, ip = cmd.validate_url("http://mixed-ips.com")
        assert not is_valid
        assert "Access to private/local resource" in error


# Function 360: Runs unit tests for the dns_caching_logic functionality.
@pytest.mark.asyncio
async def test_dns_caching_logic(mock_emulator):
    cmd = CurlCommand(mock_emulator)

    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(0, 0, 0, "", ("1.1.1.1", 80))]

        # First call - resolves and caches
        is_valid, error, ip1 = cmd.validate_url("http://cached.com")
        assert is_valid
        assert ip1 == "1.1.1.1"
        assert mock_dns.call_count == 1

        # Second call - should use cache
        is_valid, error, ip2 = cmd.validate_url("http://cached.com")
        assert is_valid
        assert ip2 == "1.1.1.1"
        assert mock_dns.call_count == 1  # Still 1


# Function 361: Runs unit tests for the dns_cache_expiry functionality.
@pytest.mark.asyncio
async def test_dns_cache_expiry(mock_emulator):
    cmd = CurlCommand(mock_emulator)

    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(0, 0, 0, "", ("1.1.1.1", 80))]

        # Use a frozen time
        with patch("time.time") as mock_time:
            mock_time.return_value = 1000.0

            # Resolve and cache
            cmd.validate_url("http://expiry.com")
            assert mock_dns.call_count == 1

            # After 30 seconds - still cached
            mock_time.return_value = 1030.0
            cmd.validate_url("http://expiry.com")
            assert mock_dns.call_count == 1

            # After 61 seconds - expired
            mock_time.return_value = 1061.0
            cmd.validate_url("http://expiry.com")
            assert mock_dns.call_count == 2
