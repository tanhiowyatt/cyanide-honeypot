from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.core.server import SSHServerFactory
from cyanide.services.telnet_handler import TelnetHandler


@pytest.fixture
def mock_honeypot():
    hp = MagicMock()
    hp.config = {"ssh": {"auth_delay": 1.0}, "telnet": {"auth_delay": 1.0}}
    hp.is_valid_user.return_value = True
    hp.logger = MagicMock()
    hp.stats = MagicMock()
    hp.tracer = MagicMock()
    hp.services = MagicMock()
    return hp


@pytest.mark.asyncio
async def test_ssh_auth_delay(mock_honeypot):
    factory = SSHServerFactory(mock_honeypot)
    factory.conn_id = "test_conn"
    factory.src_ip = "1.2.3.4"

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        success = await factory.validate_password("user", "pass")
        assert success is True
        mock_sleep.assert_called_once_with(1.0)


@pytest.mark.asyncio
async def test_telnet_auth_delay(mock_honeypot):
    handler = TelnetHandler(mock_honeypot, mock_honeypot.config)
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()

    # Mock inputs for _perform_auth
    reader.readuntil.side_effect = [b"user\n", b"pass\n"]

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        # We need to run _perform_auth specifically
        success, user, b_in, b_out = await handler._perform_auth(
            reader, writer, "sess_id", "1.2.3.4"
        )
        assert success is True
        mock_sleep.assert_called_once_with(1.0)


@pytest.mark.asyncio
async def test_ssh_no_delay_on_failure(mock_honeypot):
    mock_honeypot.is_valid_user.return_value = False
    factory = SSHServerFactory(mock_honeypot)

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        success = await factory.validate_password("user", "wrong")
        assert success is False
        mock_sleep.assert_not_called()
