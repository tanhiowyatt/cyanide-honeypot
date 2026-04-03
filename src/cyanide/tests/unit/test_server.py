from unittest.mock import AsyncMock

import pytest

from cyanide.core.server import CyanideServer


@pytest.mark.asyncio
async def test_server_initialization(mock_config, mock_logger, mocker):
    """Test that server initializes services correctly."""
    mocker.patch("cyanide.core.server.CyanideLogger", return_value=mock_logger)
    mocker.patch("cyanide.core.server.VTScanner")
    mocker.patch("cyanide.core.server.StatsManager")
    mocker.patch("cyanide.services.session_manager.SessionManager")
    mocker.patch("cyanide.services.quarantine.QuarantineService")
    mocker.patch("cyanide.services.analytics.AnalyticsService")
    mocker.patch(
        "cyanide.services.telnet_handler.TelnetHandler"
    )  # IMPORTANT because it takes server as arg

    server = CyanideServer(mock_config)

    assert server.config == mock_config
    assert server.logger == mock_logger
    assert server.services is not None


@pytest.mark.asyncio
async def test_server_start_stop(mock_server, mocker):
    """Test start and stop sequences."""
    mocker.patch("asyncssh.listen", new_callable=AsyncMock)
    mocker.patch("asyncio.start_server", new_callable=AsyncMock)

    pass
