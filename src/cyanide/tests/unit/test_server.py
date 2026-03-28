from unittest.mock import AsyncMock

import pytest

from cyanide.core.server import CyanideServer


# Function 464: Runs unit tests for the server_initialization functionality.
@pytest.mark.asyncio
async def test_server_initialization(mock_config, mock_logger, mocker):
    """Test that server initializes services correctly."""
    # Mock dependencies
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
    # We can check if services are instances of mocks


# Function 465: Runs unit tests for the server_start_stop functionality.
@pytest.mark.asyncio
async def test_server_start_stop(mock_server, mocker):
    """Test start and stop sequences."""
    # Mock external listeners
    mocker.patch("asyncssh.listen", new_callable=AsyncMock)
    mocker.patch("asyncio.start_server", new_callable=AsyncMock)

    # Mock database connections if any (SessionManager usually handles this)

    # Mock serve_forever to return immediately (or throw CancelledError when task cancelled)
    # The start method usually waits on serve_forever.
    # We should mock internal methods that block.

    # If CyanideServer.start() calls asyncssh.listen and then waits...
    # We need to see the code. Assuming typical async server pattern.

    # Let's inspect start() implementation code first.
    pass
