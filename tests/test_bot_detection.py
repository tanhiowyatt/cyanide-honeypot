import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from cyanide.core.server import SSHSession


@pytest.fixture
def mock_honeypot():
    hp = MagicMock()
    hp.config = {"ml": {"enabled": True}}
    hp.ml_enabled = True
    hp.ml_filter = True
    hp.logger = MagicMock()
    hp.logger.log_event_async = AsyncMock()
    hp.logger.log_command = AsyncMock()
    hp.stats = MagicMock()
    hp._analyze_command = MagicMock()
    return hp


@pytest.mark.asyncio
async def test_bot_detection_by_timing(mock_honeypot):
    session = SSHSession(mock_honeypot, MagicMock(), "1.1.1.1", 1234)
    session.channel = MagicMock()

    # Simulate rapid keystrokes properly
    # First keystroke
    await session._process_input("l")
    # Second keystroke (force timing)
    session.keystrokes = [time.time(), time.time() + 0.005]
    await session._process_input("s\n")

    # Verify is_bot=True was passed
    args, kwargs = mock_honeypot._analyze_command.call_args
    assert kwargs["is_bot"] is True


@pytest.mark.asyncio
async def test_bot_detection_by_paste(mock_honeypot):
    session = SSHSession(mock_honeypot, MagicMock(), "1.1.1.1", 1234)
    session.channel = MagicMock()

    # Simulate a paste
    await session._process_input("whoami\n")

    args, kwargs = mock_honeypot._analyze_command.call_args
    assert kwargs["is_bot"] is True


@pytest.mark.asyncio
async def test_human_typing_timing(mock_honeypot):
    session = SSHSession(mock_honeypot, MagicMock(), "1.1.1.1", 1234)
    session.channel = MagicMock()

    # Set slow keystrokes (100ms gap)
    session.keystrokes.append(time.time() - 0.2)
    session.keystrokes.append(time.time() - 0.1)

    session.buf = "id\n"
    await session._process_input("")

    args, kwargs = mock_honeypot._analyze_command.call_args
    assert kwargs["is_bot"] is False
