import time
from unittest.mock import MagicMock

import pytest

from cyanide.core.server import SSHSession


@pytest.fixture
def mock_honeypot():
    hp = MagicMock()
    hp.config = {"ml": {"enabled": True}}
    hp.ml_enabled = True
    hp.ml_filter = True
    hp.logger = MagicMock()
    hp.logger.log_event = MagicMock()
    hp.stats = MagicMock()
    hp._analyze_command = MagicMock()
    return hp


@pytest.mark.asyncio
async def test_bot_detection_by_timing(mock_honeypot):
    session = SSHSession(mock_honeypot, MagicMock(), "1.1.1.1", 1234, "test-id")
    session.channel = MagicMock()

    await session._process_input("l")
    session.keystrokes = [time.time(), time.time() + 0.005]
    await session._process_input("s\n")
    args, kwargs = mock_honeypot._analyze_command.call_args
    assert kwargs["is_bot"] is True


@pytest.mark.asyncio
async def test_bot_detection_by_paste(mock_honeypot):
    session = SSHSession(mock_honeypot, MagicMock(), "1.1.1.1", 1234, "test-id")
    session.channel = MagicMock()

    long_cmd = "echo 'exploit' > /tmp/x; chmod +x /tmp/x; /tmp/x; rm /tmp/x;" * 5 + "\n"
    await session._process_input(long_cmd)

    args, kwargs = mock_honeypot._analyze_command.call_args
    assert kwargs["is_bot"] is True


@pytest.mark.asyncio
async def test_human_typing_timing(mock_honeypot):
    session = SSHSession(mock_honeypot, MagicMock(), "1.1.1.1", 1234, "test-id")
    session.channel = MagicMock()

    session.keystrokes.append(time.time() - 0.2)
    session.keystrokes.append(time.time() - 0.1)

    session.buf = "id\n"
    await session._process_input("")

    args, kwargs = mock_honeypot._analyze_command.call_args
    assert kwargs["is_bot"] is False
