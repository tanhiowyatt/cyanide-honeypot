from unittest.mock import patch

import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.ping import PingCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
@patch("socket.getaddrinfo")
async def test_ping_basic(mock_getaddrinfo, shell):
    mock_getaddrinfo.return_value = [(None, None, None, None, ("8.8.8.8", 0))]
    cmd = PingCommand(shell)
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 1
    assert "Destination address required" in stderr

    stdout, stderr, rc = await cmd.execute(["8.8.8.8"])
    assert rc == 0
    assert "PING 8.8.8.8" in stdout
    stdout, stderr, rc = await cmd.execute(["8.8.8.8"])
    assert rc == 0
    assert "2 packets transmitted, 2 received" in stdout
