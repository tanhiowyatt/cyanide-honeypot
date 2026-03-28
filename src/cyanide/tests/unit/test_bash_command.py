import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.bash import BashCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
async def test_bash_more(shell):
    cmd = BashCommand(shell)
    # bash -i
    stdout, stderr, rc = await cmd.execute(["-i"])
    assert "welcome" in stdout
    # bash -c (missing cmd)
    stdout, stderr, rc = await cmd.execute(["-c"])
    assert stdout == ""
    # other flag
    stdout, stderr, rc = await cmd.execute(["-l"])
    assert rc == 0
