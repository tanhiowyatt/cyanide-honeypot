import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.uname import UnameCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
async def test_uname_basic(shell):
    cmd = UnameCommand(shell)
    # uname
    stdout, stderr, rc = await cmd.execute([])
    assert stdout == "Linux\n"
    # uname -a
    stdout, stderr, rc = await cmd.execute(["-a"])
    assert "Linux server" in stdout
    # uname -r
    stdout, stderr, rc = await cmd.execute(["-r"])
    assert "5.15.0" in stdout
    # uname -z (invalid)
    stdout, stderr, rc = await cmd.execute(["-z"])
    assert rc == 1
    assert "invalid option" in stderr


@pytest.mark.asyncio
async def test_uname_profile(shell, mock_fs):
    cmd = UnameCommand(shell)
    mock_fs.profile = {"uname_a": "CustomOS 1.0", "uname_r": "1.0-custom"}

    stdout, stderr, rc = await cmd.execute(["-a"])
    assert "CustomOS 1.0" in stdout
    stdout, stderr, rc = await cmd.execute(["-r"])
    assert "1.0-custom" in stdout
