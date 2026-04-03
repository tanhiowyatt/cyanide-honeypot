import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.id import IdCommand
from cyanide.vfs.commands.ps import PsCommand
from cyanide.vfs.commands.uname import UnameCommand
from cyanide.vfs.commands.whoami import WhoamiCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
async def test_uname(shell):
    cmd = UnameCommand(shell)

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "Linux" in stdout

    stdout, stderr, rc = await cmd.execute(["-a"])
    assert rc == 0
    assert "Linux" in stdout


@pytest.mark.asyncio
async def test_whoami(shell):
    cmd = WhoamiCommand(shell)

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "root" in stdout.strip()


@pytest.mark.asyncio
async def test_id(shell):
    cmd = IdCommand(shell)

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "uid=0(root)" in stdout
    assert "gid=0(root)" in stdout
    assert "groups=0(root)" in stdout


@pytest.mark.asyncio
async def test_ps(shell):
    cmd = PsCommand(shell)

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "PID TTY          TIME CMD" in stdout
    assert "bash" in stdout
    assert "1" in stdout
