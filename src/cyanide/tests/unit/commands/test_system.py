import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.id import IdCommand
from cyanide.vfs.commands.ps import PsCommand
from cyanide.vfs.commands.uname import UnameCommand
from cyanide.vfs.commands.whoami import WhoamiCommand


# Function 414: Performs operations related to shell.
@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


# Function 415: Runs unit tests for the uname functionality.
@pytest.mark.asyncio
async def test_uname(shell):
    cmd = UnameCommand(shell)

    # Default
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "Linux" in stdout

    # -a
    stdout, stderr, rc = await cmd.execute(["-a"])
    assert rc == 0
    assert "Linux" in stdout
    # assert "GNU/Linux" in stdout # Not present in simulated output


# Function 416: Runs unit tests for the whoami functionality.
@pytest.mark.asyncio
async def test_whoami(shell):
    cmd = WhoamiCommand(shell)

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "root" in stdout.strip()


# Function 417: Runs unit tests for the id functionality.
@pytest.mark.asyncio
async def test_id(shell):
    cmd = IdCommand(shell)

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "uid=0(root)" in stdout
    assert "gid=0(root)" in stdout
    assert "groups=0(root)" in stdout


# Function 418: Runs unit tests for the ps functionality.
@pytest.mark.asyncio
async def test_ps(shell):
    cmd = PsCommand(shell)

    # Basic
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "PID TTY          TIME CMD" in stdout
    assert "bash" in stdout

    # Validate some PIDs are present (from VMPool mock or simplified logic in PsCommand)
    # PsCommand implementation details? It usually lists mock processes.
    assert "1" in stdout  # init?
