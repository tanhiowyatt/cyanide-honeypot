import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.cd import CdCommand
from cyanide.vfs.commands.ls import LsCommand
from cyanide.vfs.commands.pwd import PwdCommand


# Function 381: Performs operations related to shell.
@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


# Function 382: Runs unit tests for the cd functionality.
@pytest.mark.asyncio
async def test_cd(shell, mock_fs):
    cmd = CdCommand(shell)

    mock_fs.mkdir_p("/root/dir")

    # Absolute path
    stdout, stderr, rc = await cmd.execute(["/root/dir"])
    assert rc == 0
    assert shell.cwd == "/root/dir"

    # Relative path
    stdout, stderr, rc = await cmd.execute([".."])
    assert rc == 0
    assert shell.cwd == "/root"

    # Missing directory
    stdout, stderr, rc = await cmd.execute(["missing"])
    assert rc != 0
    assert "No such file or directory" in stderr


# Function 383: Runs unit tests for the pwd functionality.
@pytest.mark.asyncio
async def test_pwd(shell):
    cmd = PwdCommand(shell)
    shell.cwd = "/test/cwd"

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert stdout.strip() == "/test/cwd"


# Function 384: Runs unit tests for the ls functionality.
@pytest.mark.asyncio
async def test_ls(shell, mock_fs):
    cmd = LsCommand(shell)

    # Setup files
    mock_fs.mkfile("/root/file1.txt")
    mock_fs.mkfile("/root/file2.txt")
    mock_fs.mkdir_p("/root/dir1")

    # List current dir
    shell.cwd = "/root"
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "file1.txt" in stdout
    assert "file2.txt" in stdout
    assert "dir1" in stdout

    # List specific dir
    mock_fs.mkfile("/tmp/temp.txt")
    stdout, stderr, rc = await cmd.execute(["/tmp"])
    assert rc == 0
    assert "temp.txt" in stdout

    # Long format
    stdout, stderr, rc = await cmd.execute(["-l"])
    assert rc == 0
    assert "root" in stdout  # owner

    # Missing dir
    stdout, stderr, rc = await cmd.execute(["/missing"])
    assert rc != 0
