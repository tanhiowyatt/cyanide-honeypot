import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.cd import CdCommand
from cyanide.vfs.commands.ls import LsCommand
from cyanide.vfs.commands.pwd import PwdCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


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


@pytest.mark.asyncio
async def test_pwd(shell):
    cmd = PwdCommand(shell)
    shell.cwd = "/test/cwd"

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert stdout.strip() == "/test/cwd"


@pytest.mark.asyncio
async def test_ls(shell, mock_fs):
    cmd = LsCommand(shell)

    mock_fs.mkfile("/root/file1.txt")
    mock_fs.mkfile("/root/file2.txt")
    mock_fs.mkdir_p("/root/dir1")

    shell.cwd = "/root"
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "file1.txt" in stdout
    assert "file2.txt" in stdout
    assert "dir1" in stdout

    mock_fs.mkfile("/tmp/temp.txt")
    stdout, stderr, rc = await cmd.execute(["/tmp"])
    assert rc == 0
    assert "temp.txt" in stdout

    stdout, stderr, rc = await cmd.execute(["-l"])
    assert rc == 0
    assert "root" in stdout
    stdout, stderr, rc = await cmd.execute(["/missing"])
    assert rc != 0
