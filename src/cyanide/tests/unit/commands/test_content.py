import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.cat import CatCommand
from cyanide.vfs.commands.head import HeadCommand
from cyanide.vfs.commands.tail import TailCommand


# Function 354: Performs operations related to shell.
@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


# Function 355: Runs unit tests for the cat functionality.
@pytest.mark.asyncio
async def test_cat(shell, mock_fs):
    cmd = CatCommand(shell)

    mock_fs.mkfile("/root/file.txt", content="line1\nline2")

    # Cat file
    stdout, stderr, rc = await cmd.execute(["/root/file.txt"])
    assert rc == 0
    assert "line1\nline2" in stdout

    # Missing file
    stdout, stderr, rc = await cmd.execute(["missing.txt"])
    assert rc != 0

    # Multiple files
    mock_fs.mkfile("/root/file2.txt", content="content2")
    stdout, stderr, rc = await cmd.execute(["/root/file.txt", "/root/file2.txt"])
    assert rc == 0
    assert "line1" in stdout
    assert "content2" in stdout


# Function 356: Runs unit tests for the head functionality.
@pytest.mark.asyncio
async def test_head(shell, mock_fs):
    cmd = HeadCommand(shell)

    content = "\n".join([f"line{i}" for i in range(20)])
    mock_fs.mkfile("/root/long.txt", content=content)

    # Default (10 lines)
    stdout, stderr, rc = await cmd.execute(["/root/long.txt"])
    assert rc == 0
    lines = stdout.strip().split("\n")
    assert len(lines) == 10
    assert lines[0] == "line0"

    # -n lines
    stdout, stderr, rc = await cmd.execute(["-n", "5", "/root/long.txt"])
    assert rc == 0
    lines = stdout.strip().split("\n")
    assert len(lines) == 5


# Function 357: Runs unit tests for the tail functionality.
@pytest.mark.asyncio
async def test_tail(shell, mock_fs):
    cmd = TailCommand(shell)

    content = "\n".join([f"line{i}" for i in range(20)])
    mock_fs.mkfile("/root/long.txt", content=content)

    # Default (10 lines)
    stdout, stderr, rc = await cmd.execute(["/root/long.txt"])
    assert rc == 0
    lines = stdout.strip().split("\n")
    assert len(lines) == 10
    assert lines[-1] == "line19"

    # -n lines
    stdout, stderr, rc = await cmd.execute(["-n", "5", "/root/long.txt"])
    assert rc == 0
    lines = stdout.strip().split("\n")
    assert len(lines) == 5
    assert lines[-1] == "line19"
