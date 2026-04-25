import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.cat import CatCommand
from cyanide.vfs.commands.grep import GrepCommand
from cyanide.vfs.commands.head import HeadCommand
from cyanide.vfs.commands.tail import TailCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
async def test_cat_edge_cases(shell, mock_fs):
    cmd = CatCommand(shell)

    # cat on directory
    mock_fs.mkdir_p("/root/dir")
    stdout, stderr, rc = await cmd.execute(["dir"])
    assert rc != 0
    assert "Is a directory" in stderr

    # cat with no args
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0  # In this emulation it just returns success or nothing


@pytest.mark.asyncio
async def test_head_tail_edge_cases(shell, mock_fs):
    head_cmd = HeadCommand(shell)
    tail_cmd = TailCommand(shell)

    # head missing file
    stdout, stderr, rc = await head_cmd.execute(["missing"])
    assert rc != 0

    # tail missing file
    stdout, stderr, rc = await tail_cmd.execute(["missing"])
    assert rc != 0

    # head/tail on directory
    mock_fs.mkdir_p("/root/dir")
    stdout, stderr, rc = await head_cmd.execute(["dir"])
    assert rc != 0
    stdout, stderr, rc = await tail_cmd.execute(["dir"])
    assert rc != 0


@pytest.mark.asyncio
async def test_grep_edge_cases(shell, mock_fs):
    cmd = GrepCommand(shell)
    mock_fs.mkfile("/root/file.txt", content="line1\nline2\nmatch this\nline4")

    # grep simple
    stdout, stderr, rc = await cmd.execute(["match", "file.txt"])
    assert rc == 0
    assert "match this" in stdout

    # grep -i
    stdout, stderr, rc = await cmd.execute(["-i", "MATCH", "file.txt"])
    assert rc == 0
    assert "match this" in stdout

    # grep -v
    stdout, stderr, rc = await cmd.execute(["-v", "line", "file.txt"])
    assert rc == 0
    assert "match this" in stdout
    assert "line1" not in stdout

    # grep missing file
    stdout, stderr, rc = await cmd.execute(["match", "missing"])
    assert rc != 0

    # grep on directory
    mock_fs.mkdir_p("/root/dir")
    stdout, stderr, rc = await cmd.execute(["match", "dir"])
    assert rc != 0

    # grep missing pattern
    stdout, stderr, rc = await cmd.execute(["-i"])
    assert rc != 0
