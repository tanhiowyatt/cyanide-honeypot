from unittest.mock import patch

import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.cp import CpCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
async def test_cp_basic(shell, mock_fs):
    cmd = CpCommand(shell)
    mock_fs.mkfile("/root/file1.txt", content="content1")

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 1
    assert "missing file operand" in stderr

    stdout, stderr, rc = await cmd.execute(["file1.txt"])
    assert rc == 1
    assert "missing file operand" in stderr

    with patch.object(shell, "resolve_path", side_effect=["/root/file2.txt", "/root/file1.txt"]):
        stdout, stderr, rc = await cmd.execute(["file1.txt", "file2.txt"])
        assert rc == 0
        assert mock_fs.exists("/root/file2.txt")
        assert mock_fs.get_content("/root/file2.txt") == "content1"


@pytest.mark.asyncio
async def test_cp_directory(shell, mock_fs):
    cmd = CpCommand(shell)
    mock_fs.mkdir_p("/root/dir1")

    with patch.object(shell, "resolve_path", side_effect=["/root/dir2", "/root/dir1"]):
        stdout, stderr, rc = await cmd.execute(["dir1", "dir2"])
        assert rc == 1
        assert "omitting directory" in stderr
