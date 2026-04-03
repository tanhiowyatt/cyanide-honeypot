from unittest.mock import MagicMock, patch

import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.chmod import ChmodCommand
from cyanide.vfs.commands.rmdir import RmdirCommand
from cyanide.vfs.commands.su import SuCommand
from cyanide.vfs.commands.sudo import SudoCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
async def test_chmod(shell, mock_fs):
    cmd = ChmodCommand(shell)
    mock_fs.mkfile("/root/script.sh", perm="-rw-r--r--")

    stdout, stderr, rc = await cmd.execute([])
    assert rc == 1
    assert "missing operand" in stderr

    node = mock_fs.get_node("/root/script.sh")
    with patch.object(shell, "resolve_path", return_value="/root/script.sh"):
        with patch.object(mock_fs, "get_node", return_value=node):
            await cmd.execute(["777", "script.sh"])
            assert node.perm == "-rwxrwxrwx"

    node.perm = "-rw-r--r--"
    with patch.object(shell, "resolve_path", return_value="/root/script.sh"):
        with patch.object(mock_fs, "get_node", return_value=node):
            await cmd.execute(["+x", "script.sh"])
            assert node.perm[3] == "x"
            assert node.perm[6] == "x"
            assert node.perm[9] == "x"


@pytest.mark.asyncio
async def test_rmdir(shell, mock_fs):
    cmd = RmdirCommand(shell)
    mock_fs.mkdir_p("/root/empty")

    mock_parent = MagicMock()
    node = mock_fs.get_node("/root/empty")
    node._parent = mock_parent

    with patch.object(shell, "resolve_path", return_value="/root/empty"):
        with patch.object(mock_fs, "get_node", return_value=node):
            stdout, stderr, rc = await cmd.execute(["empty"])
            assert rc == 0
            mock_parent.remove_child.assert_called_with("empty")


@pytest.mark.asyncio
async def test_su(shell, mock_fs):
    cmd = SuCommand(shell)
    mock_fs.mkdir_p("/home")

    stdout, stderr, rc = await cmd.execute(["-", "guest"])
    assert stdout == "Password: "
    await cmd.execute(["-", "guest"])
    stdout, stderr, rc = cmd._on_password("admin")
    assert rc == 0
    assert shell.username == "guest"
    assert mock_fs.exists("/home/guest")


@pytest.mark.asyncio
async def test_sudo(shell, mock_fs):
    cmd = SudoCommand(shell)

    # sudo -l (list privileges)
    stdout, stderr, rc = await cmd.execute(["-l"])
    assert rc == 0
    assert "may run the following commands" in stdout

    # sudo with no args
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 1
    assert "usage: sudo" in stderr

    # sudo -i (interactive root shell)
    stdout, stderr, rc = await cmd.execute(["-i"])
    assert rc == 0
    assert shell.username == "root"
    assert shell.cwd == "/root"

    # sudo -u guest whoami
    shell.username = "root"
    # Note: sudo.py imports ShellEmulator inside _handle_command
    # To avoid recursion or dependency issues in tests, we can mock the inner execute
    with patch("cyanide.core.emulator.ShellEmulator.execute", return_value=("guest\n", "", 0)):
        stdout, stderr, rc = await cmd.execute(["-u", "guest", "whoami"])
        assert rc == 0
        assert stdout == "guest\n"


@pytest.mark.asyncio
async def test_sudo_invalid_args(shell, mock_fs):
    cmd = SudoCommand(shell)
    # sudo -u (missing user)
    stdout, stderr, rc = await cmd.execute(["-u"])
    assert rc == 1
    assert "option requires an argument" in stderr
