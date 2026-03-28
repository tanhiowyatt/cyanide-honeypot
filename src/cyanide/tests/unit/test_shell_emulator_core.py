from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def mock_fs():
    fs = FakeFilesystem()
    fs.mkdir_p("/root")
    fs.mkdir_p("/home/guest")
    fs.mkfile("/root/test.txt", content="hello")
    return fs


@pytest.fixture
def emulator(mock_fs):
    return ShellEmulator(mock_fs, username="root")


def test_emulator_init(emulator):
    assert emulator.username == "root"
    assert emulator.cwd == "/root"
    assert emulator.env["USER"] == "root"
    assert "PATH" in emulator.env


def test_resolve_path(emulator):
    assert emulator.resolve_path("/etc/passwd") == "/etc/passwd"
    assert emulator.resolve_path("test.txt") == "/root/test.txt"
    emulator.cwd = "/home/guest"
    assert emulator.resolve_path("file.txt") == "/home/guest/file.txt"


def test_expand_vars(emulator):
    emulator.env["FOO"] = "bar"
    assert emulator._expand_vars("echo $FOO") == "echo bar"
    assert emulator._expand_vars("echo ${FOO}") == "echo bar"
    assert emulator._expand_vars("echo $MISSING") == "echo "


def test_parse_chain(emulator):
    nodes = emulator._parse_chain("ls -l; echo hello && pwd || exit")
    assert len(nodes) == 4
    assert nodes[0].cmd_line == "ls -l"
    assert nodes[0].operator == ";"
    assert nodes[1].cmd_line == "echo hello"
    assert nodes[1].operator == "&&"
    assert nodes[2].cmd_line == "pwd"
    assert nodes[2].operator == "||"
    assert nodes[3].cmd_line == "exit"
    assert nodes[3].operator is None


def test_split_ignore_quotes(emulator):
    parts = emulator._split_ignore_quotes("echo 'a | b' | grep a", "|")
    assert len(parts) == 2
    assert parts[0] == "echo 'a | b'"
    assert parts[1] == "grep a"


@pytest.mark.asyncio
async def test_execute_pipeline_redirection(emulator, mock_fs):
    # Mock _execute_single_command to return custom output
    with patch.object(
        emulator, "_execute_single_command", AsyncMock(return_value=("output\n", "", 0))
    ):
        # Test > redirection
        await emulator._execute_pipeline("echo something > /root/out.txt")
        assert mock_fs.get_content("/root/out.txt") == "output\n"

        # Test >> redirection
        await emulator._execute_pipeline("echo more >> /root/out.txt")
        assert mock_fs.get_content("/root/out.txt") == "output\noutput\n"


@pytest.mark.asyncio
async def test_execute_with_pending_input(emulator):
    callback = MagicMock(return_value=("success", "", 0))
    emulator.pending_input_callback = callback
    emulator.pending_input_prompt = "Password: "

    stdout, stderr, rc = await emulator.execute("secret")

    assert stdout == "success"
    assert rc == 0
    callback.assert_called_with("secret")
    assert emulator.pending_input_callback is None


def test_check_permission(emulator, mock_fs):
    mock_fs.mkfile("/root/secret", perm="-rw-------", owner="root")
    mock_fs.mkfile("/home/guest/pub", perm="-rw-r--r--", owner="guest")

    # Root can do anything
    assert emulator.check_permission("/root/secret", "r") is True

    # Guest cannot read root secret
    emulator.username = "guest"
    assert emulator.check_permission("/root/secret", "r") is False

    # Guest can read their own pub
    assert emulator.check_permission("/home/guest/pub", "r") is True

    # Guest cannot write to their own pub if it's read-only
    # Update memory_overlay directly because nodes are transient
    mock_fs.memory_overlay["/home/guest/pub"]["perm"] = "-r--r--r--"
    assert emulator.check_permission("/home/guest/pub", "w") is False


def test_resolve_alias(emulator):
    cmd, params = emulator._resolve_alias("ll", ["/tmp"])
    assert cmd == "ls"
    assert params == ["-alF", "/tmp"]

    cmd, params = emulator._resolve_alias("unknown", ["arg"])
    assert cmd == "unknown"
    assert params == ["arg"]


@pytest.mark.asyncio
async def test_execute_max_chain_depth(emulator):
    emulator.max_chain_depth = 2
    stdout, stderr, rc = await emulator.execute("a; b; c")
    assert rc == 1
    assert "maximum command chain depth exceeded" in stderr


@pytest.mark.asyncio
async def test_execute_max_output_size(emulator):
    emulator.max_output_size = 5
    with patch.object(
        emulator, "_execute_single_command", AsyncMock(return_value=("long output", "", 0))
    ):
        stdout, stderr, rc = await emulator.execute("echo long")
        assert "output truncated" in stdout
        assert "maximum output size exceeded" in stderr
        assert rc == 1
