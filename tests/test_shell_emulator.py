import pytest

from cyanide.core.emulator import ShellEmulator

# --- Mocks ---


class MockCommand:
    """Mock command for testing shell orchestration."""

    def __init__(self, emulator):
        self.emulator = emulator

    async def execute(self, args, input_data=""):
        if args and args[0] == "fail":
            return "", "command failed\n", 1
        elif args and args[0] == "echo":
            return " ".join(args[1:]) + "\n", "", 0
        elif args and args[0] == "input":
            return f"received: {input_data}", "", 0

        output = f"executed {' '.join(args)}"
        if input_data:
            output += f" with input: {input_data}"
        return output, "", 0


# --- Fixtures ---


@pytest.fixture
def mock_command_map(mocker):
    """Patch the global COMMAND_MAP with our mock command."""
    mock_map = {"test": MockCommand, "echo": MockCommand}  # Re-use for simple echo logic
    mocker.patch.dict("cyanide.vfs.commands.COMMAND_MAP", mock_map)
    return mock_map


@pytest.fixture
def shell(mock_fs, mock_command_map):
    """Return a ShellEmulator instance with mocked commands."""
    return ShellEmulator(mock_fs, username="testuser")


# --- Tests ---


@pytest.mark.asyncio
async def test_parse_chain_simple(shell):
    """Test parsing a simple command."""
    nodes = shell._parse_chain("test arg1")
    assert len(nodes) == 1
    assert nodes[0].cmd_line == "test arg1"
    assert nodes[0].operator is None


@pytest.mark.asyncio
async def test_parse_chain_complex(shell):
    """Test parsing multiple operators."""
    cmd = "test 1 && test 2 || test 3 ; test 4"
    nodes = shell._parse_chain(cmd)

    assert len(nodes) == 4
    assert nodes[0].cmd_line == "test 1"
    assert nodes[0].operator == "&&"

    assert nodes[1].cmd_line == "test 2"
    assert nodes[1].operator == "||"

    assert nodes[2].cmd_line == "test 3"
    assert nodes[2].operator == ";"

    assert nodes[3].cmd_line == "test 4"
    assert nodes[3].operator is None


@pytest.mark.asyncio
async def test_parse_chain_quotes(shell):
    """Test that operators inside quotes are ignored."""
    cmd = "test '&&' && test 2"
    nodes = shell._parse_chain(cmd)

    assert len(nodes) == 2
    assert nodes[0].cmd_line == "test '&&'"
    assert nodes[0].operator == "&&"


@pytest.mark.asyncio
async def test_execute_basic(shell):
    """Test basic execution."""
    stdout, stderr, rc = await shell.execute("test hello")
    assert "executed hello" in stdout
    assert rc == 0


@pytest.mark.asyncio
async def test_execute_and_operator(shell):
    """Test && operator logic."""
    # Success -> Success
    stdout, _, rc = await shell.execute("test 1 && test 2")
    assert "executed 1" in stdout
    assert "executed 2" in stdout
    assert rc == 0

    # Fail -> Skip
    stdout, stderr, rc = await shell.execute("test fail && test 2")
    assert "command failed" in stderr
    assert "executed 2" not in stdout
    # RC should be from the failed command
    assert rc == 1


@pytest.mark.asyncio
async def test_execute_or_operator(shell):
    """Test || operator logic."""
    # Fail -> Execute
    stdout, stderr, rc = await shell.execute("test fail || test 2")
    assert "executed 2" in stdout
    assert rc == 0  # Final RC is 0

    # Success -> Skip
    stdout, stderr, rc = await shell.execute("test 1 || test 2")
    assert "executed 1" in stdout
    assert "executed 2" not in stdout


@pytest.mark.asyncio
async def test_execute_semicolon(shell):
    """Test ; operator logic."""
    # Fail -> Execute
    stdout, stderr, rc = await shell.execute("test fail ; test 2")
    assert "command failed" in stderr
    assert "executed 2" in stdout


@pytest.mark.asyncio
async def test_redirection_overwrite(shell, mock_fs):
    """Test > redirection."""
    mock_fs.mkdir_p("/home/testuser")

    await shell.execute("test content > output.txt")

    assert mock_fs.exists("/home/testuser/output.txt")
    content = mock_fs.get_content("/home/testuser/output.txt")
    assert "executed content" in content


@pytest.mark.asyncio
async def test_redirection_append(shell, mock_fs):
    """Test >> redirection."""
    mock_fs.mkdir_p("/home/testuser")
    mock_fs.mkfile("/home/testuser/log.txt", content="initial\n")

    await shell.execute("test append >> log.txt")

    content = mock_fs.get_content("/home/testuser/log.txt")
    assert "initial\n" in content
    assert "executed append" in content


@pytest.mark.asyncio
async def test_pipe(shell):
    """Test | pipe logic."""
    # Output of 1 passed to 2
    # MockCommand "input" args will echo input_data

    # We used testcmd which returns input_data in output if present
    stdout, _, _ = await shell.execute("test origin | test receiver")
    assert "executed receiver with input: executed origin" in stdout


@pytest.mark.asyncio
async def test_resolve_path(shell):
    """Test path resolution."""
    assert shell.resolve_path("/absolute") == "/absolute"
    assert shell.resolve_path("relative") == "/home/testuser/relative"
    assert shell.resolve_path("../parent") == "/home/parent"


@pytest.mark.asyncio
async def test_permissions_root(mock_fs):
    """Test root permissions."""
    mock_fs.mkdir_p("/etc")
    shell = ShellEmulator(mock_fs, username="root")
    mock_fs.mkfile("/etc/shadow", owner="root", perm="-rw-------")

    # Root can read anything
    assert shell.check_permission("/etc/shadow", "r") is True
    assert shell.check_permission("/etc/shadow", "w") is True


@pytest.mark.asyncio
async def test_permissions_user(mock_fs):
    """Test regular user permissions."""
    mock_fs.mkdir_p("/etc")
    mock_fs.mkdir_p("/tmp")
    mock_fs.mkdir_p("/home/user")

    shell = ShellEmulator(mock_fs, username="user")
    mock_fs.mkfile("/etc/shadow", owner="root", perm="-rw-------")
    mock_fs.mkfile("/tmp/public", owner="root", perm="-rw-rw-rw-")
    mock_fs.mkfile("/home/user/private", owner="user", perm="-rw-------")

    # Cannot read root file
    assert shell.check_permission("/etc/shadow", "r") is False

    # Can read/write public file
    assert shell.check_permission("/tmp/public", "r") is True
    assert shell.check_permission("/tmp/public", "w") is True

    # Can read own file
    assert shell.check_permission("/home/user/private", "r") is True


@pytest.mark.asyncio
async def test_unknown_command(shell):
    """Test execution of unknown command."""
    stdout, stderr, rc = await shell.execute("unknown_cmd")
    assert "command not found" in stderr
    assert rc == 127
