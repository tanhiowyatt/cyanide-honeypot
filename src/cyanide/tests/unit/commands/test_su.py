import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.su import SuCommand
from cyanide.vfs.engine import FakeFilesystem


# Function 407: Performs operations related to fs.
@pytest.fixture
def fs():
    return FakeFilesystem()


# Function 408: Performs operations related to emulator.
@pytest.fixture
def emulator(fs):
    fs.mkdir_p("/home/admin", owner="admin")
    return ShellEmulator(fs, username="admin")


# Function 409: Runs unit tests for the su_root_prompt functionality.
@pytest.mark.asyncio
async def test_su_root_prompt(emulator):
    su = SuCommand(emulator)
    stdout, stderr, rc = await su.execute([])
    assert "Password:" in stdout
    assert emulator.pending_input_callback is not None
    assert emulator.pending_input_prompt == "Password: "


# Function 410: Runs unit tests for the su_root_success functionality.
@pytest.mark.asyncio
async def test_su_root_success(emulator):
    su = SuCommand(emulator)
    await su.execute([])
    # Simulate entering password
    res = emulator.pending_input_callback("root")
    import inspect

    if inspect.isawaitable(res):
        stdout, stderr, rc = await res
    else:
        stdout, stderr, rc = res
    assert rc == 0
    assert emulator.username == "root"
    # su without - should not change directory
    assert emulator.cwd == "/home/admin"


# Function 411: Runs unit tests for the cat_root_auto_auth functionality.
@pytest.mark.asyncio
async def test_cat_root_auto_auth(emulator, fs):
    fs.mkdir_p("/root", owner="root")
    fs.mkfile("/root/secret", content="hidden", owner="root")

    # This should trigger auth_and_execute via Emulator
    stdout, stderr, rc = await emulator.execute("cat /root/secret")

    assert "password for admin" in stdout
    assert emulator.pending_input_callback is not None

    # Provide password
    stdout, stderr, rc = await emulator.execute("password")
    assert "hidden" in stdout
    assert rc == 0
    assert emulator.username == "root"


# Function 412: Runs unit tests for the ls_root_auto_auth functionality.
@pytest.mark.asyncio
async def test_ls_root_auto_auth(emulator, fs):
    fs.mkdir_p("/root", owner="root")

    # ls /root
    stdout, stderr, rc = await emulator.execute("ls /root")
    assert "password for admin" in stdout

    # Provide password
    stdout, stderr, rc = await emulator.execute("password")
    assert rc == 0
    assert emulator.username == "root"


# Function 413: Runs unit tests for the grep_root_auto_auth functionality.
@pytest.mark.asyncio
async def test_grep_root_auto_auth(emulator, fs):
    fs.mkdir_p("/root", owner="root")
    fs.mkfile("/root/secret", content="target string", owner="root")

    # grep target /root/secret
    stdout, stderr, rc = await emulator.execute("grep target /root/secret")
    assert "password for admin" in stdout

    # Provide password
    stdout, stderr, rc = await emulator.execute("password")
    assert "target string" in stdout
    assert rc == 0
