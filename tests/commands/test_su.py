import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.su import SuCommand
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def fs():
    return FakeFilesystem()


@pytest.fixture
def emulator(fs):
    fs.mkdir_p("/home/admin", owner="admin")
    return ShellEmulator(fs, username="admin")


@pytest.mark.asyncio
async def test_su_root_prompt(emulator):
    su = SuCommand(emulator)
    stdout, stderr, rc = await su.execute([])
    assert "Password:" in stdout
    assert emulator.pending_input_callback is not None
    assert emulator.pending_input_prompt == "Password: "


@pytest.mark.asyncio
async def test_su_root_success(emulator):
    su = SuCommand(emulator)
    await su.execute([])
    # Simulate entering password
    stdout, stderr, rc = await emulator.pending_input_callback("root")
    assert rc == 0
    assert emulator.username == "root"
    # su without - should not change directory
    assert emulator.cwd == "/home/admin"


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
