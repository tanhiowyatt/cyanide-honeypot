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
    res = emulator.pending_input_callback("root")
    import inspect

    if inspect.isawaitable(res):
        stdout, stderr, rc = await res
    else:
        stdout, stderr, rc = res
    assert rc == 0
    assert emulator.username == "root"
    assert emulator.cwd == "/home/admin"


@pytest.mark.asyncio
async def test_cat_root_auto_auth(emulator, fs):
    fs.mkdir_p("/root", owner="root")
    fs.mkfile("/root/secret", content="hidden", owner="root")
    stdout, stderr, rc = await emulator.execute("cat /root/secret")

    assert "password for admin" in stdout
    assert emulator.pending_input_callback is not None
    stdout, stderr, rc = await emulator.execute("password")
    assert "hidden" in stdout
    assert rc == 0
    assert emulator.username == "root"


@pytest.mark.asyncio
async def test_ls_root_auto_auth(emulator, fs):
    fs.mkdir_p("/root", owner="root")
    stdout, stderr, rc = await emulator.execute("ls /root")
    assert "password for admin" in stdout
    stdout, stderr, rc = await emulator.execute("password")
    assert rc == 0
    assert emulator.username == "root"


@pytest.mark.asyncio
async def test_grep_root_auto_auth(emulator, fs):
    fs.mkdir_p("/root", owner="root")
    fs.mkfile("/root/secret", content="target string", owner="root")

    stdout, stderr, rc = await emulator.execute("grep target /root/secret")
    assert "password for admin" in stdout

    stdout, stderr, rc = await emulator.execute("password")
    assert "target string" in stdout
    assert rc == 0
