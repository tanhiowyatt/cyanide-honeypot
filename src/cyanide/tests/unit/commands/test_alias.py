import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def emulator():
    fs = FakeFilesystem()
    return ShellEmulator(fs, username="root")


@pytest.mark.asyncio
async def test_alias_defaults(emulator):
    out, err, rc = await emulator.execute("alias")
    assert rc == 0
    assert "alias l='ls -CF'" in out
    assert "alias ls='ls --color=auto'" in out


@pytest.mark.asyncio
async def test_alias_setting(emulator):
    out, err, rc = await emulator.execute("alias mycmd='echo hello'")
    assert rc == 0
    out, err, rc = await emulator.execute("alias mycmd")
    assert "alias mycmd='echo hello'" in out
    assert rc == 0


@pytest.mark.asyncio
async def test_alias_execution(emulator):
    await emulator.execute("alias myecho='echo hello world'")
    out, err, rc = await emulator.execute("myecho")
    assert "hello world" in out

    out, err, rc = await emulator.execute("myecho again")
    assert "hello world again" in out


@pytest.mark.asyncio
async def test_unalias(emulator):
    out, err, rc = await emulator.execute("alias l")
    assert rc == 0

    out, err, rc = await emulator.execute("unalias l")
    assert rc == 0

    out, err, rc = await emulator.execute("alias l")
    assert rc == 1
    assert "not found" in err or "not found" in out

    out, err, rc = await emulator.execute("l")
    assert rc == 127
    assert "command not found" in err or "command not found" in out
