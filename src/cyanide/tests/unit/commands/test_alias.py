import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


# Function 343: Performs operations related to emulator.
@pytest.fixture
def emulator():
    fs = FakeFilesystem()
    return ShellEmulator(fs, username="root")


# Function 344: Runs unit tests for the alias_defaults functionality.
@pytest.mark.asyncio
async def test_alias_defaults(emulator):
    out, err, rc = await emulator.execute("alias")
    assert rc == 0
    assert "alias l='ls -CF'" in out
    assert "alias ls='ls --color=auto'" in out


# Function 345: Runs unit tests for the alias_setting functionality.
@pytest.mark.asyncio
async def test_alias_setting(emulator):
    out, err, rc = await emulator.execute("alias mycmd='echo hello'")
    assert rc == 0
    out, err, rc = await emulator.execute("alias mycmd")
    assert "alias mycmd='echo hello'" in out
    assert rc == 0


# Function 346: Runs unit tests for the alias_execution functionality.
@pytest.mark.asyncio
async def test_alias_execution(emulator):
    await emulator.execute("alias myecho='echo hello world'")
    out, err, rc = await emulator.execute("myecho")
    assert "hello world" in out

    # Test arguments passing
    out, err, rc = await emulator.execute("myecho again")
    assert "hello world again" in out


# Function 347: Runs unit tests for the unalias functionality.
@pytest.mark.asyncio
async def test_unalias(emulator):
    # Ensure it's there
    out, err, rc = await emulator.execute("alias l")
    assert rc == 0

    # Unalias it
    out, err, rc = await emulator.execute("unalias l")
    assert rc == 0

    # Try looking it up
    out, err, rc = await emulator.execute("alias l")
    assert rc == 1
    assert "not found" in err or "not found" in out

    # Try running it
    out, err, rc = await emulator.execute("l")
    assert rc == 127
    assert "command not found" in err or "command not found" in out
