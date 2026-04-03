import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def emulator():
    fs = FakeFilesystem()
    return ShellEmulator(fs)


@pytest.mark.asyncio
async def test_complex_command_chains(emulator):
    out, err, code = await emulator.execute("echo A && echo B")
    assert "A" in out
    assert "B" in out
    assert code == 0

    out, err, code = await emulator.execute("false || echo C")
    assert "C" in out
    assert code == 0

    out, err, code = await emulator.execute("echo E; echo F")
    assert "E" in out
    assert "F" in out


@pytest.mark.asyncio
async def test_environment_variables(emulator):
    await emulator.execute("export TEST_VAR=hello")
    out, err, code = await emulator.execute("echo $TEST_VAR")
    assert "hello" in out
