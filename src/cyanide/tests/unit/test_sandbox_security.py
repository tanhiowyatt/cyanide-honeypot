from pathlib import Path

import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def emulator():
    fs = FakeFilesystem()
    return ShellEmulator(fs)


def test_vfs_sandbox_isolation(emulator):
    assert emulator.resolve_path("../../../etc/shadow") == "/etc/shadow"
    assert emulator.resolve_path("/../../etc/passwd") == "/etc/passwd"
    assert not emulator.fs.exists("/Users")
    assert not emulator.fs.exists("/etc/hostname.real_host")
    assert not emulator.fs.exists("/sbin/init.real_host")


@pytest.mark.asyncio
async def test_sandbox_write_protection(emulator):

    v_path = "/tmp/evil.txt"
    emulator.fs.mkdir_p("/tmp")
    emulator.fs.mkfile(v_path, content="EVIL")

    assert emulator.fs.exists(v_path)
    assert not Path(v_path).exists()
