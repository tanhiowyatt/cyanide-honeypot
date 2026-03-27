from pathlib import Path

import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def emulator():
    fs = FakeFilesystem()
    return ShellEmulator(fs)


def test_vfs_sandbox_isolation(emulator):
    # 1. Attempt to resolve path that leads out of the root
    # VFS should normalize and keep it within the root /
    assert emulator.resolve_path("../../../etc/shadow") == "/etc/shadow"
    assert emulator.resolve_path("/../../etc/passwd") == "/etc/passwd"

    # 2. Verify that there's NO link to the real host filesystem
    # FakeFilesystem should only contain what is in memory OR pre-defined
    assert not emulator.fs.exists(
        "/Users"
    )  # Unless we are on Mac and it's there? No, emulated VFS.

    # Check a definitively non-existent path in VFS that might exist on host (e.g. /etc/hosts)
    # but we want to make sure it doesn't accidentally pull from reality.
    assert not emulator.fs.exists("/etc/hostname.real_host")
    assert not emulator.fs.exists("/sbin/init.real_host")


@pytest.mark.asyncio
async def test_sandbox_write_protection(emulator):
    # Try to write to a sensitive path that isn't supposed to be writable in some profiles
    # (Though in emulated mode, we usually allow writing to virtual files)
    # The real check is that it DOES NOT write to the host disk.

    v_path = "/tmp/evil.txt"
    emulator.fs.mkdir_p("/tmp")
    emulator.fs.mkfile(v_path, content="EVIL")

    # Check it exists in VFS
    assert emulator.fs.exists(v_path)

    # Check it DOES NOT exist on actual host disk
    assert not Path(v_path).exists()
