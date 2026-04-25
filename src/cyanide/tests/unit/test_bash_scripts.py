import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def emulator():
    fs = FakeFilesystem()
    config = {"users": [{"user": "root", "pass": "cyanide"}]}
    return ShellEmulator(fs, username="admin", config=config)


@pytest.mark.asyncio
async def test_bash_script_execution(emulator):
    # 1. Create a script
    script_content = "echo hello\nmkdir /tmp/test_bash\ntouch /tmp/test_bash/file"
    emulator.fs.mkfile("/tmp/script.sh", content=script_content, perm="-rwxr-xr-x")

    # 2. Execute directly
    stdout, stderr, rc = await emulator.execute("/tmp/script.sh")

    assert "hello" in stdout
    assert emulator.fs.exists("/tmp/test_bash")
    assert emulator.fs.exists("/tmp/test_bash/file")
    assert rc == 0


@pytest.mark.asyncio
async def test_bash_command_explicit(emulator):
    # 1. Create a script without +x
    script_content = "echo secret"
    emulator.fs.mkfile("/tmp/secret.sh", content=script_content, perm="-rw-r--r--")

    # 2. Execute via bash command (should work even without +x)
    stdout, stderr, rc = await emulator.execute("bash /tmp/secret.sh")
    assert "secret" in stdout
    assert rc == 0

    # 3. Execute directly (should fail with Permission denied)
    stdout, stderr, rc = await emulator.execute("/tmp/secret.sh")
    assert "Permission denied" in stderr
    assert rc == 126


@pytest.mark.asyncio
async def test_bash_script_missing(emulator):
    stdout, stderr, rc = await emulator.execute("bash /tmp/nonexistent.sh")
    assert "No such file or directory" in stderr
    assert rc == 127
