import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


# Function 372: Performs operations related to fs.
@pytest.fixture
def fs():
    return FakeFilesystem()


# Function 373: Performs operations related to emulator.
@pytest.fixture
def emulator(fs):
    return ShellEmulator(fs, username="admin")


# Function 374: Runs unit tests for the network_commands functionality.
@pytest.mark.asyncio
async def test_network_commands(emulator):
    # ip addr
    stdout, _, rc = await emulator.execute("ip addr")
    assert "eth0" in stdout
    assert "192.168.1.15" in stdout

    # ifconfig
    stdout, _, rc = await emulator.execute("ifconfig")
    assert "eth0" in stdout

    # route -n
    stdout, _, rc = await emulator.execute("route -n")
    assert "192.168.1.1" in stdout


# Function 375: Runs unit tests for the system_commands functionality.
@pytest.mark.asyncio
async def test_system_commands(emulator):
    # history
    await emulator.execute("ls")
    await emulator.execute("pwd")
    stdout, _, _ = await emulator.execute("history")
    assert "1  ls" in stdout
    assert "2  pwd" in stdout

    # env
    stdout, _, _ = await emulator.execute("env")
    assert "USER=admin" in stdout
    assert "PATH=" in stdout

    # free -m
    stdout, _, _ = await emulator.execute("free -m")
    assert "Mem:" in stdout
    assert "8192" in stdout


# Function 376: Runs unit tests for the dev_tools functionality.
@pytest.mark.asyncio
async def test_dev_tools(emulator):
    # python -V
    stdout, _, _ = await emulator.execute("python -V")
    assert "Python 3.10.12" in stdout

    # gc - (gcc)
    _, stderr, rc = await emulator.execute("gcc")
    assert "fatal error" in stderr


# Function 377: Runs unit tests for the find_grep_recursive functionality.
@pytest.mark.asyncio
async def test_find_grep_recursive(emulator, fs):
    fs.mkdir_p("/tmp/testdir")
    fs.mkfile("/tmp/testdir/file1.txt", content="target string here")
    fs.mkfile("/tmp/testdir/file2.log", content="nothing")

    # find
    stdout, _, _ = await emulator.execute("find /tmp -name *.txt")
    assert "file1.txt" in stdout
    assert "file2.log" not in stdout

    # grep -r
    stdout, _, _ = await emulator.execute("grep -r target /tmp")
    assert "file1.txt:target string here" in stdout


# Function 378: Runs unit tests for the privesc_mocks functionality.
@pytest.mark.asyncio
async def test_privesc_mocks(emulator):
    # sudo -l
    stdout, _, _ = await emulator.execute("sudo -l")
    assert "may run the following commands" in stdout

    # pkexec
    stdout, _, _ = await emulator.execute("pkexec ls /root")
    assert "password for admin" in stdout  # Triggers auto-auth


# Function 379: Runs unit tests for the network_randomization functionality.
@pytest.mark.asyncio
async def test_network_randomization(emulator):
    # ifconfig should differ on multiple calls if not using same seed logic for stats
    # Actually my stats logic uses random.randint directly, but MAC is stable per user.
    out1, _, _ = await emulator.execute("ifconfig")
    out2, _, _ = await emulator.execute("ifconfig")
    # stats change
    assert out1 != out2

    # netstat should also change
    ns1, _, _ = await emulator.execute("netstat")
    ns2, _, _ = await emulator.execute("netstat")
    assert ns1 != ns2


# Function 380: Runs unit tests for the system_randomization functionality.
@pytest.mark.asyncio
async def test_system_randomization(emulator):
    # finger should change (different sessions/times)
    f1, _, _ = await emulator.execute("finger")
    f2, _, _ = await emulator.execute("finger")
    assert f1 != f2

    # free should change (different mem usage)
    m1, _, _ = await emulator.execute("free -m")
    m2, _, _ = await emulator.execute("free -m")
    assert m1 != m2
