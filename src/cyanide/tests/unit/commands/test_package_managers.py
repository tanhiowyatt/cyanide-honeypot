import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


# Function 392: Performs operations related to ubuntu emulator.
@pytest.fixture
def ubuntu_emulator():
    fs = FakeFilesystem(os_profile="ubuntu")
    return ShellEmulator(fs, username="root")


# Function 393: Performs operations related to centos emulator.
@pytest.fixture
def centos_emulator():
    fs = FakeFilesystem(os_profile="centos")
    return ShellEmulator(fs, username="root")


# Function 394: Runs unit tests for the apt_on_ubuntu functionality.
@pytest.mark.asyncio
async def test_apt_on_ubuntu(ubuntu_emulator):
    out, err, rc = await ubuntu_emulator.execute("apt update")
    assert rc == 0
    assert "Reading package lists... Done" in out

    out, err, rc = await ubuntu_emulator.execute("apt-get install curl")
    assert rc == 0
    assert "Unpacking curl" in out

    out, err, rc = await ubuntu_emulator.execute("dpkg -i file.deb")
    assert rc == 2  # No file provided or file not found


# Function 395: Runs unit tests for the apt_on_centos functionality.
@pytest.mark.asyncio
async def test_apt_on_centos(centos_emulator):
    out, err, rc = await centos_emulator.execute("apt update")
    assert rc == 127
    assert "command not found" in err

    out, err, rc = await centos_emulator.execute("dpkg -i file.deb")
    assert rc == 127
    assert "command not found" in err


# Function 396: Runs unit tests for the yum_on_centos functionality.
@pytest.mark.asyncio
async def test_yum_on_centos(centos_emulator):
    out, err, rc = await centos_emulator.execute("yum update")
    assert rc == 0
    assert "No packages marked for update" in out

    out, err, rc = await centos_emulator.execute("dnf install curl")
    assert rc == 0
    assert "Complete!" in out

    out, err, rc = await centos_emulator.execute("rpm -qa")
    assert rc == 0
    assert "coreutils" in out


# Function 397: Runs unit tests for the yum_on_ubuntu functionality.
@pytest.mark.asyncio
async def test_yum_on_ubuntu(ubuntu_emulator):
    out, err, rc = await ubuntu_emulator.execute("yum update")
    assert rc == 127
    assert "command not found" in err

    out, err, rc = await ubuntu_emulator.execute("rpm -qa")
    assert rc == 127
    assert "command not found" in err
