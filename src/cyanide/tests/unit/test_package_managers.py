from unittest.mock import patch

import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.apt import AptCommand
from cyanide.vfs.commands.dpkg import DpkgCommand
from cyanide.vfs.commands.rpm import RpmCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
async def test_rpm_basic(shell, mock_fs):
    mock_fs.os_profile = "centos"
    cmd = RpmCommand(shell)
    stdout, stderr, rc = await cmd.execute([])
    assert "RPM version" in stdout

    stdout, stderr, rc = await cmd.execute(["-i"])
    assert rc == 1
    assert "no packages given" in stderr

    mock_fs.mkfile("/root/pkg.rpm", content="data")
    with patch.object(shell, "resolve_path", return_value="/root/pkg.rpm"):
        stdout, stderr, rc = await cmd.execute(["-i", "pkg.rpm"])
        assert rc == 0
        assert "Updating / installing" in stdout

    stdout, stderr, rc = await cmd.execute(["-qa"])
    assert "bash" in stdout

    stdout, stderr, rc = await cmd.execute(["-q", "bash"])
    assert "bash" in stdout


@pytest.mark.asyncio
async def test_dpkg_basic(shell, mock_fs):
    mock_fs.os_profile = "ubuntu"
    cmd = DpkgCommand(shell)

    stdout, stderr, rc = await cmd.execute([])
    assert "need an action option" in stderr
    assert rc == 2

    mock_fs.mkfile("/root/pkg.deb", content="data")
    with patch.object(shell, "resolve_path", return_value="/root/pkg.deb"):
        stdout, stderr, rc = await cmd.execute(["-i", "pkg.deb"])
        assert rc == 0
        assert "Selecting previously unselected package" in stdout

    stdout, stderr, rc = await cmd.execute(["-l"])
    assert "Desired=Unknown" in stdout


@pytest.mark.asyncio
async def test_apt_basic(shell, mock_fs):
    mock_fs.os_profile = "ubuntu"
    cmd = AptCommand(shell)

    stdout, stderr, rc = await cmd.execute(["update"])
    assert rc == 0
    assert "Reading package lists... Done" in stdout
    stdout, stderr, rc = await cmd.execute(["install", "-y", "nmap"])
    assert rc == 0
    assert "Setting up nmap" in stdout

    stdout, stderr, rc = await cmd.execute(["search", "nmap"])
    assert "nmap" in stdout
