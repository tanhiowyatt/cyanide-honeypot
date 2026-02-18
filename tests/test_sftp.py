from unittest.mock import MagicMock

import asyncssh
import pytest

from cyanide.core.sftp import CyanideSFTPServer


@pytest.mark.asyncio
async def test_sftp_init(mock_fs):
    """Test SFTP server initialization."""
    channel = MagicMock()
    channel.get_server().username = "root"
    sftp = CyanideSFTPServer(channel, mock_fs)
    assert sftp.fs == mock_fs
    assert sftp.username == "root"


@pytest.mark.asyncio
async def test_sftp_opendir_readdir(mock_fs):
    """Test reading directories."""
    channel = MagicMock()
    channel.get_server().username = "root"
    sftp = CyanideSFTPServer(channel, mock_fs)

    mock_fs.mkfile("/root/file1", content="cnt")

    handle = sftp.opendir("/root")
    entries = sftp.readdir(handle)

    # entries is a list of SFTPName
    names = [e.filename for e in entries]
    assert "file1" in names

    # Should raise for file
    with pytest.raises(asyncssh.SFTPError):
        sftp.opendir("/root/file1")


@pytest.mark.asyncio
async def test_sftp_read_file(mock_fs):
    """Test reading files."""
    channel = MagicMock()
    channel.get_server().username = "root"
    sftp = CyanideSFTPServer(channel, mock_fs)

    mock_fs.mkfile("/root/test.txt", content="Hello")

    handle = sftp.open("/root/test.txt", asyncssh.FXF_READ, None)
    data = sftp.read(handle, 0, 100)
    assert data == b"Hello"
    sftp.close(handle)


@pytest.mark.asyncio
async def test_sftp_write_file(mock_fs):
    """Test writing files and quarantine callback."""
    channel = MagicMock()
    channel.get_server().username = "root"
    quarantine_cb = MagicMock()

    sftp = CyanideSFTPServer(channel, mock_fs, quarantine_callback=quarantine_cb)

    handle = sftp.open("/root/hack.sh", asyncssh.FXF_WRITE | asyncssh.FXF_CREAT, None)
    sftp.write(handle, 0, b"rm -rf /")
    sftp.close(handle)

    # Check filesystem
    assert mock_fs.exists("/root/hack.sh")
    # Verify content in FS
    # mkfile/DynamicFile/File store content. DynamicFile stores function.
    content = mock_fs.get_content("/root/hack.sh")
    # content might be bytes or str depending on implementation.
    # sftp.py encodes/decodes.
    # If we wrote bytes, sftp.close commits bytes.
    # sftp.py line 200: existing.content = content (bytes)
    # sftp.py line 207: new_file = File(..., content=content)
    # File node probably stores exactly what's passed.
    assert content in [b"rm -rf /", "rm -rf /"]

    # Check quarantine
    quarantine_cb.assert_called_once()
    args = quarantine_cb.call_args[0]
    assert args[0] == "/root/hack.sh"
    assert args[1] == b"rm -rf /"
