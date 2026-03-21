from unittest.mock import MagicMock

import asyncssh
import pytest

from cyanide.vfs.engine import FakeFilesystem
from cyanide.vfs.sftp import CyanideSFTPFile, CyanideSFTPHandler


@pytest.fixture
def mock_chan():
    chan = MagicMock(spec=asyncssh.SSHServerChannel)
    conn = MagicMock(spec=asyncssh.SSHClientConnection)
    chan.get_connection.return_value = conn
    conn.get_extra_info.return_value = "root"
    # Setup mock factory/honeypot context
    conn.cyanide_factory = MagicMock()
    conn.cyanide_factory.honeypot = MagicMock()
    fs = FakeFilesystem()
    fs.mkdir_p("/tmp")  # Ensure /tmp exists
    conn.cyanide_factory.fs = fs
    conn.cyanide_factory.conn_id = "test_sftp_123"
    conn.cyanide_factory.src_ip = "1.2.3.4"
    conn.cyanide_factory.honeypot.config = {
        "ssh": {"allow_upload": True, "allow_download": True, "max_total_upload_mb_per_session": 1}
    }
    conn.cyanide_factory.honeypot.logger = MagicMock()
    return chan


@pytest.fixture
def sftp_handler(mock_chan):
    return CyanideSFTPHandler(mock_chan)


@pytest.mark.asyncio
async def test_sftp_file_read_write(sftp_handler):
    """Test CyanideSFTPFile read and write operations."""
    buffer = bytearray(b"initial data")
    sftp_file = CyanideSFTPFile(sftp_handler, "/tmp/test.txt", buffer, is_write=True)

    # Test read
    data = await sftp_file.read(0, 7)
    assert data == b"initial"

    # Test read out of bounds
    data = await sftp_file.read(20, 5)
    assert data == b""

    # Test write
    await sftp_file.write(8, b"new")
    assert bytes(buffer) == b"initial newa"

    # Test write with extension
    await sftp_file.write(15, b"end")
    assert len(buffer) == 18
    assert buffer[12:15] == b"\0\0\0"
    assert buffer[15:] == b"end"


@pytest.mark.asyncio
async def test_sftp_file_seek_tell(sftp_handler):
    """Test seek and tell operations on SFTP file."""
    sftp_file = CyanideSFTPFile(sftp_handler, "/test", bytearray(b"0123456789"), is_write=True)

    await sftp_file.seek(5, 0)  # ABS
    assert await sftp_file.tell() == 5

    await sftp_file.seek(2, 1)  # CUR
    assert await sftp_file.tell() == 7

    await sftp_file.seek(-2, 2)  # END
    assert await sftp_file.tell() == 8

    with pytest.raises(asyncssh.SFTPBadMessage):
        await sftp_file.seek(0, 5)


@pytest.mark.asyncio
async def test_sftp_file_close_upload(sftp_handler, mock_chan):
    """Test file close triggers VFS save and quarantine for writes."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    honeypot = mock_chan.get_connection().cyanide_factory.honeypot

    content = b"highly malicious"
    sftp_file = CyanideSFTPFile(sftp_handler, "/tmp/malware.sh", bytearray(content), is_write=True)

    await sftp_file.close()

    assert fs.exists("/tmp/malware.sh")
    assert fs.get_content("/tmp/malware.sh") == content.decode()
    honeypot.save_quarantine_file.assert_called_once_with(
        "malware.sh", content, sftp_handler.session_id, sftp_handler.src_ip
    )


@pytest.mark.asyncio
async def test_sftp_handler_scandir(sftp_handler, mock_chan):
    """Test scandir implementation."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    fs.mkdir_p("/test_dir")
    fs.mkfile("/test_dir/file1.txt", content="1")
    fs.mkfile("/test_dir/file2.txt", content="2")

    names = []
    async for name in sftp_handler.scandir("/test_dir"):
        names.append(name.filename)

    assert "file1.txt" in names
    assert "file2.txt" in names
    assert len(names) == 2


@pytest.mark.asyncio
async def test_sftp_handler_permissions(sftp_handler, mock_chan):
    """Test upload/download permission enforcement."""
    config = mock_chan.get_connection().cyanide_factory.honeypot.config

    # Disable uploads
    config["ssh"]["allow_upload"] = False
    with pytest.raises(asyncssh.SFTPPermissionDenied):
        await sftp_handler.open(
            "/test", asyncssh.FXF_WRITE | asyncssh.FXF_CREAT, asyncssh.SFTPAttrs()
        )

    # Disable downloads
    config["ssh"]["allow_upload"] = True
    config["ssh"]["allow_download"] = False
    with pytest.raises(asyncssh.SFTPPermissionDenied):
        await sftp_handler.open("/test", asyncssh.FXF_READ, asyncssh.SFTPAttrs())


@pytest.mark.asyncio
async def test_sftp_upload_limit_exceeded(sftp_handler, mock_chan):
    """Test that session upload limit is enforced."""
    config = mock_chan.get_connection().cyanide_factory.honeypot.config
    config["ssh"]["max_total_upload_mb_per_session"] = 0  # 0MB limit

    sftp_file = CyanideSFTPFile(sftp_handler, "/test", bytearray(), is_write=True)
    with pytest.raises(asyncssh.SFTPPermissionDenied, match="Session upload limit exceeded"):
        await sftp_file.write(0, b"some data")


@pytest.mark.asyncio
async def test_sftp_handler_ops(sftp_handler, mock_chan):
    """Test various SFTP handler operations (mkdir, remove, rename, stat)."""
    fs = mock_chan.get_connection().cyanide_factory.fs

    # mkdir
    await sftp_handler.mkdir("/new_dir", asyncssh.SFTPAttrs())
    assert fs.exists("/new_dir")

    # rename
    fs.mkfile("/old.txt", content="old")
    await sftp_handler.rename("/old.txt", "/new.txt")
    assert not fs.exists("/old.txt")
    assert fs.exists("/new.txt")

    # stat
    attrs = await sftp_handler.stat("/new.txt")
    assert attrs.size == len("old")
    assert fs.get_content("/new.txt") == "old"

    # remove
    await sftp_handler.remove("/new.txt")
    assert not fs.exists("/new.txt")


@pytest.mark.asyncio
async def test_sftp_handler_realpath(sftp_handler):
    """Test realpath decoding and returning."""
    assert sftp_handler.realpath(b"/some/path") == b"/some/path"
    assert sftp_handler.realpath("/another/path") == b"/another/path"


@pytest.mark.asyncio
async def test_sftp_handler_missing_file_errors(sftp_handler):
    """Test that appropriate errors are raised for missing files."""
    with pytest.raises(asyncssh.SFTPNoSuchFile):
        await sftp_handler.stat("/nonexistent")

    with pytest.raises(asyncssh.SFTPNoSuchFile):
        await sftp_handler.remove("/nonexistent")

    with pytest.raises(asyncssh.SFTPNoSuchFile):
        await sftp_handler.open("/nonexistent", asyncssh.FXF_READ, asyncssh.SFTPAttrs())
