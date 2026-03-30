from unittest.mock import MagicMock

import asyncssh
import pytest

from cyanide.vfs.engine import FakeFilesystem
from cyanide.vfs.sftp import CyanideSFTPHandler


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
async def test_sftp_handler_read_write(sftp_handler):
    """Test CyanideSFTPHandler read and write operations."""
    # Open a file to get a handle
    handle = await sftp_handler.open(
        "/tmp/test.txt", asyncssh.FXF_WRITE | asyncssh.FXF_CREAT, asyncssh.SFTPAttrs()
    )

    # Test write
    await sftp_handler.write(handle, 0, b"initial data")

    # Test read
    data = await sftp_handler.read(handle, 0, 7)
    assert data == b"initial"

    # Test read out of bounds
    data = await sftp_handler.read(handle, 20, 5)
    assert data == b""

    # Test write middle
    await sftp_handler.write(handle, 8, b"new")
    # Verify buffer indirectly via read
    buffer_data = await sftp_handler.read(handle, 0, 20)
    assert buffer_data.startswith(b"initial new")

    # Test write with extension
    await sftp_handler.write(handle, 15, b"end")
    final_data = await sftp_handler.read(handle, 0, 30)
    assert final_data[15:18] == b"end"
    assert final_data[12:15] == b"\0\0\0"


@pytest.mark.asyncio
async def test_sftp_handler_close_upload(sftp_handler, mock_chan):
    """Test file close triggers VFS save and quarantine for writes."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    honeypot = mock_chan.get_connection().cyanide_factory.honeypot

    content = b"highly malicious"
    handle = await sftp_handler.open(
        "/tmp/malware.sh", asyncssh.FXF_WRITE | asyncssh.FXF_CREAT, asyncssh.SFTPAttrs()
    )
    await sftp_handler.write(handle, 0, content)
    await sftp_handler.close(handle)

    assert fs.exists("/tmp/malware.sh")
    assert fs.get_content("/tmp/malware.sh") == content
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

    handle = await sftp_handler.open(
        "/test", asyncssh.FXF_WRITE | asyncssh.FXF_CREAT, asyncssh.SFTPAttrs()
    )
    with pytest.raises(asyncssh.SFTPPermissionDenied, match="Session upload limit exceeded"):
        await sftp_handler.write(handle, 0, b"some data")


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
    assert sftp_handler._get_node_content("/new.txt") == b"old"

    # remove
    await sftp_handler.remove("/new.txt")
    assert not fs.exists("/new.txt")


@pytest.mark.asyncio
async def test_sftp_handler_realpath(sftp_handler):
    """Test realpath decoding and returning."""
    assert sftp_handler.realpath(b"/some/path") == b"/some/path"
    assert sftp_handler.realpath("/another/path") == "/another/path"


@pytest.mark.asyncio
async def test_sftp_handler_missing_file_errors(sftp_handler):
    """Test that appropriate errors are raised for missing files."""
    with pytest.raises(asyncssh.SFTPNoSuchFile):
        await sftp_handler.stat("/nonexistent")

    with pytest.raises(asyncssh.SFTPNoSuchFile):
        await sftp_handler.remove("/nonexistent")

    with pytest.raises(asyncssh.SFTPNoSuchFile):
        await sftp_handler.open("/nonexistent", asyncssh.FXF_READ, asyncssh.SFTPAttrs())


@pytest.mark.asyncio
async def test_sftp_handler_fstat_fsetstat(sftp_handler, mock_chan):
    """Test fstat and fsetstat on handles."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    fs.mkfile("/test.txt", content="data")
    handle = await sftp_handler.open("/test.txt", asyncssh.FXF_READ, asyncssh.SFTPAttrs())

    attrs = await sftp_handler.fstat(handle)
    assert attrs.size == 4

    await sftp_handler.fsetstat(handle, asyncssh.SFTPAttrs())
    # Just check it logs or doesn't crash


@pytest.mark.asyncio
async def test_sftp_handler_write_read_only(sftp_handler, mock_chan):
    """Test write on a handle opened for reading."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    fs.mkfile("/test.txt", content="data")
    handle = await sftp_handler.open("/test.txt", asyncssh.FXF_READ, asyncssh.SFTPAttrs())

    with pytest.raises(asyncssh.SFTPPermissionDenied, match="File not open for writing"):
        await sftp_handler.write(handle, 0, b"more data")


@pytest.mark.asyncio
async def test_sftp_handler_rename_fail(sftp_handler, mock_chan):
    """Test rename failure when move fails in VFS."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    fs.move = MagicMock(return_value=False)
    with pytest.raises(asyncssh.SFTPNoSuchFile):
        await sftp_handler.rename("/old", "/new")


@pytest.mark.asyncio
async def test_sftp_handler_scandir_bytes(sftp_handler, mock_chan):
    """Test scandir when path is passed as bytes."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    fs.mkdir_p("/test_bytes")
    fs.mkfile("/test_bytes/file.txt", content="test")

    names = []
    async for name in sftp_handler.scandir(b"/test_bytes"):
        names.append(name.filename)
    assert b"file.txt" in names


@pytest.mark.asyncio
async def test_sftp_handler_scandir_error(sftp_handler, mock_chan):
    """Test scandir error handling."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    fs.list_dir = MagicMock(side_effect=Exception("List error"))
    with pytest.raises(asyncssh.SFTPNoSuchFile):
        async for _ in sftp_handler.scandir("/any"):
            pass


@pytest.mark.asyncio
async def test_sftp_handler_rmdir(sftp_handler, mock_chan):
    """Test rmdir (delegates to remove)."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    fs.mkdir_p("/dir_to_remove")
    await sftp_handler.rmdir("/dir_to_remove")
    assert not fs.exists("/dir_to_remove")


@pytest.mark.asyncio
async def test_sftp_handler_lstat(sftp_handler, mock_chan):
    """Test lstat (delegates to stat)."""
    fs = mock_chan.get_connection().cyanide_factory.fs
    fs.mkfile("/lstat_test.txt", content="lstat")
    attrs = await sftp_handler.lstat("/lstat_test.txt")
    assert attrs.size == 5


@pytest.mark.asyncio
async def test_sftp_handler_setstat(sftp_handler):
    """Test setstat logging."""
    await sftp_handler.setstat("/path", asyncssh.SFTPAttrs())
    # No crash


@pytest.mark.asyncio
async def test_sftp_parse_mode_dir(sftp_handler):
    """Test directory mode parsing."""
    # Mocking node for _get_attrs
    node = MagicMock()
    node.perm = "drwxr-xr-x"
    node.owner = "root"
    node.group = "root"
    node.size = 4096

    attrs = sftp_handler._get_attrs(node)
    assert attrs.permissions & 0o40000  # S_IFDIR
