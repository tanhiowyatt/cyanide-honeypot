import struct
from unittest.mock import ANY, AsyncMock, MagicMock

import pytest

from cyanide.vfs.rsync import RsyncHandler


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.honeypot.config = {"ssh": {"rsync": {"enabled": True, "allow_upload": True}}}
    session.src_ip = "127.0.0.1"
    session.username = "root"
    session.conn_id = "test_conn"
    session.channel = MagicMock()
    session.channel.read = AsyncMock()
    # Mock fs
    session.fs = MagicMock()
    return session


@pytest.mark.asyncio
async def test_rsync_handshake_and_push(mock_session):
    handler = RsyncHandler(mock_session)
    # 31 as 4-byte little-endian
    mock_session.channel.read.side_effect = [struct.pack("<i", 31), b"\x00"]

    rc = await handler.handle("rsync --server -vlogDtpr . dest")
    assert rc == 13  # Permission denied (push failed)
    mock_session.channel.write.assert_called()


@pytest.mark.asyncio
async def test_rsync_pull(mock_session):
    handler = RsyncHandler(mock_session)
    # Handshake 31
    mock_session.channel.read.side_effect = [struct.pack("<i", 31)]
    # Pull = --sender
    rc = await handler.handle("rsync --server --sender -vlogDtpr . src")
    assert rc == 13
    mock_session.channel.write_stderr.assert_called()


@pytest.mark.asyncio
async def test_rsync_handshake_fail(mock_session):
    """Test handshake failure when client version is invalid."""
    handler = RsyncHandler(mock_session)
    # Return -1 for handshake
    mock_session.channel.read.side_effect = [b""]
    rc = await handler.handle("rsync --server . dest")
    assert rc == 1


@pytest.mark.asyncio
async def test_rsync_push_upload_disabled(mock_session):
    """Test rsync push when upload is disabled in config."""
    mock_session.honeypot.config["ssh"]["rsync"]["allow_upload"] = False
    handler = RsyncHandler(mock_session)
    # Handshake 31, then end of file list (0)
    mock_session.channel.read.side_effect = [struct.pack("<i", 31), b"\x00"]
    rc = await handler.handle("rsync --server . dest")
    assert rc == 13
    # Check that denied reason was logged
    mock_session.honeypot.logger.log_event.assert_any_call("conn_test_conn", "rsync_denied", ANY)


@pytest.mark.asyncio
async def test_rsync_file_list_parsing(mock_session):
    """Test minimal file list parsing."""
    handler = RsyncHandler(mock_session)
    # Handshake 31
    # File list:
    # 1. flags=0x01 (just a file, no mtime/mode/size yet)
    # 2. l2=5
    # 3. name="test1"
    # 4. size=varint(10)
    # 5. mtime=int(1234567)
    # 6. mode=int(0o644)
    # 7. flags=0 (end)
    mock_session.channel.read.side_effect = [
        struct.pack("<i", 31),
        b"\x01",
        b"\x05",
        b"test1",
        b"\x0a",  # varint 10
        struct.pack("<i", 1234567),
        struct.pack("<i", 0o644),
        b"\x00",
    ]
    rc = await handler.handle("rsync --server . dest")
    assert rc == 13
    # Verify file list event
    mock_session.honeypot.logger.log_event.assert_any_call("conn_test_conn", "rsync_filelist", ANY)


@pytest.mark.asyncio
async def test_rsync_read_error(mock_session):
    """Test error handling during rsync processing."""
    handler = RsyncHandler(mock_session)
    mock_session.channel.read.side_effect = Exception("Network error")
    rc = await handler.handle("rsync --server . dest")
    assert rc == 1
