from unittest.mock import AsyncMock, MagicMock

import pytest

from cyanide.vfs.engine import FakeFilesystem
from cyanide.vfs.rsync import RsyncHandler
from cyanide.vfs.sftp import CyanideSFTPHandler


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.honeypot = MagicMock()
    session.honeypot.config = {
        "ssh": {
            "allow_upload": True,
            "allow_download": True,
            "max_upload_size_mb": 50,
            "max_total_upload_mb_per_session": 200,
        }
    }
    session.honeypot.logger = MagicMock()
    session.honeypot.save_quarantine_file = MagicMock()
    session.fs = FakeFilesystem()
    session.src_ip = "192.168.1.100"
    session.username = "root"
    session.conn_id = "test_conn"
    session.channel = MagicMock()

    # SFTP session context
    conn = MagicMock()
    conn.get_extra_info.return_value = "root"
    session.channel.get_connection.return_value = conn
    conn.cyanide_factory = MagicMock()
    conn.cyanide_factory.honeypot = session.honeypot
    conn.cyanide_factory.fs = session.fs
    conn.cyanide_factory.conn_id = session.conn_id
    conn.cyanide_factory.src_ip = session.src_ip

    return session


@pytest.fixture
def mock_process():
    process = MagicMock()
    process.stdin = AsyncMock()
    process.stdout = MagicMock()
    process.stderr = MagicMock()
    process.channel = MagicMock()
    return process


@pytest.mark.asyncio
async def test_rsync_handshake_and_error(mock_session, mock_process):
    # Test RsyncHandler in process_factory mode
    import struct

    # Server sends our version (31) and we read client version (31)
    mock_process.stdin.read.return_value = struct.pack("<i", 31)

    handler = RsyncHandler(mock_session, process=mock_process)
    rc = await handler.handle("rsync --server . /tmp/test")

    # Return 13 (EACCES) for realistic permission denied behavior
    assert rc == 13

    # Should have sent binary version greeting (decoded via latin-1 in handler)
    mock_process.channel.write.assert_any_call(struct.pack("<i", 31).decode("latin-1"))

    # Should log operations
    mock_session.honeypot.logger.log_event.assert_called()


@pytest.mark.asyncio
async def test_sftp_upload_via_handler(mock_session):
    handler = CyanideSFTPHandler(mock_session.channel)
    mock_session.fs.mkdir_p("/tmp")

    import asyncssh

    file_obj = await handler.open(
        "/tmp/test.txt", asyncssh.FXF_WRITE | asyncssh.FXF_CREAT, asyncssh.SFTPAttrs()
    )

    await file_obj.write(0, b"hello sftp/scp")
    await file_obj.close()

    # Check if file was created in VFS
    assert mock_session.fs.exists("/tmp/test.txt")
    assert mock_session.fs.get_content("/tmp/test.txt") == "hello sftp/scp"

    # Check quarantine called
    mock_session.honeypot.save_quarantine_file.assert_called_with(
        "test.txt", b"hello sftp/scp", "conn_test_conn", "192.168.1.100"
    )
