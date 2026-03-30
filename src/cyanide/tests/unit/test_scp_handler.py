from unittest.mock import AsyncMock, MagicMock

import pytest

from cyanide.vfs.engine import FakeFilesystem
from cyanide.vfs.scp import ScpHandler


@pytest.fixture
def mock_session(mock_logger):
    session = MagicMock()
    session.honeypot = MagicMock()
    session.honeypot.config = {"ssh": {"allow_upload": True}}
    session.honeypot.logger = mock_logger
    session.honeypot.save_quarantine_file = MagicMock()
    session.fs = FakeFilesystem()
    session.src_ip = "1.2.3.4"
    # ScpHandler now initializes session_id based on conn_id or session_id
    session.conn_id = "test_conn"
    session.username = "root"
    return session


@pytest.fixture
def mock_process():
    process = MagicMock()
    process.stdin = AsyncMock()
    # ScpHandler._write expects process.channel.write
    process.channel = MagicMock()
    return process


@pytest.mark.asyncio
async def test_scp_upload_sink_mode(mock_session, mock_process):
    """Test full SCP upload (sink mode -t)."""
    handler = ScpHandler(mock_session, process=mock_process)
    mock_session.fs.mkdir_p("/tmp")

    # Mock full protocol sequence
    # 1. C0644 12 test.txt -> 2. content -> 3. NULL (EOF) -> 4. E (Done)
    mock_process.stdin.read.side_effect = [
        b"C0644 12 test.txt\n",
        b"hello world\n",  # Exactly 12 bytes
        b"\0",  # EOF NULL marker (mandatory)
        b"E\n",
        b"",
    ]

    rc = await handler.handle("scp -t /tmp")

    assert rc == 0
    assert mock_session.fs.exists("/tmp/test.txt")
    assert mock_session.fs.get_content("/tmp/test.txt") == b"hello world\n"
    # Verify logger
    mock_session.honeypot.logger.log_event.assert_called()


@pytest.mark.asyncio
async def test_scp_upload_invalid_header(mock_session, mock_process):
    """Test behavior on invalid SCP header."""
    handler = ScpHandler(mock_session, process=mock_process)
    mock_process.stdin.read.side_effect = [b"INVALID HEADER\n", b""]

    rc = await handler.handle("scp -t /tmp")

    assert rc == 1
    # Should send a protocol error message
    assert mock_process.channel.write.called
    # Updated to match actual ScpHandler message
    assert "Unknown protocol command" in mock_process.channel.write.call_args[0][0]


@pytest.mark.asyncio
async def test_scp_save_to_vfs_error(mock_session, mock_process):
    """Test handling of VFS write errors."""
    handler = ScpHandler(mock_session, process=mock_process)
    # Force failure in mkfile
    mock_session.fs.mkfile = MagicMock(side_effect=RuntimeError("VFS FUll"))

    # Note: re-added the NULL byte
    mock_process.stdin.read.side_effect = [b"C0644 4 f.txt\n", b"data", b"\0", b""]

    rc = await handler.handle("scp -t /tmp")

    assert rc == 1
    # Check if we logged the error and sent error message to client
    assert mock_process.channel.write.called
    assert "Internal error saving file" in mock_process.channel.write.call_args[0][0]
