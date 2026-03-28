from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.vfs.engine import FakeFilesystem
from cyanide.vfs.scp import ScpHandler


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.honeypot = MagicMock()
    session.honeypot.logger = MagicMock()
    session.honeypot.save_quarantine_file = MagicMock()
    session.fs = FakeFilesystem()
    session.src_ip = "1.2.3.4"
    session.session_id = "test_session_123"
    session.username = "root"
    # channel.read must be AsyncMock, but channel.write should be MagicMock (synchronous)
    session.channel = MagicMock()
    session.channel.read = AsyncMock()
    session.channel.write = MagicMock()
    return session


@pytest.fixture
def mock_process():
    process = MagicMock()
    process.stdin = AsyncMock()
    process.channel = MagicMock()
    return process


@pytest.mark.asyncio
async def test_scp_handler_direct_session_mode(mock_session):
    """Test ScpHandler without a process object (direct session mode)."""
    handler = ScpHandler(mock_session)
    mock_session.fs.mkdir_p("/tmp")

    # Simulate SCP protocol: metadata -> content -> null -> E
    mock_session.channel.read.side_effect = [b"C0644 4 test.txt\n", b"data", b"\0", b"E\n", b""]

    rc = await handler.handle("scp -t /tmp")
    assert rc == 0
    assert mock_session.fs.exists("/tmp/test.txt")
    assert mock_session.fs.get_content("/tmp/test.txt") == "data"
    # Verify it used session.channel, not process.stdin
    assert mock_session.channel.read.called


@pytest.mark.asyncio
async def test_scp_read_string_data(mock_session):
    """Test ScpHandler._read handles string data from channel."""
    handler = ScpHandler(mock_session)
    mock_session.channel.read.return_value = "string_data"

    data = await handler._read(10)
    assert data == b"string_data"
    assert isinstance(data, bytes)


@pytest.mark.asyncio
async def test_scp_read_exception(mock_session):
    """Test ScpHandler._read handles exceptions gracefully."""
    handler = ScpHandler(mock_session)
    mock_session.channel.read.side_effect = Exception("Read error")

    data = await handler._read(10)
    assert data == b""


@pytest.mark.asyncio
async def test_scp_write_exception(mock_session):
    """Test ScpHandler._write handles exceptions gracefully."""
    handler = ScpHandler(mock_session)
    mock_session.channel.write.side_effect = Exception("Write error")

    # Should not raise exception
    handler._write(b"data")
    assert mock_session.channel.write.called


@pytest.mark.asyncio
async def test_scp_read_file_data_early_eof(mock_session):
    """Test _read_file_data handles early EOF from client."""
    handler = ScpHandler(mock_session)
    # Expect 10 bytes, but only get 5
    mock_session.channel.read.side_effect = [b"12345", b""]

    data = await handler._read_file_data(10)
    assert data == b"12345"
    assert len(data) == 5


@pytest.mark.asyncio
async def test_scp_save_to_vfs_no_fs(mock_session):
    """Test _save_to_vfs when no filesystem is available."""
    mock_session.fs = None
    handler = ScpHandler(mock_session)

    # Should not raise
    handler._save_to_vfs("/tmp/test", b"content")


@pytest.mark.asyncio
async def test_scp_save_to_vfs_exception(mock_session):
    """Test _save_to_vfs when mkfile raises an exception."""
    handler = ScpHandler(mock_session)
    with patch.object(mock_session.fs, "mkfile", side_effect=Exception("Disk full")):
        # Should not raise
        handler._save_to_vfs("/tmp/test", b"content")


@pytest.mark.asyncio
async def test_scp_invalid_header_protocol_error(mock_session):
    """Test protocol error on invalid header."""
    handler = ScpHandler(mock_session)
    mock_session.channel.read.side_effect = [b"CINVALID\n", b""]

    rc = await handler.handle("scp -t /tmp")
    assert rc == 1
    # Check if error message was sent
    mock_session.channel.write.assert_any_call("\x01SCP Protocol Error: Invalid header\n")


@pytest.mark.asyncio
async def test_scp_shlex_split_failure(mock_session):
    """Test handle() with a command that causes shlex.split to fail."""
    handler = ScpHandler(mock_session)
    # Ensure read doesn't hang
    mock_session.channel.read.return_value = b""
    # Unbalanced quotes cause shlex to fail
    rc = await handler.handle('scp -t "unbalanced')
    assert rc == 0  # It falls back to dest_dir="."
    # Verify first ACK was sent
    mock_session.channel.write.assert_any_call("\0")


@pytest.mark.asyncio
async def test_scp_non_sink_mode(mock_session):
    """Test ScpHandler in non-sink mode (e.g. source mode -f)."""
    handler = ScpHandler(mock_session)
    rc = await handler.handle("scp -f /etc/passwd")
    # Currently non-sink is not implemented, returns 0 immediately
    assert rc == 0
    # No ACK should be sent to start protocol in source mode if not implemented
    assert mock_session.channel.write.call_count == 0


@pytest.mark.asyncio
async def test_scp_unsupported_commands(mock_session):
    """Test that unsupported commands (like T) are just ACKed."""
    handler = ScpHandler(mock_session)
    mock_session.channel.read.side_effect = [b"T1234567 0 1234567 0\n", b"E\n", b""]

    rc = await handler.handle("scp -t /tmp")
    assert rc == 0
    # Expected: Initial ACK + ACK for T + ACK for E = 3 ACKs
    assert mock_session.channel.write.call_count == 3
