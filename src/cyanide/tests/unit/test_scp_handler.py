from unittest.mock import ANY, AsyncMock, MagicMock

import pytest

from cyanide.vfs.engine import FakeFilesystem
from cyanide.vfs.scp import ScpHandler


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.honeypot = MagicMock()
    session.honeypot.config = {"ssh": {"allow_upload": True}}
    session.honeypot.logger = MagicMock()
    session.honeypot.save_quarantine_file = MagicMock()
    session.fs = FakeFilesystem()
    session.src_ip = "1.2.3.4"
    session.conn_id = "test_conn"
    session.username = "root"
    return session


@pytest.fixture
def mock_process():
    process = MagicMock()
    process.stdin = AsyncMock()
    process.channel = MagicMock()
    return process


@pytest.mark.asyncio
async def test_scp_upload_sink_mode(mock_session, mock_process):
    handler = ScpHandler(mock_session, process=mock_process)
    mock_session.fs.mkdir_p("/tmp")

    # Simulate SCP sink protocol for a file named 'malware.sh' with content 'echo hi'
    metadata = b"C0644 7 malware.sh\n"
    content = b"echo hi"

    # Sequence of reads:
    # 1. First header
    # 2. Content
    # 3. Trailing null
    # 4. E (End of transfer)
    mock_process.stdin.read.side_effect = [
        metadata,  # Metadata header
        content,  # File content
        b"\0",  # Trailing null from client
        b"E\n",  # End command
        b"",  # End of stream
    ]

    rc = await handler.handle("scp -t /tmp")

    assert rc == 0
    # Verify file created in VFS
    assert mock_session.fs.exists("/tmp/malware.sh")
    assert mock_session.fs.get_content("/tmp/malware.sh") == "echo hi"

    # Verify logging and quarantine
    mock_session.honeypot.save_quarantine_file.assert_called_with(
        "malware.sh", b"echo hi", "conn_test_conn", "1.2.3.4"
    )
    mock_session.honeypot.logger.log_event.assert_any_call(
        "conn_test_conn", "scp_upload_complete", ANY
    )


@pytest.mark.asyncio
async def test_scp_upload_invalid_header(mock_session, mock_process):
    handler = ScpHandler(mock_session, process=mock_process)

    mock_process.stdin.read.side_effect = [b"XINVALID\n", b""]

    rc = await handler.handle("scp -t /tmp")
    # It should just exit or handle normally
    assert rc == 0
    # Should have sent an ACK for the initial connection then ignore or ACK the invalid line
    assert mock_process.channel.write.call_count >= 1


@pytest.mark.asyncio
async def test_scp_handle_no_sink(mock_session, mock_process):
    """Test handler when -t (sink mode) is not present."""
    handler = ScpHandler(mock_session, process=mock_process)
    rc = await handler.handle("scp -f /tmp/file")
    assert rc == 0
    mock_session.honeypot.logger.log_event.assert_called_with(
        "conn_test_conn", "scp_exec_detected", ANY
    )
    # Check that direction was "download"
    call_args = mock_session.honeypot.logger.log_event.call_args[0]
    assert call_args[2]["direction"] == "download"


@pytest.mark.asyncio
async def test_scp_unsupported_command(mock_session, mock_process):
    """Test handling of unsupported commands like T or D."""
    handler = ScpHandler(mock_session, process=mock_process)
    # Simulate T command followed by E
    mock_process.stdin.read.side_effect = [b"T1234567 0 1234567 0\n", b"E\n", b""]

    rc = await handler.handle("scp -t /tmp")
    assert rc == 0
    # Initial ACK + ACK for T + ACK for E
    assert mock_process.channel.write.call_count >= 3


@pytest.mark.asyncio
async def test_scp_invalid_c_header(mock_session, mock_process):
    """Test C header with invalid format."""
    handler = ScpHandler(mock_session, process=mock_process)
    # C header with wrong number of parts
    mock_process.stdin.read.side_effect = [b"C0644 missing_size filename\n", b""]

    rc = await handler.handle("scp -t /tmp")
    assert rc == 1
    # Check that error message was written
    mock_process.channel.write.assert_any_call("\x01SCP Protocol Error: Invalid header\n")


@pytest.mark.asyncio
async def test_scp_save_to_vfs_error(mock_session, mock_process):
    """Test exception handling during VFS save."""
    handler = ScpHandler(mock_session, process=mock_process)
    mock_session.fs.mkfile = MagicMock(side_effect=Exception("VFS Error"))

    metadata = b"C0644 4 test.txt\n"
    content = b"data"
    mock_process.stdin.read.side_effect = [metadata, content, b"\0", b"E\n", b""]

    rc = await handler.handle("scp -t /tmp")
    assert rc == 0  # We still want to return 0 to the client usually in this honeypot
    # Error should be logged to project logger (not event logger necessarily)
    # But here we just check it didn't crash
