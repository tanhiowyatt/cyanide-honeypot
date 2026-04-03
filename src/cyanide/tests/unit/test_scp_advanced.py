import asyncio
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
async def test_scp_handler_direct_session_mode(mock_session):
    """Test ScpHandler without a process object (using session.channel directly)."""
    mock_session.channel = MagicMock()
    mock_session.channel.read = AsyncMock()
    # Mock data for sequence: C0644 5 test.txt\n + data
    mock_session.channel.read.side_effect = [
        b"C0644 5 test.txt\n",
        b"hello",
        b"E\n",
        b"",
    ]

    handler = ScpHandler(mock_session, process=None)
    mock_session.fs.mkdir_p("/tmp")

    rc = await handler.handle("scp -t /tmp")

    assert rc == 0
    assert mock_session.fs.exists("/tmp/test.txt")
    assert mock_session.fs.get_content("/tmp/test.txt") == b"hello"


@pytest.mark.asyncio
async def test_scp_upload_permission_denied(mock_session, mock_process):
    """Test placeholder for SCP upload permission verification."""
    pass


@pytest.mark.asyncio
async def test_scp_handler_read_error(mock_session, mock_process):
    """Test handler behavior on unexpected read errors from channel."""
    handler = ScpHandler(mock_session, process=mock_process)
    mock_process.stdin.read.side_effect = asyncio.TimeoutError()

    rc = await handler.handle("scp -t /tmp")
    assert rc == 0


@pytest.mark.asyncio
async def test_scp_source_mode_not_found(mock_session, mock_process):
    """Test ScpHandler in source mode (-f) for non-existent file."""
    handler = ScpHandler(mock_session, process=mock_process)
    # Scp source mode detects -f. It then waits for an initial ACK ( b"\0" ).

    mock_process.stdin.read.side_effect = [b"\0", b""]

    # We assume /nonexistent doesn't exist in mock_session.fs
    rc = await handler.handle("scp -f /nonexistent")

    assert rc == 1
    # Check if we wrote an error message starting with \x01
    assert mock_process.channel.write.called
    assert "\x01SCP: No such file" in mock_process.channel.write.call_args[0][0]


@pytest.mark.asyncio
async def test_scp_source_send_file(mock_session, mock_process):
    """Test sending a file from honeypot to client (source mode -f)."""
    handler = ScpHandler(mock_session, process=mock_process)
    mock_session.fs.mkfile("/src.txt", content="source data")

    mock_process.stdin.read.side_effect = [
        b"\0",  # Initial ACK
        b"\0",  # Header ACK
        b"\0",  # Final ACK wait
    ]

    rc = await handler.handle("scp -f /src.txt")

    assert rc == 0
    all_writes = "".join([call[0][0] for call in mock_process.channel.write.call_args_list])
    assert "source data" in all_writes
    assert "C0644" in all_writes


@pytest.mark.asyncio
async def test_scp_source_missing_initial_ack(mock_session, mock_process):
    """Test that source mode fails if the client doesn't send the initial null byte."""
    handler = ScpHandler(mock_session, process=mock_process)
    mock_session.fs.mkfile("/src.txt", content="data")

    mock_process.stdin.read.side_effect = [b"\x01Error\n"]

    rc = await handler.handle("scp -f /src.txt")
    assert rc == 1
