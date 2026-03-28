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
async def test_scp_directory_recursive(mock_session, mock_process):
    handler = ScpHandler(mock_session, process=mock_process)
    mock_session.fs.mkdir_p("/tmp")

    # Sequence for:
    # 1. D0755 0 dir1
    # 2. C0644 4 file1 (data)
    # 3. E
    # 4. E (End of transfer - initial dest_dir)
    mock_process.stdin.read.side_effect = [
        b"D0755 0 dir1\n",
        b"C0644 4 file1\n",
        b"data",
        b"\0",
        b"E\n",
        b"E\n",
        b"",
    ]

    rc = await handler.handle("scp -r -t /tmp")
    assert rc == 0
    assert mock_session.fs.exists("/tmp/dir1")
    assert mock_session.fs.exists("/tmp/dir1/file1")
    assert mock_session.fs.get_content("/tmp/dir1/file1") == "data"


@pytest.mark.asyncio
async def test_scp_nested_directories(mock_session, mock_process):
    handler = ScpHandler(mock_session, process=mock_process)
    mock_session.fs.mkdir_p("/tmp")

    # D dir_a -> D dir_b -> C file -> E (b) -> E (a) -> E (final)
    mock_process.stdin.read.side_effect = [
        b"D0755 0 dir_a\n",
        b"D0755 0 dir_b\n",
        b"C0644 4 file\n",
        b"data",
        b"\0",
        b"E\n",
        b"E\n",
        b"E\n",
        b"",
    ]

    rc = await handler.handle("scp -r -t /tmp")
    assert rc == 0
    assert mock_session.fs.exists("/tmp/dir_a/dir_b/file")
    assert mock_session.fs.get_content("/tmp/dir_a/dir_b/file") == "data"


@pytest.mark.asyncio
async def test_scp_invalid_dir_header(mock_session, mock_process):
    handler = ScpHandler(mock_session, process=mock_process)
    mock_session.fs.mkdir_p("/tmp")

    # Invalid D header
    mock_process.stdin.read.side_effect = [b"D0755 broken_dir\n", b"E\n", b""]

    rc = await handler.handle("scp -r -t /tmp")
    assert rc == 0
    # Error message should be written to channel
    assert mock_process.channel.write.called
