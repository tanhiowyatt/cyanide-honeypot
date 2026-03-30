from unittest.mock import AsyncMock, MagicMock

import pytest

from cyanide.vfs.scp import ScpHandler


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.honeypot = MagicMock()
    session.honeypot.logger = MagicMock()
    session.fs = MagicMock()
    session.fs.is_dir.return_value = False
    session.src_ip = "1.2.3.4"
    session.conn_id = "test_123"
    session.channel = MagicMock()
    session.channel.read = AsyncMock()
    session.channel.write = MagicMock()
    return session


@pytest.mark.asyncio
async def test_scp_sink_file_upload(mock_session):
    handler = ScpHandler(mock_session)

    # Simulate C0644 5 test.txt\n + 'hello'
    mock_session.channel.read.side_effect = [b"C0644 5 test.txt\n", b"hello", b""]  # End of stream

    rc = await handler.handle("scp -t /tmp/test.txt")
    assert rc == 0

    # Check VFS save
    mock_session.fs.mkfile.assert_called_once()
    args, kwargs = mock_session.fs.mkfile.call_args
    assert args[0] == "/tmp/test.txt"
    assert kwargs["content"] == b"hello"

    # Check quarantine
    mock_session.honeypot.save_quarantine_file.assert_called_with(
        "test.txt", b"hello", "conn_test_123", "1.2.3.4"
    )

    # Check ACKs (1 initial + 1 metadata + 1 file)
    assert mock_session.channel.write.call_count == 3
    for call in mock_session.channel.write.call_args_list:
        assert call.args[0] == "\0"


@pytest.mark.asyncio
async def test_scp_sink_invalid_header(mock_session):
    handler = ScpHandler(mock_session)
    mock_session.channel.read.side_effect = [b"INVALID\n"]

    rc = await handler.handle("scp -t /tmp")
    assert rc == 1
    # Should have sent initial ACK then error for unknown command
    mock_session.channel.write.assert_any_call("\x01SCP: Unknown protocol command: INVALID\n")


@pytest.mark.asyncio
async def test_scp_sink_vfs_error(mock_session):
    handler = ScpHandler(mock_session)
    mock_session.channel.read.side_effect = [b"C0644 5 test.txt\n", b"hello"]
    # Simulate VFS error
    mock_session.honeypot.save_quarantine_file.side_effect = Exception("Disk Full")

    rc = await handler.handle("scp -t /tmp")
    assert rc == 1

    # Check error message sent to client
    found_error = False
    for call in mock_session.channel.write.call_args_list:
        if "\x01SCP: Internal error" in call.args[0]:
            found_error = True
            break
    assert found_error


@pytest.mark.asyncio
async def test_scp_sink_directory_creation(mock_session):
    handler = ScpHandler(mock_session)
    mock_session.channel.read.side_effect = [b"D0755 0 subdir\n", b"E\n", b""]

    rc = await handler.handle("scp -t /tmp")
    assert rc == 0

    mock_session.fs.mkdir_p.assert_called_with("/tmp/subdir")
    # Initial ACK + D ACK + E ACK
    assert mock_session.channel.write.call_count == 3
