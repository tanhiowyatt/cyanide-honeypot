import asyncio
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from cyanide.vfs.rsync import RsyncHandler
from cyanide.vfs.sftp import CyanideSFTPHandler


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.src_ip = "1.2.3.4"
    session.username = "root"
    session.conn_id = "test_id"
    session.honeypot = MagicMock()
    session.honeypot.config = {"ssh": {"rsync": {"enabled": True}}}
    session.honeypot.logger = MagicMock()
    session.fs = MagicMock()
    return session


@pytest.mark.asyncio
async def test_rsync_init_no_fs(mock_session):
    mock_session.fs = None
    mock_session.honeypot.get_filesystem.return_value = "fallback_fs"
    handler = RsyncHandler(mock_session)
    assert handler.fs == "fallback_fs"
    mock_session.honeypot.get_filesystem.assert_called_with("1.2.3.4")


@pytest.mark.asyncio
async def test_rsync_read_edge_cases(mock_session):
    handler = RsyncHandler(mock_session)

    assert await handler._read(0) == b""
    assert await handler._read(-1) == b""

    mock_session.channel.read = AsyncMock(side_effect=asyncio.TimeoutError())
    assert await handler._read(10) == b""

    mock_session.channel.read = AsyncMock(side_effect=RuntimeError("fail"))
    assert await handler._read(10) == b""


@pytest.mark.asyncio
async def test_rsync_handle_disabled(mock_session):
    mock_session.honeypot.config["ssh"]["rsync"]["enabled"] = False
    handler = RsyncHandler(mock_session)
    handler._write = MagicMock()

    assert await handler.handle("rsync --server .") == 1
    handler.logger.log_event.assert_any_call(ANY, "rsync_denied", ANY)


@pytest.mark.asyncio
async def test_rsync_handle_parse_error(mock_session):
    handler = RsyncHandler(mock_session)
    mock_session.channel.read = AsyncMock(return_value=b"")
    result = await handler.handle("rsync --server 'unclosed")
    assert result == 1


@pytest.mark.asyncio
async def test_rsync_handle_push_error(mock_session):
    handler = RsyncHandler(mock_session)
    handler._write = MagicMock()
    handler._read_int = AsyncMock(return_value=31)
    with patch.object(RsyncHandler, "_read_file_list", side_effect=ValueError("list error")):
        result = await handler._handle_push("/tmp")
        assert result == 13
        handler.honeypot.logger.log_event.assert_any_call("conn_test_id", "rsync_error", ANY)


@pytest.mark.asyncio
async def test_rsync_pull_with_process(mock_session):
    mock_process = MagicMock()
    handler = RsyncHandler(mock_session, process=mock_process)

    result = handler._handle_pull("/src")
    assert result == 13
    mock_process.channel.write_stderr.assert_called()


@pytest.mark.asyncio
async def test_sftp_init_fallback(mock_session):
    mock_chan = MagicMock()
    mock_chan.get_connection.return_value = MagicMock()
    setattr(mock_chan.get_connection.return_value, "cyanide_factory", None)
    mock_chan.honeypot = mock_session.honeypot
    mock_chan.fs = mock_session.fs
    mock_chan.session_id = "backup_id"
    mock_chan.src_ip = "5.6.7.8"

    handler = CyanideSFTPHandler(mock_chan)
    assert handler.session_id == "backup_id"
    assert handler.src_ip == "5.6.7.8"


@pytest.mark.asyncio
async def test_sftp_handler_close_readonly(mock_session):
    mock_chan = MagicMock()
    mock_chan.get_connection.return_value = MagicMock()
    setattr(
        mock_chan.get_connection.return_value,
        "cyanide_factory",
        MagicMock(honeypot=mock_session.honeypot),
    )
    handler = CyanideSFTPHandler(mock_chan)
    handler.fs = mock_session.fs
    handler._log_op = MagicMock()

    handle = b"h_readonly"
    handler.file_handles[handle] = {
        "path": "/test.txt",
        "buffer": bytearray(b"data"),
        "is_write": False,
        "pos": 0,
    }

    await handler.close(handle)
    handler._log_op.assert_called_with("close", "/test.txt")


@pytest.mark.asyncio
async def test_sftp_get_node_content_types(mock_session):
    mock_chan = MagicMock()
    mock_chan.get_connection.return_value = MagicMock()
    setattr(
        mock_chan.get_connection.return_value,
        "cyanide_factory",
        MagicMock(honeypot=mock_session.honeypot),
    )

    handler = CyanideSFTPHandler(mock_chan)
    handler.fs = MagicMock()

    handler.fs.get_content.return_value = "hello"
    assert handler._get_node_content("/f") == b"hello"

    handler.fs.get_content.return_value = b"world"
    assert handler._get_node_content("/f") == b"world"

    handler.fs.get_content.return_value = None
    assert handler._get_node_content("/f") == b""


@pytest.mark.asyncio
async def test_sftp_get_attrs_mtime_int(mock_session):
    mock_chan = MagicMock()
    mock_chan.get_connection.return_value = MagicMock()
    setattr(
        mock_chan.get_connection.return_value,
        "cyanide_factory",
        MagicMock(honeypot=mock_session.honeypot),
    )
    handler = CyanideSFTPHandler(mock_chan)

    node = MagicMock()
    node.size = 100
    node.perm = "-rw-r--r--"
    node.owner = "root"
    node.group = "root"
    node.mtime = 1234567890

    attrs = handler._get_attrs(node)
    assert attrs.mtime == 1234567890
