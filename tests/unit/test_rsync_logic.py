import struct
from unittest.mock import AsyncMock, MagicMock

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
async def test_rsync_disabled(mock_session):
    mock_session.honeypot.config["ssh"]["rsync"]["enabled"] = False
    handler = RsyncHandler(mock_session)
    rc = await handler.handle("rsync --server . dest")
    assert rc == 1
