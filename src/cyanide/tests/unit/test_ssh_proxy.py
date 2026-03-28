from unittest.mock import AsyncMock, MagicMock

import pytest

from cyanide.network.ssh_proxy import (
    CyanideSSHServer,
    ProxyClientChannel,
    ProxyServerSession,
)


@pytest.fixture
def mock_fs():
    return MagicMock()


@pytest.fixture
def ssh_server(mock_fs):
    return CyanideSSHServer(pool=None, target_host="1.2.3.4", target_port=22, fs=mock_fs)


def test_ssh_server_connection_made(ssh_server):
    conn = MagicMock()
    conn.get_extra_info.return_value = ("5.6.7.8", 1234)
    ssh_server.connection_made(conn)
    assert ssh_server.src_ip == "5.6.7.8"
    assert ssh_server.session_id is not None


def test_ssh_server_auth(ssh_server):
    assert ssh_server.password_auth_supported() is True
    assert ssh_server.validate_password("user", "pass") is True
    assert ssh_server.public_key_auth_supported() is True
    assert ssh_server.validate_public_key("user", "key") is True


@pytest.mark.asyncio
async def test_ssh_server_session_requested(ssh_server):
    ssh_server.session_id = "s1"
    ssh_server.src_ip = "1.2.3.4"
    session = await ssh_server.session_requested()
    assert isinstance(session, ProxyServerSession)


@pytest.fixture
def proxy_session(mock_fs):
    return ProxyServerSession(
        pool=None,
        target_host="1.2.3.4",
        target_port=22,
        session_id="s1",
        src_ip="5.6.7.8",
        fs=mock_fs,
    )


def test_proxy_session_requests(proxy_session):
    assert proxy_session.shell_requested() is True
    assert proxy_session.pending_request == ("shell", None)
    assert proxy_session.exec_requested("ls") is True
    assert proxy_session.pending_request == ("exec", "ls")
    assert proxy_session.pty_requested(None, None, None) is True


@pytest.mark.asyncio
async def test_proxy_session_get_target(proxy_session):
    # No pool
    host, port = await proxy_session._get_target()
    assert host == "1.2.3.4"
    assert port == 22

    # With pool
    proxy_session.pool = AsyncMock()
    proxy_session.pool.reserve_target.return_value = MagicMock(host="10.0.0.1", port=2222)
    host, port = await proxy_session._get_target()
    assert host == "10.0.0.1"
    assert port == 2222


@pytest.mark.asyncio
async def test_proxy_session_connection_lost(proxy_session):
    proxy_session.send_task = MagicMock()
    proxy_session.backend_conn = MagicMock()
    proxy_session.pool = AsyncMock()
    proxy_session.lease = MagicMock()

    proxy_session.connection_lost(None)
    assert proxy_session.send_task.cancel.called
    assert proxy_session.backend_conn.close.called
    assert proxy_session.pool.release_target.called


def test_proxy_client_channel_connection_lost():
    peer_chan = MagicMock()
    client_chan = ProxyClientChannel(session_id="s1", src_ip="5.6.7.8", peer_channel=peer_chan)
    client_chan.send_task = MagicMock()
    client_chan.connection_lost(None)
    assert client_chan.send_task.cancel.called
    assert peer_chan.close.called


def test_proxy_server_session_signals(proxy_session):
    proxy_session.backend_channel = MagicMock()
    proxy_session.terminal_window_resized(80, 24, 0, 0)
    proxy_session.backend_channel.change_terminal_size.assert_called_with(80, 24, 0, 0)

    proxy_session.break_received(100)
    proxy_session.backend_channel.send_break.assert_called_with(100)

    proxy_session.signal_received("SIGINT")
    proxy_session.backend_channel.send_signal.assert_called_with("SIGINT")

    proxy_session.eof_received()
    proxy_session.backend_channel.write_eof.assert_called_once()

    proxy_session.data_received(b"test", None)
    assert proxy_session.buffer == [b"test"]


@pytest.mark.asyncio
async def test_proxy_client_channel_methods():
    chan = ProxyClientChannel("sess1", "127.0.0.1", MagicMock())
    chan.connection_made(MagicMock())
    assert chan.send_task is not None

    chan.data_received(b"test", None)
    assert chan.buffer == [b"test"]

    chan.eof_received()
    chan.peer_channel.write_eof.assert_called_once()
