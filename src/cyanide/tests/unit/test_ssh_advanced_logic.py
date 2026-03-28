import asyncio
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from cyanide.core.server import CyanideServer, SSHServerFactory


@pytest.fixture
def mock_honeypot():
    hp = MagicMock(spec=CyanideServer)
    hp.config = {
        "ssh": {
            "enabled": True,
            "port": 2222,
            "data_path": "/tmp/cyanide_test_keys",
            "auth_tries": 5,
            "rekey_limit": "512M",
        }
    }
    hp.logger = MagicMock()
    hp.tracer = MagicMock()
    # Mock services and session manager
    hp.services = MagicMock()
    hp.services.session = MagicMock()
    hp.services.session.can_accept.return_value = (True, "OK")
    hp.services.session.active_sessions = 0
    hp.services.analytics = MagicMock()
    hp.services.analytics.geoip = MagicMock()
    hp.services.analytics.geoip.lookup = AsyncMock(
        return_value={"country": "Local Network", "city": "Internal"}
    )
    hp.services.analytics.log_geoip = MagicMock()

    # Mock tracer.start_as_current_span to work as a context manager
    span_mock = MagicMock()
    hp.tracer.start_as_current_span.return_value.__enter__.return_value = span_mock
    # Mock get_filesystem
    hp.get_filesystem.return_value = MagicMock()
    return hp


def test_ssh_factory_init(mock_honeypot):
    factory = SSHServerFactory(mock_honeypot)
    assert factory.honeypot == mock_honeypot
    assert factory._max_auth_tries == 5
    assert len(factory.conn_id) == 8


@pytest.mark.asyncio
async def test_ssh_factory_connection_made_logging(mock_honeypot, tmp_path):
    # Set logger.log_dir to a real temp path so connection_made doesn't
    # create spurious MagicMock/ directories on disk.
    mock_honeypot.logger.log_dir = str(tmp_path)
    factory = SSHServerFactory(mock_honeypot)

    # Mock connection object using the correct asyncssh extra_info keys
    mock_conn = MagicMock()
    mock_conn._kex_alg = b"curve25519-sha256"
    mock_conn._server_host_key_alg = b"ssh-ed25519"
    mock_conn.get_extra_info.side_effect = lambda key, default=None: {
        "peername": ("1.2.3.4", 12345),
        "client_version": "SSH-2.0-TestClient",
        "send_cipher": "aes256-gcm@openssh.com",
        "send_mac": "hmac-sha2-512",
        "send_compression": "none",
    }.get(key, default)

    with patch("asyncio.create_task") as mock_task:
        factory.connection_made(mock_conn)
        mock_task.assert_called()
    await factory.begin_auth("root")

    # Check if log_event was called with correct connect info
    mock_honeypot.logger.log_event.assert_any_call(
        "conn_" + factory.conn_id,
        "ssh.connect",
        {
            "src_ip": "1.2.3.4",
            "src_port": 12345,
            "geoip": {"country": "Local Network", "city": "Internal"},
        },
    )

    # Check if fingerprinting was also logged
    mock_honeypot.logger.log_event.assert_any_call(
        "conn_" + factory.conn_id,
        "client_fingerprint",
        ANY,
    )


def test_ssh_factory_publickey_auth(mock_honeypot):
    factory = SSHServerFactory(mock_honeypot)
    assert factory.publickey_auth_supported() is True

    # Mock key object
    mock_key = MagicMock()
    mock_key.get_fingerprint.return_value = "fp123"
    mock_key.export_public_key.return_value = b"ssh-rsa AAA..."

    result = factory.validate_publickey("attacker", mock_key)
    assert result is False  # Always fail to force password

    # Check logging
    mock_honeypot.logger.log_event.assert_called_with(
        "conn_" + factory.conn_id,
        "auth.publickey",
        {
            "username": "attacker",
            "fingerprint": "fp123",
            "key": "ssh-rsa AAA...",
            "success": False,
        },
    )


@pytest.mark.asyncio
async def test_server_get_host_keys_generation(tmp_path):
    # Setup CyanideServer with actual instance but mocked dependencies
    conf = {"ssh": {"data_path": str(tmp_path / "keys"), "enabled": True}}

    with (
        patch("cyanide.core.server.CyanideLogger"),
        patch("cyanide.core.server.VTScanner"),
        patch("cyanide.core.server.StatsManager"),
        patch("cyanide.services.session_manager.SessionManager"),
        patch("cyanide.services.quarantine.QuarantineService"),
        patch("cyanide.services.analytics.AnalyticsService"),
    ):

        server = CyanideServer(conf)

        # Mock asyncssh key gen/read
        with patch("asyncssh.generate_private_key") as mock_gen:

            # Make sure chmod doesn't fail by mocking Path.chmod or making file exist
            with patch("pathlib.Path.chmod") as mock_chmod:
                mock_key = MagicMock()
                mock_gen.return_value = mock_key

                keys = server._get_host_keys()

                # Should try to generate 3 keys: rsa, ed25519, p256
                assert mock_gen.call_count == 3
                assert len(keys) == 3
                assert mock_chmod.call_count == 3


@pytest.mark.asyncio
async def test_server_rekey_limit_parsing(tmp_path):
    conf = {
        "ssh": {"rekey_limit": "500M", "enabled": True, "port": 2222},
        "telnet": {"enabled": False},
        "metrics": {"enabled": False},
        "ml": {"enabled": False},
        "cleanup": {"enabled": False},
    }

    with (
        patch("cyanide.core.server.CyanideLogger"),
        patch("cyanide.core.server.VTScanner"),
        patch("cyanide.core.server.StatsManager"),
        patch("cyanide.services.session_manager.SessionManager"),
        patch("cyanide.services.quarantine.QuarantineService"),
        patch("cyanide.services.analytics.AnalyticsService"),
        patch("cyanide.core.server.VMPool") as mock_vm_pool_cls,
    ):

        mock_vm_pool_cls.return_value.start = MagicMock()
        server = CyanideServer(conf)

        async def dummy_coro(*args, **kwargs):
            pass

        server.async_logger = MagicMock()
        server.async_logger.stop = MagicMock(side_effect=dummy_coro)
        server._start_vm_pool = MagicMock()
        server._start_telnet_service = MagicMock(side_effect=dummy_coro)
        server._start_smtp_service = MagicMock(side_effect=dummy_coro)
        server._get_host_keys = MagicMock(return_value=[])
        server.profile = {"ssh_banner": "SSH-2.0-OpenSSH_8.9"}

        mock_ssh_server = MagicMock()
        mock_ssh_server.close = MagicMock()

        async def dummy_coro2(*args, **kwargs):
            pass

        mock_ssh_server.wait_closed = MagicMock(side_effect=dummy_coro2)

        with patch("asyncssh.listen", new_callable=AsyncMock) as mock_listen:
            mock_listen.return_value = mock_ssh_server
            # Run start in a task because it waits on _stop_event.wait()
            task = asyncio.create_task(server.start())
            await asyncio.sleep(0.1)

            mock_listen.assert_called()
            args, kwargs = mock_listen.call_args
            # 500M = 500 * 1024 * 1024 = 524288000
            assert kwargs["rekey_bytes"] == 500 * 1024 * 1024

            # Clean up
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
