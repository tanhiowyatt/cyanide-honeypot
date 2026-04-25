import asyncio
from unittest.mock import MagicMock, patch

import pytest

from cyanide.core.server import CyanideServer, ServiceRegistry, SSHSession


@pytest.fixture
def base_config():
    return {
        "ml": {"enabled": False},
        "logging": {"directory": "/tmp/cyanide_test"},
        "honeypot": {"hostname": "test-honeypot"},
    }


def test_server_init_logger_failure(base_config):
    # Test logger init failure
    with patch("cyanide.core.server.CyanideLogger", side_effect=Exception("logger fail")):
        with pytest.raises(Exception, match="logger fail"):
            CyanideServer(base_config)


def test_server_init_stats_failure(base_config):
    # Test stats init failure
    with patch("cyanide.core.server.CyanideLogger"):
        with patch("cyanide.core.server.StatsManager", side_effect=Exception("stats fail")):
            with pytest.raises(Exception, match="stats fail"):
                CyanideServer(base_config)


def test_server_init_session_failure(base_config):
    # Test SessionManager failure
    with patch("cyanide.core.server.CyanideLogger"):
        with patch("cyanide.core.server.StatsManager"):
            with patch("cyanide.core.server.SessionManager", side_effect=Exception("session fail")):
                with pytest.raises(Exception, match="session fail"):
                    CyanideServer(base_config)


def test_server_init_quarantine_failure(base_config):
    # Test QuarantineService failure
    with patch("cyanide.core.server.CyanideLogger"):
        with patch("cyanide.core.server.StatsManager"):
            with patch("cyanide.core.server.SessionManager"):
                with patch(
                    "cyanide.core.server.QuarantineService",
                    side_effect=Exception("quarantine fail"),
                ):
                    with pytest.raises(Exception, match="quarantine fail"):
                        CyanideServer(base_config)


def test_server_init_analytics_failure(base_config):
    # Test AnalyticsService failure
    with patch("cyanide.core.server.CyanideLogger"):
        with patch("cyanide.core.server.StatsManager"):
            with patch("cyanide.core.server.SessionManager"):
                with patch(
                    "cyanide.core.server.AnalyticsService", side_effect=Exception("analytics fail")
                ):
                    with pytest.raises(Exception, match="analytics fail"):
                        CyanideServer(base_config)


def test_server_init_ioc_failure(base_config):
    # Test IOCReporter failure
    with patch("cyanide.core.server.CyanideLogger"):
        with patch("cyanide.core.server.StatsManager"):
            with patch("cyanide.core.server.SessionManager"):
                with patch("cyanide.core.server.AnalyticsService"):
                    with patch(
                        "cyanide.core.server.IOCReporter", side_effect=Exception("ioc fail")
                    ):
                        with pytest.raises(Exception, match="ioc fail"):
                            CyanideServer(base_config)


@pytest.mark.asyncio
async def test_ssh_session_disconnect_with_exc():
    mock_hp = MagicMock()
    mock_fs = MagicMock()
    session = SSHSession(mock_hp, mock_fs, "1.2.3.4", 1234, "conn1")

    # Add a task to background_tasks
    mock_task = MagicMock()
    session._background_tasks.add(mock_task)

    session.connection_lost(Exception("lost"))

    mock_task.cancel.assert_called()
    assert len(session._background_tasks) == 0
    mock_hp.logger.log_event.assert_any_call(
        "conn_conn1", "session_disconnect", {"src_ip": "1.2.3.4", "reason": "error: lost"}
    )


def test_ssh_info_fallback_unknown():
    mock_hp = MagicMock()
    mock_fs = MagicMock()
    session = SSHSession(mock_hp, mock_fs, "1.2.3.4", 1234, "conn1")

    # Use a spec that doesn't include 'missing_attr'
    mock_conn = MagicMock(spec=["get_extra_info"])
    mock_conn.get_extra_info.return_value = None

    # Test fallback to unknown when attribute also missing
    val = session._get_ssh_info(mock_conn, "nonexistent", "missing_attr")
    assert val == "unknown"


@pytest.mark.asyncio
async def test_ssh_session_connection_made_error_handling():
    mock_hp = MagicMock()
    # log_geoip must return a coroutine
    mock_hp.log_geoip = MagicMock(return_value=asyncio.sleep(0))
    mock_fs = MagicMock()
    session = SSHSession(mock_hp, mock_fs, "1.2.3.4", 1234, "conn1")

    mock_chan = MagicMock()
    mock_conn = MagicMock()
    mock_chan.get_connection.return_value = mock_conn

    # Force error in _log_ssh_details
    with patch.object(session, "_log_ssh_details", side_effect=Exception("log error")):
        session.connection_made(mock_chan)
        # Should not raise exception
        mock_hp.stats.on_connect.assert_called()


def test_service_registry_init():
    mock_session = MagicMock()
    mock_quarantine = MagicMock()
    mock_analytics = MagicMock()
    mock_ioc = MagicMock()
    registry = ServiceRegistry(mock_session, mock_quarantine, mock_analytics, mock_ioc)
    assert registry.session == mock_session
    assert registry.telnet is None


@pytest.mark.asyncio
async def test_handle_shell_session_errors():
    mock_process = MagicMock()
    mock_sess = MagicMock()

    # Simulate an error during stdin iteration
    mock_process.stdin.__aiter__.side_effect = Exception("stream error")
    mock_process.stdout.drain = MagicMock(return_value=asyncio.sleep(0))

    await CyanideServer._handle_shell_session(mock_process, mock_sess)
    mock_sess.session_ended.assert_called()


@pytest.mark.asyncio
async def test_handle_shell_session_data_error():
    mock_process = MagicMock()
    mock_sess = MagicMock()

    # Simulate one successful read then an error in data_received
    mock_process.stdin.__aiter__.return_value = [b"ls\n"]
    mock_sess.data_received.side_effect = Exception("data error")
    mock_process.stdout.drain = MagicMock(return_value=asyncio.sleep(0))

    await CyanideServer._handle_shell_session(mock_process, mock_sess)
    mock_sess.session_ended.assert_called()


@pytest.mark.asyncio
async def test_server_vfs_init_error(base_config):
    mock_logger = MagicMock()
    with patch("cyanide.core.server.CyanideLogger", return_value=mock_logger):
        with patch("cyanide.core.server.FakeFilesystem", side_effect=Exception("fs fail")):
            # Should catch fs error and fallback
            server = CyanideServer(base_config)
            assert server.resolved_profile_name == "debian"
            mock_logger.log_event.assert_any_call(
                "system", "vfs_init_error", {"profile": "debian", "error": "fs fail"}
            )


@pytest.mark.asyncio
async def test_server_service_registry_error(base_config):
    mock_logger = MagicMock()
    with patch("cyanide.core.server.CyanideLogger", return_value=mock_logger):
        with patch("cyanide.core.server.ServiceRegistry", side_effect=Exception("reg fail")):
            with pytest.raises(Exception, match="reg fail"):
                CyanideServer(base_config)
            mock_logger.log_event.assert_any_call(
                "system", "service_init_error", {"service": "ServiceRegistry", "error": "reg fail"}
            )
