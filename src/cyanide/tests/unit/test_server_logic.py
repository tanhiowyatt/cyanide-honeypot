import asyncio
import time
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from cyanide.core.server import CyanideServer, SSHSession


@pytest.fixture
def mock_config():
    return {
        "logging": {"directory": "/tmp/cyanide_test_logs"},
        "ssh": {
            "port": 2222,
            "enabled": True,
            "version": "SSH-2.0-TestBanner",
            "sftp_enabled": True,
            "rsync_enabled": True,
            "scp_enabled": True,
        },
        "users": [{"user": "admin", "pass": "password"}],
        "os_profile": "debian",
        "honeytokens": ["/etc/shadow"],
    }


@pytest.fixture
def server(mock_config):
    with (
        patch("cyanide.core.server.CyanideLogger") as mock_logger,
        patch("cyanide.core.server.StatsManager"),
        patch("cyanide.core.server.setup_telemetry"),
        patch("cyanide.core.server.SessionManager"),
        patch("cyanide.core.server.QuarantineService"),
        patch("cyanide.core.server.AnalyticsService"),
        patch("cyanide.core.server.TelnetHandler"),
        patch("cyanide.core.server.FakeFilesystem"),
    ):
        mock_logger.return_value.log_dir = "/tmp/cyanide_test_logs"
        return CyanideServer(mock_config)


def test_parse_ssh_rekey(server):
    assert server._parse_ssh_rekey("") == 1024**3
    assert server._parse_ssh_rekey(None) == 1024**3
    assert server._parse_ssh_rekey("1G") == 1024**3
    assert server._parse_ssh_rekey("512M") == 512 * 1024**2
    assert server._parse_ssh_rekey("64K") == 64 * 1024
    assert server._parse_ssh_rekey("123") == 123


@pytest.mark.asyncio
async def test_handle_exec_session_rsync(server):
    process = MagicMock()
    process.command = "rsync --server ."
    sess = MagicMock()
    factory = MagicMock()
    factory.honeypot.config = server.config

    with patch("cyanide.core.server.RsyncHandler") as mock_rsync:
        mock_handler = mock_rsync.return_value
        mock_handler.handle = AsyncMock(return_value=13)

        await server._handle_exec_session(process, sess, factory, process.command)
        process.exit.assert_called_with(13)


@pytest.mark.asyncio
async def test_handle_exec_session_scp(server):
    process = MagicMock()
    process.command = "scp -t /tmp"
    sess = MagicMock()
    factory = MagicMock()
    factory.honeypot.config = server.config

    with patch("cyanide.core.server.ScpHandler") as mock_scp:
        mock_handler = mock_scp.return_value
        mock_handler.handle = AsyncMock(return_value=0)

        await server._handle_exec_session(process, sess, factory, process.command)
        process.exit.assert_called_with(0)


@pytest.mark.asyncio
async def test_handle_exec_session_normal(server):
    process = MagicMock()
    process.command = "uname -a"
    sess = MagicMock()
    sess._async_exec = AsyncMock()
    factory = MagicMock()
    factory.honeypot.config = server.config

    await server._handle_exec_session(process, sess, factory, process.command)
    sess._async_exec.assert_called_with("uname -a")


@pytest.mark.asyncio
async def test_start_telnet_service(server):
    server.config["telnet"] = {"enabled": True, "port": 23, "backend_mode": "emulated"}

    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_listen:
        await server._start_telnet_service()
        mock_listen.assert_called()
        server.logger.log_event.assert_any_call("system", "service_started", ANY)

    server.config["telnet"]["backend_mode"] = "proxy"
    with patch("cyanide.core.server.TCPProxy") as mock_proxy:
        mock_proxy_inst = mock_proxy.return_value
        mock_proxy_inst.start = AsyncMock()
        await server._start_telnet_service()
        mock_proxy_inst.start.assert_called()


@pytest.mark.asyncio
async def test_start_smtp_service(server):
    server.config["smtp"] = {"enabled": True, "port": 25, "backend_mode": "emulated"}

    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_listen:
        await server._start_smtp_service()
        mock_listen.assert_called()

    with patch("asyncio.start_server", side_effect=Exception("Failed")):
        await server._start_smtp_service()
        server.logger.log_event.assert_any_call("system", "smtp_error", ANY)


@pytest.mark.asyncio
async def test_server_stop(server):
    server.ssh_server = MagicMock()
    server.ssh_server.close = MagicMock()
    server.ssh_server.wait_closed = AsyncMock()

    task = asyncio.create_task(asyncio.sleep(10))
    server.background_tasks = [task]

    mock_ssh = server.ssh_server
    await server.stop()
    mock_ssh.close.assert_called()
    assert task.cancelled()


def test_get_host_keys(server):
    with (
        patch("cyanide.core.server.Path.mkdir"),
        patch("cyanide.core.server.Path.exists", return_value=True),
        patch("asyncssh.read_private_key", return_value="mock_key"),
    ):
        keys = server._get_host_keys()
        assert len(keys) > 0
        assert "mock_key" in keys


def test_get_ssh_options(server):
    host_keys = ["mock_key"]
    ssh_conf = server.config["ssh"]
    ssh_opts, version, algs = server._get_ssh_options(ssh_conf, host_keys)

    assert version == "TestBanner"
    assert ssh_opts["server_host_keys"] == host_keys
    assert "sftp_factory" in ssh_opts


def test_is_valid_user(server):
    assert server.is_valid_user("admin", "password") is True
    assert server.is_valid_user("admin", "wrong") is False
    assert server.is_valid_user("unknown", "password") is False


def test_analyze_command(server):
    server.services = MagicMock()
    server.tracer = MagicMock()
    server._analyze_command("ls", "root", "127.0.0.1", "session1", "ssh", is_bot=True)
    server.services.analytics.analyze_command.assert_called_with(
        "ls", "127.0.0.1", "session1", is_bot=True
    )


def test_fs_audit_hook(server):
    # normal
    server._fs_audit_hook("open", "/tmp/file", session_id="session1", src_ip="127.0.0.1")
    server.logger.log_event.assert_any_call("session1", "fs_audit", ANY)

    # honeytokens
    server._fs_audit_hook("open", "/etc/shadow", session_id="session1", src_ip="127.0.0.1")
    server.stats.on_honeytoken.assert_called_with("/etc/shadow")
    server.logger.log_event.assert_any_call("session1", "CRITICAL_ALERT", ANY)


def test_get_filesystem(server):
    server.vfs_persistence = True
    server.vfs_cache[("127.0.0.1", None)] = "cached_fs"
    assert server.get_filesystem("session1", "127.0.0.1") == "cached_fs"
    server.vfs_persistence = False
    with patch("cyanide.core.server.FakeFilesystem", return_value="new_fs"):
        fs = server.get_filesystem("session1", "127.0.0.2")
        assert fs == "new_fs"

    with patch(
        "cyanide.core.server.FakeFilesystem",
        side_effect=[Exception("test"), "fallback"],
    ):
        fs = server.get_filesystem("session1", "127.0.0.3")
        assert fs == "fallback"


def test_get_health_status(server):
    server.ssh_server = None
    server.telnet_server = None
    server.smtp_server = None
    server.config["ssh"] = {"enabled": True}
    server.config["telnet"] = {"enabled": True}
    server.config["smtp"] = {"enabled": True}

    import json

    status = json.loads(server._get_health_status())
    assert status["status"] == "unhealthy"

    server.ssh_server = True
    server.telnet_server = True
    server.smtp_server = True
    status = json.loads(server._get_health_status())
    assert status["status"] == "healthy"


@pytest.mark.asyncio
async def test_start_vm_pool(server):
    server.config["pool"] = {"enabled": False}
    with patch("cyanide.core.server.VMPool") as mock_pool:
        mock_pool.return_value.start = AsyncMock()
        server._start_vm_pool()
        assert len(server.background_tasks) > 0
        mock_pool.return_value.start.assert_called()

    server.background_tasks = []
    server.config["pool"] = {"enabled": True, "mode": "libvirt"}
    with patch("cyanide.core.libvirt_pool.LibvirtPool"):
        server._start_vm_pool()
        server.logger.log_event.assert_any_call("system", "service_started", ANY)


def test_log_tty(server):
    sess = MagicMock()
    sess.tty_log_path_jsonl = "/tmp/tty.jsonl"
    sess.tty_log_path = "/tmp/tty.log"
    sess.tty_timing_path = "/tmp/tty.time"
    sess.last_log_time = 0
    server.async_logger.log = MagicMock()

    with patch("time.time", return_value=123.0):
        server._log_tty(sess, "IN", b"test")
        server._log_tty(sess, "OUT", "test_str")
        assert server.async_logger.log.call_count >= 2


def test_route_metrics_request(server):
    server.stats.get_stats.return_value = {"a": 1}
    server.stats.to_prometheus.return_value = "stat{} 1"

    res, ct = server._route_metrics_request("/metrics")
    assert "text/plain" in ct
    res, ct = server._route_metrics_request("/logs/stats")
    assert ct == "application/json"
    res, ct = server._route_metrics_request("/health")
    assert ct == "application/json"
    res, ct = server._route_metrics_request("/logs/foo")
    assert "Not Found" in res
    res, ct = server._route_metrics_request("/unknown")
    assert "Not Found" in res


@pytest.mark.asyncio
async def test_start_metrics_server(server):
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_listen:
        await server.start_metrics_server()
        mock_listen.assert_called()


@pytest.mark.asyncio
async def test_cleanup_loop(server):
    with (
        patch("cyanide.core.cleanup.CleanupManager") as mock_manager,
        patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError]) as mock_sleep,
    ):
        mock_manager.return_value.enabled = False
        try:
            await server._cleanup_loop()
        except asyncio.CancelledError:
            pass

        mock_sleep.side_effect = [None, None, asyncio.CancelledError]
        mock_manager.return_value.enabled = True
        mock_manager.return_value.interval = 3600
        mock_manager.return_value.retention_days = 7
        mock_manager.return_value.cleanup_files.return_value = {
            "deleted": 5,
            "bytes_freed": 1024,
        }
        try:
            await server._cleanup_loop()
        except asyncio.CancelledError:
            pass
        mock_manager.return_value.cleanup_files.assert_called()


@pytest.fixture
def ssh_session(server):
    sess = SSHSession(server, MagicMock(), "127.0.0.1", 54321, "test_conn_1")
    sess.channel = MagicMock()
    return sess


@pytest.mark.asyncio
async def test_ssh_session_exec_requested(ssh_session):
    assert ssh_session.exec_requested(" ") is False
    ssh_session.honeypot.services.analytics = MagicMock(ml_enabled=True)
    ssh_session.honeypot._analyze_command = MagicMock()
    ssh_session._async_exec = AsyncMock()
    assert ssh_session.exec_requested("ls -la") is True
    assert "ls -la" in ssh_session.commands


@pytest.mark.asyncio
async def test_ssh_session_async_exec_system_exit(ssh_session):
    with patch("cyanide.core.server.ShellEmulator") as mock_shell:
        mock_shell.return_value.execute = AsyncMock(side_effect=SystemExit(2))
        ssh_session._write_exec_output = MagicMock()
        await ssh_session._async_exec("test")
        ssh_session._write_exec_output.assert_called()


@pytest.mark.asyncio
async def test_ssh_session_async_exec_error(ssh_session):
    with patch("cyanide.core.server.ShellEmulator") as mock_shell:
        mock_shell.return_value.execute = AsyncMock(side_effect=Exception("Test Error"))
        ssh_session.channel.exit = MagicMock()
        await ssh_session._async_exec("test")
        ssh_session.channel.exit.assert_called_with(1)


def test_ssh_session_write_to_process_channel(ssh_session):
    ssh_session.process = MagicMock()
    ssh_session._log_tty = MagicMock()
    ssh_session._write_to_process(b"out", b"err", 0)
    ssh_session.process.stdout.write.assert_called()

    ssh_session.process = None
    ssh_session._write_to_channel(b"out", b"err", 0)
    ssh_session.channel.write.assert_called()


def test_ssh_session_ended(ssh_session):
    ssh_session.start_time = time.time() - 10
    ssh_session.keystrokes = [1.0, 1.5, 2.0]
    ssh_session.session_ended()
    ssh_session.honeypot.logger.log_event.assert_called()
