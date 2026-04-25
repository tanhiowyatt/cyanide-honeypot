import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.core.server import CyanideServer


@pytest.mark.asyncio
async def test_metrics_auth_failure():
    config = {
        "metrics": {"enabled": True, "token": "secret_token", "port": 0},
    }
    server = CyanideServer(config)

    mock_reader = AsyncMock()
    mock_reader.readuntil.return_value = (
        b"GET /metrics HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n"
    )

    mock_writer = MagicMock()
    mock_writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    await server._handle_metrics_request(mock_reader, mock_writer)
    assert b"401 Unauthorized" in mock_writer.write.call_args[0][0]


@pytest.mark.asyncio
async def test_metrics_remote_config():
    config = {
        "metrics": {"enabled": True, "port": 0, "allow_remote": True},
    }
    server = CyanideServer(config)
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        await server.start_metrics_server()
        mock_start.assert_called()
        args, _ = mock_start.call_args
        assert args[1] == "0.0.0.0"


@pytest.mark.asyncio
async def test_metrics_handler_error():
    server = CyanideServer({"metrics": {"enabled": True}})
    mock_reader = AsyncMock()
    mock_reader.readuntil.side_effect = Exception("metrics read fail")

    mock_writer = MagicMock()
    mock_writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    mock_writer.wait_closed = AsyncMock()

    with patch.object(server.logger, "log_event") as mock_log:
        await server._handle_metrics_request(mock_reader, mock_writer)
        assert any("metrics_handler_error" in str(call) for call in mock_log.call_args_list)


@pytest.mark.asyncio
async def test_pkexec_coverage():
    from cyanide.vfs.commands.pkexec import PkexecCommand

    mock_emu = MagicMock()
    mock_emu.username = "user"
    mock_emu.execute = AsyncMock(return_value=("pk_out", "", 0))
    cmd = PkexecCommand(mock_emu)

    out, err, code = await cmd.execute([])
    assert "must specify" in err

    mock_emu.username = "root"
    out, err, code = await cmd.execute(["id"])
    assert out == "pk_out"


@pytest.mark.asyncio
async def test_su_coverage():
    from cyanide.vfs.commands.su import SuCommand

    mock_emu = MagicMock()
    mock_emu.username = "user"
    mock_emu.execute = AsyncMock(return_value=("su_out", "", 0))
    cmd = SuCommand(mock_emu)

    out, err, code = await cmd.execute(["-c", "id"])
    assert out == "su_out"

    mock_emu.pending_input_prompt = ""
    await cmd.execute(["root"])
    assert "Password:" in mock_emu.pending_input_prompt


@pytest.mark.asyncio
async def test_engine_extra_coverage():
    from cyanide.vfs.engine import FakeFilesystem

    fs = FakeFilesystem(os_profile="debian")
    fs.move("/nonexistent", "/tmp/new")
    fs.mkfile("/tmp/a_file", b"data")
    fs.remove("/tmp/a_file")


@pytest.mark.asyncio
async def test_ssh_session_extra_coverage():
    from cyanide.core.server import SSHSession

    mock_honeypot = MagicMock()
    mock_honeypot.logger = MagicMock()
    mock_fs = MagicMock()

    session = SSHSession(mock_honeypot, mock_fs, "127.0.0.1", 12345, "123")
    session.session_id = "test_session"
    session.src_ip = "127.0.0.1"

    # Coverage for env_received
    session.env_received(b"TERM", b"xterm")
    session.env_received("LANG", "en_US.UTF-8")

    # Coverage for terminal_size_changed
    session.terminal_size_changed(80, 24, 0, 0)

    # Coverage for shell_requested, exec_requested
    session.shell_requested()
    session.exec_requested("ls -la")
    session.subsystem_requested("sftp")

    # Keystroke dynamics coverage
    session.start_time = time.time() - 10
    session.keystrokes = [time.time() - 5, time.time() - 4, time.time() - 2]
    session.username = "root"
    session.commands = ["ls", "id"]
    session.bytes_in = 100
    session.bytes_out = 200
    session.client_version = "SSH-2.0-OpenSSH_8.2p1"

    # Coverage for connection_lost
    session.connection_lost(Exception("test error"))
    session.connection_lost(None)

    # Coverage for _log_ssh_details
    mock_conn = MagicMock()
    mock_conn.get_extra_info.return_value = "mock_algo"
    session._log_ssh_details(mock_conn)


@pytest.mark.asyncio
async def test_profile_loader_edge_cases():
    from pathlib import Path

    from cyanide.vfs.profile_loader import load

    with patch("builtins.open", MagicMock(side_effect=Exception("YAML error"))):
        try:
            load("invalid", Path("/tmp"))
        except Exception:
            pass


@pytest.mark.asyncio
async def test_wget_extra_coverage():
    from cyanide.vfs.commands.wget import WgetCommand

    mock_emu = MagicMock()
    cmd = WgetCommand(mock_emu)

    out, err, code = await cmd.execute([])
    assert "missing URL" in err

    out, err, code = await cmd.execute(["not_a_url"])
    assert code != 0
