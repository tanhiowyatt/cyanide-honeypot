import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.services.telnet_handler import TelnetHandler


@pytest.fixture
def mock_server(mock_logger):
    server = MagicMock()
    server.logger = mock_logger
    server.services = MagicMock()
    server.stats = MagicMock()
    server.is_valid_user.return_value = True
    server.get_filesystem.return_value = MagicMock()
    server._log_tty = MagicMock()  # Mock _log_tty
    return server


@pytest.fixture
def telnet_handler(mock_server):
    config = {"session_timeout": 60}
    return TelnetHandler(mock_server, config)


@pytest.mark.asyncio
async def test_telnet_auth_success(telnet_handler, mock_server):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    writer.get_extra_info.return_value = ("1.2.3.4", 12345)

    with patch.object(telnet_handler, "_prepare_session", return_value=("s1", MagicMock(), True)):
        with patch.object(telnet_handler, "_send_banner", return_value=5):
            with patch.object(telnet_handler, "_perform_auth", return_value=(True, "root", 10, 10)):
                with patch.object(telnet_handler, "_run_shell", return_value=(10, 10, ["ls"])):
                    await telnet_handler.handle_connection(reader, writer)
                    writer.close.assert_called()


@pytest.mark.asyncio
async def test_telnet_auth_failure(telnet_handler, mock_server):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    writer.get_extra_info.return_value = ("1.2.3.4", 12345)

    with patch.object(telnet_handler, "_prepare_session", return_value=("s1", MagicMock(), True)):
        with patch.object(telnet_handler, "_send_banner", return_value=0):
            with patch.object(telnet_handler, "_perform_auth", return_value=(False, "", 10, 10)):
                await telnet_handler.handle_connection(reader, writer)
                writer.close.assert_called()


@pytest.mark.asyncio
async def test_telnet_perform_auth(telnet_handler, mock_server):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()

    reader.readuntil.side_effect = [b"root\n", b"cyanide\n"]
    mock_server.is_valid_user.return_value = True
    success, user, b_in, b_out = await telnet_handler._perform_auth(reader, writer, "s1", "1.2.3.4")
    assert success is True
    assert user == "root"

    reader.readuntil.side_effect = [b"root\n", b"wrong\n"]
    mock_server.is_valid_user.return_value = False
    success, user, b_in, b_out = await telnet_handler._perform_auth(reader, writer, "s1", "1.2.3.4")
    assert success is False


@pytest.mark.asyncio
async def test_telnet_run_shell(telnet_handler):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    shell = AsyncMock()
    shell.cwd = "/root"
    shell.execute.return_value = ("output\n", "", 0)

    reader.readuntil.side_effect = [b"ls\n", b"exit\n"]

    b_in, b_out, cmds = await telnet_handler._run_shell(
        reader, writer, shell, MagicMock(), "s1", "1.2.3.4", "root"
    )
    assert "ls" in cmds
    assert len(cmds) == 2
    assert shell.execute.called


@pytest.mark.asyncio
async def test_telnet_run_shell_empty_cmd(telnet_handler):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    shell = AsyncMock()
    shell.cwd = "/root"

    reader.readuntil.side_effect = [b"\n", b"exit\n"]
    b_in, b_out, cmds = await telnet_handler._run_shell(
        reader, writer, shell, MagicMock(), "s1", "1.2.3.4", "root"
    )
    assert len(cmds) == 1
    assert cmds[0] == "exit"


@pytest.mark.asyncio
async def test_telnet_run_shell_timeout(telnet_handler):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    shell = AsyncMock()

    reader.readuntil.side_effect = asyncio.TimeoutError
    b_in, b_out, cmds = await telnet_handler._run_shell(
        reader, writer, shell, MagicMock(), "s1", "1.2.3.4", "root"
    )
    assert any(b"Timeout" in call.args[0] for call in writer.write.call_args_list)


@pytest.mark.asyncio
async def test_telnet_command_not_found(telnet_handler):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    shell = AsyncMock()
    shell.cwd = "/root"
    shell.execute.return_value = ("", "command not found\n", 127)

    reader.readuntil.side_effect = [b"nonexistent\n", b"exit\n"]
    await telnet_handler._run_shell(reader, writer, shell, MagicMock(), "s1", "1.2.3.4", "root")
    assert telnet_handler.stats.on_command_not_found.called


@pytest.mark.asyncio
async def test_telnet_send_banner_no_issue(mock_config):
    server = MagicMock()
    server.profile = {"os_name": "Ubuntu 20.04"}

    m_fs = MagicMock()
    m_fs.get_node.return_value = None
    server.get_filesystem.return_value = m_fs

    handler = TelnetHandler(server, mock_config)
    writer = MagicMock()
    writer.drain = AsyncMock()

    result = await handler._send_banner(writer, m_fs)

    assert result > 0
    assert writer.write.called
    args, _ = writer.write.call_args
    assert b"Ubuntu 20.04" in args[0]


def test_get_prompt(telnet_handler):
    assert telnet_handler._get_prompt("root", "/root") == "root@server:~$ "
    assert telnet_handler._get_prompt("guest", "/home/guest") == "guest@server:~$ "
    assert telnet_handler._get_prompt("root", "/tmp") == "root@server:/tmp$ "
