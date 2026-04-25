import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.services.smtp_handler import SMTPHandler


@pytest.fixture
def mock_server():
    server = MagicMock()
    server.config = {"honeypot": {"hostname": "test-smtp-server"}}
    server.stats = MagicMock()
    server.logger = MagicMock()
    return server


@pytest.fixture
def smtp_handler(mock_server):
    return SMTPHandler(mock_server, {})


@pytest.fixture
def mock_streams():
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = ("1.2.3.4", 12345)
    return reader, writer


@pytest.mark.asyncio
async def test_smtp_session_init(smtp_handler, mock_streams):
    _, writer = mock_streams
    src_ip, session_id, hostname, start_time = smtp_handler._init_session(writer)

    assert src_ip == "1.2.3.4"
    assert session_id.startswith("smtp_")
    assert hostname == "test-smtp-server"
    assert isinstance(start_time, float)

    smtp_handler.logger.log_event.assert_called_with(
        session_id,
        "connect",
        {"protocol": "smtp", "src_ip": "1.2.3.4", "src_port": 12345},
    )
    smtp_handler.stats.on_connect.assert_called_with("smtp", "1.2.3.4")


@pytest.mark.asyncio
async def test_smtp_helo_command(smtp_handler, mock_streams):
    reader, writer = mock_streams
    await smtp_handler._cmd_helo(reader, writer, [], "1.2.3.4", "test-host")
    writer.write.assert_called_with(b"250 test-host Hello 1.2.3.4\r\n")


@pytest.mark.asyncio
async def test_smtp_mail_rcpt_commands(smtp_handler, mock_streams):
    reader, writer = mock_streams
    await smtp_handler._cmd_mail(
        reader, writer, ["FROM:<test@example.com>"], "1.2.3.4", "test-host"
    )
    writer.write.assert_any_call(b"250 2.1.0 Ok\r\n")
    await smtp_handler._cmd_rcpt(reader, writer, ["TO:<rcpt@example.com>"], "1.2.3.4", "test-host")
    writer.write.assert_any_call(b"250 2.1.5 Ok\r\n")


@pytest.mark.asyncio
async def test_smtp_data_command(smtp_handler, mock_streams):
    reader, writer = mock_streams
    reader.readline.side_effect = [b"Subject: Test\r\n", b"Hello world\r\n", b".\r\n"]

    await smtp_handler._cmd_data(reader, writer, [], "1.2.3.4", "test-host")

    writer.write.assert_any_call(b"354 End data with <CR><LF>.<CR><LF>\r\n")
    writer.write.assert_any_call(b"250 2.0.0 Ok: queued as 12345\r\n")
    assert reader.readline.call_count == 3


@pytest.mark.asyncio
async def test_smtp_quit_command(smtp_handler, mock_streams):
    reader, writer = mock_streams
    should_continue = await smtp_handler._cmd_quit(reader, writer, [], "1.2.3.4", "test-host")
    assert should_continue is False
    writer.write.assert_called_with(b"221 2.0.0 Bye\r\n")


@pytest.mark.asyncio
async def test_smtp_unrecognized_command(smtp_handler, mock_streams):
    reader, writer = mock_streams
    should_continue = await smtp_handler._handle_command(
        reader, writer, "UNKNOWN", [], "1.2.3.4", "test-host"
    )
    assert should_continue is True
    writer.write.assert_called_with(b"502 5.5.2 Error: command not recognized\r\n")


@pytest.mark.asyncio
async def test_smtp_command_loop(smtp_handler, mock_streams):
    reader, writer = mock_streams
    reader.readline.side_effect = [b"HELO test.com\r\n", b"QUIT\r\n"]
    reader.at_eof.side_effect = [False, False, True]

    await smtp_handler._command_loop(reader, writer, "sess123", "1.2.3.4", "test-host")

    assert reader.readline.call_count == 2
    writer.write.assert_any_call(b"250 test-host Hello 1.2.3.4\r\n")
    writer.write.assert_any_call(b"221 2.0.0 Bye\r\n")


@pytest.mark.asyncio
async def test_smtp_full_connection_flow(smtp_handler, mock_streams):
    reader, writer = mock_streams
    reader.readline.side_effect = [b"QUIT\r\n"]
    reader.at_eof.side_effect = [False, True]

    with patch.object(
        smtp_handler,
        "_init_session",
        return_value=("1.2.3.4", "sess123", "test-host", 100.0),
    ):
        await smtp_handler.handle_connection(reader, writer)

    writer.write.assert_any_call(b"220 test-host ESMTP Postfix\r\n")
    writer.write.assert_any_call(b"221 2.0.0 Bye\r\n")
    writer.close.assert_called_once()


@pytest.mark.asyncio
async def test_smtp_error_handling(smtp_handler, mock_streams):
    reader, writer = mock_streams
    with patch.object(
        smtp_handler, "_command_loop", side_effect=Exception("Connection reset by peer")
    ):
        with patch.object(
            smtp_handler,
            "_init_session",
            return_value=("1.2.3.4", "sess_err", "test-host", 100.0),
        ):
            await smtp_handler.handle_connection(reader, writer)

    smtp_handler.logger.log_event.assert_any_call(
        "sess_err", "error", {"message": "SMTP Error: Connection reset by peer"}
    )


@pytest.mark.asyncio
async def test_smtp_other_commands(smtp_handler, mock_streams):
    reader, writer = mock_streams
    await smtp_handler._cmd_vrfy(reader, writer, [], "1.2.3.4", "test-host")
    writer.write.assert_any_call(
        b"252 2.1.5 Cannot VRFY user, but will accept message and attempt delivery\r\n"
    )
    await smtp_handler._cmd_noop(reader, writer, [], "1.2.3.4", "test-host")
    writer.write.assert_any_call(b"250 2.0.0 Ok\r\n")
    await smtp_handler._cmd_rset(reader, writer, [], "1.2.3.4", "test-host")
    writer.write.assert_any_call(b"250 2.0.0 Reset state\r\n")
