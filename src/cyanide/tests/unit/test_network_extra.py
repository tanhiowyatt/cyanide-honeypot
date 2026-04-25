from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.network.tcp_proxy import TCPProxy


@pytest.mark.asyncio
async def test_tcp_proxy_connection_error():
    # Mocking open_connection to fail
    with patch("asyncio.open_connection", side_effect=Exception("connection refused")):
        proxy = TCPProxy("127.0.0.1", 12345, "127.0.0.1", 54321)
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("1.2.3.4", 12345)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        await proxy.handle_client(mock_reader, mock_writer)

        mock_writer.close.assert_called()


@pytest.mark.asyncio
async def test_tcp_proxy_data_transfer():
    mock_reader_client = AsyncMock()
    mock_writer_client = MagicMock()
    mock_writer_client.get_extra_info.return_value = ("1.2.3.4", 12345)
    mock_writer_client.wait_closed = AsyncMock()

    mock_reader_remote = AsyncMock()
    mock_writer_remote = MagicMock()
    mock_writer_remote.get_extra_info.return_value = ("5.6.7.8", 54321)
    mock_writer_remote.wait_closed = AsyncMock()

    # Simulate data then EOF
    mock_reader_client.read.side_effect = [b"hello", b""]
    mock_reader_remote.read.side_effect = [b"world", b""]

    with patch("asyncio.open_connection", return_value=(mock_reader_remote, mock_writer_remote)):
        proxy = TCPProxy("127.0.0.1", 12345, "127.0.0.1", 54321)
        await proxy.handle_client(mock_reader_client, mock_writer_client)

    mock_writer_remote.write.assert_called_with(b"hello")
    mock_writer_client.write.assert_called_with(b"world")
