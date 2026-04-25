from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.network.tcp_proxy import TCPProxy


@pytest.fixture
def tcp_proxy():
    return TCPProxy(listen_host="0.0.0.0", listen_port=8080, target_host="1.2.3.4", target_port=80)


@pytest.mark.asyncio
async def test_tcp_proxy_start_stop(tcp_proxy):
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_server = MagicMock()
        mock_start.return_value = mock_server
        await tcp_proxy.start()
        assert tcp_proxy.server == mock_server
        tcp_proxy.close()
        mock_server.close.assert_called()


@pytest.mark.asyncio
async def test_tcp_proxy_forward(tcp_proxy):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()

    reader.read.side_effect = [b"hello", b""]

    await tcp_proxy.forward(reader, writer, "test", "sess123")
    writer.write.assert_called_with(b"hello")
    assert writer.drain.called


@pytest.mark.asyncio
async def test_tcp_proxy_handle_client(tcp_proxy):
    client_reader = AsyncMock()
    client_writer = MagicMock()
    client_writer.get_extra_info.return_value = ("5.6.7.8", 1234)
    client_writer.wait_closed = AsyncMock()

    target_reader = AsyncMock()
    target_writer = MagicMock()
    target_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = (target_reader, target_writer)
        with patch.object(tcp_proxy, "forward", new_callable=AsyncMock):
            await tcp_proxy.handle_client(client_reader, client_writer)
            mock_connect.assert_called_with("1.2.3.4", 80)
            target_writer.close.assert_called()
            client_writer.close.assert_called()
