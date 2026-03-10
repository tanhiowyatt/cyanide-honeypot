import asyncio
from unittest.mock import MagicMock, patch

import pytest

from cyanide.core.config_schema import CyanideConfig
from cyanide.core.server import SSHServerFactory


def test_ssh_config_forwarding_loading():
    """Verify that pydantic schema correctly loads forwarding rules."""
    data = {
        "ssh": {
            "forwarding_enabled": True,
            "forward_redirect_enabled": True,
            "forward_redirect_rules": {"80": "1.1.1.1:80"},
        }
    }
    # In practice, CyanideConfig is often initialized from a dict that matches it
    config = CyanideConfig(**data)
    assert config.ssh.forwarding_enabled is True
    assert config.ssh.forward_redirect_rules["80"] == "1.1.1.1:80"


def test_ssh_forwarding_rejection():
    """Verify that forwarding is rejected when disabled."""
    mock_honeypot = MagicMock()
    # Pydantic-like dict to match .get() calls in server.py
    mock_honeypot.config = {"ssh": {"forwarding_enabled": False}}

    factory = SSHServerFactory(mock_honeypot)
    factory.src_ip = "1.2.3.4"
    factory.conn_id = "test"

    # Mock logger
    mock_honeypot.logger.log_event = MagicMock()

    # -L: (dest_host, dest_port, src_host, src_port)
    assert factory.direct_tcpip_requested("host", 80, "src", 123) is False
    # -R: (dest_host, dest_port, orig_host, orig_port)
    assert factory.connection_requested("host", 80, "orig", 443) is False


@pytest.mark.asyncio
async def test_ssh_forwarding_policy_router():
    """Verify the policy router correctly identifies redirect targets."""
    mock_honeypot = MagicMock()
    # Mocking the dictionary structure used in server.py
    mock_honeypot.config = {
        "ssh": {
            "forwarding_enabled": True,
            "forward_redirect_enabled": True,
            "forward_redirect_rules": {"80": "redirect.server:8080"},
        }
    }

    factory = SSHServerFactory(mock_honeypot)
    factory.src_ip = "1.2.3.4"
    factory.conn_id = "test"

    # Mock log_event
    mock_honeypot.logger.log_event = MagicMock()

    # Mock open_connection to avoid real network
    with patch("asyncio.open_connection", new_callable=MagicMock) as mock_conn:
        mock_reader = MagicMock()
        f_read1: asyncio.Future = asyncio.Future()
        f_read1.set_result(b"")
        f_read2: asyncio.Future = asyncio.Future()
        f_read2.set_result(b"")
        mock_reader.read.side_effect = [f_read1, f_read2]

        mock_writer = MagicMock()
        mock_writer.wait_closed = MagicMock(return_value=asyncio.Future())
        mock_writer.wait_closed.return_value.set_result(None)

        f_conn: asyncio.Future = asyncio.Future()
        f_conn.set_result((mock_reader, mock_writer))
        mock_conn.return_value = f_conn

        chan = MagicMock()
        # Mock chan.read() as a coroutine returning b""
        f_read: asyncio.Future = asyncio.Future()
        f_read.set_result(b"")
        chan.read.return_value = f_read

        # Mock drain
        f_drain: asyncio.Future = asyncio.Future()
        f_drain.set_result(None)
        chan.drain.return_value = f_drain

        chan.at_eof.side_effect = [False, True]

        # Test the redirect logic
        await factory.direct_tcpip(chan, "original.com", 80, "client.home", 123)

        # Check call: (host, port)
        mock_conn.assert_called()
        args, kwargs = mock_conn.call_args
        assert args[0] == "redirect.server"
        assert args[1] == 8080


def test_algo_config_parsing():
    """Verify that algorithm preferences are correctly parsed into the config object."""
    data = {
        "ssh": {
            "ciphers": ["aes256-ctr"],
            "macs": ["hmac-sha2-256"],
            "kex_algs": ["curve25519-sha256"],
        }
    }
    config = CyanideConfig(**data)
    assert config.ssh.ciphers == ["aes256-ctr"]
    assert config.ssh.macs == ["hmac-sha2-256"]
    assert config.ssh.kex_algs == ["curve25519-sha256"]
