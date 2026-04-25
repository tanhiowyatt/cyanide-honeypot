import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.core.server import CyanideServer


@pytest.fixture
def mock_config():
    return {
        "logging": {"directory": "var/log/cyanide"},
        "otel": {"enabled": False},
        "users": [{"user": "root", "pass": "cyanide"}],
        "honeytokens": ["/etc/shadow"],
    }


@pytest.fixture
def server(mock_config):
    with (
        patch("cyanide.core.server.CyanideLogger"),
        patch("cyanide.core.server.setup_telemetry"),
        patch("cyanide.core.server.SessionManager"),
        patch("cyanide.core.server.QuarantineService"),
        patch("cyanide.core.server.VTScanner"),
        patch("cyanide.core.server.AnalyticsService"),
        patch("cyanide.core.server.TelnetHandler"),
        patch("cyanide.core.server.FakeFilesystem"),
        patch("cyanide.core.server.VMPool"),
    ):
        return CyanideServer(mock_config)


def test_server_is_valid_user(server):
    assert server.is_valid_user("root", "cyanide") is True
    assert server.is_valid_user("root", "wrong") is False
    assert server.is_valid_user("admin", "cyanide") is False


def test_server_fs_audit_hook(server):
    server.stats = MagicMock()
    server.logger = MagicMock()
    server._fs_audit_hook("open", "/etc/passwd")
    assert server.logger.log_event.called

    server._fs_audit_hook("open", "/etc/shadow")
    assert server.stats.on_honeytoken.called


def test_server_route_metrics_request(server):
    server.stats = MagicMock()
    server.stats.to_prometheus.return_value = "prom_metrics"
    server.stats.get_stats.return_value = {"sessions": 1}

    content, ctype = server._route_metrics_request("/metrics")
    assert content == "prom_metrics"

    content, ctype = server._route_metrics_request("/logs/stats")
    assert "sessions" in content

    content, ctype = server._route_metrics_request("/health")
    assert "healthy" in content

    content, ctype = server._route_metrics_request("/")
    assert "cyanide_control_plane" in content

    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.isfile", return_value=True),
        patch(
            "builtins.open",
            MagicMock(
                return_value=MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(read=MagicMock(return_value="log content"))
                    )
                )
            ),
        ),
    ):
        content, ctype = server._route_metrics_request("/logs/server")
        assert "log content" in content


@pytest.mark.asyncio
async def test_server_handle_metrics_request(server):
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()

    reader.readuntil.return_value = b"GET /metrics HTTP/1.1\r\n\r\n"
    server.stats = MagicMock()
    server.stats.to_prometheus.return_value = "metrics"

    await server._handle_metrics_request(reader, writer)
    assert b"metrics" in writer.write.call_args[0][0]

    reader.readuntil.side_effect = asyncio.TimeoutError
    await server._handle_metrics_request(reader, writer)


def test_server_parse_ssh_rekey():
    assert CyanideServer._parse_ssh_rekey("1G") == 1024**3
    assert CyanideServer._parse_ssh_rekey("512M") == 512 * 1024**2
    assert CyanideServer._parse_ssh_rekey("100K") == 100 * 1024
    assert CyanideServer._parse_ssh_rekey("1000") == 1000
    assert CyanideServer._parse_ssh_rekey("") == 1024**3


def test_server_get_health_status(server):
    server.ssh_server = MagicMock()
    server.telnet_server = None
    server.stats.start_time = 0

    status = json.loads(server._get_health_status())
    assert status["status"] == "healthy"

    server.ssh_server = None
    status = json.loads(server._get_health_status())
    assert status["status"] == "unhealthy"
