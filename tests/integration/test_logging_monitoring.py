import json
import os

import pytest

from cyanide.core.stats import StatsManager
from cyanide.logger import CyanideLogger


@pytest.fixture
def log_dir(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    return str(d)


def test_stats_to_prometheus():
    stats = StatsManager()
    stats.on_connect("ssh", "192.168.1.1")
    stats.on_auth("ssh", "192.168.1.1", "root", "123456", True)
    stats.on_command("ssh", "192.168.1.1", "root", "id")

    output = stats.to_prometheus()

    assert "cyanide_active_sessions 1" in output
    assert "cyanide_total_sessions_total 1" in output
    assert 'cyanide_protocols_total{protocol="ssh"} 1' in output


@pytest.mark.asyncio
async def test_cyanide_logger_structure(log_dir):
    logger = CyanideLogger(log_dir)
    session_id = "test_sess_123"

    # Test generic event
    logger.log_event(session_id, "test_event", {"foo": "bar"})

    # Test command logging (ELK/SIEM format)
    await logger.log_command(session_id, "ssh", "1.2.3.4", "root", "whoami")

    # Verify file content
    log_file = os.path.join(log_dir, "cyanide-log.json")
    assert os.path.exists(log_file)

    with open(log_file, "r") as f:
        lines = f.readlines()
        assert len(lines) >= 2

        # Check first event
        event1 = json.loads(lines[0])
        assert event1["eventid"] == "test_event"
        assert event1["session"] == session_id
        assert event1["data"]["foo"] == "bar"
        assert "timestamp" in event1

        # Check command event (SIEM format)
        event2 = json.loads(lines[1])
        assert event2["eventid"] == "command.input"
        assert event2["input"] == "whoami"
        assert event2["src_ip"] == "1.2.3.4"
        assert event2["protocol"] == "ssh"
