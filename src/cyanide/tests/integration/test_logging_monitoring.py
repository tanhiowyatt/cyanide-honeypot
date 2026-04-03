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
    stats.on_auth("root", "123456", True)
    stats.on_command("ssh", "192.168.1.1", "root", "id")

    output = stats.to_prometheus()

    assert "cyanide_active_sessions 1" in output
    assert "cyanide_total_sessions_total 1" in output
    assert 'cyanide_protocols_total{protocol="ssh"} 1' in output


@pytest.mark.asyncio
async def test_cyanide_logger_structure(log_dir):
    logger = CyanideLogger({"logging": {"directory": log_dir}})
    session_id = "test_sess_123"

    logger.log_event(session_id, "test_event", {"foo": "bar"})

    logger.log_event(
        session_id,
        "command.input",
        {"protocol": "ssh", "src_ip": "1.2.3.4", "username": "root", "input": "whoami"},
    )

    server_log = os.path.join(log_dir, "cyanide-server.json")
    assert os.path.exists(server_log)
    with open(server_log, "r") as f:
        data = json.loads(f.read())
        assert data["eventid"] == "test_event"
        assert data["foo"] == "bar"

    fs_log = os.path.join(log_dir, "cyanide-fs.json")
    assert os.path.exists(fs_log)
    with open(fs_log, "r") as f:
        data = json.loads(f.read())
        assert data["eventid"] == "command.input"
        assert data["input"] == "whoami"
