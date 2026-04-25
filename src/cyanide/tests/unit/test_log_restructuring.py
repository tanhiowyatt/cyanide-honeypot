import json
import time

import pytest

from cyanide.logger import CyanideLogger


def wait_for_log_line(path, timeout=1.0):
    start_time = time.time()
    while time.time() - start_time < timeout:
        if path.exists():
            with open(path, "r") as f:
                line = f.readline()
                if line:
                    return line
        time.sleep(0.1)
    return ""


@pytest.fixture
def temp_log_dir(tmp_path):
    log_dir = tmp_path / "var/log/cyanide"
    log_dir.mkdir(parents=True)
    return log_dir


def test_log_file_creation(temp_log_dir):
    CyanideLogger({"logging": {"directory": str(temp_log_dir)}})

    assert (temp_log_dir / "cyanide-server.json").exists()
    assert (temp_log_dir / "cyanide-vfs.json").exists()
    assert (temp_log_dir / "cyanide-ml.json").exists()
    assert (temp_log_dir / "cyanide-stats.json").exists()


def test_event_routing(temp_log_dir):
    logger = CyanideLogger({"logging": {"directory": str(temp_log_dir)}})

    # 1. Server event
    logger.log_event("system", "service_started", {"service": "test"})
    # 2. FS event
    logger.log_event("sess1", "command.input", {"input": "whoami"})
    # 3. ML event
    logger.log_event("sess2", "ml_thought", {"verdict": "clean"})
    # 4. Stats event
    logger.log_event("system", "stats", {"uptime": 100})

    line = wait_for_log_line(temp_log_dir / "cyanide-server.json")
    assert line, "Server log line empty"
    data = json.loads(line)
    assert data["eventid"] == "service_started"

    line = wait_for_log_line(temp_log_dir / "cyanide-vfs.json")
    assert line, "FS log line empty"
    data = json.loads(line)
    assert data["eventid"] == "command.input"

    line = wait_for_log_line(temp_log_dir / "cyanide-ml.json")
    assert line, "ML log line empty"
    data = json.loads(line)
    assert data["eventid"] == "ml_thought"

    line = wait_for_log_line(temp_log_dir / "cyanide-stats.json")
    assert line, "Stats log line empty"
    data = json.loads(line)
    assert data["eventid"] == "stats"


def test_log_command_routing(temp_log_dir):
    logger = CyanideLogger({"logging": {"directory": str(temp_log_dir)}})
    logger.log_event(
        "sess1",
        "command.input",
        {"protocol": "ssh", "src_ip": "1.2.3.4", "username": "root", "input": "uptime"},
    )

    line = wait_for_log_line(temp_log_dir / "cyanide-vfs.json")
    assert line, "FS log line empty for command"
    data = json.loads(line)
    assert data["eventid"] == "command.input"
    assert data["input"] == "uptime"


def test_log_event_async_routing(temp_log_dir):
    logger = CyanideLogger({"logging": {"directory": str(temp_log_dir)}})
    logger.log_event("sess3", "ml_anomaly", {"score": 0.9})

    line = wait_for_log_line(temp_log_dir / "cyanide-ml.json")
    assert line, "ML log line empty for anomaly"
    data = json.loads(line)
    assert data["eventid"] == "ml_anomaly"
    assert data["score"] == 0.9
