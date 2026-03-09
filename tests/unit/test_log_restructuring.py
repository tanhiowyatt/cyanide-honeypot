import json

import pytest

from cyanide.logger import CyanideLogger


@pytest.fixture
def temp_log_dir(tmp_path):
    log_dir = tmp_path / "var/log/cyanide"
    log_dir.mkdir(parents=True)
    return log_dir


def test_log_file_creation(temp_log_dir):
    # Instantiate logger to trigger file creation
    CyanideLogger(str(temp_log_dir))

    # Check if all four files are created as loggers are initialized (handlers open files)
    assert (temp_log_dir / "cyanide-server.json").exists()
    assert (temp_log_dir / "cyanide-fs.json").exists()
    assert (temp_log_dir / "cyanide-ml.json").exists()
    assert (temp_log_dir / "cyanide-stats.json").exists()


def test_event_routing(temp_log_dir):
    logger = CyanideLogger(str(temp_log_dir))

    # 1. Server event
    logger.log_event("system", "service_started", {"service": "test"})
    # 2. FS event
    logger.log_event("sess1", "command.input", {"input": "whoami"})
    # 3. ML event
    logger.log_event("sess2", "ml_thought", {"verdict": "clean"})
    # 4. Stats event
    logger.log_event("system", "stats", {"uptime": 100})

    # Verify content in respective files
    with open(temp_log_dir / "cyanide-server.json", "r") as f:
        data = json.loads(f.read())
        assert data["eventid"] == "service_started"

    with open(temp_log_dir / "cyanide-fs.json", "r") as f:
        data = json.loads(f.read())
        assert data["eventid"] == "command.input"

    with open(temp_log_dir / "cyanide-ml.json", "r") as f:
        data = json.loads(f.read())
        assert data["eventid"] == "ml_thought"

    with open(temp_log_dir / "cyanide-stats.json", "r") as f:
        data = json.loads(f.read())
        assert data["eventid"] == "stats"


@pytest.mark.asyncio
async def test_log_command_routing(temp_log_dir):
    logger = CyanideLogger(str(temp_log_dir))
    await logger.log_command("sess1", "ssh", "1.2.3.4", "root", "uptime")

    with open(temp_log_dir / "cyanide-fs.json", "r") as f:
        data = json.loads(f.read())
        assert data["eventid"] == "command.input"
        assert data["input"] == "uptime"


@pytest.mark.asyncio
async def test_log_event_async_routing(temp_log_dir):
    logger = CyanideLogger(str(temp_log_dir))
    await logger.log_event_async(
        {"event": "ml_anomaly", "session_id": "sess3", "src_ip": "5.5.5.5", "score": 0.9}
    )

    with open(temp_log_dir / "cyanide-ml.json", "r") as f:
        data = json.loads(f.read())
        assert data["eventid"] == "ml_anomaly"
        assert data["score"] == 0.9
