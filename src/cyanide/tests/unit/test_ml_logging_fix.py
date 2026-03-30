import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cyanide.logger import CyanideLogger
from cyanide.services.analytics import AnalyticsService
from cyanide.services.quarantine import QuarantineService


# Function to wait for log content to be written
def wait_for_log_line(path, timeout=1.0):
    start_time = time.time()
    while time.time() - start_time < timeout:
        if path.exists():
            with open(path, "r") as f:
                lines = f.readlines()
                if lines:
                    return lines
        time.sleep(0.1)
    return []


# Function 446: Handles event logging and telemetry.
@pytest.fixture
def temp_log_dir(tmp_path):
    log_dir = tmp_path / "var/log/cyanide"
    log_dir.mkdir(parents=True)
    return log_dir


# Function 447: Handles event logging and telemetry.
@pytest.fixture
def mock_logger(temp_log_dir):
    # Updated signature: pass a config dictionary
    logger = CyanideLogger({"logging": {"directory": str(temp_log_dir)}})
    return logger


# Function 448: Performs operations related to analytics svc.
@pytest.fixture
def analytics_svc(mock_logger):
    config = {
        "ml": {
            "enabled": True,
            "ml_log": str(Path(mock_logger.log_dir) / "cyanide-ml.json"),
            "model_path": "src/cyanide/assets/models/cyanideML.pkl",
        }
    }
    svc = AnalyticsService(config, mock_logger)
    return svc


# Function 450: Runs unit tests for the ml_command_logging functionality.
def test_ml_command_logging(analytics_svc):
    # Mock pipeline analyze_command and force enabled state
    analytics_svc.ml_enabled = True
    analytics_svc.ml_pipeline = MagicMock()
    analytics_svc.ml_pipeline.analyze_command.return_value = {
        "is_anomaly": True,
        "anomaly_score": 0.8,
        "reconstruction_error": 0.05,
        "classification": {"technique": "T1003"},
        "severity": "HIGH",
    }

    analytics_svc.analyze_command("ls -la", "1.1.1.1", "sess1")

    # Check if log file contains the entry
    log_path = Path(analytics_svc.logger.log_dir) / "cyanide-ml.json"

    # Use helper for reliable I/O
    lines = wait_for_log_line(log_path)
    if not lines:
        pytest.fail("Log file is empty after event")

    data = json.loads(lines[0])
    # Standardized structure: fields are flattened
    assert data["eventid"] == "ml_thought"
    assert data["command"] == "ls -la"
    assert data["verdict"] == "anomaly"


# Function 451: Runs unit tests for the ml_file_analysis_logging functionality.
def test_ml_file_analysis_logging(analytics_svc):
    # Mock pipeline analyze_command and force enabled state
    analytics_svc.ml_enabled = True
    analytics_svc.ml_pipeline = MagicMock()
    analytics_svc.ml_pipeline.analyze_command.return_value = {
        "is_anomaly": True,
        "anomaly_score": 0.9,
        "reconstruction_error": 0.1,
        "classification": {"technique": "T1105"},
        "severity": "CRITICAL",
    }

    analytics_svc.analyze_file("malware.sh", b"#!/bin/bash\nrm -rf /", "sess2", "2.2.2.2")

    # Check log file
    log_path = Path(analytics_svc.logger.log_dir) / "cyanide-ml.json"

    # Use helper for reliable I/O
    lines = wait_for_log_line(log_path)
    if not lines:
        pytest.fail("Log file is empty after analysis")

    # Find the ml_file_anomaly event (last lines)
    data = json.loads(lines[-1])
    assert data["eventid"] == "ml_file_anomaly"
    assert data["filename"] == "malware.sh"
    assert data["score"] == 0.9

    # Check the thought event (second to last)
    # Note: wait_for_log_line might return lines in order they were written
    thought_data = json.loads(lines[-2])
    assert thought_data["eventid"] == "ml_thought"
    assert thought_data["file"] == "malware.sh"
    assert thought_data["verdict"] == "anomaly"


# Function 452: Runs unit tests for the quarantine_triggers_ml functionality.
async def test_quarantine_triggers_ml(mock_logger, analytics_svc):
    config = {
        "quarantine_path": str(Path(mock_logger.log_dir).parent / "quarantine"),
        "quarantine_max_size_mb": 10,
    }
    q_svc = QuarantineService(config, mock_logger)
    # Mock services on logger (modern pattern)
    mock_logger.services = MagicMock()
    mock_logger.services.analytics = analytics_svc

    await q_svc.save_file("test_file.txt", b"some content", "sess3", "3.3.3.3")

    # Check if ML was called and force enabled state
    analytics_svc.ml_enabled = True
    analytics_svc.ml_pipeline = MagicMock()
    analytics_svc.ml_pipeline.analyze_command.return_value = {
        "is_anomaly": False,
        "anomaly_score": 0.1,
        "reconstruction_error": 0.01,
    }

    # We already called save_file, but we need to verify the call happened.
    # Actually, let's spy on analyze_file
    analytics_svc.analyze_file = MagicMock()
    await q_svc.save_file("spy_test.txt", b"spy content", "sess4", "4.4.4.4")

    analytics_svc.analyze_file.assert_called_with(
        "spy_test.txt", b"spy content", "sess4", "4.4.4.4"
    )
