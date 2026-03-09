import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cyanide.logger import CyanideLogger
from cyanide.services.analytics import AnalyticsService
from cyanide.services.quarantine import QuarantineService


@pytest.fixture
def temp_log_dir(tmp_path):
    log_dir = tmp_path / "var/log/cyanide"
    log_dir.mkdir(parents=True)
    return log_dir


@pytest.fixture
def mock_logger(temp_log_dir):
    # Use real logger for integration testing to verify file writes
    logger = CyanideLogger(str(temp_log_dir))
    return logger


@pytest.fixture
def analytics_svc(mock_logger):
    config = {
        "ml": {
            "enabled": True,
            "ml_log": str(Path(mock_logger.log_dir) / "cyanide-ml.json"),
            "model_path": "assets/models/cyanideML.pkl",
        }
    }
    svc = AnalyticsService(config, mock_logger)
    return svc


def test_ml_logging_path_creation(analytics_svc):
    # Verify that the log directory exists
    assert analytics_svc.ml_log_path.parent.exists()


def test_ml_command_logging(analytics_svc):
    # Mock pipeline analyze_command
    analytics_svc.ml_pipeline = MagicMock()
    analytics_svc.ml_pipeline.analyze_command.return_value = {
        "is_anomaly": True,
        "anomaly_score": 0.8,
        "reconstruction_error": 0.05,
        "classification": {"technique": "T1003"},
        "severity": "HIGH",
    }

    analytics_svc.analyze_command("ls -la", "root", "1.1.1.1", "sess1", "ssh")

    # Check if log file contains the entry
    # Note: AnalyticsService now uses self.logger which writes to cyanide-ml.json
    log_path = Path(analytics_svc.logger.log_dir) / "cyanide-ml.json"
    assert log_path.exists()

    with open(log_path, "r") as f:
        line = f.readline()
        data = json.loads(line)
        # Standardized structure: fields are flattened
        assert data["eventid"] == "ml_thought"
        assert data["command"] == "ls -la"
        assert data["verdict"] == "anomaly"


def test_ml_file_analysis_logging(analytics_svc):
    # Mock pipeline analyze_command
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
    with open(log_path, "r") as f:
        lines = f.readlines()
        # Find the ml_file_anomaly event
        data = json.loads(lines[-1])
        assert data["eventid"] == "ml_file_anomaly"
        assert data["filename"] == "malware.sh"
        assert data["score"] == 0.9

        # Check the thought event (second to last)
        thought_data = json.loads(lines[-2])
        assert thought_data["eventid"] == "ml_thought"
        assert thought_data["file"] == "malware.sh"
        assert thought_data["verdict"] == "anomaly"


async def test_quarantine_triggers_ml(mock_logger, analytics_svc):
    config = {
        "quarantine_path": str(Path(mock_logger.log_dir).parent / "quarantine"),
        "quarantine_max_size_mb": 10,
    }
    q_svc = QuarantineService(config, mock_logger)
    # Inject analytics service manually for the test
    q_svc.analytics_svc = analytics_svc

    await q_svc.save_file("test_file.txt", b"some content", "sess3", "3.3.3.3")

    # Check if ML was called
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
