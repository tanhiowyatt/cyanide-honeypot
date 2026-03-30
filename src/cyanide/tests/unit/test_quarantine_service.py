import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.services.quarantine import QuarantineService


@pytest.fixture
def mock_logger():
    logger = MagicMock()
    logger.services = MagicMock()
    logger.services.analytics = MagicMock()
    return logger


@pytest.fixture
def quarantine_dir(tmp_path):
    d = tmp_path / "quarantine"
    d.mkdir()
    return d


@pytest.fixture
def test_quarantine_setup(mock_logger, tmp_path):
    q_dir = tmp_path / "quarantine"
    q_dir.mkdir()
    config = {"quarantine_path": str(q_dir), "quarantine_max_size_mb": 10}
    service = QuarantineService(config, mock_logger)
    return service, q_dir


@pytest.fixture
def quarantine_service(quarantine_dir, mock_logger):
    config = {
        "quarantine_path": str(quarantine_dir),
        "quarantine_max_size_mb": 1,  # 1MB for testing
    }
    return QuarantineService(config, mock_logger)


@pytest.mark.asyncio
async def test_quarantine_save_file_success(quarantine_service, mock_logger):
    """Test standard file saving to quarantine."""
    filename = "test_malware.exe"
    content = b"malicious content"

    path = await quarantine_service.save_file(filename, content, "sess1", "1.1.1.1")

    assert path is not None
    assert Path(path).exists()
    assert Path(path).name.startswith(filename)
    assert open(path, "rb").read() == content

    # Verify analytics call
    mock_logger.services.analytics.analyze_file.assert_called_once()


@pytest.mark.asyncio
async def test_quarantine_quota_reached(quarantine_service, mock_logger, quarantine_dir):
    """Test that files are rejected when quota is reached."""
    # Create a large dummy file to fill quota (1MB = 1024*1024 bytes)
    dummy_file = quarantine_dir / "large_file"
    with open(dummy_file, "wb") as f:
        f.write(b"0" * (1024 * 1024))

    filename = "new_file.sh"
    content = b"echo 'too big'"

    path = await quarantine_service.save_file(filename, content, "sess_quota", "2.2.2.2")

    assert path is None
    # Verify warning log
    mock_logger.log_event.assert_any_call(
        "sess_quota",
        "quarantine_warning",
        {"message": "Quarantine Quota Reached (1MB). Rejecting new_file.sh"},
    )


@pytest.mark.asyncio
async def test_quarantine_vt_scanner_integration(quarantine_service, mock_logger):
    """Test VirusTotal scanner integration."""
    mock_scanner = MagicMock()
    mock_scanner.enabled = True
    mock_scanner.scan = AsyncMock(
        return_value={
            "sha256": "fake_hash",
            "malicious": True,
            "label": "Trojan.Generic",
            "link": "https://vt.com/test",
        }
    )

    quarantine_service.set_scanner(mock_scanner)

    filename = "virus.com"
    content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    await quarantine_service.save_file(filename, content, "sess_vt", "3.3.3.3")

    # Wait for background task
    await asyncio.gather(*quarantine_service._background_tasks)

    mock_scanner.scan.assert_called_once()
    mock_logger.log_event.assert_any_call(
        "sess_vt",
        "ml_malware_scan",
        {
            "src_ip": "3.3.3.3",
            "filename": filename,
            "sha256": "fake_hash",
            "malicious": True,
            "label": "Trojan.Generic",
            "vt_link": "https://vt.com/test",
        },
    )


@pytest.mark.asyncio
async def test_quarantine_save_file_exception(quarantine_service, mock_logger):
    """Test error handling when file write fails."""
    # Use patch to make aiofiles.open fail
    with patch("aiofiles.open", side_effect=Exception("Permission denied")):
        path = await quarantine_service.save_file("fail.txt", b"data", "sess_err")

        assert path is None
        mock_logger.log_event.assert_any_call(
            "sess_err", "error", {"message": "Error saving quarantine file: Permission denied"}
        )


@pytest.mark.asyncio
async def test_quarantine_scan_error_log(quarantine_service, mock_logger):
    """Test that scanner errors are logged."""
    mock_scanner = MagicMock()
    mock_scanner.enabled = True
    mock_scanner.scan = AsyncMock(side_effect=Exception("VT API Down"))

    quarantine_service.set_scanner(mock_scanner)

    # We call _scan_and_log directly for easier testing of the background logic
    await quarantine_service._scan_and_log("test.sh", b"data", "sess_scan_err", "4.4.4.4")

    # Corrected: restored missing session_id argument
    mock_logger.log_event.assert_any_call(
        "sess_scan_err",
        "ml_malware_scan_error",
        {"src_ip": "4.4.4.4", "message": "Scan Error: VT API Down"},
    )
