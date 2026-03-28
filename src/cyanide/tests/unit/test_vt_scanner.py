from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyanide.core.vt_scanner import VTScanner


@pytest.fixture
def scanner():
    return VTScanner(api_key="test_key")


@pytest.mark.asyncio
async def test_scan_clean_file(scanner):

    # Mock aiohttp.ClientSession.get
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(
        return_value={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                    "popular_threat_classification": {"suggested_threat_label": "clean"},
                }
            }
        }
    )
    mock_resp.__aenter__.return_value = mock_resp

    mock_session = MagicMock()
    mock_session.get.return_value = mock_resp
    mock_session.__aenter__.return_value = mock_session

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await scanner.scan(b"", "test.txt")
        assert result["malicious"] == 0
        assert result["label"] == "clean"


@pytest.mark.asyncio
async def test_scan_malicious_file(scanner):

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(
        return_value={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 10, "suspicious": 2},
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.win32.generic"
                    },
                }
            }
        }
    )
    mock_resp.__aenter__.return_value = mock_resp

    mock_session = MagicMock()
    mock_session.get.return_value = mock_resp
    mock_session.__aenter__.return_value = mock_session

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await scanner.scan(b"", "test.txt")
        assert result["malicious"] == 10
        assert result["label"] == "trojan.win32.generic"


@pytest.mark.asyncio
async def test_scan_upload_flow(scanner):

    # Mock GET 404
    mock_get_resp = MagicMock()
    mock_get_resp.status = 404
    mock_get_resp.__aenter__.return_value = mock_get_resp

    # Mock POST 200
    mock_post_resp = MagicMock()
    mock_post_resp.status = 200
    mock_post_resp.json = AsyncMock(return_value={"data": {"id": "analysis_id_123"}})
    mock_post_resp.__aenter__.return_value = mock_post_resp

    mock_session = MagicMock()
    mock_session.get.return_value = mock_get_resp
    mock_session.post.return_value = mock_post_resp
    mock_session.__aenter__.return_value = mock_session

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await scanner.scan(b"", "test.txt")
        assert result["status"] == "uploaded_queued"
        assert result["analysis_id"] == "analysis_id_123"
