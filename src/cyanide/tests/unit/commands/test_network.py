from unittest.mock import ANY

import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.curl import CurlCommand


# Function 385: Performs operations related to shell.
@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


# Function 386: Performs operations related to mock response.
@pytest.fixture
def mock_response(mocker):
    """Mock aiohttp response."""
    response = mocker.AsyncMock()
    response.status = 200
    response.reason = "OK"
    response.read.return_value = b"<html>content</html>"
    response.headers = {"Content-Type": "text/html"}
    response.version.major = 1
    response.version.minor = 1
    return response


# Function 387: Performs operations related to mock session.
@pytest.fixture
def mock_session(mocker, mock_response):
    """Mock aiohttp session."""
    session_cls = mocker.patch("aiohttp.ClientSession")
    session = (
        mocker.MagicMock()
    )  # Use MagicMock to avoid auto-coroutine return for methods we mock manually
    session_cls.return_value.__aenter__.return_value = session

    # Mock get - returns context manager immediately, not awaitable
    get_ctx = mocker.AsyncMock()
    get_ctx.__aenter__.return_value = mock_response
    session.get = mocker.MagicMock(return_value=get_ctx)

    # Mock head
    head_ctx = mocker.AsyncMock()
    head_ctx.__aenter__.return_value = mock_response
    session.head = mocker.MagicMock(return_value=head_ctx)

    return session


# Function 388: Runs unit tests for the curl_stdout functionality.
@pytest.mark.asyncio
async def test_curl_stdout(shell, mock_session, mock_response, mocker):
    mocker.patch("socket.getaddrinfo", return_value=[(0, 0, 0, "", ("93.184.216.34", 80))])
    cmd = CurlCommand(shell)

    stdout, stderr, rc = await cmd.execute(["http://example.com"])
    assert rc == 0
    assert "<html>content</html>" in stdout

    # Verify call uses IP and Host header
    mock_session.get.assert_called_with("http://example.com", headers={}, timeout=ANY)


# Function 389: Runs unit tests for the curl_output_file functionality.
@pytest.mark.asyncio
async def test_curl_output_file(shell, mock_fs, mock_session, mocker):
    mocker.patch("socket.getaddrinfo", return_value=[(0, 0, 0, "", ("93.184.216.34", 80))])
    cmd = CurlCommand(shell)

    stdout, stderr, rc = await cmd.execute(["-o", "out.html", "http://example.com"])
    assert rc == 0
    assert mock_fs.exists("/root/out.html")
    assert mock_fs.get_content("/root/out.html") == "<html>content</html>"


# Function 390: Runs unit tests for the curl_fail functionality.
@pytest.mark.asyncio
async def test_curl_fail(shell, mock_session, mock_response):
    cmd = CurlCommand(shell)

    # 404
    mock_response.status = 404

    stdout, stderr, rc = await cmd.execute(["http://example.com/missing"])
    assert rc == 22
    assert "returned error: 404" in stderr


# Function 391: Runs unit tests for the curl_head functionality.
@pytest.mark.asyncio
async def test_curl_head(shell, mock_session, mock_response, mocker):
    mocker.patch("socket.getaddrinfo", return_value=[(0, 0, 0, "", ("93.184.216.34", 80))])
    cmd = CurlCommand(shell)

    stdout, stderr, rc = await cmd.execute(["-I", "http://example.com"])
    assert rc == 0
    assert "HTTP/1.1 200 OK" in stdout
    assert "Content-Type: text/html" in stdout

    mock_session.head.assert_called_with("http://example.com", headers={}, timeout=ANY)
