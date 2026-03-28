from typing import Any, Dict
from unittest.mock import patch

from cyanide.output.slack import Plugin


def test_slack_init():
    config: Dict[str, Any] = {"webhook_url": "http://webhook.com", "username": "TestBot"}
    plugin = Plugin(config)
    assert plugin.webhook_url == "http://webhook.com"
    assert plugin.username == "TestBot"


@patch("requests.post")
def test_slack_write_success(mock_post):
    config: Dict[str, Any] = {"webhook_url": "http://webhook.com"}
    plugin = Plugin(config)
    mock_post.return_value.status_code = 200

    event = {"session": "s1", "eventid": "e1", "data": "test"}
    plugin.write(event)
    mock_post.assert_called_once()


@patch("requests.post")
def test_slack_write_failure(mock_post):
    config: Dict[str, Any] = {"webhook_url": "http://webhook.com"}
    plugin = Plugin(config)
    mock_post.return_value.status_code = 500

    event = {"session": "s1", "eventid": "e1", "data": "test"}
    plugin.write(event)
    mock_post.assert_called_once()


@patch("requests.post", side_effect=Exception("network error"))
def test_slack_write_exception(mock_post):
    config: Dict[str, Any] = {"webhook_url": "http://webhook.com"}
    plugin = Plugin(config)

    event = {"session": "s1", "eventid": "e1", "data": "test"}
    plugin.write(event)
    mock_post.assert_called_once()


def test_slack_no_webhook():
    config: Dict[str, Any] = {}
    plugin = Plugin(config)
    # Should return early
    plugin.write({"test": "data"})
