from unittest.mock import patch

from cyanide.output.discord import Plugin as DiscordPlugin
from cyanide.output.telegram import Plugin as TelegramPlugin


@patch("requests.post")
def test_discord_write(mock_post):
    """Test Discord webhook output."""
    config = {"webhook_url": "http://discord.com", "username": "CyanideBot"}
    plugin = DiscordPlugin(config)
    mock_post.return_value.status_code = 204

    event = {"session": "s1", "eventid": "e1", "cmd": "ls -la"}
    plugin.write(event)

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "http://discord.com"
    assert "content" in kwargs["json"]
    assert "ls -la" in kwargs["json"]["content"]
    assert "CyanideBot" in kwargs["json"]["username"]


@patch("requests.post")
def test_telegram_write(mock_post):
    """Test Telegram Bot API output."""
    config = {"token": "12345:ABCDE", "chat_id": "98765"}
    plugin = TelegramPlugin(config)
    mock_post.return_value.status_code = 200

    event = {"session": "s-tg", "eventid": "e-tg", "cmd": "whoami"}
    plugin.write(event)

    mock_post.assert_called_once()
    url = mock_post.call_args[0][0]
    assert "api.telegram.org/bot12345:ABCDE/sendMessage" in url

    kwargs = mock_post.call_args[1]
    assert kwargs["json"]["chat_id"] == "98765"
    assert "whoami" in kwargs["json"]["text"]
    assert kwargs["json"]["parse_mode"] == "HTML"


def test_missing_config():
    """Test that plugins handle missing config gracefully."""
    d_plugin = DiscordPlugin({})
    t_plugin = TelegramPlugin({})

    # Should return early without calling requests
    with patch("requests.post") as mock_post:
        d_plugin.write({"data": "test"})
        t_plugin.write({"data": "test"})
        assert not mock_post.called
