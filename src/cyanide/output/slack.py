import json
import logging
from typing import Any, Dict

import requests

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    Slack Webhook Output Plugin.
    Requires requests.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url", "")
        self.username = config.get("username", "Cyanide Honeypot")
        self.icon_emoji = config.get("icon_emoji", ":skull_and_crossbones:")

    def write(self, event: Dict[str, Any]):
        if not self.webhook_url:
            return

        session = event.get("session", "unknown")
        eventid = event.get("eventid", "unknown")
        data = {k: v for k, v in event.items() if k not in ["timestamp", "session", "eventid"]}

        text = f"*{self.username} Event*: `{eventid}`\n*Session*: `{session}`\n*Details*: ```{json.dumps(data, indent=2)}```"

        payload = {"username": self.username, "icon_emoji": self.icon_emoji, "text": text}

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=5)
            if resp.status_code != 200:
                logging.error(f"[Slack] Write error: status={resp.status_code} text={resp.text}")
        except Exception as e:
            logging.error(f"[Slack] Delivery failure: {e}")
