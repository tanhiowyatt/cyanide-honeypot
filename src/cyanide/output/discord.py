import json
import logging
from typing import Any, Dict

import requests

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    Discord Webhook Output Plugin.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url", "")
        self.username = config.get("username", "Cyanide Honeypot")

    def write(self, event: Dict[str, Any]):
        if not self.webhook_url:
            return

        session = event.get("session", "unknown")
        eventid = event.get("eventid", "unknown")
        data = {k: v for k, v in event.items() if k not in ["timestamp", "session", "eventid"]}

        content = (
            f"**{self.username} Event**: `{eventid}`\n"
            f"**Session**: `{session}`\n"
            f"**Details**: ```json\n{json.dumps(data, indent=2)}\n```"
        )

        payload = {
            "username": self.username,
            "content": content,
        }

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=5)
            if resp.status_code not in [200, 204]:
                logging.error(f"[Discord] Write error: status={resp.status_code} text={resp.text}")
        except Exception as e:
            logging.error(f"[Discord] Delivery failure: {e}")
