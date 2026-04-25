import json
import logging
from typing import Any, Dict

import requests

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    Telegram Bot Output Plugin.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.token = config.get("token", "")
        self.chat_id = config.get("chat_id", "")

    def write(self, event: Dict[str, Any]):
        if not self.token or not self.chat_id:
            return

        session = event.get("session", "unknown")
        eventid = event.get("eventid", "unknown")
        data = {k: v for k, v in event.items() if k not in ["timestamp", "session", "eventid"]}

        text = (
            f"<b>Cyanide Event</b>: <code>{eventid}</code>\n"
            f"<b>Session</b>: <code>{session}</code>\n"
            f"<b>Details</b>:\n<pre>{json.dumps(data, indent=2)}</pre>"
        )

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
        }

        try:
            resp = requests.post(url, json=payload, timeout=5)
            if resp.status_code != 200:
                logging.error(f"[Telegram] Write error: status={resp.status_code} text={resp.text}")
        except Exception as e:
            logging.error(f"[Telegram] Delivery failure: {e}")
