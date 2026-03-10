import json
import logging
from typing import Any, Dict

import hpfeeds

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    HPFeeds Output Plugin.
    Requires hpfeeds.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "hpfeeds.honeycloud.net")
        self.port = config.get("port", 10000)
        self.ident = config.get("ident")
        self.secret = config.get("secret")
        self.channel = config.get("channel", "cyanide.events")
        self.client = None
        self._connect()

    def _connect(self):
        try:
            if not self.ident or not self.secret:
                logging.error("[HPFeeds] ident and secret are required")
                return

            self.client = hpfeeds.new(self.host, self.port, self.ident, self.secret)
        except Exception as e:
            logging.error(f"[HPFeeds] Connection failed: {e}")
            self.client = None

    def write(self, event: Dict[str, Any]):
        if not self.client:
            self._connect()
            if not self.client:
                return

        try:
            payload = json.dumps(event).encode("utf-8")
            self.client.publish(self.channel, payload)
        except Exception as e:
            logging.error(f"[HPFeeds] Write failure: {e}")
            self.client = None
