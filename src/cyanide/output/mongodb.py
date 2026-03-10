import logging
from typing import Any, Dict

import pymongo

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    MongoDB Output Plugin.
    Requires pymongo.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.uri = config.get("uri", "mongodb://127.0.0.1:27017/")
        self.database = config.get("database", "cyanide")
        self.collection = config.get("collection", "events")
        self.client = None
        self.db = None
        self._connect()

    def _connect(self):
        try:
            self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=5000)
            self.client.admin.command("ping")  # Test connection
            self.db = self.client[self.database]
        except Exception as e:
            logging.error(f"[MongoDB] Connection failed: {e}")
            self.client = None

    def write(self, event: Dict[str, Any]):
        if not self.client:
            self._connect()
            if not self.client:
                return

        try:
            self.db[self.collection].insert_one(event.copy())
        except Exception as e:
            logging.error(f"[MongoDB] Write failure: {e}")
            self.client = None
