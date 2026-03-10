import logging
from typing import Any, Dict

from elasticsearch import Elasticsearch

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    Elasticsearch Output Plugin.
    Requires elasticsearch.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.hosts = config.get("hosts", ["http://127.0.0.1:9200"])
        self.index = config.get("index", "cyanide-events")
        self.user = config.get("user", "")
        self.password = config.get("password", "")
        self.client = None
        self._connect()

    def _connect(self):
        try:
            if self.user and self.password:
                self.client = Elasticsearch(self.hosts, basic_auth=(self.user, self.password))
            else:
                self.client = Elasticsearch(self.hosts)
        except Exception as e:
            logging.error(f"[Elasticsearch] Connection failed: {e}")
            self.client = None

    def write(self, event: Dict[str, Any]):
        if not self.client:
            self._connect()
            if not self.client:
                return

        try:
            self.client.index(index=self.index, document=event)
        except Exception as e:
            logging.error(f"[Elasticsearch] Write failure: {e}")
