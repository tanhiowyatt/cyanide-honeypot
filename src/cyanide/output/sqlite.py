import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    SQLite Output Plugin for local lightweight metrics.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.db_path = config.get("path", "var/log/cyanide/events.sqlite")
        self.table = config.get("table", "events")
        self.conn = None
        self._init_db()

    def _init_db(self):
        try:
            path = Path(self.db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    session TEXT,
                    eventid TEXT,
                    data JSON
                )
            """)
            self.conn.commit()
        except Exception as e:
            logging.error(f"[SQLite] Failed to initialize database: {e}")

    def write(self, event: Dict[str, Any]):
        if not self.conn:
            return

        timestamp = event.get("timestamp")
        session = event.get("session")
        eventid = event.get("eventid")

        data = {k: v for k, v in event.items() if k not in ["timestamp", "session", "eventid"]}

        try:
            cursor = self.conn.cursor()
            cursor.execute(
                f"INSERT INTO {self.table} (timestamp, session, eventid, data) VALUES (?, ?, ?, ?)",
                (timestamp, session, eventid, json.dumps(data)),
            )
            self.conn.commit()
        except Exception as e:
            logging.error(f"[SQLite] Failed to write event: {e}")
