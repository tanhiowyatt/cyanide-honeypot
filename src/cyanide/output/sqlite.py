import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    SQLite Output Plugin for local lightweight metrics.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.db_path = config.get("path", "var/log/cyanide/events.sqlite")
        self.table = config.get("table", "events")

        import re

        if not re.match(r"^\w+$", self.table):
            raise ValueError(f"Invalid table name (must be alphanumeric/underscore): {self.table}")

        self.conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        try:
            path = Path(self.db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            # nosemgrep: python.lang.security.audit.formatted-sql-query.formatted-sql-query, python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
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
            # nosemgrep: python.lang.security.audit.formatted-sql-query.formatted-sql-query, python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
            cursor.execute(
                f"INSERT INTO {self.table} (timestamp, session, eventid, data) VALUES (?, ?, ?, ?)",
                (timestamp, session, eventid, json.dumps(data)),
            )
            self.conn.commit()
        except Exception as e:
            logging.error(f"[SQLite] Failed to write event: {e}")

    def close(self):
        if self.conn:
            self.conn.close()
            logging.info("[SQLite] Database connection closed.")
            self.conn = None
