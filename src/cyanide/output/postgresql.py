import json
import logging
from typing import Any, Dict

import psycopg

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    PostgreSQL Output Plugin.
    Requires psycopg.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "127.0.0.1")
        self.port = config.get("port", 5432)
        self.user = config.get("user", "cyanide")
        self.password = config.get("password", "")
        self.database = config.get("database", "cyanide")
        self.table = config.get("table", "events")
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            conn_str = f"host={self.host} port={self.port} dbname={self.database} user={self.user} password={self.password}"
            self.conn = psycopg.connect(conn_str)
            with self.conn.cursor() as cursor:
                cursor.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self.table} (
                        id SERIAL PRIMARY KEY,
                        timestamp VARCHAR(255),
                        session VARCHAR(255),
                        eventid VARCHAR(255),
                        data JSONB
                    )
                """)
            self.conn.commit()
        except Exception as e:
            logging.error(f"[PostgreSQL] Connection failed: {e}")
            self.conn = None

    def write(self, event: Dict[str, Any]):
        if not self.conn or self.conn.closed:
            self._connect()
            if not self.conn:
                return

        timestamp = event.get("timestamp")
        session = event.get("session")
        eventid = event.get("eventid")
        data = {k: v for k, v in event.items() if k not in ["timestamp", "session", "eventid"]}

        try:
            with self.conn.cursor() as cursor:
                query = f"INSERT INTO {self.table} (timestamp, session, eventid, data) VALUES (%s, %s, %s, %s)"
                cursor.execute(query, (timestamp, session, eventid, json.dumps(data)))
            self.conn.commit()
        except Exception as e:
            logging.error(f"[PostgreSQL] Write failure: {e}")
            self.conn = None
