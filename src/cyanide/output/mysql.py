import json
import logging
from typing import Any, Dict

import mysql.connector

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    MySQL Output Plugin.
    Requires mysql-connector-python.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "127.0.0.1")
        self.port = config.get("port", 3306)
        self.user = config.get("user", "cyanide")
        self.password = config.get("password", "")
        self.database = config.get("database", "cyanide")
        self.table = config.get("table", "events")
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            self.conn = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
            )
            cursor = self.conn.cursor()
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp VARCHAR(255),
                    session VARCHAR(255),
                    eventid VARCHAR(255),
                    data JSON
                )
            """)
            self.conn.commit()
            cursor.close()
        except Exception as e:
            logging.error(f"[MySQL] Connection failed: {e}")
            self.conn = None

    def write(self, event: Dict[str, Any]):
        if not self.conn or not self.conn.is_connected():
            self._connect()
            if not self.conn:
                return

        timestamp = event.get("timestamp")
        session = event.get("session")
        eventid = event.get("eventid")
        data = {k: v for k, v in event.items() if k not in ["timestamp", "session", "eventid"]}

        try:
            cursor = self.conn.cursor()
            query = f"INSERT INTO {self.table} (timestamp, session, eventid, data) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (timestamp, session, eventid, json.dumps(data)))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            logging.error(f"[MySQL] Write failure: {e}")
            self.conn = None  # Force reconnect next time
