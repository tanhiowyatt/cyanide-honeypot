import logging
from typing import Any, Dict

from rethinkdb import r

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    RethinkDB Output Plugin.
    Requires rethinkdb.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "127.0.0.1")
        self.port = config.get("port", 28015)
        self.database = config.get("database", "cyanide")
        self.table = config.get("table", "events")
        self.user = config.get("user", "admin")
        self.password = config.get("password", "")
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            self.conn = r.connect(
                host=self.host,
                port=self.port,
                db=self.database,
                user=self.user,
                password=self.password,
            )

            # Check database and table existence
            if self.database not in r.db_list().run(self.conn):
                r.db_create(self.database).run(self.conn)
            if self.table not in r.db(self.database).table_list().run(self.conn):
                r.db(self.database).table_create(self.table).run(self.conn)

        except Exception as e:
            logging.error(f"[RethinkDB] Connection failed: {e}")
            self.conn = None

    def write(self, event: Dict[str, Any]):
        if not self.conn or not self.conn.is_open():
            self._connect()
            if not self.conn:
                return

        try:
            r.table(self.table).insert(event).run(self.conn)
        except Exception as e:
            logging.error(f"[RethinkDB] Write failure: {e}")
            self.conn = None
