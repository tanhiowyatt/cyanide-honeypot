import json
import logging
import socket
import zlib
from typing import Any, Dict

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    Graylog Extended Log Format (GELF) Output Plugin over UDP.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "127.0.0.1")
        self.port = config.get("port", 12201)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def write(self, event: Dict[str, Any]):
        gelf = {
            "version": "1.1",
            "host": event.get("session", "cyanide_sensor"),
            "short_message": event.get("eventid", "cyanide_event"),
            "timestamp": event.get("timestamp"),
            "level": 6,
        }

        for k, v in event.items():
            if k not in ["timestamp", "session", "eventid"]:
                if isinstance(v, (dict, list)):
                    gelf[f"_{k}"] = json.dumps(v)
                else:
                    gelf[f"_{k}"] = v

        payload = json.dumps(gelf).encode("utf-8")
        if len(payload) > 512:
            payload = zlib.compress(payload)

        try:
            self.sock.sendto(payload, (self.host, self.port))
        except Exception as e:
            logging.error(f"[Graylog] UDP delivery failure: {e}")
