import logging
from typing import Any, Dict, List

import requests

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    SANS ISC DShield Output Plugin.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.userid = config.get("userid", "")
        self.authkey = config.get("authkey", "")
        self.batch_size = config.get("batch_size", 50)
        self.url = config.get("url", "https://isc.sans.edu/api/submit/file")
        self.buffer: List[str] = []

    def write(self, event: Dict[str, Any]):
        if not self.userid or not self.authkey:
            return

        if event.get("eventid") not in ["client_fingerprint", "auth"]:
            return

        data = event.get("data", {})
        srcip = data.get("client_ip", "0.0.0.0")
        srcport = data.get("client_port", "0")
        destip = event.get("server_ip", "0.0.0.0")
        destport = data.get("dst_port", 2222)

        line = f"{event.get('timestamp')}\t{srcip}\t{srcport}\t{destip}\t{destport}\tTCP\tACCEPT"
        self.buffer.append(line)

        if len(self.buffer) >= self.batch_size:
            self.flush()

    def flush(self):
        if not self.buffer:
            return

        payload = "\n".join(self.buffer)
        headers = {
            "Content-Type": "text/plain",
            "X-Dshield-AuthID": self.userid,
            "X-Dshield-AuthKey": self.authkey,
        }

        try:
            resp = requests.post(self.url, data=payload, headers=headers, timeout=10)
            if resp.status_code != 200:
                logging.error(f"[DShield] Submit error: {resp.text}")
        except Exception as e:
            logging.error(f"[DShield] Delivery failure: {e}")
        finally:
            self.buffer = []
