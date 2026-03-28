import json
import logging
import logging.handlers
from typing import Any, Dict

from .base import OutputPlugin


class Plugin(OutputPlugin):
    """
    Syslog Output Plugin for UNIX sockets and network Syslog forwarding.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.address = config.get("address", "/dev/log")
        self.facility = config.get("facility", "user")

        facility_map = {
            "auth": logging.handlers.SysLogHandler.LOG_AUTH,
            "cron": logging.handlers.SysLogHandler.LOG_CRON,
            "daemon": logging.handlers.SysLogHandler.LOG_DAEMON,
            "local0": logging.handlers.SysLogHandler.LOG_LOCAL0,
            "local1": logging.handlers.SysLogHandler.LOG_LOCAL1,
            "local2": logging.handlers.SysLogHandler.LOG_LOCAL2,
            "local3": logging.handlers.SysLogHandler.LOG_LOCAL3,
            "local4": logging.handlers.SysLogHandler.LOG_LOCAL4,
            "local5": logging.handlers.SysLogHandler.LOG_LOCAL5,
            "local6": logging.handlers.SysLogHandler.LOG_LOCAL6,
            "local7": logging.handlers.SysLogHandler.LOG_LOCAL7,
            "user": logging.handlers.SysLogHandler.LOG_USER,
        }
        fac = facility_map.get(self.facility.lower(), logging.handlers.SysLogHandler.LOG_USER)

        self.logger = logging.getLogger("cyanide_syslog_plugin")
        self.logger.setLevel(logging.INFO)

        if self.logger.handlers:
            self.logger.handlers.clear()

        try:
            if isinstance(self.address, str):
                handler = logging.handlers.SysLogHandler(address=self.address, facility=fac)
            elif isinstance(self.address, (list, tuple)) and len(self.address) == 2:
                handler = logging.handlers.SysLogHandler(
                    address=(self.address[0], int(self.address[1])), facility=fac
                )
            else:
                handler = logging.handlers.SysLogHandler(address="/dev/log", facility=fac)

            formatter = logging.Formatter("Cyanide: %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        except Exception as e:
            logging.error(f"[Syslog] Initialization failure: {e}")

    def write(self, event: Dict[str, Any]):
        try:
            payload = json.dumps(event)
            self.logger.info(payload)
        except Exception as e:
            logging.error(f"[Syslog] Write failure: {e}")
