import json
import logging
import os
import datetime

class CyanideLogger:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        self.cyanide_log = self._setup_logger("cyanide", os.path.join(log_dir, "cyanide.json"))
        # self.auth_log = self._setup_logger("auth", os.path.join(log_dir, "auth.json"))

    def _setup_logger(self, name, path):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        # Avoid duplicate handlers
        if not logger.handlers:
            handler = logging.FileHandler(path)
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def log_event(self, session_id, event_type, data):
        """Log a generic event in structured JSON."""
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "session": session_id,
            "eventid": event_type,
            "data": data
        }
        self.cyanide_log.info(json.dumps(entry))

    async def log_command(self, session_id, protocol, src_ip, username, command, client_version="unknown"):
        """Log a command execution event (compatibility wrapper)."""
        data = {
            "protocol": protocol,
            "src_ip": src_ip,
            "username": username,
            "input": command,
            "client_version": client_version
        }
        self.log_event(session_id, "command.input", data)
        
    async def log_event_async(self, data_dict):
        """Async wrapper for log_event to match HoneypotServer expectations."""
        # HoneypotServer passes a dict with 'event' key, we map it to our structure
        event_type = data_dict.pop("event", "unknown")
        session_id = data_dict.pop("session_id", "unknown")
        self.log_event(session_id, event_type, data_dict)

