import datetime
import json
import logging
import os


class CyanideLogger:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # 1. Server Log - System events, errors, lifecycle
        self.server_log = self._setup_logger(
            "cyanide_server", os.path.join(log_dir, "cyanide-server.json")
        )

        # 2. FS Log - Hacker activity: commands, auth, file uploads, TTY
        self.fs_log = self._setup_logger("cyanide_fs", os.path.join(log_dir, "cyanide-fs.json"))

        # 3. ML Log - Detailed ML verdicts and thoughts
        self.ml_log = self._setup_logger("cyanide_ml", os.path.join(log_dir, "cyanide-ml.json"))

        # 4. Stats Log - Periodic snapshots
        self.stats_log = self._setup_logger(
            "cyanide_stats", os.path.join(log_dir, "cyanide-stats.json")
        )

    def _setup_logger(self, name, path):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)

        # In case this logger already has handlers (e.g. from previous tests),
        # we check if they point to the same file. To keep it simple and robust,
        # we'll just clear existing handlers and add the new one.
        if logger.handlers:
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)

        handler = logging.FileHandler(path)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _get_target_logger(self, event_type):
        """Routes event target logger based on event_type."""
        # Hacker activity (FS/Interactive)
        if event_type in [
            "command.input",
            "auth",
            "file.quarantine",
            "tty.input",
            "client_fingerprint",
            "client_geo",
        ]:
            return self.fs_log
        # ML Logic
        if event_type.startswith("ml_") or event_type == "ml_thought":
            return self.ml_log
        # Statistics
        if event_type == "stats":
            return self.stats_log
        # Default: Server system log
        return self.server_log

    def log_event(self, session_id, event_type, data):
        """Log a generic event in structured JSON, routed to proper file."""
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "session": session_id,
            "eventid": event_type,
        }
        if isinstance(data, dict):
            entry.update(data)
        else:
            entry["data"] = data

        logger = self._get_target_logger(event_type)
        logger.info(json.dumps(entry))

    async def log_command(
        self, session_id, protocol, src_ip, username, command, client_version="unknown"
    ):
        """Log a command execution event (compatibility wrapper)."""
        event_type = "command.input"
        entry = {
            "eventid": event_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "session": session_id,
            "src_ip": src_ip,
            "username": username,
            "protocol": protocol,
            "input": command,
            "client_version": client_version,
        }
        self.fs_log.info(json.dumps(entry))

    async def log_event_async(self, data_dict):
        """Async wrapper for log_event to match CyanideServer expectations."""
        # Make a copy to avoid mutating the original
        data = data_dict.copy()
        event_type = data.pop("event", "unknown")
        session_id = data.pop("session_id", "unknown")
        src_ip = data.pop("src_ip", "unknown")

        # Merge basic fields
        entry = {
            "eventid": event_type,
            "timestamp": datetime.datetime.now().isoformat(),
            "session": session_id,
            "src_ip": src_ip,
        }
        # Merge rest of data
        entry.update(data)

        logger = self._get_target_logger(event_type)
        logger.info(json.dumps(entry))
