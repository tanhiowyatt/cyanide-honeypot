import datetime
import json
import logging
from pathlib import Path


class CyanideLogger:
    # Function 100: Initializes the class instance and its attributes.
    def __init__(self, log_dir, output_config=None, logging_config=None):
        self.log_dir = Path(log_dir)
        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True, exist_ok=True)

        self.output_config = output_config or {}
        self.logging_config = logging_config or {
            "logtype": "plain",
            "rotation": {
                "strategy": "time",
                "when": "midnight",
                "interval": 1,
                "backup_count": 14,
                "max_bytes": 10485760,
            },
        }
        self.plugins = self._load_plugins()

        self.server_log = self._setup_logger("cyanide_server", self.log_dir / "cyanide-server.json")

        self.fs_log = self._setup_logger("cyanide_fs", self.log_dir / "cyanide-fs.json")

        self.ml_log = self._setup_logger("cyanide_ml", self.log_dir / "cyanide-ml.json")

        self.stats_log = self._setup_logger("cyanide_stats", self.log_dir / "cyanide-stats.json")

    def _load_plugins(self):
        plugins = []
        import importlib

        VALID_PLUGINS = {
            "dshield",
            "elasticsearch",
            "graylog",
            "hpfeeds",
            "mongodb",
            "mysql",
            "postgresql",
            "rethinkdb",
            "slack",
            "splunk_hec",
            "sqlite",
            "syslog",
            "mock_plugin",
            "failer",
        }

        for plugin_name, plugin_cfg in self.output_config.items():
            if not isinstance(plugin_cfg, dict) or not plugin_cfg.get("enabled", False):
                continue

            if plugin_name not in VALID_PLUGINS:
                logging.warning(f"Prevented loading of untrusted output plugin: {plugin_name}")
                continue

            try:
                module = importlib.import_module(f"cyanide.output.{plugin_name}")
                plugin_class = getattr(module, "Plugin")
                plugin_instance = plugin_class(plugin_cfg)
                plugin_instance.start()
                plugins.append(plugin_instance)
                logging.info(f"Loaded output plugin: {plugin_name}")
            except ImportError as e:
                logging.error(
                    f"Failed to load output plugin {plugin_name}: {e}. Try installing extras with pip install .[outputs]"
                )
            except Exception as e:
                logging.error(f"Failed to load output plugin {plugin_name}: {e}")

        return plugins

    # Function 101: Sets up initial configuration and state.
    def _setup_logger(self, name, path):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)

        if logger.handlers:
            for existing_handler in logger.handlers[:]:
                logger.removeHandler(existing_handler)

        logtype = self.logging_config.get("logtype", "plain")
        rotation = self.logging_config.get("rotation", {})

        handler: logging.Handler
        if logtype == "rotating":
            strategy = rotation.get("strategy", "time")
            backup_count = rotation.get("backup_count", 14)

            if strategy == "time":
                from logging.handlers import TimedRotatingFileHandler

                when = rotation.get("when", "midnight")
                interval = rotation.get("interval", 1)
                handler = TimedRotatingFileHandler(
                    path, when=when, interval=interval, backupCount=backup_count
                )
            elif strategy == "size":
                from logging.handlers import RotatingFileHandler

                max_bytes = rotation.get("max_bytes", 10485760)
                handler = RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count)
            else:
                handler = logging.FileHandler(path)
        else:
            handler = logging.FileHandler(path)

        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    # Function 102: Handles event logging and telemetry.
    def _get_target_logger(self, event_type):
        """Routes event target logger based on event_type."""
        if event_type in [
            "command.input",
            "auth",
            "file.quarantine",
            "tty.input",
            "client_fingerprint",
            "client_geo",
            "rsync_exec_detected",
            "rsync_handshake",
            "rsync_filelist",
            "rsync_denied",
            "rsync_error",
            "scp_op",
            "sftp_op",
        ]:
            return self.fs_log
        if event_type.startswith("ml_") or event_type == "ml_thought":
            return self.ml_log
        if event_type == "stats":
            return self.stats_log
        return self.server_log

    # Function 103: Handles event logging and telemetry.
    def log_event(self, session_id, event_type, data):
        """Log a generic event in structured JSON, routed to proper file."""
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "session": session_id,
            "eventid": event_type,
        }
        if isinstance(data, dict):
            entry.update(data)
        else:
            entry["data"] = data

        logger = self._get_target_logger(event_type)
        logger.info(json.dumps(entry))

        for plugin in self.plugins:
            plugin.emit(entry.copy())
