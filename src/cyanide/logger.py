import datetime
import json
import logging
from pathlib import Path
from typing import Any, Optional


class CyanideLogger:
    # Function 100: Initializes the class instance and its attributes.
    def __init__(self, config, async_logger=None):
        self.config = config or {}
        self.log_dir = Path(
            self.config.get("logging", {}).get("directory", "var/log/cyanide")
        ).resolve()
        try:
            if not self.log_dir.exists():
                self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            import sys

            print(f"WARNING: Could not create log directory {self.log_dir}: {e}", file=sys.stderr)

        self.output_config = self.config.get("output", {})
        self.logging_config = self.config.get("logging", {})
        self.async_logger = async_logger
        self.plugins = self._load_plugins()
        self.geoip_cache: dict[str, dict[str, Any]] = {}
        self.session_to_ip: dict[str, str] = {}

        # Log paths are now consistently derived from unified config or defaults
        self.server_log_path = (self.log_dir / "cyanide-server.json").resolve()
        self.server_log = self._setup_logger("cyanide_server", self.server_log_path)

        self.fs_log_path = (self.log_dir / "cyanide-fs.json").resolve()
        self.fs_log = self._setup_logger("cyanide_fs", self.fs_log_path)

        # ML log path from config if present, otherwise default
        ml_cfg = self.config.get("ml", {})
        ml_log_str = ml_cfg.get("ml_log", str(self.log_dir / "cyanide-ml.json"))
        self.ml_log_path = Path(ml_log_str).resolve()

        # Ensure directory exists and file is touchable
        try:
            self.ml_log_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.ml_log_path.exists():
                self.ml_log_path.touch()
        except Exception as e:
            import sys

            print(f"ERROR: Failed to prepare ML log at {self.ml_log_path}: {e}", file=sys.stderr)

        self.ml_log = self._setup_logger("cyanide_ml", self.ml_log_path)

        self.stats_log_path = (self.log_dir / "cyanide-stats.json").resolve()
        self.stats_log = self._setup_logger("cyanide_stats", self.stats_log_path)
        self.session_logs: dict[str, dict[str, Path]] = {}

    def register_session_log(
        self, session_id: str, jsonl_path: Path, ml_json_path: Path, src_ip: Optional[str] = None
    ):
        """Register a session's log paths for event mirroring."""
        self.session_logs[session_id] = {
            "jsonl": jsonl_path,
            "ml_json": ml_json_path,
        }
        if src_ip:
            self.session_to_ip[session_id] = src_ip

    def unregister_session_log(self, session_id: str):
        """Unregister a session's log paths."""
        if session_id in self.session_logs:
            del self.session_logs[session_id]

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
                # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
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
        try:
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
                    handler = RotatingFileHandler(
                        path, maxBytes=max_bytes, backupCount=backup_count
                    )
                else:
                    handler = logging.FileHandler(path)
            else:
                handler = logging.FileHandler(path)
        except OSError as e:
            import sys

            print(
                f"WARNING: Could not initialize file logger for {name} ({path}): {e}. Falling back to stdout.",
                file=sys.stderr,
            )
            handler = logging.StreamHandler(sys.stdout)

        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    # Function 102: Handles event logging and telemetry.
    def _get_target_logger_info(self, event_type):
        """Routes event target logger and its path based on event_type."""
        if event_type in [
            "command.input",
            "auth",
            "file.quarantine",
            "tty.input",
            "tty.out",
            "tty.in",
            "client_fingerprint",
            "client_geo",
            "ssh.connect",
            "ssh_negotiated",
            "session.start",
            "session.end",
            "rsync_exec_detected",
            "rsync_handshake",
            "rsync_filelist",
            "rsync_denied",
            "rsync_error",
            "scp_op",
            "sftp_op",
        ]:
            return self.fs_log, self.fs_log_path
        if event_type.startswith("ml_") or event_type == "ml_thought":
            return self.ml_log, self.ml_log_path
        if event_type == "stats":
            return self.stats_log, self.stats_log_path
        return self.server_log, self.server_log_path

    def _resolve_geoip(self, src_ip, caller_geoip):
        """Determine GeoIP info based on cache, local stubs, or provided data."""
        if src_ip and src_ip in self.geoip_cache:
            return self.geoip_cache[src_ip]

        # Handle local/private networks
        if src_ip and (
            src_ip in ("127.0.0.1", "localhost", "::1")
            or src_ip.startswith("192.168.")
            or src_ip.startswith("10.")
        ):
            return {
                "country": "Local Network",
                "city": "Internal",
                "isp": "Private IP Space",
                "org": "Internal",
            }
        return caller_geoip

    def _prepare_log_entry(self, session_id, event_type, data):
        """Constructs the log entry with strict field ordering."""
        # Baseline entry for non-dict data
        if not isinstance(data, dict):
            return {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "session": session_id,
                "eventid": event_type,
                "data": data,
            }

        # Dict data processing
        payload = data.copy()
        payload.pop("session", None)
        payload.pop("eventid", None)
        payload.pop("timestamp", None)

        # Resolve src_ip and sync with session cache
        src_ip = payload.pop("src_ip", None)
        if not src_ip and session_id in self.session_to_ip:
            src_ip = self.session_to_ip[session_id]
        if src_ip and session_id not in self.session_to_ip:
            self.session_to_ip[session_id] = src_ip

        # Resolve geoip
        caller_geoip = payload.pop("geoip", None)
        resolved_geoip = self._resolve_geoip(src_ip, caller_geoip)

        # Build entry with strict field order:
        # timestamp → session → eventid → src_ip → [payload] → geoip
        entry: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "session": session_id,
            "eventid": event_type,
        }
        if src_ip:
            entry["src_ip"] = src_ip

        entry.update(payload)

        if resolved_geoip:
            entry["geoip"] = resolved_geoip

        return entry

    def _mirror_to_session(self, session_id, event_type, line):
        """Mirror event to session-specific log files if registered."""
        if session_id not in self.session_logs:
            return

        paths = self.session_logs[session_id]
        try:
            # Audit Mirroring
            if self.async_logger:
                self.async_logger.log(paths["jsonl"], line)
            else:
                with open(paths["jsonl"], "a") as f:
                    f.write(line)

            # ML Mirroring
            if event_type.startswith("ml_") or event_type == "ml_thought":
                if self.async_logger:
                    self.async_logger.log(paths["ml_json"], line)
                else:
                    with open(paths["ml_json"], "a") as f:
                        f.write(line)
        except Exception as e:
            logging.error(f"Failed to mirror event to session log {session_id}: {e}")

    # Function 103: Handles event logging and telemetry.
    def _sanitize_log_entry(self, entry: Any) -> Any:
        """Deeply convert entry values to JSON-serializable types."""
        if isinstance(entry, dict):
            return {k: self._sanitize_log_entry(v) for k, v in entry.items()}
        if isinstance(entry, list):
            return [self._sanitize_log_entry(v) for v in entry]
        if isinstance(entry, Path):
            return str(entry)
        if hasattr(entry, "item"):  # Handles most numpy types (score, error)
            return entry.item()
        return entry

    def log_event(self, session_id, event_type, data):
        """Log a generic event in structured JSON, routed to proper file and mirrored."""
        entry = self._prepare_log_entry(session_id, event_type, data)
        entry = self._sanitize_log_entry(entry)
        logger, log_path = self._get_target_logger_info(event_type)

        try:
            line = json.dumps(entry) + "\n"
        except (TypeError, ValueError) as e:
            import sys

            print(
                f"ERROR: CyanideLogger failed to serialize event {event_type}: {e}", file=sys.stderr
            )
            return

        # Global logging
        if self.async_logger:
            self.async_logger.log(log_path, line)
        else:
            logger.info(line.strip())
            for h in logger.handlers:
                h.flush()

        # Session-specific mirroring
        self._mirror_to_session(session_id, event_type, line)

        # Output plugins
        for plugin in self.plugins:
            plugin.emit(entry.copy())
