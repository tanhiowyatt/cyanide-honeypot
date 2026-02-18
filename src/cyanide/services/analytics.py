import datetime
import json
from typing import Dict

# Import dependencies (handle circular imports carefully if needed)
# Here we assume these are available
from cyanide.core.geoip import GeoIP
from cyanide.core.stats import StatsManager


class AnalyticsService:
    """
    Handles ML analysis, GeoIP enrichment, and statistics.
    """

    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.stats = StatsManager()
        self.geoip = GeoIP()

        # ML Initialization
        self.ml_enabled = config.get("ml", {}).get("enabled", False)
        self.ml_online_learning = config.get("ml", {}).get("online_learning", False)
        self.ml_filter = None
        self.kb = None

        if self.ml_enabled:
            self._init_ml()

    def _init_ml(self):
        try:
            from pathlib import Path

            from cyanide.ml import CyanideML

            config_path = self.config.get("ml", {}).get(
                "model_path", "src/cyanide.ml/cyanideML.pkl"
            )
            model_path = Path(config_path).parent

            if (model_path / "cyanideML.pkl").exists():
                self.logger.log_event(
                    "system",
                    "system_status",
                    {"message": f"Loading CyanideML pipeline from {model_path}..."},
                )
                self.ml_pipeline = CyanideML(str(model_path))
                # Backward compatibility for server.py checks
                self.ml_filter = self.ml_pipeline
            else:
                self.logger.log_event(
                    "system",
                    "system_warning",
                    {"message": "ML models not found. Analysis will be skipped."},
                )
                self.ml_enabled = False
                return

            self.ml_log_path = self.config.get("ml", {}).get(
                "ml_log", "var/log/cyanide/cyanideML-log.json"
            )

        except (ImportError, ModuleNotFoundError) as e:
            self.logger.log_event(
                "system", "error", {"message": f"ML Module could not be loaded: {e}"}
            )
            self.ml_enabled = False
        except Exception as e:
            self.logger.log_event("system", "error", {"message": f"Failed to init ML model: {e}"})
            self.ml_enabled = False

    def analyze_command(self, cmd: str, username: str, src_ip: str, session_id: str, protocol: str):
        """Run command through ML pipeline and alert if anomaly."""
        if not self.ml_enabled or not getattr(self, "ml_pipeline", None):
            return

        try:
            # Analyze command
            result = self.ml_pipeline.analyze_command(cmd)

            is_anomaly = result["is_anomaly"]

            # Log ML 'thought'
            ml_log_entry = {
                "timestamp": datetime.datetime.now().isoformat(),
                "src_ip": src_ip,
                "session_id": session_id,
                "verdict": "anomaly" if is_anomaly else "clean",
                "score": result["anomaly_score"],
                "error": result["reconstruction_error"],
                "command": cmd,
                "classification": result.get("classification"),
                "severity": result.get("severity"),
            }

            with open(self.ml_log_path, "a") as f:
                f.write(json.dumps(ml_log_entry) + "\n")

            if is_anomaly:
                self.logger.log_event(
                    session_id,
                    "ml_anomaly",
                    {
                        "score": result["anomaly_score"],
                        "error": result["reconstruction_error"],
                        "cmd": cmd,
                        "classification": result.get("classification"),
                        "severity": result.get("severity"),
                    },
                )

        except Exception as e:
            self.logger.log_event(session_id, "error", {"message": f"ML Error: {e}"})

    async def log_geoip(self, session_id: str, ip: str, protocol: str):
        """Async GeoIP enrichment logging."""
        geo_data = await self.geoip.lookup(ip)
        if geo_data:
            await self.logger.log_event_async(
                {
                    "event": "client_geo",
                    "session_id": session_id,
                    "protocol": protocol,
                    "src_ip": ip,
                    "geo": geo_data,
                }
            )
