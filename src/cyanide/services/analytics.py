from typing import Dict


# Import dependencies (handle circular imports carefully if needed)
# Here we assume these are available
class AnalyticsService:
    """
    Handles ML analysis, GeoIP enrichment, and statistics.
    """

    # Function 181: Initializes the class instance and its attributes.
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.logger.log_event(
            "system",
            "service_init",
            {"service": "AnalyticsService", "message": "Starting AnalyticsService"},
        )

        try:
            # Local imports to avoid circular dependencies
            from cyanide.core.geoip import GeoIP
            from cyanide.core.stats import StatsManager

            self.stats = StatsManager()
            self.geoip = GeoIP()
            self.logger.log_event(
                "system",
                "service_init_status",
                {"service": "AnalyticsService", "message": "Components initialized successfully"},
            )
        except Exception as e:
            self.logger.log_event(
                "system", "service_init_error", {"service": "AnalyticsService", "error": str(e)}
            )

        # ML Initialization
        self.ml_enabled = config.get("ml", {}).get("enabled", False)
        self.ml_online_learning = config.get("ml", {}).get("online_learning", False)
        self.ml_pipeline = None
        self.kb = None

        if self.ml_enabled:
            self._init_ml()

    # Function 182: Performs operations related to init ml.
    def _init_ml(self):
        try:
            from pathlib import Path

            from cyanide.ml import CyanideML

            config_path = self.config.get("ml", {}).get(
                "model_path", "src/cyanide/ml/cyanideML.pkl"
            )
            model_path = Path(config_path).parent

            if (model_path / "cyanideML.pkl").exists():
                self.logger.log_event(
                    "system",
                    "system_status",
                    {"message": f"Loading CyanideML pipeline from {model_path}..."},
                )
                self.ml_pipeline = CyanideML(str(model_path))
            else:
                self.logger.log_event(
                    "system",
                    "system_warning",
                    {"message": "ML models not found. Analysis will be skipped."},
                )
                self.ml_enabled = False
                return

            self.ml_log_path = Path(
                self.config.get("ml", {}).get("ml_log", "var/log/cyanide/ml.json")
            )

            # Ensure log directory exists
            self.ml_log_path.parent.mkdir(parents=True, exist_ok=True)

        except (ImportError, ModuleNotFoundError) as e:
            self.logger.log_event(
                "system", "error", {"message": f"ML Module could not be loaded: {e}"}
            )
            self.ml_enabled = False
        except Exception as e:
            self.logger.log_event("system", "error", {"message": f"Failed to init ML model: {e}"})
            self.ml_enabled = False

    # Function 183: Performs operations related to analyze command.
    def analyze_command(
        self,
        cmd: str,
        username: str,
        src_ip: str,
        session_id: str,
        protocol: str,
        is_bot: bool = False,
    ):
        """Run command through ML pipeline and alert if anomaly."""
        if not self.ml_enabled or self.ml_pipeline is None:
            return

        try:
            # Analyze command
            result = self.ml_pipeline.analyze_command(cmd)

            is_anomaly = result["is_anomaly"]
            source_type = "bot" if is_bot else "human"

            # Log ML 'thought' via centralized logger
            self.logger.log_event(
                session_id,
                "ml_thought",
                {
                    "src_ip": src_ip,
                    "verdict": "anomaly" if is_anomaly else "clean",
                    "source_type": source_type,
                    "score": result["anomaly_score"],
                    "error": result["reconstruction_error"],
                    "command": cmd,
                    "classification": result.get("classification"),
                    "severity": result.get("severity"),
                },
            )

            if is_anomaly:
                self.logger.log_event(
                    session_id,
                    "ml_anomaly",
                    {
                        "score": result["anomaly_score"],
                        "error": result["reconstruction_error"],
                        "source_type": source_type,
                        "cmd": cmd,
                        "classification": result.get("classification"),
                        "severity": result.get("severity"),
                    },
                )

        except Exception as e:
            self.logger.log_event(session_id, "error", {"message": f"ML Error: {e}"})

    # Function 184: Performs operations related to analyze file.
    def analyze_file(self, filename: str, content: bytes, session_id: str, src_ip: str):
        """Analyze uploaded file content and filename via ML."""
        if not self.ml_enabled or self.ml_pipeline is None:
            return

        try:
            # Combine filename and snippet of content for analysis
            # Most attackers use specific filenames or content patterns
            sample_len = 100
            content_snippet = content[:sample_len].decode("utf-8", "ignore")
            analysis_str = f"FILE_UPLOAD: {filename} CONTENT: {content_snippet}"

            # Analyze
            result = self.ml_pipeline.analyze_command(analysis_str)
            is_anomaly = result["is_anomaly"]

            # Log ML 'thought' via centralized logger
            self.logger.log_event(
                session_id,
                "ml_thought",
                {
                    "src_ip": src_ip,
                    "verdict": "anomaly" if is_anomaly else "clean",
                    "score": result["anomaly_score"],
                    "error": result["reconstruction_error"],
                    "file": filename,
                    "type": "file_upload",
                    "classification": result.get("classification"),
                    "severity": result.get("severity"),
                },
            )

            if is_anomaly:
                self.logger.log_event(
                    session_id,
                    "ml_file_anomaly",
                    {
                        "score": result["anomaly_score"],
                        "filename": filename,
                        "classification": result.get("classification"),
                        "severity": result.get("severity"),
                    },
                )
        except Exception as e:
            self.logger.log_event(session_id, "error", {"message": f"ML File Analysis Error: {e}"})

    # Function 185: Handles event logging and telemetry.
    async def log_geoip(self, session_id: str, ip: str, protocol: str):
        """Async GeoIP enrichment logging."""
        geo_data = await self.geoip.lookup(ip)
        if geo_data:
            self.logger.log_event(
                session_id,
                "client_geo",
                {
                    "protocol": protocol,
                    "src_ip": ip,
                    "geo": geo_data,
                },
            )
