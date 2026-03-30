from typing import Dict, Optional


class AnalyticsService:
    """
    Handles ML analysis, GeoIP enrichment, and statistics.
    """

    # Function 181: Initializes the class instance and its attributes.
    def __init__(self, config: Dict, logger, session_mgr=None):
        self.config = config
        self.logger = logger
        self.session_mgr = session_mgr
        self.logger.log_event(
            "system",
            "service_init",
            {"service": "AnalyticsService", "message": "Starting AnalyticsService"},
        )

        try:
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

            from cyanide.core.paths import get_package_root
            from cyanide.ml import CyanideML

            pkg_root = get_package_root()

            possible_paths = [
                Path(self.config.get("ml", {}).get("model_path", "")),
                pkg_root / "assets" / "models" / "cyanideML.pkl",
                Path("src/cyanide/assets/models/cyanideML.pkl"),
                Path("assets/models/cyanideML.pkl"),
                pkg_root / "ml" / "cyanideML.pkl",
            ]

            final_model_path: Optional[Path] = None
            for p in possible_paths:
                if p and p.exists():
                    final_model_path = p
                    break

            if final_model_path:
                self.logger.log_event(
                    "system",
                    "system_status",
                    {"message": f"Loading CyanideML pipeline from {final_model_path}..."},
                )
                self.ml_pipeline = CyanideML(str(final_model_path.parent))
            else:
                self.logger.log_event(
                    "system",
                    "system_warning",
                    {"message": "ML models not found. Analysis will be skipped."},
                )
                self.ml_enabled = False
                return

        except ImportError as e:
            self.logger.log_event(
                "system", "error", {"message": f"ML Module could not be loaded: {e}"}
            )
            self.ml_enabled = False
        except Exception as e:
            self.logger.log_event("system", "error", {"message": f"Failed to init ML model: {e}"})
            self.ml_enabled = False

    # Function 183: Performs operations related to analyze command.
    def analyze_command(self, cmd: str, src_ip: str, session_id: str, is_bot: bool = False):
        """Analyze a command string for tools and anomalies."""
        # Record command in session stats
        if self.session_mgr:
            self.session_mgr.record_command(session_id)

        # Automated Tool Detection
        automated_tools = ["wget", "curl", "python ", "perl ", "ruby ", "gcc ", "chmod +x"]
        detected_tool = next((tool.strip() for tool in automated_tools if tool in cmd), None)
        if detected_tool:
            self.logger.log_event(
                session_id,
                "tool_detection",
                {"src_ip": src_ip, "tool": detected_tool, "command": cmd},
            )

        # ML Anomaly Detection
        if not self.ml_enabled or self.ml_pipeline is None:
            return

        try:
            result = self.ml_pipeline.analyze_command(cmd)
            is_anomaly = result["is_anomaly"]
            source_type = "bot" if is_bot else "human"

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
            sample_len = 100
            content_snippet = content[:sample_len].decode("utf-8", "ignore")
            analysis_str = f"FILE_UPLOAD: {filename} CONTENT: {content_snippet}"

            result = self.ml_pipeline.analyze_command(analysis_str)
            is_anomaly = result["is_anomaly"]

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
    def _identify_threats(self, ptr_data: Optional[str]) -> list[str]:
        """Identify known scanners and bots from reverse DNS (PTR) records."""
        if not ptr_data:
            return []

        threat_intel = []
        low_ptr = ptr_data.lower()
        # Dictionary mapping for common scanner signatures
        signatures = {
            "shodan": "Shodan Scanner",
            "censys": "Censys Scanner",
            "shadowserver": "Shadowserver Scanner",
            "bolt": "Bot/Crawler",
            "crawl": "Bot/Crawler",
        }

        for signature, label in signatures.items():
            if signature in low_ptr and label not in threat_intel:
                threat_intel.append(label)

        return threat_intel

    def _enrich_geoip_cache(
        self, ip: str, geo_data: dict, ptr_data: Optional[str], threat_intel: list[str]
    ):
        """Updates the logger's GeoIP cache with enriched data including PTR and threats."""
        if not hasattr(self.logger, "geoip_cache"):
            return

        enriched_geo = geo_data.copy()
        enriched_geo["ptr"] = ptr_data
        if threat_intel:
            enriched_geo["threat_intel"] = threat_intel

        self.logger.geoip_cache[ip] = enriched_geo

    # Function 185: Handles event logging and telemetry.
    async def log_geoip(self, ip: str):
        """Async GeoIP enrichment logging."""
        geo_data = await self.geoip.lookup(ip)
        ptr_data = await self.geoip.lookup_ptr(ip)
        threat_intel = self._identify_threats(ptr_data)

        if geo_data:
            self._enrich_geoip_cache(ip, geo_data, ptr_data, threat_intel)
