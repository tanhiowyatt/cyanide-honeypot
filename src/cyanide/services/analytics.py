import asyncio
from typing import Dict, List, Optional


class AnalyticsService:
    """
    Handles ML analysis, GeoIP enrichment, and statistics.
    """

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
                {
                    "service": "AnalyticsService",
                    "message": "Components initialized successfully",
                },
            )
        except Exception as e:
            self.logger.log_event(
                "system",
                "service_init_error",
                {"service": "AnalyticsService", "error": str(e)},
            )

        self.ml_enabled = config.get("ml", {}).get("enabled", False)
        self.ml_online_learning = config.get("ml", {}).get("online_learning", False)
        self.ml_pipeline = None
        self.kb = None
        self.ioc_reporter = None

        if self.ml_enabled:
            self._init_ml()

    def set_ioc_reporter(self, reporter):
        """Set the IOC reporter for this service."""
        self.ioc_reporter = reporter

    async def run_online_learning_loop(self):
        """Background task for periodic ML retraining based on accumulated data."""
        if not self.ml_online_learning or not self.ml_enabled:
            self.logger.log_event(
                "system",
                "ml_online_learning_status",
                {"status": "disabled", "reason": "online_learning or ml disabled"},
            )
            return

        interval_days = self.config.get("ml", {}).get("retraining_interval_days", 7)
        interval_seconds = max(3600, interval_days * 86400)  # Min 1 hour

        self.logger.log_event(
            "system",
            "ml_online_learning_status",
            {"status": "starting", "interval_days": interval_days},
        )

        while True:
            await asyncio.sleep(interval_seconds)
            try:
                self.logger.log_event(
                    "system", "ml_retraining_start", {"message": "Starting periodic ML retraining"}
                )

                commands = self._fetch_training_data()
                if commands and self.ml_pipeline:
                    # Offload to thread to not block event loop if fit is heavy
                    # However, fit is currently synchronous in model.py
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, self.ml_pipeline.retrain, commands)

                    self.logger.log_event(
                        "system", "ml_retraining_complete", {"count": len(commands)}
                    )
                else:
                    self.logger.log_event(
                        "system", "ml_retraining_skipped", {"reason": "No training data found"}
                    )
            except Exception as e:
                self.logger.log_event("system", "ml_retraining_error", {"error": str(e)})

    def _fetch_training_data(self) -> List[str]:
        """Fetches recent commands from StatsManager buffer for retraining."""
        if not hasattr(self, "stats") or not self.stats:
            return []

        commands = [entry["command"] for entry in self.stats.recent_commands if "command" in entry]
        return list(set(commands))  # Deduplicate

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

    def analyze_command(self, cmd: str, src_ip: str, session_id: str, is_bot: bool = False):
        """Analyze a command string for tools and anomalies."""
        if self.session_mgr:
            self.session_mgr.record_command(session_id)

        automated_tools = [
            "wget",
            "curl",
            "python ",
            "perl ",
            "ruby ",
            "gcc ",
            "chmod +x",
        ]
        detected_tool = next((tool.strip() for tool in automated_tools if tool in cmd), None)
        if detected_tool:
            self.logger.log_event(
                session_id,
                "tool_detection",
                {"src_ip": src_ip, "tool": detected_tool, "command": cmd},
            )

            if self.ioc_reporter:
                import re

                urls = set(re.findall(r"https?://[^\s<>\"']+", cmd))
                for url in urls:
                    self.ioc_reporter.add_ioc(
                        "url",
                        url,
                        f"Automated tool detection: {detected_tool}",
                        session_id,
                        severity="low",
                    )

                url_domains = {
                    re.sub(r"[:/].*$", "", re.sub(r"^https?://", "", url))
                    for url in urls
                }
                domains = {
                    domain
                    for domain in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", cmd)
                    if domain not in url_domains
                }
                for domain in domains:
                    self.ioc_reporter.add_ioc(
                        "domain",
                        domain,
                        f"Automated tool detection: {detected_tool}",
                        session_id,
                        severity="low",
                    )
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
                if self.ioc_reporter:
                    self.ioc_reporter.add_ioc(
                        "ipv4-addr",
                        src_ip,
                        f"Malicious source IP (anomaly score: {result['anomaly_score']})",
                        session_id,
                        severity="high",
                    )

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

                if self.ioc_reporter:
                    # Extract URLs or suspicious strings from the command
                    import re

                    urls = re.findall(r"https?://[^\s<>\"']+", cmd)
                    for url in urls:
                        self.ioc_reporter.add_ioc(
                            "url",
                            url,
                            "Extracted from anomalous command",
                            session_id,
                            severity="high",
                        )

                    ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", cmd)
                    for ip in ips:
                        self.ioc_reporter.add_ioc(
                            "ipv4-addr",
                            ip,
                            "IP extracted from anomalous command",
                            session_id,
                            severity="high",
                        )

        except Exception as e:
            self.logger.log_event(session_id, "error", {"message": f"ML Error: {e}"})

    def analyze_auth(self, username, password, src_ip, session_id):
        """Analyze authentication attempt for IOC extraction."""
        if self.ioc_reporter:
            # Check if this user/pass combo is part of a common attack list
            # For now, we log all failed attempts from known malicious IPs
            # or simply log them as text IOCs
            self.ioc_reporter.add_ioc(
                "credential",
                f"{username}:{password}",
                "Credential attempt from attacker",
                session_id,
                severity="low",
            )

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

                if self.ioc_reporter:
                    import hashlib

                    file_hash = hashlib.sha256(content).hexdigest()
                    self.ioc_reporter.add_ioc(
                        "file-hash",
                        file_hash,
                        f"Anomalous file upload: {filename}",
                        session_id,
                        severity=result.get("severity", "medium"),
                    )
        except Exception as e:
            self.logger.log_event(session_id, "error", {"message": f"ML File Analysis Error: {e}"})

    def _identify_threats(self, ptr_data: Optional[str]) -> list[str]:
        """Identify known scanners and bots from reverse DNS (PTR) records."""
        if not ptr_data:
            return []

        threat_intel = []
        low_ptr = ptr_data.lower()
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

    async def log_geoip(self, ip: str):
        """Async GeoIP enrichment logging."""
        geo_data = await self.geoip.lookup(ip)
        ptr_data = await self.geoip.lookup_ptr(ip)
        threat_intel = self._identify_threats(ptr_data)

        if geo_data:
            self._enrich_geoip_cache(ip, geo_data, ptr_data, threat_intel)
