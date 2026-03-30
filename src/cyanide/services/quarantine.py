import asyncio
from pathlib import Path
from typing import Dict, Optional, Set

import aiofiles


class QuarantineService:
    """
    Manages quarantine directory and file saving with quota checks.
    """

    # Function 186: Initializes the class instance and its attributes.
    def __init__(self, config: Dict, logger):
        self.logger = logger
        self.config = config

        self.quarantine_path = Path(config.get("quarantine_path", "var/quarantine"))
        self.quarantine_path.mkdir(parents=True, exist_ok=True)

        self.quarantine_max_mb = config.get("quarantine_max_size_mb", 500)

        self.vt_scanner = None
        self._background_tasks: Set[asyncio.Task] = set()

    # Function 187: Configures or sets scanner.
    def set_scanner(self, scanner):
        self.vt_scanner = scanner

    # Function 188: Performs operations related to save file.
    async def save_file(
        self,
        filename: str,
        content: bytes,
        session_id: str = "unknown",
        src_ip: str = "unknown",
        sub_dir: Optional[str] = None,
    ) -> Optional[str]:
        """
        Save a file to quarantine if quota allows.
        Returns the path to the saved file or None.
        """
        try:
            current_size = sum(
                f.stat().st_size for f in self.quarantine_path.glob("*") if f.is_file()
            )
            content_size = len(content)

            if (current_size + content_size) > (self.quarantine_max_mb * 1024 * 1024):
                self.logger.log_event(
                    session_id,
                    "quarantine_warning",
                    {
                        "message": f"Quarantine Quota Reached ({self.quarantine_max_mb}MB). Rejecting {filename}"
                    },
                )
                return None

            # Format: filename_sessionid
            safe_name = f"{Path(filename).name}_{session_id}"
            target_path_main = self.quarantine_path / safe_name

            # Always save to the main quarantine folder
            async with aiofiles.open(target_path_main, "wb") as f:
                await f.write(content)

            # Also save to the session-specific quarantine folder if sub_dir is provided
            if sub_dir:
                log_dir_conf = self.config.get("logging", {}).get("directory", "var/log/cyanide")
                log_base = Path(log_dir_conf) / "tty" / sub_dir
                target_base_session = log_base / "quarantine"
                target_base_session.mkdir(parents=True, exist_ok=True)

                # Initialize missing log files if they don't exist (consistency for forenics)
                for log_file in ["transcript.log", "timing.time", "ml_analysis.json"]:
                    p = log_base / log_file
                    if not p.exists():
                        p.touch()

                target_path_sess = target_base_session / safe_name

                async with aiofiles.open(target_path_sess, "wb") as f:
                    await f.write(content)

            if self.vt_scanner and self.vt_scanner.enabled:
                task = asyncio.create_task(
                    self._scan_and_log(filename, content, session_id, src_ip)
                )
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)

            if hasattr(self.logger, "services") and hasattr(self.logger.services, "analytics"):
                self.logger.services.analytics.analyze_file(filename, content, session_id, src_ip)
            return str(target_path_main)
        except Exception as e:
            self.logger.log_event(
                session_id, "error", {"message": f"Error saving quarantine file: {e}"}
            )
            return None

    # Function 189: Handles event logging and telemetry.
    async def _scan_and_log(self, filename: str, content: bytes, session_id: str, src_ip: str):
        """Background task to scan file and log results."""
        if not self.vt_scanner:
            return
        try:
            result = await self.vt_scanner.scan(content, filename)
            if result:
                self.logger.log_event(
                    session_id,
                    "ml_malware_scan",
                    {
                        "src_ip": src_ip,
                        "filename": filename,
                        "sha256": result.get("sha256"),
                        "malicious": result.get("malicious"),
                        "label": result.get("label"),
                        "vt_link": result.get("link"),
                    },
                )
        except Exception as e:
            self.logger.log_event(
                session_id,
                "ml_malware_scan_error",
                {
                    "src_ip": src_ip,
                    "message": f"Scan Error: {e}",
                },
            )
