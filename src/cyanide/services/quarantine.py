import asyncio
import time
from pathlib import Path
from typing import Dict, Optional


class QuarantineService:
    """
    Manages quarantine directory and file saving with quota checks.
    """

    def __init__(self, config: Dict, logger):
        self.logger = logger
        self.config = config

        self.quarantine_path = Path(config.get("quarantine_path", "var/quarantine"))
        self.quarantine_path.mkdir(parents=True, exist_ok=True)

        # Quarantine quota (in MB)
        self.quarantine_max_mb = config.get("quarantine_max_size_mb", 500)

        # VirusTotal Integration (optional dependency)
        # We'll inject the scanner or handle it here if needed.
        # For now, let's keep it simple and maybe handle scanning via callback or event
        self.vt_scanner = None  # Set by server if needed

    def set_scanner(self, scanner):
        self.vt_scanner = scanner

    async def save_file(
        self, filename: str, content: bytes, session_id: str = "unknown", src_ip: str = "unknown"
    ) -> Optional[str]:
        """
        Save a file to quarantine if quota allows.
        Returns the path to the saved file or None.
        """
        try:
            # Check Disk Quota
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

            timestamp = int(time.time())
            safe_name = f"{timestamp}_{Path(filename).name}"
            target_path = self.quarantine_path / safe_name

            with open(target_path, "wb") as f:
                f.write(content)

            # Trigger Async Analysis if scanner is available
            if self.vt_scanner and self.vt_scanner.enabled:
                asyncio.create_task(self._scan_and_log(filename, content, session_id, src_ip))

            return str(target_path)
        except Exception as e:
            self.logger.log_event(
                session_id, "error", {"message": f"Error saving quarantine file: {e}"}
            )
            return None

    async def _scan_and_log(self, filename: str, content: bytes, session_id: str, src_ip: str):
        """Background task to scan file and log results."""
        try:
            result = await self.vt_scanner.scan(content, filename)
            if result:
                await self.logger.log_event_async(
                    {
                        "event": "malware_scan",
                        "session_id": session_id,
                        "src_ip": src_ip,
                        "filename": filename,
                        "sha256": result.get("sha256"),
                        "malicious": result.get("malicious"),
                        "label": result.get("label"),
                        "vt_link": result.get("link"),
                    }
                )
        except Exception as e:
            await self.logger.log_event_async(
                {
                    "event": "scan_error",
                    "session_id": session_id,
                    "src_ip": src_ip,
                    "message": f"Scan Error: {e}",
                }
            )
