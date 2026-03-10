import os
import time
from pathlib import Path
from typing import Optional


class CleanupManager:
    """Manages automatic cleanup of old logs and data."""

    # Function 14: Initializes the class instance and its attributes.
    def __init__(self, config, logger=None):
        """Initialize with configuration dict.

        Args:
            config: Full config dict, expects 'cleanup' key.
            logger: Optional CyanideLogger instance.
        """
        self.config = config.get("cleanup", {})
        self.logger = logger
        self.enabled = str(self.config.get("enabled", "true")).lower() == "true"
        self.interval = int(self.config.get("interval", 3600))
        self.retention_days = int(self.config.get("retention_days", 7))

        # Parse paths CSV or list
        raw_paths = self.config.get("paths", "var/log/cyanide,var/quarantine")
        if isinstance(raw_paths, str):
            self.target_paths = [p.strip() for p in raw_paths.split(",")]
        else:
            self.target_paths = raw_paths

    # Function 15: Performs operations related to cleanup files.
    def cleanup_files(
        self, retention_days_override: Optional[int] = None, dry_run: bool = False
    ) -> dict:
        """Run cleanup logic.

        Args:
            retention_days_override: Optional override for days.
            dry_run: If True, only simulate deletion.

        Returns:
            dict: Statistics of deleted files per path.
        """
        if not self.enabled and retention_days_override is None:
            return {"status": "disabled"}

        days = self.retention_days
        if retention_days_override is not None:
            days = retention_days_override

        # Calculate cutoff timestamp
        cutoff_time = time.time() - (days * 86400)
        stats = {"deleted": 0, "bytes_freed": 0, "errors": 0}

        for path_str in self.target_paths:
            base_path = Path(path_str)
            if not base_path.exists():
                continue

            for root, dirs, files in os.walk(base_path):
                for name in files:
                    file_path = Path(root) / name
                    try:
                        mtime = file_path.stat().st_mtime
                        if mtime < cutoff_time:
                            size = file_path.stat().st_size
                            if not dry_run:
                                file_path.unlink()
                            stats["deleted"] += 1
                            stats["bytes_freed"] += size
                    except Exception as e:
                        if self.logger:
                            self.logger.log_event(
                                "system",
                                "cleanup_error",
                                {"path": str(file_path), "message": str(e)},
                            )
                        stats["errors"] += 1

        return stats
