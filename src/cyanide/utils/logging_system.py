import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import aiohttp


class HoneypotLogger:
    """Centralized logging system for honeypot events and commands.

    Creates separate log directories for server operations and attacker activity.
    All attack logs are written in JSONL format for easy parsing and analysis.
    Includes GeoIP enrichment for source IPs.
    """

    def __init__(self, log_dir: str = "logs"):
        """Initialize logging system with directory structure.

        Args:
            log_dir: Base directory for all logs (default: 'logs').
                    Creates subdirectories: server/ and attacks/

        Note:
            Sets up rotating file handlers and initializes GeoIP cache.
        """
        self.log_dir = Path(log_dir)
        self.attack_log_dir = self.log_dir / "attacks"
        self.server_log_dir = self.log_dir / "server"

        self.attack_log_dir.mkdir(parents=True, exist_ok=True)
        self.server_log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("honeypot")
        self.logger.setLevel(logging.INFO)

        # Configure file handler for application logs (server logs)
        fh = logging.FileHandler(self.server_log_dir / "app.log")
        fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(fh)

        self.geoip_cache: Dict[str, Any] = {}

        # We don't use file handler for attacks here directly because we rotate manually by date in log_event

    async def _get_geoip(self, ip: str) -> Dict[str, Any]:
        """Fetch GeoIP data from ipinfo.io (free tier, no token needed for basic)."""
        if ip in ("127.0.0.1", "0.0.0.0", "::1"):
            return {"country": "Local", "city": "Local", "org": "Localhost"}

        if ip in self.geoip_cache:
            return self.geoip_cache[ip]

        try:
            # Use aiohttp for async request
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://ipinfo.io/{ip}/json", timeout=3) as response:
                    if response.status == 200:
                        data = await response.json()
                        geo = {
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "org": data.get("org", "Unknown"),  # ISP/Org
                            "loc": data.get(
                                "loc", "Unknown"
                            ),  # invalid for security sometimes but useful
                        }
                        self.geoip_cache[ip] = geo
                        return geo
        except Exception:
            pass

        return {}

    async def log_event(self, event_data: Dict[str, Any]):
        """Log event to JSONL file with enterprise schema."""
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")

        # Enterprise Schema
        log_entry = {
            "timestamp": now.isoformat(),
            "level": event_data.get("level", "INFO"),
            "service": "honeypot",
            "protocol": event_data.get("protocol", "unknown"),
            "event_type": event_data.get("event", "unknown"),
            "src_ip": event_data.get("src_ip", "unknown"),
            "src_port": event_data.get("src_port", 0),
            "session_id": event_data.get("session_id", "unknown"),
            "client_version": event_data.get("client_version", ""),  # SSH Client String
            "details": event_data,  # Embed original data as details
        }

        # Add GeoIP if src_ip available
        if "src_ip" in event_data:
            geo = await self._get_geoip(event_data["src_ip"])
            if geo:
                log_entry["geoip"] = geo

        # Flatten specific keys for easier indexing if needed, but 'details' keeps it clean
        if "command" in event_data:
            log_entry["command"] = event_data["command"]
        if "username" in event_data:
            log_entry["user"] = event_data["username"]

        if "username" in event_data:
            log_entry["user"] = event_data["username"]

        log_file = self.attack_log_dir / f"honeypot-{today}.jsonl"

        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Failed to log event: {e}")

    async def log_command(self, session_id, protocol, src_ip, username, command, client_version=""):
        """Helper for granular command logging."""
        await self.log_event(
            {
                "event": "command_execution",
                "protocol": protocol,
                "session_id": session_id,
                "src_ip": src_ip,
                "username": username,
                "command": command,
                "client_version": client_version,
            }
        )
