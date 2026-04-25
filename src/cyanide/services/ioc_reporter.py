import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class IOCReporter:
    """
    Aggregates Indicators of Compromise (IOCs) and exports them in STIX 2.1 format.
    """

    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.iocs: List[Dict[str, Any]] = []

        # Ensure absolute path for Docker consistency
        raw_dir = config.get("logging", {}).get("directory", "var/log/cyanide")
        if not raw_dir.startswith("/"):
            raw_dir = "/app/" + raw_dir

        self.report_dir = Path(raw_dir) / "reports"
        self.report_path = self.report_dir / "cyanide_iocs.stix.json"
        self.misp_report_path = self.report_dir / "cyanide_iocs.misp.json"

        self.logger.log_event(
            "system",
            "service_init",
            {"service": "IOCReporter", "message": f"Starting IOCReporter at {self.report_dir}"},
        )

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        description: str,
        source_session: str,
        severity: str = "medium",
    ):
        """Add a new IOC to the internal collection and trigger immediate report update."""
        ioc_entry = {
            "type": ioc_type,
            "value": value,
            "description": description,
            "session": source_session,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.iocs.append(ioc_entry)
        self.logger.log_event(
            source_session,
            "ioc_extracted",
            {"type": ioc_type, "value": value, "severity": severity},
        )
        # Immediate report generation for better responsiveness (quiet mode for tests)
        self.generate_reports(quiet=True)

    def generate_reports(self, quiet: bool = False):
        """Generate both STIX and MISP reports."""
        self.generate_stix_report(quiet=quiet)
        self.generate_misp_report(quiet=quiet)

    def generate_stix_report(self, quiet: bool = False) -> Optional[str]:
        """Generate a STIX 2.1 Bundle containing all extracted IOCs."""
        if not self.iocs:
            import logging

            logging.debug("IOCReporter: No IOCs collected, skipping STIX report.")
            return None

        import logging

        logging.info(f"IOCReporter: Generating STIX report at {self.report_path}")

        bundle_id = f"bundle--{uuid.uuid4()}"
        objects = []

        # Create Identity for the Honeypot
        honeypot_identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid4()}",
            "name": self.config.get("honeypot", {}).get("hostname", "Cyanide-Honeypot"),
            "description": "Cyanide Honeypot Sensor",
            "identity_class": "system",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
        }
        objects.append(honeypot_identity)

        for ioc in self.iocs:
            indicator_id = f"indicator--{uuid.uuid4()}"

            # Map internal types to STIX patterns
            pattern = ""
            if ioc["type"] == "ipv4-addr":
                pattern = f"[ipv4-addr:value = '{ioc['value']}']"
            elif ioc["type"] == "url":
                pattern = f"[url:value = '{ioc['value']}']"
            elif ioc["type"] == "file-hash":
                pattern = f"[file:hashes.'SHA-256' = '{ioc['value']}']"
            elif ioc["type"] == "domain":
                pattern = f"[domain-name:value = '{ioc['value']}']"
            elif ioc["type"] == "credential":
                pattern = f"[user-account:user_id = '{ioc['value']}']"
            else:
                # Fallback to a generic note or skip
                continue

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": ioc["timestamp"],
                "modified": ioc["timestamp"],
                "name": f"IOC from {ioc['session']}",
                "description": ioc["description"],
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ioc["timestamp"],
                "created_by_ref": honeypot_identity["id"],
            }
            objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            with open(self.report_path, "w") as f:
                json.dump(bundle, f, indent=2)

            if self.iocs and not quiet:
                self.logger.log_event(
                    "system",
                    "ioc_report_generated",
                    {"format": "stix2.1", "path": str(self.report_path), "count": len(self.iocs)},
                )
            return str(self.report_path)
        except Exception as e:
            self.logger.log_event(
                "system", "error", {"message": f"Failed to save STIX report: {e}"}
            )
            return None

    def generate_misp_report(self, quiet: bool = False) -> Optional[str]:
        """Generate a MISP JSON report containing all extracted IOCs."""
        if not self.iocs:
            import logging

            logging.debug("IOCReporter: No IOCs collected, skipping MISP report.")
            return None

        import logging

        logging.info(f"IOCReporter: Generating MISP report at {self.misp_report_path}")

        event: Dict[str, Any] = {
            "Event": {
                "uuid": str(uuid.uuid4()),
                "info": f"Cyanide Honeypot IOC Report - {datetime.now().date()}",
                "threat_level_id": "2",  # Medium
                "analysis": "1",  # Ongoing
                "Attribute": [],
            }
        }

        type_map = {
            "ipv4-addr": "ip-src",
            "url": "url",
            "file-hash": "sha256",
            "domain": "domain",
            "credential": "text",
        }

        attributes: List[Dict[str, Any]] = []
        for ioc in self.iocs:
            misp_type = type_map.get(ioc["type"], "other")
            attr = {
                "type": misp_type,
                "value": ioc["value"],
                "comment": f"Session: {ioc['session']} - {ioc['description']}",
                "timestamp": int(datetime.fromisoformat(ioc["timestamp"]).timestamp()),
                "to_ids": True,
            }
            attributes.append(attr)

        event["Event"]["Attribute"] = attributes

        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            with open(self.misp_report_path, "w") as f:
                json.dump(event, f, indent=2)

            if self.iocs and not quiet:
                self.logger.log_event(
                    "system",
                    "ioc_report_generated",
                    {"format": "misp", "path": str(self.misp_report_path), "count": len(self.iocs)},
                )
            return str(self.misp_report_path)
        except Exception as e:
            self.logger.log_event(
                "system", "error", {"message": f"Failed to save MISP report: {e}"}
            )
            return None
