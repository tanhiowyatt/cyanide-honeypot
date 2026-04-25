import json
from pathlib import Path

from cyanide.services.ioc_reporter import IOCReporter


class MockLogger:
    def __init__(self):
        self.events = []

    def log_event(self, session, event_type, data):
        self.events.append({"session": session, "type": event_type, "data": data})


def test_ioc_reporter_stix_export(tmp_path):
    """Test STIX 2.1 bundle generation."""
    config = {
        "logging": {"directory": str(tmp_path)},
        "honeypot": {"hostname": "test-sensor-01"},
    }
    logger = MockLogger()
    reporter = IOCReporter(config, logger)

    # Add various IOCs
    reporter.add_ioc("ipv4-addr", "1.2.3.4", "Attack source", "sess-1")
    reporter.add_ioc("url", "http://evil.com/x.sh", "Payload URL", "sess-1")
    reporter.add_ioc(
        "file-hash",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Malware SHA256",
        "sess-2",
    )
    reporter.add_ioc("domain", "attacker.com", "C2 Domain", "sess-3")

    # Generate report
    report_path = reporter.generate_stix_report()

    assert report_path is not None
    assert Path(report_path).exists()
    assert reporter.report_path == Path(report_path)

    with open(report_path, "r") as f:
        bundle = json.load(f)

    assert bundle["type"] == "bundle"
    assert "id" in bundle
    assert isinstance(bundle["objects"], list)

    # We expect 1 Identity + 4 Indicators = 5 objects
    assert len(bundle["objects"]) == 5

    types = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in types
    assert types.count("indicator") == 4

    # Verify a specific indicator (IPv4)
    ipv4_indicator = next(
        obj
        for obj in bundle["objects"]
        if obj["type"] == "indicator" and "ipv4-addr" in obj["pattern"]
    )
    assert ipv4_indicator["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert ipv4_indicator["spec_version"] == "2.1"


def test_ioc_reporter_empty():
    """Test that it doesn't crash or generate reports when empty."""
    config = {"logging": {"directory": "/tmp/nonexistent"}}
    logger = MockLogger()
    reporter = IOCReporter(config, logger)

    assert reporter.generate_stix_report() is None
