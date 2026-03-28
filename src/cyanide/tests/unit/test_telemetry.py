from unittest.mock import patch

from cyanide.core.telemetry import setup_telemetry


def test_setup_telemetry_disabled():
    with patch("opentelemetry.trace.get_tracer"):
        tracer = setup_telemetry("service", {"enabled": False}, "1.0")
        assert tracer is not None


def test_setup_telemetry_enabled():
    with (
        patch("opentelemetry.sdk.trace.TracerProvider"),
        patch("opentelemetry.sdk.resources.Resource"),
        patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter"),
        patch("opentelemetry.sdk.trace.export.BatchSpanProcessor"),
        patch("opentelemetry.trace.set_tracer_provider"),
        patch("opentelemetry.trace.get_tracer"),
    ):

        tracer = setup_telemetry("service", {"enabled": True}, "1.0")
        assert tracer is not None
