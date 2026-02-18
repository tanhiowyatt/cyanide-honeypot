import os
from typing import Any

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter


def setup_telemetry(service_name: str, config: dict, version: str = "1.0.0"):
    """Initialize OpenTelemetry using configuration."""
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": version,
        }
    )

    provider = TracerProvider(resource=resource)

    otel_enabled = config.get("enabled", False)
    otlp_endpoint = config.get("endpoint")
    exporter_type = config.get("exporter", "otlp")

    if otel_enabled and exporter_type == "otlp" and otlp_endpoint:
        exporter: "Any" = OTLPSpanExporter(endpoint=otlp_endpoint)
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
        print(f"[*] Telemetry: OTLP Exporter enabled ({otlp_endpoint})")
    elif os.getenv("CYANIDE_DEBUG_TRACE"):
        # Fallback to Console for debugging if env var set
        exporter = ConsoleSpanExporter()
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
        print("[*] Telemetry: Console Exporter enabled")

    # Only set global provider if not already set (prevents warnings in tests)
    from opentelemetry.trace import ProxyTracerProvider

    if isinstance(trace.get_tracer_provider(), ProxyTracerProvider):
        trace.set_tracer_provider(provider)

    return trace.get_tracer(service_name)
