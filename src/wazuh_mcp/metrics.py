"""
Prometheus metrics exporter for Wazuh MCP Server.

Exposes a /metrics endpoint (port 9090 by default) with:
- Tool call counters (wazuh_mcp_tool_calls_total)
- Tool call latency histogram (wazuh_mcp_tool_duration_seconds)
- Rate limit hit counter (wazuh_mcp_rate_limits_total)
- Wazuh API connection health gauge (wazuh_mcp_api_up)
- Audit log entry count (wazuh_mcp_audit_entries_total)
- Active tool calls gauge (wazuh_mcp_active_requests)
- Total errors by tool (wazuh_mcp_tool_errors_total)

Start alongside the main server:
    from wazuh_mcp.metrics import start_metrics_server
    start_metrics_server(port=9090)

Or via environment:
    WAZUH_METRICS_PORT=9090
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Optional

try:
    from prometheus_client import (
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        start_http_server,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = logging.getLogger("wazuh-mcp.metrics")

# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

if PROMETHEUS_AVAILABLE:
    tool_calls = Counter(
        "wazuh_mcp_tool_calls_total",
        "Total number of MCP tool calls",
        ["tool", "status"],
    )

    tool_duration = Histogram(
        "wazuh_mcp_tool_duration_seconds",
        "Tool call duration in seconds",
        ["tool"],
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    )

    rate_limits = Counter(
        "wazuh_mcp_rate_limits_total",
        "Total number of rate-limit rejections",
        ["tool"],
    )

    api_up = Gauge(
        "wazuh_mcp_api_up",
        "Whether the Wazuh API is reachable (1=up, 0=down)",
    )

    audit_entries = Counter(
        "wazuh_mcp_audit_entries_total",
        "Total number of audit log entries written",
    )

    active_requests = Gauge(
        "wazuh_mcp_active_requests",
        "Number of in-flight tool calls",
    )

    tool_errors = Counter(
        "wazuh_mcp_tool_errors_total",
        "Total number of tool call errors",
        ["tool", "error_type"],
    )
else:
    # Stub classes for when prometheus_client is not installed
    class _StubMetric:
        def labels(self, **kw):
            return self

        def inc(self, amount=1):
            pass

        def dec(self, amount=1):
            pass

        def set(self, value):
            pass

        def observe(self, value):
            pass

        def time(self):
            return _StubContext()

    class _StubContext:
        def __enter__(self):
            pass

        def __exit__(self, *a):
            pass

    tool_calls = _StubMetric()
    tool_duration = _StubMetric()
    rate_limits = _StubMetric()
    api_up = _StubMetric()
    audit_entries = _StubMetric()
    active_requests = _StubMetric()
    tool_errors = _StubMetric()


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def record_tool_call(tool_name: str, duration: float, status: str = "success") -> None:
    """Record a completed tool call."""
    tool_calls.labels(tool=tool_name, status=status).inc()
    tool_duration.labels(tool=tool_name).observe(duration)


def record_rate_limit(tool_name: str) -> None:
    """Record a rate-limit rejection."""
    rate_limits.labels(tool=tool_name).inc()


def record_api_status(is_up: bool) -> None:
    """Update the Wazuh API connectivity gauge."""
    api_up.set(1 if is_up else 0)


def record_audit_entry() -> None:
    """Increment the audit log entry counter."""
    audit_entries.inc()


def record_error(tool_name: str, error_type: str = "unknown") -> None:
    """Record a tool call error."""
    tool_errors.labels(tool=tool_name, error_type=error_type).inc()


def request_started() -> None:
    """Mark a request as in-flight."""
    active_requests.inc()


def request_finished() -> None:
    """Mark a request as completed."""
    active_requests.dec()


# ---------------------------------------------------------------------------
# Metrics server
# ---------------------------------------------------------------------------

_metrics_thread: Optional[threading.Thread] = None


def start_metrics_server(port: int = 9090, addr: str = "127.0.0.1") -> None:
    """
    Start a Prometheus HTTP metrics server on a background thread.

    Args:
        port: Port to bind the /metrics endpoint on.
        addr: Interface to bind; prometheus_client defaults to all of them.
    """
    global _metrics_thread
    if not PROMETHEUS_AVAILABLE:
        logger.warning(
            "prometheus_client not installed. Install with: pip install prometheus-client"
        )
        return

    if _metrics_thread is not None:
        logger.warning("Metrics server already running")
        return

    def _run():
        logger.info("Prometheus /metrics endpoint starting on %s:%d", addr, port)
        start_http_server(port, addr=addr)
        # start_http_server runs in a daemon thread internally

    _metrics_thread = threading.Thread(target=_run, daemon=True, name="metrics-http")
    _metrics_thread.start()
    logger.info("Metrics server started on :%d/metrics", port)


def get_metrics() -> bytes:
    """Return the current Prometheus metrics as bytes (for embedded use)."""
    if not PROMETHEUS_AVAILABLE:
        return b"# prometheus_client not installed\n"
    return generate_latest(REGISTRY)
