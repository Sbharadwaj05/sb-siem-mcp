"""
Entry point for the Wazuh MCP server — production-hardened.

Features:
- 28 tools across 9 domains (alerts, hunting, compliance, agents,
  groups, lists, manager, response, analysis)
- RBAC (4 built-in roles: viewer, analyst, admin, soc)
- Rate limiting per-tool (token bucket, configurable)
- API response sanitization (credential redaction)
- Immutable audit logging for destructive actions
- Prometheus /metrics endpoint for SOC monitoring
- OpenAPI 3.0 / Swagger UI at /docs
- Smart field selection for token-efficient LLM output
- SSE transport support for streaming alerts
- Multi-manager support (round-robin client pool)

Start:  python -m wazuh_mcp.server
"""

from __future__ import annotations

import logging
import os
import sys

from mcp.server.fastmcp import FastMCP

from wazuh_mcp import __version__
from wazuh_mcp.client import WazuhClient
from wazuh_mcp.logging_config import configure_logging
from wazuh_mcp.tools import (
    agents,
    alerts,
    compliance,
    groups,
    hunting,
    lists,
    manager,
    response,
)
from wazuh_mcp.tools import analysis as analysis_tools

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

configure_logging()
logger = logging.getLogger("wazuh-mcp")

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="Wazuh MCP Server",
    instructions=(
        "You are an AI security analyst with full access to a Wazuh SIEM/XDR platform. "
        "You can query alerts, investigate threats, check compliance, manage agents, "
        "and trigger incident response actions (with confirmation). "
        "Always explain your findings in clear security terms and cite specific "
        "alert IDs, MITRE techniques, and agent names when presenting results.\n\n"
        "⚠️ Destructive tools (wazuh_run_active_response, wazuh_agent_command) "
        "require a two-step confirmation flow. You will see a confirmation prompt "
        "before any destructive action executes. Never bypass this.\n\n"
        "💡 Use 'triage' mode for quick alert overviews and 'detail' mode for "
        "deep investigations. Set compact_output=True for token efficiency."
    ),
)

# ---------------------------------------------------------------------------
# Multi-manager client pool
# ---------------------------------------------------------------------------

# Support connecting to multiple Wazuh managers for fault tolerance.
# Configure via WAZUH_API_URLS (comma-separated) or single WAZUH_API_URL.
_urls_raw = os.getenv(
    "WAZUH_API_URLS", os.getenv("WAZUH_API_URL", "https://localhost:55000")
)
_manager_urls = [u.strip() for u in _urls_raw.split(",") if u.strip()]

# Default client (first manager) — with automatic fallback to extras
_extra_clients: list[WazuhClient] = []
for url in _manager_urls[1:]:
    _extra_clients.append(WazuhClient(base_url=url))

_client = WazuhClient(base_url=_manager_urls[0], fallback_clients=_extra_clients)

if len(_manager_urls) > 1:
    logger.info("Multi-manager mode: %d managers configured", len(_manager_urls))

# ---------------------------------------------------------------------------
# Register all tool modules (9 domains, 24+ tools)
# ---------------------------------------------------------------------------

alerts.register_alerts(mcp, _client)
agents.register_agents(mcp, _client)
compliance.register_compliance(mcp, _client)
hunting.register_hunting(mcp, _client)
manager.register_manager(mcp, _client)
response.register_response(mcp, _client)
groups.register_groups(mcp, _client)
lists.register_lists(mcp, _client)
analysis_tools.register_analysis(mcp, _client)

logger.info("Registered 9 tool modules")

# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server (stdio transport for Claude Desktop / Cursor)."""
    logger.info("Starting Wazuh MCP Server v%s (production-hardened)", __version__)
    logger.info("Connected to: %s", _manager_urls[0])
    if len(_manager_urls) > 1:
        logger.info("Additional managers: %s", ", ".join(_manager_urls[1:]))

    # Start with stdio transport (default for Claude Desktop / Cursor)
    mcp.run(transport="stdio")


def main_sse() -> None:
    """
    Run the MCP server with SSE transport for streaming alert support.

    Exposes:
      - http://127.0.0.1:8000/sse           — SSE endpoint
      - http://127.0.0.1:8000/messages      — message endpoint
      - http://127.0.0.1:8000/health        — health check (auto)
      - http://127.0.0.1:9090/metrics       — Prometheus metrics
      - http://127.0.0.1:8000/docs          — Swagger UI
      - http://127.0.0.1:8000/openapi.json   — OpenAPI spec
    """
    logger.info("Starting Wazuh MCP Server v%s (SSE transport)", __version__)

    # Start Prometheus metrics on a background thread
    from wazuh_mcp.metrics import start_metrics_server

    metrics_port = int(os.getenv("WAZUH_METRICS_PORT", "9090"))
    start_metrics_server(port=metrics_port)

    mcp.run(
        transport="sse",
        host=os.getenv("WAZUH_MCP_HOST", "127.0.0.1"),
        port=int(os.getenv("WAZUH_MCP_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
