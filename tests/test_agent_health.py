"""
wazuh_agent_health must count agents the way Wazuh's own summary does.

Runs the real tool through FastMCP.call_tool with only the client
mocked. The mock data mirrors Wazuh 4.14.8: /agents/summary/status
leaves out the manager (agent 000), /agents includes it, and the
keep-alive field is camelCase.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.tools.agents import register_agents

SUMMARY = {
    "connection": {
        "active": 1,
        "disconnected": 1,
        "never_connected": 0,
        "pending": 0,
        "total": 2,
    },
    "configuration": {"synced": 2, "not_synced": 0, "total": 2},
}
AGENTS = {
    "affected_items": [
        {
            "id": "000",
            "name": "wazuh.manager",
            "status": "active",
            "os": {"name": "Amazon Linux"},
            "version": "Wazuh v4.14.8",
            "lastKeepAlive": "9999-12-31T23:59:59+00:00",
        },
        {
            "id": "001",
            "name": "web-1",
            "status": "active",
            "os": {"name": "Ubuntu"},
            "version": "Wazuh v4.14.8",
            "lastKeepAlive": "2026-10-06T17:00:00+00:00",
        },
        {
            "id": "002",
            "name": "db-1",
            "ip": "10.0.0.7",
            "status": "disconnected",
            "os": {"name": "Ubuntu"},
            "version": "Wazuh v4.14.7",
            "lastKeepAlive": "2026-10-05T08:00:00+00:00",
        },
    ],
    "total_affected_items": 3,
}


@pytest_asyncio.fixture
async def health() -> dict:
    client = AsyncMock(spec=WazuhClient)
    client.agent_summary.return_value = SUMMARY
    client.list_agents.return_value = AGENTS
    mcp = FastMCP("test")
    register_agents(mcp, client)

    result = await mcp.call_tool("wazuh_agent_health", {})
    blocks = result[0] if isinstance(result, tuple) else result
    return json.loads(blocks[0].text)


@pytest.mark.asyncio
async def test_totals_agree_with_wazuh_summary(health):
    """The manager is not an agent; every count must leave it out."""
    assert health["total_agents"] == health["connection_summary"]["connection"]["total"]
    assert sum(health["os_breakdown"].values()) == health["total_agents"]
    assert sum(health["version_breakdown"].values()) == health["total_agents"]
    assert "Amazon Linux" not in health["os_breakdown"]


@pytest.mark.asyncio
async def test_disconnected_agent_reports_last_keepalive(health):
    [agent] = health["disconnected_agents"]

    assert agent["id"] == "002"
    assert agent["last_keepalive"] == "2026-10-05T08:00:00+00:00"
