"""
wazuh_query_vulnerabilities on Wazuh 4.x. Added October 2026.

4.x serves vulnerabilities from the indexer (wazuh-states-vulnerabilities-*);
the REST endpoint /vulnerability/{agent_id} is gone. Before this fix, the
indexer fallback dropped agent_id and search, so a query for one agent
returned the whole fleet under that agent's label. Checked live on Wazuh
4.14.8: agent_id="999" returned agent 001's 22 CVEs as "Vulnerabilities for
agent 999". Field names and values below are taken from that index:
agent.id, vulnerability.id and vulnerability.severity are keyword fields,
and severity is stored capitalised ("High").
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.errors import WazuhAPIError
from wazuh_mcp.indexer import IndexerClient
from wazuh_mcp.tools.analysis import register_analysis
from wazuh_mcp.tools.hunting import register_hunting

EMPTY = {"affected_items": [], "total_affected_items": 0}


@pytest.mark.asyncio
async def test_indexer_filters_by_agent_cve_severity_and_search():
    idx = IndexerClient(base_url="https://indexer.test:9200")
    idx._search = AsyncMock(return_value=EMPTY)

    await idx.vulnerabilities(
        agent_id="003", cve="cve-2024-3094", severity="critical", search="xz"
    )

    must = idx._search.await_args.args[1]["bool"]["must"]
    assert {"term": {"agent.id": "003"}} in must
    # Models send "critical" and lower-case CVE IDs; the index stores
    # "Critical" and "CVE-...", and keyword terms are case-sensitive.
    assert {
        "term": {"vulnerability.severity": {"value": "critical", "case_insensitive": True}}
    } in must
    assert {
        "term": {"vulnerability.id": {"value": "cve-2024-3094", "case_insensitive": True}}
    } in must
    assert {"query_string": {"query": "xz"}} in must


@pytest.mark.asyncio
async def test_client_fallback_keeps_agent_and_search():
    client = WazuhClient(base_url="https://wazuh.test:55000")
    client._get = AsyncMock(side_effect=WazuhAPIError(404, "Not found"))
    client._indexer.vulnerabilities = AsyncMock(return_value=EMPTY)

    await client.vulnerabilities(agent_id="003", search="xz")

    kwargs = client._indexer.vulnerabilities.await_args.kwargs
    assert kwargs["agent_id"] == "003"
    assert kwargs["search"] == "xz"


@pytest.mark.asyncio
async def test_client_without_agent_goes_straight_to_the_indexer():
    client = WazuhClient(base_url="https://wazuh.test:55000")
    client._get = AsyncMock()
    client._indexer.vulnerabilities = AsyncMock(return_value=EMPTY)

    await client.vulnerabilities(cve="CVE-2024-3094")

    client._get.assert_not_called()
    assert client._indexer.vulnerabilities.await_args.kwargs["agent_id"] is None


@pytest.mark.asyncio
async def test_tool_answers_a_fleet_wide_cve_question():
    client = AsyncMock(spec=WazuhClient)
    client.vulnerabilities.return_value = EMPTY
    mcp = FastMCP("test")
    register_hunting(mcp, client)

    result = await mcp.call_tool("wazuh_query_vulnerabilities", {"cve": "CVE-2024-3094"})
    out = json.loads((result[0] if isinstance(result, tuple) else result)[0].text)

    assert client.vulnerabilities.await_args.kwargs["agent_id"] is None
    assert "fleet" in out["summary"]


@pytest.mark.asyncio
async def test_heatmap_counts_severity_from_indexer_documents():
    """4.x documents nest severity under "vulnerability"; the heatmap read
    a top-level "severity", so every CVE counted as Unknown and the live
    heatmap reported 0 vulnerabilities for an agent with 22."""
    client = AsyncMock(spec=WazuhClient)
    client.list_agents.return_value = {
        "affected_items": [{"id": "001", "name": "web-1"}],
        "total_affected_items": 1,
    }
    client.vulnerabilities.return_value = {
        "affected_items": [
            {"agent": {"id": "001"}, "vulnerability": {"id": "CVE-1", "severity": "High"}},
            {"agent": {"id": "001"}, "vulnerability": {"id": "CVE-2", "severity": "Critical"}},
        ],
        "total_affected_items": 2,
    }
    mcp = FastMCP("test")
    register_analysis(mcp, client)

    result = await mcp.call_tool("wazuh_vulnerability_heatmap", {})
    out = json.loads((result[0] if isinstance(result, tuple) else result)[0].text)

    assert out["totals_by_severity"]["critical"] == 1
    assert out["totals_by_severity"]["high"] == 1
    assert out["total_vulnerabilities"] == 2
