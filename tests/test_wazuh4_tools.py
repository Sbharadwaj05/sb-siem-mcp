"""
Tools that failed against a live Wazuh 4.14.8 manager. Added October 2026.

Found by calling all 28 tools against the local lab (official wazuh-docker
single-node plus one agent). The response shapes below are the ones that
manager returned.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.errors import WazuhAPIError
from wazuh_mcp.tools.analysis import register_analysis
from wazuh_mcp.tools.hunting import register_hunting
from wazuh_mcp.tools.manager import register_manager

CLUSTER_OFF = WazuhAPIError(400, "HTTP 400: Cluster is not running")


def client_with_routes(routes: dict) -> WazuhClient:
    """A real WazuhClient whose _get answers from a path -> data table."""
    client = WazuhClient(base_url="https://wazuh.test:55000")

    async def fake_get(path, params=None):
        answer = routes[path]
        if isinstance(answer, Exception):
            raise answer
        return answer

    client._get = AsyncMock(side_effect=fake_get)
    return client


async def call(register, client, tool, **arguments) -> dict:
    mcp = FastMCP("test")
    register(mcp, client)
    result = await mcp.call_tool(tool, arguments)
    return json.loads((result[0] if isinstance(result, tuple) else result)[0].text)


# --- wazuh_sca_checks: 4.x has no /sca/{agent}/checks without a policy -----


@pytest.mark.asyncio
async def test_sca_checks_uses_the_agents_only_policy():
    client = client_with_routes(
        {
            "/sca/001": {"affected_items": [{"policy_id": "cis_amazon_linux_2023"}]},
            "/sca/001/checks/cis_amazon_linux_2023": {
                "affected_items": [{"id": 1}],
                "total_affected_items": 45,
            },
        }
    )

    data = await client.sca_checks("001", result="failed")

    assert data["total_affected_items"] == 45
    paths = [c.args[0] for c in client._get.await_args_list]
    assert "/sca/001/checks" not in paths


@pytest.mark.asyncio
async def test_sca_checks_asks_for_a_policy_when_there_are_several():
    client = client_with_routes(
        {"/sca/001": {"affected_items": [{"policy_id": "cis_a"}, {"policy_id": "cis_b"}]}}
    )

    with pytest.raises(ValueError, match="cis_a, cis_b"):
        await client.sca_checks("001")


# --- wazuh_search_mitre: 4.x filters techniques with q=external_id=... ------


@pytest.mark.asyncio
async def test_mitre_filters_by_external_id():
    client = client_with_routes({"/mitre/techniques": {"affected_items": []}})

    await client.mitre(technique_id="T1110")

    params = client._get.await_args.kwargs["params"]
    assert params["q"] == "external_id=T1110"
    assert "technique_id" not in params


# --- cluster tools on a single-node manager --------------------------------


@pytest.mark.asyncio
async def test_cluster_status_on_a_single_node_manager():
    client = client_with_routes(
        {"/cluster/status": {"enabled": "no", "running": "no"}, "/cluster/nodes": CLUSTER_OFF}
    )

    out = await call(register_manager, client, "wazuh_cluster_status")

    assert "error" not in out
    assert out["cluster_status"] == {"enabled": "no", "running": "no"}


@pytest.mark.asyncio
async def test_cluster_node_stats_on_a_single_node_manager():
    client = client_with_routes(
        {
            "/cluster/wazuh.manager/stats": CLUSTER_OFF,
            "/cluster/wazuh.manager/info": CLUSTER_OFF,
            "/manager/daemons/stats": {"affected_items": [{"events": 10}]},
            "/manager/info": {"affected_items": [{"version": "v4.14.8"}]},
        }
    )

    out = await call(register_manager, client, "wazuh_cluster_node_stats", node_id="wazuh.manager")

    assert "error" not in out
    assert out["configuration"] == {"affected_items": [{"version": "v4.14.8"}]}


# --- wazuh_rules_coverage_map: REST rules carry mitre as a list --------------


@pytest.mark.asyncio
async def test_coverage_map_reads_mitre_as_a_list():
    client = AsyncMock(spec=WazuhClient)
    client.list_rules.return_value = {
        "affected_items": [
            {"id": 5710, "level": 5, "mitre": ["T1110", "T1021.004"], "pci_dss": ["10.2.4"]},
            {"id": 5712, "level": 10, "mitre": ["T1110"]},
        ],
        "total_affected_items": 2,
    }

    out = await call(register_analysis, client, "wazuh_rules_coverage_map")

    assert "error" not in out
    assert sorted(out["mitre_coverage"]) == ["T1021.004", "T1110"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode, expected_select", [("triage", "external_id,name,tactics"), ("detail", None)]
)
async def test_search_mitre_sends_mitre_fields_not_alert_fields(mode, expected_select):
    """The output-mode field lists are alert fields (timestamp, id, location,
    rule.*); /mitre/techniques rejects them: "Not a valid select field"."""
    client = AsyncMock(spec=WazuhClient)
    client.mitre.return_value = {"affected_items": [], "total_affected_items": 0}

    out = await call(register_hunting, client, "wazuh_search_mitre", technique_id="T1110", mode=mode)

    assert "error" not in out
    assert client.mitre.await_args.kwargs["select"] == expected_select
