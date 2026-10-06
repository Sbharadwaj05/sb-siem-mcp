"""
WazuhClient.run_active_response must send what the Wazuh 4.x API accepts.

Checked against a live Wazuh 4.14.8 manager in October 2026:
- PUT /active-response targets agents with the agents_list query
  parameter; a body containing agent_id or custom is rejected with
  "Invalid field found {'agent_id', 'custom'}".
- Active-response scripts read the IP from alert.data.srcip; with only
  arguments, host-deny logs "Cannot read 'srcip' from data".
- A command starting with "!" runs that script on the agent by name.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.errors import WazuhAPIError


@pytest.fixture
def client():
    c = WazuhClient(base_url="https://wazuh.test:55000")
    c._request = AsyncMock(return_value={"affected_items": ["001"]})
    return c


@pytest.mark.asyncio
async def test_targets_agent_by_query_and_passes_srcip_as_alert_data(client):
    await client.run_active_response(
        agent_id="001", command="firewall-drop", arguments=["srcip", "10.0.0.50", "-"]
    )

    client._request.assert_awaited_once_with(
        "PUT",
        "/active-response",
        params={"agents_list": "001"},
        json={
            "command": "firewall-drop",
            "arguments": ["srcip", "10.0.0.50", "-"],
            "alert": {"data": {"srcip": "10.0.0.50"}},
        },
    )


@pytest.mark.asyncio
async def test_without_arguments_sends_only_the_command(client):
    await client.run_active_response(agent_id="005", command="restart-wazuh")

    client._request.assert_awaited_once_with(
        "PUT",
        "/active-response",
        params={"agents_list": "005"},
        json={"command": "restart-wazuh"},
    )


@pytest.mark.asyncio
async def test_custom_runs_the_agent_script_by_name(client):
    await client.run_active_response(agent_id="002", command="restart.sh", custom=True)

    sent = client._request.await_args.kwargs["json"]
    assert sent == {"command": "!restart.sh"}


@pytest.mark.asyncio
async def test_invalid_srcip_is_rejected_before_sending(client):
    with pytest.raises(ValueError):
        await client.run_active_response(
            agent_id="001", command="firewall-drop", arguments=["srcip", "10.0.0.50;id"]
        )

    client._request.assert_not_called()


def test_api_error_names_the_per_agent_reason():
    """Wazuh puts the useful reason in failed_items, not in message."""
    resp = httpx.Response(
        200,
        json={
            "data": {
                "affected_items": [],
                "failed_items": [
                    {
                        "error": {
                            "code": 1652,
                            "message": "The command used is not defined in the configuration.",
                        },
                        "id": ["001"],
                    }
                ],
            },
            "message": "AR command was not sent to any agent",
            "error": 1,
        },
    )

    with pytest.raises(WazuhAPIError) as excinfo:
        WazuhClient._unwrap(resp)

    assert "not defined in the configuration" in excinfo.value.message
