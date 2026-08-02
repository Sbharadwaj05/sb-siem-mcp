"""
Agent & fleet management tools.

- wazuh_list_agents
- wazuh_get_agent
- wazuh_agent_health
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.output import compact, filter_agent_select, get_agent_select_for_mode
from wazuh_mcp.safe_tool import safe_tool
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result
from wazuh_mcp.validators import (
    validate_agent_id,
    validate_duration,
    validate_limit,
    validate_offset,
    validate_soft_text,
)


def register_agents(mcp: FastMCP, client: WazuhClient) -> None:
    """Register all agent-management tools on the MCP server."""

    @mcp.tool(
        name="wazuh_list_agents",
        description=(
            "List all Wazuh agents with their status, OS, version, and last connection. "
            "Filter by status ('active', 'disconnected', 'never_connected'), "
            "search by name or IP, and control pagination."
        ),
    )
    @safe_tool("wazuh_list_agents")
    async def wazuh_list_agents(
        status: Optional[str] = types.Field(
            default=None,
            description="Filter by connection status: 'active', 'disconnected', 'never_connected', 'pending'",
        ),
        older_than: Optional[str] = types.Field(
            default=None,
            description="Show agents not seen in this duration (e.g., '1d', '4h', '30m')",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Search by agent name, IP, or ID",
        ),
        sort: Optional[str] = types.Field(
            default=None,
            description="Sort field, prefix with '-' for descending (e.g., '-lastKeepAlive')",
        ),
        limit: int = types.Field(
            default=50,
            description="Maximum agents to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
        mode: str = types.Field(
            default="triage",
            description="Output mode: 'triage', 'detail', 'compliance', 'hunting', 'fleet'",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        if status is not None:
            validate_soft_text(status, param_name="status")
        if older_than is not None:
            validate_duration(older_than)
        if search is not None:
            validate_soft_text(search)
        if sort is not None:
            validate_soft_text(sort)
        limit = validate_limit(limit, max_limit=500)
        offset = validate_offset(offset)

        # /agents only accepts agent fields — the alert-shaped mode sets used
        # by the alert tools would 400 the whole request.
        select = filter_agent_select(get_agent_select_for_mode(mode))

        data = await client.list_agents(
            status=status,
            older_than=older_than,
            select=select,
            search=search,
            sort=sort,
            limit=limit,
            offset=offset,
        )
        items = extract_items(data)
        total = extract_total(data)

        summary = f"Found {total} agent(s)"
        if status:
            summary += f" with status '{status}'"
        if search:
            summary += f" matching '{search}'"

        result = paginated_result(items, total, offset, limit, summary=summary)
        if compact_output:
            result = compact(result)
        return format_json(result)

    @mcp.tool(
        name="wazuh_get_agent",
        description=(
            "Get detailed information about a specific agent: configuration, "
            "enabled modules, OS details, group membership, and connection history."
        ),
    )
    @safe_tool("wazuh_get_agent")
    async def wazuh_get_agent(
        agent_id: str = types.Field(
            description="The agent ID to inspect (e.g., '001')",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        validate_agent_id(agent_id)
        agent = await client.get_agent(agent_id)
        if compact_output:
            agent = compact(agent)
        return format_json(agent)

    @mcp.tool(
        name="wazuh_agent_health",
        description=(
            "Get a fleet-wide health overview: counts by connection status, "
            "agents by OS/platform, version distribution, and stale agents. "
            "Use this for daily ops check or before an investigation."
        ),
    )
    @safe_tool("wazuh_agent_health")
    async def wazuh_agent_health(
        stale_threshold_hours: int = types.Field(
            default=24,
            description="Hours after which an agent is considered stale (default: 24)",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # Fetch agent summary (counts by status)
        summary_data = await client.agent_summary()
        status_counts = summary_data if isinstance(summary_data, dict) else {}

        # Fetch full agent list for detailed breakdown
        agents_data = await client.list_agents(limit=500)
        agent_items = extract_items(agents_data)

        os_counter: Counter = Counter()
        version_counter: Counter = Counter()
        stale_agents: list[dict] = []
        disconnected_agents: list[dict] = []

        for agent in agent_items:
            os_name = agent.get("os", {}).get("name", "unknown")
            os_counter[os_name] += 1

            version = agent.get("version", "unknown")
            version_counter[version] += 1

            agent_status = agent.get("status", "unknown")
            if agent_status == "disconnected":
                disconnected_agents.append(
                    {
                        "id": agent.get("id"),
                        "name": agent.get("name"),
                        "ip": agent.get("ip"),
                        "last_keepalive": agent.get("last_keepalive"),
                        "version": version,
                    }
                )

        health_report = {
            "connection_summary": status_counts,
            "total_agents": len(agent_items),
            "disconnected_agents": disconnected_agents,
            "os_breakdown": dict(os_counter.most_common()),
            "version_breakdown": dict(version_counter.most_common()),
            "stale_threshold_hours": stale_threshold_hours,
        }
        if compact_output:
            health_report = compact(health_report)
        return format_json(health_report)
