"""
Manager & cluster administration tools.

- wazuh_manager_stats
- wazuh_cluster_status
- wazuh_rules_info
- wazuh_manager_logs
- wazuh_cluster_node_stats
"""

from __future__ import annotations

from typing import Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.output import compact
from wazuh_mcp.safe_tool import safe_tool
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result
from wazuh_mcp.validators import (
    validate_compliance_id,
    validate_limit,
    validate_mitre_technique,
    validate_offset,
    validate_soft_text,
)


def register_manager(mcp: FastMCP, client: WazuhClient) -> None:
    """Register all manager/cluster tools on the MCP server."""

    @mcp.tool(
        name="wazuh_manager_stats",
        description=(
            "Retrieve Wazuh manager daemon statistics: events per second (EPS), "
            "queue sizes, processed events, and daemon health. Essential for "
            "capacity planning and troubleshooting performance issues."
        ),
    )
    @safe_tool("wazuh_manager_stats")
    async def wazuh_manager_stats(
        daemon: Optional[str] = types.Field(
            default=None,
            description=(
                "Specific daemon to query: 'analysisd', 'remoted', 'syscheckd', "
                "'wmodules', 'authd', 'monitord', 'logcollector'. Leave empty for all."
            ),
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        if daemon is not None:
            validate_soft_text(daemon, param_name="daemon")

        data = await client.manager_stats(daemon=daemon)
        if compact_output:
            data = compact(data)
        return format_json(data)

    @mcp.tool(
        name="wazuh_cluster_status",
        description=(
            "Get the Wazuh cluster health status: node list, sync status, "
            "and connectivity between manager nodes. Use this when checking "
            "if the cluster is healthy or diagnosing replication failures."
        ),
    )
    @safe_tool("wazuh_cluster_status")
    async def wazuh_cluster_status(
        include_nodes: bool = types.Field(
            default=True,
            description="Include detailed per-node information in the response",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        status_data = await client.cluster_status()
        # A single-node manager reports {"enabled": "no", "running": "no"},
        # and /cluster/nodes then fails with "Cluster is not running".
        running = isinstance(status_data, dict) and status_data.get("running") == "yes"
        nodes_data = await client.cluster_nodes() if include_nodes and running else {}

        result = {
            "cluster_status": status_data,
            "nodes": nodes_data,
        }
        if compact_output:
            result = compact(result)
        return format_json(result)

    @mcp.tool(
        name="wazuh_rules_info",
        description=(
            "Search and list Wazuh detection rules. Filter by rule level, "
            "compliance framework (PCI DSS, GDPR, HIPAA, NIST 800-53), "
            "or MITRE ATT&CK technique. Essential for understanding your "
            "detection coverage and tuning rules."
        ),
    )
    @safe_tool("wazuh_rules_info")
    async def wazuh_rules_info(
        search: Optional[str] = types.Field(
            default=None,
            description="Search rules by name, description, or ID",
        ),
        level: Optional[int] = types.Field(
            default=None,
            description="Filter by rule level (0-15). Higher = more severe.",
        ),
        pci: Optional[str] = types.Field(
            default=None,
            description="Filter by PCI DSS requirement (e.g., '10.2.5')",
        ),
        gdpr: Optional[str] = types.Field(
            default=None,
            description="Filter by GDPR article (e.g., 'Art._32')",
        ),
        hipaa: Optional[str] = types.Field(
            default=None,
            description="Filter by HIPAA control (e.g., '164.312.b')",
        ),
        nist_800_53: Optional[str] = types.Field(
            default=None,
            description="Filter by NIST 800-53 control (e.g., 'AU-12')",
        ),
        mitre_technique: Optional[str] = types.Field(
            default=None,
            description="Filter by MITRE ATT&CK technique ID (e.g., 'T1059')",
        ),
        limit: int = types.Field(
            default=100,
            description="Maximum rules to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        if search is not None:
            validate_soft_text(search)
        if pci is not None:
            validate_compliance_id(pci, param_name="pci")
        if gdpr is not None:
            validate_compliance_id(gdpr, param_name="gdpr")
        if hipaa is not None:
            validate_compliance_id(hipaa, param_name="hipaa")
        if nist_800_53 is not None:
            validate_compliance_id(nist_800_53, param_name="nist_800_53")
        if mitre_technique is not None:
            validate_mitre_technique(mitre_technique)
        limit = validate_limit(limit, max_limit=500)
        offset = validate_offset(offset)

        data = await client.list_rules(
            search=search,
            level=level,
            pci=pci,
            gdpr=gdpr,
            hipaa=hipaa,
            nist_800_53=nist_800_53,
            mitre=mitre_technique,
            limit=limit,
            offset=offset,
        )
        items = extract_items(data)
        total = extract_total(data)

        summary = f"Found {total} rule(s)"
        if search:
            summary += f" matching '{search}'"
        if level:
            summary += f" at level {level}"
        filters = [f for f in [pci, gdpr, hipaa, nist_800_53, mitre_technique] if f]
        if filters:
            summary += f" — compliance: {', '.join(filters)}"

        result = paginated_result(items, total, offset, limit, summary=summary)
        if compact_output:
            result = compact(result)
        return format_json(result)

    @mcp.tool(
        name="wazuh_manager_logs",
        description=(
            "Retrieve Wazuh manager logs for troubleshooting. "
            "Filter by category ('ossec', 'api', 'all'), search for "
            "specific errors or warnings, and paginate through results."
        ),
    )
    @safe_tool("wazuh_manager_logs")
    async def wazuh_manager_logs(
        category: Optional[str] = types.Field(
            default=None,
            description="Log category: 'all', 'ossec', or 'api'",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Search logs for specific text (error messages, etc.)",
        ),
        limit: int = types.Field(
            default=50,
            description="Maximum log entries to return (1-200)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        if category is not None:
            validate_soft_text(category, param_name="category")
        if search is not None:
            validate_soft_text(search)
        limit = validate_limit(limit, max_limit=200)
        offset = validate_offset(offset)

        data = await client.manager_logs(
            category=category,
            search=search,
            sort="-timestamp",
            limit=limit,
            offset=offset,
        )
        items = extract_items(data)
        total = extract_total(data)
        summary = "Manager logs"
        if category:
            summary += f" (category: {category})"
        if search:
            summary += f" matching '{search}'"
        result = paginated_result(items, total, offset, limit, summary=summary)
        if compact_output:
            result = compact(result)
        return format_json(result)

    @mcp.tool(
        name="wazuh_cluster_node_stats",
        description=(
            "Get detailed statistics for a specific Wazuh cluster node. "
            "Shows per-node EPS, queue sizes, daemon status, and resource "
            "utilization. Essential for diagnosing cluster imbalances."
        ),
    )
    @safe_tool("wazuh_cluster_node_stats")
    async def wazuh_cluster_node_stats(
        node_id: str = types.Field(
            description="Cluster node ID to inspect (e.g., 'master-node', 'worker-1')",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        validate_soft_text(node_id, param_name="node_id")

        stats = await client.cluster_node_stats(node_id)
        info = await client.cluster_node_info(node_id)
        result = {"node_id": node_id, "configuration": info, "statistics": stats}
        if compact_output:
            result = compact(result)
        return format_json(result)
