"""
Alert triage & investigation tools.

- wazuh_list_alerts
- wazuh_get_alert
- wazuh_alert_summary
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.output import compact, get_select_for_mode
from wazuh_mcp.safe_tool import safe_tool
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result
from wazuh_mcp.validators import (
    validate_agent_id,
    validate_limit,
    validate_mitre_technique,
    validate_offset,
    validate_rule_id,
    validate_soft_text,
)


def register_alerts(mcp: FastMCP, client: WazuhClient) -> None:
    """Register all alert-related tools on the MCP server."""

    @mcp.tool(
        name="wazuh_list_alerts",
        description=(
            "Query Wazuh security alerts with powerful filters. "
            "Use this to triage incidents, hunt for specific threat patterns, "
            "or get an overview of recent security events."
        ),
    )
    @safe_tool("wazuh_list_alerts")
    async def wazuh_list_alerts(
        agent_id: Optional[str] = types.Field(
            default=None,
            description="Filter alerts to a specific agent ID (e.g., '001')",
        ),
        agents_list: Optional[str] = types.Field(
            default=None,
            description="Comma-separated agent IDs to filter (e.g., '001,002,003')",
        ),
        min_level: Optional[int] = types.Field(
            default=None,
            description="Minimum rule level (3-15). Higher = more severe. Use 12+ for critical only.",
        ),
        rule_id: Optional[str] = types.Field(
            default=None,
            description="Filter by a specific Wazuh rule ID (e.g., '5710' for SSH brute force)",
        ),
        rule_ids: Optional[str] = types.Field(
            default=None,
            description="Comma-separated rule IDs (e.g., '5710,5712,5760')",
        ),
        mitre_id: Optional[str] = types.Field(
            default=None,
            description="Filter by MITRE ATT&CK technique ID (e.g., 'T1110' for brute force)",
        ),
        search: Optional[str] = types.Field(
            default=None,
            description="Free-text search across alert fields (IP, hostname, command, etc.)",
        ),
        sort: Optional[str] = types.Field(
            default=None,
            description="Sort field, prefix with '-' for descending (e.g., '-timestamp')",
        ),
        limit: int = types.Field(
            default=50,
            description="Maximum number of alerts to return (1-500)",
        ),
        offset: int = types.Field(
            default=0,
            description="Pagination offset for scrolling through results",
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
        if agent_id is not None:
            validate_agent_id(agent_id)
        if rule_id is not None:
            validate_rule_id(rule_id)
        if mitre_id is not None:
            validate_mitre_technique(mitre_id)
        if search is not None:
            validate_soft_text(search)
        if sort is not None:
            validate_soft_text(sort)
        limit = validate_limit(limit, max_limit=500)
        offset = validate_offset(offset)

        # Resolve select from mode if available
        select = get_select_for_mode(mode)

        data = await client.list_alerts(
            agent_id=agent_id,
            agents_list=agents_list,
            min_level=min_level,
            rule_id=rule_id,
            rule_ids=rule_ids,
            mitre_id=mitre_id,
            search=search,
            select=select,
            sort=sort or "-timestamp",
            limit=limit,
            offset=offset,
        )
        items = extract_items(data)
        total = extract_total(data)

        # Add a human-readable summary
        summary_parts = [f"Found {total} alert(s)"]
        if min_level:
            summary_parts.append(f"with level >= {min_level}")
        if rule_id:
            summary_parts.append(f"for rule {rule_id}")
        if mitre_id:
            summary_parts.append(f"mapped to {mitre_id}")

        result = paginated_result(
            items, total, offset, limit, summary=" | ".join(summary_parts)
        )
        if compact_output:
            result = compact(result)
        return format_json(result)

    @mcp.tool(
        name="wazuh_get_alert",
        description=(
            "Fetch a single Wazuh alert by its ID with full contextual detail. "
            "Use this when investigating a specific alert from wazuh_list_alerts results."
        ),
    )
    @safe_tool("wazuh_get_alert")
    async def wazuh_get_alert(
        alert_id: str = types.Field(
            description="The alert ID to retrieve (from wazuh_list_alerts output)",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        validate_soft_text(alert_id, param_name="alert_id")
        alert = await client.get_alert(alert_id)
        if compact_output:
            alert = compact(alert)
        return format_json(alert)

    @mcp.tool(
        name="wazuh_alert_summary",
        description=(
            "Get a high-level summary of recent alerts: severity distribution, "
            "top attacking IPs, most triggered rules, and MITRE technique coverage. "
            "Use this as the first step in security posture assessment or shift handoff."
        ),
    )
    @safe_tool("wazuh_alert_summary")
    async def wazuh_alert_summary(
        hours_back: int = types.Field(
            default=24,
            description="Number of hours to look back for the summary (default: 24)",
        ),
        min_level: int = types.Field(
            default=7,
            description="Minimum alert level to include (default: 7, moderate and above)",
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
        select = (
            get_select_for_mode(mode)
            or "rule.id,rule.level,rule.description,rule.mitre.id,agent.id,agent.name,data.srcip,timestamp"
        )
        data = await client.list_alerts(
            min_level=min_level,
            sort="-timestamp",
            limit=500,
            select=select,
        )
        items = extract_items(data)
        total = extract_total(data)

        if not items:
            return format_json(
                {
                    "summary": f"No alerts level >= {min_level} in the last {hours_back}h",
                    "total": 0,
                }
            )

        # Compute aggregates
        level_counts = Counter()
        rule_counts: Counter = Counter()
        mitre_counts: Counter = Counter()
        agent_counts: Counter = Counter()
        srcip_counts: Counter = Counter()

        for alert in items:
            rule = alert.get("rule", {})
            agent = alert.get("agent", {})
            data_fields = alert.get("data", {})

            level = rule.get("level", "unknown")
            rule_desc = rule.get("description", "unknown")
            level_counts[level] += 1
            rule_counts[rule_desc] += 1

            for mitre_entry in rule.get("mitre", {}).get("id", []) or []:
                mitre_counts[mitre_entry] += 1

            agent_name = agent.get("name", "unknown")
            agent_counts[agent_name] += 1

            srcip = data_fields.get("srcip")
            if srcip:
                srcip_counts[srcip] += 1

        summary = {
            "total_alerts_analyzed": len(items),
            "total_alerts_available": total,
            "time_window_hours": hours_back,
            "min_level": min_level,
            # Levels are numeric; key them as strings and order by severity
            # rather than by frequency, which is what a histogram wants.
            "severity_distribution": {
                str(level): count
                for level, count in sorted(
                    level_counts.items(),
                    key=lambda kv: (isinstance(kv[0], int), kv[0]),
                    reverse=True,
                )
            },
            "top_rules": dict(rule_counts.most_common(10)),
            "top_mitre_techniques": dict(mitre_counts.most_common(10)),
            "top_agents": dict(agent_counts.most_common(10)),
            "top_source_ips": dict(srcip_counts.most_common(10)),
        }
        if compact_output:
            summary = compact(summary)
        return format_json(summary)
