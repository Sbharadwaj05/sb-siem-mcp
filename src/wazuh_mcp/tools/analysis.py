"""
Advanced security analysis tools.

- wazuh_rules_coverage_map  — MITRE/NIST/PCI/GDPR rule coverage matrix
- wazuh_vulnerability_heatmap — CVE severity heatmap across agents
- wazuh_incident_timeline  — auto-generated incident timeline
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.output import compact
from wazuh_mcp.safe_tool import safe_tool
from wazuh_mcp.utils import extract_items, extract_total, format_json, paginated_result
from wazuh_mcp.validators import (
    validate_limit,
    validate_severity,
    validate_soft_text,
)


def register_analysis(mcp: FastMCP, client: WazuhClient) -> None:
    """Register advanced security analysis tools."""

    @mcp.tool(
        name="wazuh_rules_coverage_map",
        description=(
            "Generate a coverage map showing which Wazuh rules map to which "
            "MITRE ATT&CK techniques, NIST 800-53 controls, PCI DSS requirements, "
            "GDPR articles, and HIPAA controls. Essential for compliance gap "
            "analysis and detection engineering."
        ),
    )
    @safe_tool("wazuh_rules_coverage_map")
    async def wazuh_rules_coverage_map(
        framework: Optional[str] = types.Field(
            default=None,
            description=(
                "Filter by framework: 'mitre', 'nist_800_53', 'pci_dss', "
                "'gdpr', 'hipaa'. Leave empty for all frameworks."
            ),
        ),
        min_level: int = types.Field(
            default=5,
            description="Minimum rule level to include (default: 5)",
        ),
        limit: int = types.Field(
            default=500,
            description="Maximum rules to analyze (1-1000)",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        if framework is not None:
            validate_soft_text(framework, param_name="framework")
        limit = validate_limit(limit, max_limit=1000)

        # Fetch rules with compliance mappings
        kwargs: dict = {"limit": limit}
        if framework:
            if framework == "nist_800_53":
                kwargs["nist_800_53"] = "*"
            elif framework == "mitre":
                kwargs["mitre"] = "*"
            elif framework == "pci_dss":
                kwargs["pci"] = "*"
            elif framework == "gdpr":
                kwargs["gdpr"] = "*"
            elif framework == "hipaa":
                kwargs["hipaa"] = "*"

        data = await client.list_rules(**kwargs)
        items = extract_items(data)

        # Build coverage matrix
        mitre_map: dict = defaultdict(list)
        nist_map: dict = defaultdict(list)
        pci_map: dict = defaultdict(list)
        gdpr_map: dict = defaultdict(list)
        hipaa_map: dict = defaultdict(list)
        level_distribution: Counter = Counter()
        total_rules = 0

        for rule in items:
            rule_id = rule.get("id", "unknown")
            level = rule.get("level", 0)
            if level < min_level:
                continue

            total_rules += 1
            level_distribution[level] += 1

            mitre_ids = rule.get("mitre", {}).get("id", []) or []
            for m_id in mitre_ids:
                mitre_map[m_id].append(str(rule_id))

            nist_ids = rule.get("nist_800_53", []) or []
            for n_id in nist_ids:
                nist_map[n_id].append(str(rule_id))

            pci_ids = rule.get("pci_dss", []) or []
            for p_id in pci_ids:
                pci_map[p_id].append(str(rule_id))

            gdpr_ids = rule.get("gdpr", []) or []
            for g_id in gdpr_ids:
                gdpr_map[g_id].append(str(rule_id))

            hipaa_ids = rule.get("hipaa", []) or []
            for h_id in hipaa_ids:
                hipaa_map[h_id].append(str(rule_id))

        coverage = {
            "total_rules_analyzed": total_rules,
            "min_level": min_level,
            "level_distribution": dict(level_distribution.most_common()),
            "mitre_coverage": {
                technique: {"rule_count": len(rules), "rule_ids": rules[:10]}
                for technique, rules in sorted(mitre_map.items())
            },
            "nist_800_53_coverage": {
                control: {"rule_count": len(rules), "rule_ids": rules[:10]}
                for control, rules in sorted(nist_map.items())
            },
            "pci_dss_coverage": {
                req: {"rule_count": len(rules), "rule_ids": rules[:10]}
                for req, rules in sorted(pci_map.items())
            },
            "gdpr_coverage": {
                article: {"rule_count": len(rules), "rule_ids": rules[:10]}
                for article, rules in sorted(gdpr_map.items())
            },
            "hipaa_coverage": {
                control: {"rule_count": len(rules), "rule_ids": rules[:10]}
                for control, rules in sorted(hipaa_map.items())
            },
        }
        if compact_output:
            coverage = compact(coverage)
        return format_json(coverage)

    @mcp.tool(
        name="wazuh_vulnerability_heatmap",
        description=(
            "Generate a vulnerability heatmap showing CVE severity distribution "
            "across agents. Identifies which systems have the most critical "
            "unpatched vulnerabilities. Essential for patch prioritization."
        ),
    )
    @safe_tool("wazuh_vulnerability_heatmap")
    async def wazuh_vulnerability_heatmap(
        severity: Optional[str] = types.Field(
            default=None,
            description="Filter by minimum severity: 'Critical', 'High', 'Medium', 'Low'",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        if severity is not None:
            validate_severity(severity)

        # Get all agents
        agents_data = await client.list_agents(limit=500)
        agent_items = extract_items(agents_data)

        heatmap: list[dict] = []
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0

        sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        min_sev_value = sev_order.get(severity, 0) if severity else 0

        for agent in agent_items:
            agent_id = str(agent.get("id", ""))
            agent_name = agent.get("name", "unknown")

            try:
                vuln_data = await client.vulnerabilities(agent_id=agent_id, limit=500)
                vuln_items = extract_items(vuln_data)

                counts: Counter = Counter()
                for vuln in vuln_items:
                    # Indexer documents (Wazuh 4.x) nest it under "vulnerability";
                    # the old REST API put it at the top level.
                    sev = (vuln.get("vulnerability") or {}).get("severity") or vuln.get(
                        "severity", "Unknown"
                    )
                    counts[sev] += 1

                critical = counts.get("Critical", 0)
                high = counts.get("High", 0)
                medium = counts.get("Medium", 0)
                low = counts.get("Low", 0)

                total_critical += critical
                total_high += high
                total_medium += medium
                total_low += low

                heatmap.append(
                    {
                        "agent_id": agent_id,
                        "agent_name": agent_name,
                        "critical": critical,
                        "high": high,
                        "medium": medium,
                        "low": low,
                        "total": critical + high + medium + low,
                        "risk_score": critical * 10 + high * 5 + medium * 2 + low,
                    }
                )
            except Exception:
                continue

        # Sort by risk score descending
        heatmap.sort(key=lambda x: x["risk_score"], reverse=True)

        summary = {
            "agents_analyzed": len(heatmap),
            "total_vulnerabilities": total_critical
            + total_high
            + total_medium
            + total_low,
            "totals_by_severity": {
                "critical": total_critical,
                "high": total_high,
                "medium": total_medium,
                "low": total_low,
            },
            "top_risky_agents": heatmap[:20],
        }
        if compact_output:
            summary = compact(summary)
        return format_json(summary)

    @mcp.tool(
        name="wazuh_incident_timeline",
        description=(
            "After identifying a security incident, reconstruct a timeline of "
            "all related events leading to it. Takes an alert ID, traces back "
            "through related events on the same agent, and builds a chronological "
            "timeline of what happened."
        ),
    )
    @safe_tool("wazuh_incident_timeline")
    async def wazuh_incident_timeline(
        alert_id: str = types.Field(
            description="The starting alert ID to build a timeline from",
        ),
        lookback_hours: int = types.Field(
            default=24,
            description="Hours to look back for related events (default: 24)",
        ),
        max_events: int = types.Field(
            default=100,
            description="Maximum timeline events to include",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        validate_soft_text(alert_id, param_name="alert_id")

        # Get the source alert
        alert = await client.get_alert(alert_id)
        agent_id = alert.get("agent", {}).get("id", "")
        srcip = alert.get("data", {}).get("srcip", "")

        if not agent_id:
            return format_json(
                {
                    "error": "Could not determine agent ID from alert. Cannot build timeline."
                }
            )

        timeline_events: list[dict] = []
        timeline_events.append(
            {
                "sequence": 0,
                "type": "TRIGGER_ALERT",
                "timestamp": alert.get("timestamp", "unknown"),
                "alert_id": alert_id,
                "rule": alert.get("rule", {}).get("description", "unknown"),
                "level": alert.get("rule", {}).get("level", 0),
                "source": "alert",
            }
        )

        # Search for related events on same agent
        if srcip:
            event_data = await client.search_events(
                search=srcip,
                limit=max_events,
                sort="-timestamp",
            )
            events = extract_items(event_data)
            for i, event in enumerate(events[: max_events - 1], start=1):
                timeline_events.append(
                    {
                        "sequence": i,
                        "type": "RELATED_EVENT",
                        "timestamp": event.get("timestamp", "unknown"),
                        "data": event.get("data", {}),
                        "rule": event.get("rule", {}).get("description", ""),
                        "source": "event",
                    }
                )

        # Sort by timestamp
        timeline_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        result = {
            "alert_id": alert_id,
            "agent_id": agent_id,
            "lookback_hours": lookback_hours,
            "total_events": len(timeline_events),
            "timeline": timeline_events,
        }
        if compact_output:
            result = compact(result)
        return format_json(result)
