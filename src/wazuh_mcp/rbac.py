"""
Role-Based Access Control (RBAC) for Wazuh MCP tools.

Restricts which tools are available based on the authenticated
Wazuh API user's role. Configured via environment variables or
a JSON policy file.

Role hierarchy (least → most privilege):
  viewer  — Read-only: alerts, agents, compliance, rules
  analyst — Viewer + threat hunting, MITRE search, groups, lists
  admin   — Analyst + manager stats, logs, cluster management
  soc     — Admin + active response, agent commands ⚠️

Default: If no RBAC config is found, all tools are available
(backward-compatible with existing deployments).

Usage:
  Set WAZUH_RBAC_ROLE=analyst to restrict to analyst-level tools.
  Set WAZUH_RBAC_POLICY=/path/to/rbac.json for custom policies.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Set

logger = logging.getLogger("wazuh-mcp.rbac")

# ---------------------------------------------------------------------------
# Built-in role definitions — which tools each role adds to the one below
# ---------------------------------------------------------------------------

_ROLE_ADDITIONS: Dict[str, FrozenSet[str]] = {
    "viewer": frozenset(
        {
            # Alerts (read-only)
            "wazuh_list_alerts",
            "wazuh_get_alert",
            "wazuh_alert_summary",
            # Agents (read-only)
            "wazuh_list_agents",
            "wazuh_get_agent",
            "wazuh_agent_health",
            # Compliance (read-only)
            "wazuh_sca_status",
            "wazuh_sca_checks",
            "wazuh_compliance_report",
            # Rules (read-only)
            "wazuh_rules_info",
            "wazuh_rules_coverage_map",
            # Groups (read-only)
            "wazuh_list_groups",
            "wazuh_get_group",
            "wazuh_group_agents",
        }
    ),
    "analyst": frozenset(
        {
            # Everything viewer has, plus:
            # Hunting
            "wazuh_search_events",
            "wazuh_query_fim",
            "wazuh_query_vulnerabilities",
            "wazuh_search_mitre",
            # Lists (read-only)
            "wazuh_list_cdb_lists",
            "wazuh_get_cdb_list",
            # Analysis
            "wazuh_incident_timeline",
            "wazuh_vulnerability_heatmap",
        }
    ),
    "admin": frozenset(
        {
            # Everything analyst has, plus:
            # Manager
            "wazuh_manager_stats",
            "wazuh_manager_logs",
            "wazuh_cluster_status",
            "wazuh_cluster_node_stats",
        }
    ),
    "soc": frozenset(
        {
            # Everything admin has, plus:
            # Active response ⚠️
            "wazuh_run_active_response",
            "wazuh_agent_command",
        }
    ),
}

# Roles are cumulative: each one holds every tool of the tiers below it.
ROLE_TOOLS: Dict[str, FrozenSet[str]] = {}
_granted: FrozenSet[str] = frozenset()
for _role, _tools in _ROLE_ADDITIONS.items():
    _granted = _granted | _tools
    ROLE_TOOLS[_role] = _granted


def _load_custom_policy(path: str) -> Dict[str, FrozenSet[str]]:
    """Load a custom RBAC policy from a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    policy: Dict[str, FrozenSet[str]] = {}
    for role, tools in data.items():
        if isinstance(tools, list):
            policy[role] = frozenset(tools)
        elif isinstance(tools, dict) and "inherits" in tools:
            # Support role inheritance
            base = policy.get(tools["inherits"], frozenset())
            extra = frozenset(tools.get("tools", []))
            policy[role] = base | extra
        else:
            policy[role] = frozenset(tools)
    return policy


class RBACEnforcer:
    """
    Enforces tool access based on the authenticated user's role.

    Thread-safe read-only after initialization.
    """

    def __init__(
        self,
        policy: Optional[Dict[str, FrozenSet[str]]] = None,
        default_role: Optional[str] = None,
    ) -> None:
        self._policy = policy or {}
        self._default_role = default_role
        self._enabled = bool(self._policy)

        if self._enabled:
            all_tools: Set[str] = set()
            for tools in self._policy.values():
                all_tools.update(tools)
            logger.info(
                "RBAC enabled: %d roles, %d unique tools protected",
                len(self._policy),
                len(all_tools),
            )

    def is_allowed(self, tool_name: str, role: Optional[str] = None) -> bool:
        """
        Check if a tool is allowed for the given role.

        Returns True if:
        - RBAC is disabled (no policy loaded)
        - The role has explicit access to the tool
        - No role is specified (defer to default_role or allow)
        """
        if not self._enabled:
            return True

        effective_role = role or self._default_role
        if effective_role is None:
            # No role specified and no default — allow all (backward compat)
            return True

        allowed = self._policy.get(effective_role, frozenset())
        return tool_name in allowed

    def get_allowed_tools(self, role: Optional[str] = None) -> FrozenSet[str]:
        """Return the set of tools a role is allowed to use."""
        if not self._enabled:
            return frozenset()  # empty = all allowed
        effective_role = role or self._default_role
        if effective_role is None:
            return frozenset()
        return self._policy.get(effective_role, frozenset())


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_rbac: Optional[RBACEnforcer] = None


def get_rbac_enforcer() -> RBACEnforcer:
    """Return the global RBAC enforcer singleton."""
    global _rbac
    if _rbac is None:
        policy_path = os.getenv("WAZUH_RBAC_POLICY", "")
        default_role = os.getenv("WAZUH_RBAC_ROLE", None)

        if policy_path and Path(policy_path).exists():
            policy = _load_custom_policy(policy_path)
        elif default_role:
            # Use built-in roles if a default_role is set
            policy = dict(ROLE_TOOLS)
        else:
            # No RBAC — allow everything
            policy = {}

        _rbac = RBACEnforcer(policy=policy, default_role=default_role)

    return _rbac


def check_access(tool_name: str, role: Optional[str] = None) -> bool:
    """Convenience function: check if a tool is accessible."""
    return get_rbac_enforcer().is_allowed(tool_name, role)
