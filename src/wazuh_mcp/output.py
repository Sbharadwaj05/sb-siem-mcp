"""
Token-efficient output modes and intelligent field selection.

Helps combat context-window exhaustion by:
1. Stripping verbose metadata from Wazuh API responses
2. Supporting a "compact" mode that returns minimal key fields
3. Providing smart default field sets for common query patterns:
   - 'triage' — alert overview (id, level, rule, agent, timestamp)
   - 'detail' — full investigation (all fields)
   - 'compliance' — SCA-focused (check, result, rationale)
   - 'hunting' — IOC-focused (file, hash, command, ip)
   - 'fleet' — agent management (name, status, os, version)

Usage:
    from wazuh_mcp.output import compact, select_fields, MODE_FIELDS
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Smart field sets — default fields for common query modes
# ---------------------------------------------------------------------------

MODE_FIELDS: Dict[str, str] = {
    # Alert triage: just enough to decide what to investigate
    "triage": (
        "id,timestamp,rule.id,rule.level,rule.description,"
        "rule.mitre.id,agent.id,agent.name,data.srcip,data.srcport,"
        "location,decoder.name"
    ),
    # Full investigation: everything
    "detail": (
        "id,timestamp,rule.id,rule.level,rule.description,rule.groups,"
        "rule.mitre.id,rule.mitre.tactic,rule.pci_dss,rule.gdpr,"
        "rule.hipaa,rule.nist_800_53,agent.id,agent.name,agent.ip,"
        "agent.os.name,data.srcip,data.srcport,data.dstip,data.dstport,"
        "data.proto,data.url,data.file,data.hash,data.command,"
        "data.process_name,location,decoder.name,full_log,syscheck.path"
    ),
    # Compliance: SCA-focused
    "compliance": (
        "policy_id,name,description,check.title,check.description,"
        "check.rationale,check.remediation,check.result,check.file,"
        "check.process,check.registry,check.command,score,pass,fail"
    ),
    # Threat hunting: IOC-focused
    "hunting": (
        "timestamp,agent.id,agent.name,data.srcip,data.srcport,"
        "data.dstip,data.dstport,data.proto,data.file,data.hash,"
        "data.command,data.process_name,data.url,data.domain,"
        "syscheck.path,syscheck.md5_after,syscheck.sha1_after,"
        "location,decoder.name"
    ),
    # Fleet management: agent view
    "fleet": (
        "id,name,status,ip,os.name,os.version,os.platform,"
        "version,lastKeepAlive,group,node_name,configSum"
    ),
}

# ---------------------------------------------------------------------------
# Agent endpoint field sets
# ---------------------------------------------------------------------------
# GET /agents rejects the whole request with a 400 if *any* select field is
# outside this list, so the alert-shaped sets above (rule.*, data.*, decoder.*)
# can never be sent there. This is the allowed list as of Wazuh 4.14.
AGENT_SELECT_FIELDS = frozenset(
    {
        "configSum",
        "dateAdd",
        "disconnection_time",
        "group",
        "group_config_status",
        "id",
        "ip",
        "lastKeepAlive",
        "manager",
        "mergedSum",
        "name",
        "node_name",
        "os.arch",
        "os.build",
        "os.codename",
        "os.major",
        "os.minor",
        "os.name",
        "os.platform",
        "os.uname",
        "os.version",
        "registerIP",
        "status",
        "status_code",
        "version",
    }
)

# What each output mode means for an agent listing. Every mode maps to
# something valid, so a caller asking for 'triage' on an agent tool gets a
# sensible agent view instead of a 400.
AGENT_MODE_FIELDS: Dict[str, str] = {
    "triage": "id,name,status,ip,os.name,version,lastKeepAlive",
    "fleet": (
        "id,name,status,ip,os.name,os.version,os.platform,"
        "version,lastKeepAlive,group,node_name,configSum"
    ),
    "detail": (
        "id,name,status,status_code,ip,registerIP,manager,node_name,group,"
        "group_config_status,os.name,os.version,os.platform,os.arch,os.uname,"
        "version,dateAdd,lastKeepAlive,disconnection_time,configSum,mergedSum"
    ),
    # Neither of these is an agent-shaped question, so give the minimum
    # identifying view rather than erroring.
    "compliance": "id,name,status,os.name,os.version,group",
    "hunting": "id,name,ip,os.name,status,lastKeepAlive",
}

# Fields to ALWAYS strip from output to save tokens
_VERBOSE_META = {
    "status",
    "status_code",
    "error",
    "message",
    "total_affected_items",
    "total_failed_items",
    "_id",
    "_index",
    "_score",
    "_source",
}


def get_select_for_mode(mode: str) -> Optional[str]:
    """Return the 'select' parameter string for a named mode, or None."""
    return MODE_FIELDS.get(mode)


def get_agent_select_for_mode(mode: str) -> str:
    """
    Return a 'select' string valid for the /agents endpoint.

    Unlike get_select_for_mode, this never returns None and never returns
    alert fields — an unknown mode falls back to the fleet view.
    """
    return AGENT_MODE_FIELDS.get(mode) or AGENT_MODE_FIELDS["fleet"]


def filter_agent_select(select: Optional[str]) -> Optional[str]:
    """
    Drop any field the /agents endpoint would reject.

    A single unrecognised field makes Wazuh 400 the entire request, so it is
    better to silently return fewer columns than to fail the call. Returns
    None if nothing survives, which means 'let the API return its default'.
    """
    if not select:
        return None
    kept = [f.strip() for f in select.split(",") if f.strip() in AGENT_SELECT_FIELDS]
    return ",".join(kept) if kept else None


def compact(data: Any, *, max_items: int = 10) -> Any:
    """
    Produce a token-efficient version of a Wazuh API response.

    - Limits arrays to max_items
    - Strips verbose metadata fields
    - Truncates long string values
    - Replaces repeated structures with summary counts
    """
    if isinstance(data, dict):
        compacted: Dict[str, Any] = {}
        for key, value in data.items():
            if key in _VERBOSE_META:
                continue
            compacted[key] = compact(value, max_items=max_items)
        return compacted

    if isinstance(data, list):
        return [compact(item, max_items=max_items) for item in data[:max_items]]

    if isinstance(data, str) and len(data) > 200:
        return data[:200] + f"... [{len(data) - 200} chars truncated]"

    return data


def format_for_llm(
    data: Any,
    *,
    mode: str = "triage",
    compact_output: bool = False,
) -> Any:
    """
    Format Wazuh API response for LLM consumption.

    Applies smart field selection (if mode is known) and optional
    compactification for token efficiency.

    Args:
        data: Raw Wazuh API response
        mode: 'triage', 'detail', 'compliance', 'hunting', 'fleet'
        compact_output: Enable token-efficient mode
    """
    result = data

    # Post-hoc field selection based on mode
    if mode and mode in MODE_FIELDS:
        result = _apply_field_selection(result, MODE_FIELDS[mode])

    if compact_output:
        result = compact(result)

    return result


def _apply_field_selection(data: Any, select_str: str) -> Any:
    """
    Post-hoc field selection: filter a Wazuh API response to only
    include fields listed in the select string (comma-separated
    dot-notation paths like 'rule.id,agent.name,data.srcip').

    Handles the Wazuh API envelope: if data has 'items' (from
    paginated_result), filters each item. Also handles lists
    and single dicts.
    """
    if not select_str or not data:
        return data

    fields = [f.strip() for f in select_str.split(",") if f.strip()]
    if not fields:
        return data

    # Build a tree of field paths: {"rule": {"id": {}, "level": {}}, "agent": {"name": {}}, ...}
    field_tree: Dict[str, Any] = {}
    for f in fields:
        parts = f.split(".")
        node = field_tree
        for p in parts:
            if p not in node:
                node[p] = {}
            node = node[p]

    def _filter_dict(d: dict, tree: dict) -> dict:
        """Recursively filter a dict to only include paths in the tree."""
        result: Dict[str, Any] = {}
        for key, subtree in tree.items():
            if key in d:
                value = d[key]
                if subtree and isinstance(value, dict):
                    result[key] = _filter_dict(value, subtree)
                elif subtree and isinstance(value, list):
                    result[key] = [
                        _filter_dict(item, subtree) if isinstance(item, dict) else item
                        for item in value
                    ]
                else:
                    result[key] = value
        return result

    # Handle the paginated_result envelope: {"items": [...], "total": ..., ...}
    if isinstance(data, dict) and "items" in data:
        result = dict(data)  # shallow copy
        items = data["items"]
        if isinstance(items, list):
            result["items"] = [
                _filter_dict(item, field_tree) if isinstance(item, dict) else item
                for item in items
            ]
        # Keep top-level envelope fields that aren't in the items list
        return result

    # Handle a list of dicts
    if isinstance(data, list):
        return [
            _filter_dict(item, field_tree) if isinstance(item, dict) else item
            for item in data
        ]

    # Handle a single dict
    if isinstance(data, dict):
        return _filter_dict(data, field_tree)

    return data
