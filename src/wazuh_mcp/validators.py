"""
Input validators for all MCP tool parameters.

Blocks shell metacharacters, validates IP addresses, agent IDs,
CVE IDs, and MITRE technique IDs before they reach the Wazuh API.

Raises ValueError with a descriptive message on invalid input.
"""

from __future__ import annotations

import re
from typing import List, Optional

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

AGENT_ID_RE = re.compile(r"^\d{3}$")  # e.g., "001", "042", "255"
IP_ADDRESS_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
MITRE_TACTIC_RE = re.compile(r"^TA\d{4}$")
SHELL_META_RE = re.compile(r"[;&|`$(){}[\]!<>\\'\"]")
RULE_ID_RE = re.compile(r"^\d{1,6}$")
COMPLIANCE_ID_RE = re.compile(r"^[\w._-]+$")  # e.g., "AU-12", "Art._32", "164.312.b"
DURATION_RE = re.compile(r"^\d+[smhd]$")  # e.g., "30s", "5m", "2h", "7d"


def validate_agent_id(agent_id: str, param_name: str = "agent_id") -> str:
    """Validate a Wazuh agent ID (3-digit string like '001')."""
    if not AGENT_ID_RE.fullmatch(agent_id):
        raise ValueError(
            f"Invalid {param_name}: '{agent_id}'. Expected a 3-digit agent ID (e.g., '001')."
        )
    return agent_id


def validate_ip(ip: str, param_name: str = "ip") -> str:
    """Validate an IPv4 address."""
    if not IP_ADDRESS_RE.fullmatch(ip):
        raise ValueError(
            f"Invalid {param_name}: '{ip}'. Expected a valid IPv4 address."
        )
    return ip


def validate_cve(cve: str, param_name: str = "cve") -> str:
    """Validate a CVE ID (e.g., 'CVE-2024-3094')."""
    if not CVE_RE.fullmatch(cve):
        raise ValueError(
            f"Invalid {param_name}: '{cve}'. Expected format 'CVE-YYYY-NNNNN'."
        )
    return cve


def validate_mitre_technique(
    technique_id: str, param_name: str = "technique_id"
) -> str:
    """Validate a MITRE ATT&CK technique ID (e.g., 'T1059', 'T1547.001')."""
    if not MITRE_TECHNIQUE_RE.fullmatch(technique_id):
        raise ValueError(
            f"Invalid {param_name}: '{technique_id}'. "
            "Expected format 'T####' or 'T####.###'."
        )
    return technique_id


def validate_rule_id(rule_id: str, param_name: str = "rule_id") -> str:
    """Validate a Wazuh rule ID."""
    if not RULE_ID_RE.fullmatch(rule_id):
        raise ValueError(
            f"Invalid {param_name}: '{rule_id}'. Expected a numeric rule ID (1-6 digits)."
        )
    return rule_id


def validate_free_text(
    value: str, param_name: str = "search", max_length: int = 500
) -> str:
    """
    Validate free-text input: no shell metacharacters, reasonable length.
    Most restrictive — rejects any string with shell-special chars.
    """
    if len(value) > max_length:
        raise ValueError(
            f"{param_name} exceeds maximum length of {max_length} characters."
        )
    if SHELL_META_RE.search(value):
        raise ValueError(f"{param_name} contains prohibited characters: {value!r}")
    return value


def validate_soft_text(
    value: str, param_name: str = "search", max_length: int = 500
) -> str:
    """
    Softer text validation — only rejects null bytes and enforces length.
    Used for search fields where quoted strings are legitimate.
    """
    if "\x00" in value:
        raise ValueError(f"{param_name} contains null bytes (rejected).")
    if len(value) > max_length:
        raise ValueError(
            f"{param_name} exceeds maximum length of {max_length} characters."
        )
    return value


def validate_duration(value: str, param_name: str = "older_than") -> str:
    """Validate a duration string (e.g., '30m', '2h', '7d')."""
    if not DURATION_RE.fullmatch(value):
        raise ValueError(
            f"Invalid {param_name}: '{value}'. Expected format like '30s', '5m', '2h', '7d'."
        )
    return value


def validate_compliance_id(control_id: str, param_name: str = "control_id") -> str:
    """Validate a compliance control ID (PCI, GDPR, HIPAA, NIST)."""
    if not COMPLIANCE_ID_RE.fullmatch(control_id):
        raise ValueError(
            f"Invalid {param_name}: '{control_id}'. "
            "Expected alphanumeric with dots, underscores, or hyphens."
        )
    return control_id


def validate_limit(limit: int, max_limit: int = 500) -> int:
    """Clamp and validate pagination limit."""
    if limit < 1:
        raise ValueError("limit must be >= 1")
    return min(limit, max_limit)


def validate_offset(offset: int) -> int:
    """Validate pagination offset (must be non-negative)."""
    if offset < 0:
        raise ValueError("offset must be >= 0")
    return offset


def validate_severity(severity: str) -> str:
    """Validate CVSS severity label."""
    valid = {"critical", "high", "medium", "low", "none"}
    if severity.lower() not in valid:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(valid))}."
        )
    return severity.lower()
