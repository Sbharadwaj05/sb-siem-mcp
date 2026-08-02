"""
Output sanitizer — redacts credentials, API keys, and secrets
from Wazuh response data before it reaches the LLM.

Patrols for:
- Base64-encoded credentials (common in Wazuh agent configs)
- AWS / GCP / Azure access keys
- Generic API key patterns
- Password fields in decoded alert data
- JWT tokens and session cookies
- Private SSH keys (PEM headers)

Usage:
    from wazuh_mcp.sanitizer import sanitize
    safe_data = sanitize(raw_data)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Union

# ---------------------------------------------------------------------------
# Redaction rules — compiled regex patterns
# ---------------------------------------------------------------------------

REDACTION_RULES: list[tuple[re.Pattern, str]] = [
    # AWS access key ID (AKIA...)
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_KEY_REDACTED"),
    # AWS secret access key patterns (40-char base64)
    (
        re.compile(r"(?<=[^A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?=[^A-Za-z0-9/+=])"),
        "AWS_SECRET_REDACTED",
    ),
    # GCP service account keys
    (
        re.compile(r'"private_key":\s*"-----BEGIN[^"]*-----"'),
        '"private_key":"GCP_KEY_REDACTED"',
    ),
    # Generic API keys (common patterns: sk-, key-, api-, token- prefixes)
    (re.compile(r"\b(sk-[A-Za-z0-9]{32,})\b"), "API_KEY_REDACTED"),
    (re.compile(r"\b(key-[A-Za-z0-9]{32,})\b"), "API_KEY_REDACTED"),
    # JWT tokens (header.payload.signature)
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "JWT_REDACTED",
    ),
    # Generic password patterns in JSON: "password":"..." or "passwd":"..."
    (
        re.compile(r'"(?:password|passwd|secret|token|api_key)"\s*:\s*"[^"]+?"'),
        '"REDACTED_FIELD":"***REDACTED***"',
    ),
    # Private SSH keys (PEM header)
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "SSH_KEY_REDACTED",
    ),
    # Basic auth headers (Authorization: Basic base64)
    (
        re.compile(r"(?:Authorization|auth):\s*Basic\s+[A-Za-z0-9+/=]+"),
        "AUTH_HEADER_REDACTED",
    ),
    # Bearer tokens in logs
    (re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+"), "BEARER_TOKEN_REDACTED"),
]

# Sensitive field names to redact entirely
SENSITIVE_FIELDS: set[str] = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "access_key",
    "secret_key",
    "authorization",
    "auth",
    "credential",
    "credentials",
    "ssh_key",
    "sshkey",
    "pem",
    "certificate",
}


def _redact_string(value: str) -> str:
    """Apply all redaction rules to a string value."""
    for pattern, replacement in REDACTION_RULES:
        value = pattern.sub(replacement, value)
    return value


def sanitize(data: Any, *, max_depth: int = 10) -> Any:
    """
    Recursively sanitize a data structure by redacting secrets.

    Supports dicts, lists, strings. Other types pass through unchanged.
    Guards against recursion bombs via max_depth.
    """
    if max_depth <= 0:
        return "[MAX_DEPTH_EXCEEDED]"

    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            # Keys are not always strings — aggregation counters keyed on
            # numeric fields (rule.level, for one) produce int keys.
            if isinstance(key, str) and key.lower() in SENSITIVE_FIELDS:
                sanitized[key] = "***REDACTED***"
                continue

            # Recursively sanitize nested values
            sanitized[key] = sanitize(value, max_depth=max_depth - 1)
        return sanitized

    if isinstance(data, list):
        return [sanitize(item, max_depth=max_depth - 1) for item in data]

    if isinstance(data, str):
        return _redact_string(data)

    # int, float, bool, None — pass through
    return data
