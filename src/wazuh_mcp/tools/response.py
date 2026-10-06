"""
Active response & incident response tools.

.. warning::
   These tools can execute destructive commands on remote agents.
   By default, they require explicit confirmation before any action
   is taken. This is a deliberate safety mechanism — a misconfigured
   LLM prompt must not be able to block IPs or quarantine hosts silently.

- wazuh_run_active_response
- wazuh_agent_command
"""

from __future__ import annotations

import json
import secrets
import time
from typing import List, Optional

import mcp.types as types
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.audit import record_action
from wazuh_mcp.client import WazuhClient
from wazuh_mcp.output import compact
from wazuh_mcp.safe_tool import safe_tool
from wazuh_mcp.utils import format_json
from wazuh_mcp.validators import (
    validate_agent_id,
    validate_soft_text,
)

# Simple in-memory confirmation store (cleared on server restart)
_pending_confirmations: dict[str, dict] = {}


def _generate_token(action_desc: str) -> str:
    """Produce a cryptographically random confirmation token."""
    return secrets.token_hex(16)


_TOKEN_MISMATCH_ERROR = (
    "confirmation_token was issued for a different action (tool, agent_id, "
    "command or arguments differ). It has been invalidated and nothing was "
    "executed. Call without confirm=True to get a fresh token for the action "
    "you intend to run."
)


def _issued_for_other_action(
    pending: dict,
    tool: str,
    agent_id: str,
    command: str,
    arguments: Optional[List[str]],
) -> bool:
    """True unless the token was issued for exactly this tool and action."""
    issued = (
        pending.get("tool"),
        pending.get("agent_id"),
        pending.get("command"),
        pending.get("arguments"),
    )
    return issued != (tool, agent_id, command, arguments)


def register_response(mcp: FastMCP, client: WazuhClient) -> None:
    """Register all active-response tools (with safety confirmation)."""

    CONFIRMATION_WARNING = """
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  DESTRUCTIVE ACTION — CONFIRMATION REQUIRED            ║
║                                                            ║
║  This tool can execute commands that affect running        ║
║  systems (firewall rules, process termination, host        ║
║  isolation). The action has NOT been executed yet.          ║
║                                                            ║
║  To proceed, call this tool again with confirm=True        ║
║  AND the confirmation_token shown below.                    ║
║                                                            ║
║  Confirmation token: {token}                               ║
╚══════════════════════════════════════════════════════════════╝
"""

    @mcp.tool(
        name="wazuh_run_active_response",
        description=(
            "⚠️ DESTRUCTIVE: Trigger an active-response command on a Wazuh agent. "
            "Can block IPs via firewall, quarantine hosts, run custom scripts, etc.\n\n"
            "🔒 SAFETY: By default, this tool DOES NOT execute anything. It returns a "
            "confirmation prompt showing exactly what will happen. You MUST call it "
            "again with confirm=True and the correct confirmation_token to execute."
        ),
    )
    @safe_tool("wazuh_run_active_response")
    async def wazuh_run_active_response(
        agent_id: str = types.Field(
            description="Target agent ID (e.g., '001')",
        ),
        command: str = types.Field(
            description=(
                "Active response command. Common values:\n"
                "- 'firewall-drop': Block an IP via iptables/ firewall\n"
                "- 'host-deny': Add IP to /etc/hosts.deny\n"
                "- 'restart-wazuh': Restart the Wazuh agent\n"
                "- Custom scripts defined in ossec.conf"
            ),
        ),
        arguments: Optional[str] = types.Field(
            default=None,
            description=(
                "Command arguments as a JSON array string, e.g., "
                '\'["srcip", "10.0.0.50", "-"]\' for firewall-drop'
            ),
        ),
        confirm: bool = types.Field(
            default=False,
            description=(
                "🔒 SAFETY: Set to True ONLY after reviewing the confirmation "
                "prompt. You must also provide the confirmation_token."
            ),
        ),
        confirmation_token: Optional[str] = types.Field(
            default=None,
            description=(
                "🔒 SAFETY: The token from the confirmation prompt. "
                "Required when confirm=True."
            ),
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        validate_agent_id(agent_id)
        validate_soft_text(command, param_name="command")
        if arguments is not None:
            validate_soft_text(arguments, param_name="arguments")
        if confirmation_token is not None:
            validate_soft_text(confirmation_token, param_name="confirmation_token")

        # Parse arguments if provided as JSON string
        parsed_args: Optional[List[str]] = None
        if arguments:
            try:
                parsed_args = json.loads(arguments)
                if not isinstance(parsed_args, list):
                    return format_json(
                        {
                            "error": 'arguments must be a JSON array, e.g., \'["srcip", "10.0.0.50"]\''
                        }
                    )
            except json.JSONDecodeError:
                return format_json({"error": f"Invalid JSON in arguments: {arguments}"})

        # Build action description for confirmation
        action_desc = f"Active response: '{command}' on agent {agent_id}"
        if parsed_args:
            action_desc += f" with args {parsed_args}"

        # --- CONFIRMATION GATE ---
        if not confirm:
            token = _generate_token(action_desc)
            _pending_confirmations[token] = {
                "tool": "wazuh_run_active_response",
                "agent_id": agent_id,
                "command": command,
                "arguments": parsed_args,
                "created_at": time.time(),
                "expires_at": time.time() + 300,  # 5-minute expiry
            }

            return CONFIRMATION_WARNING.format(token=token) + format_json(
                {
                    "status": "AWAITING_CONFIRMATION",
                    "action": action_desc,
                    "confirmation_token": token,
                    "expires_in_seconds": 300,
                    "instructions": (
                        "Review the action above. If you intend to execute it, "
                        "call wazuh_run_active_response again with "
                        f"confirm=True and confirmation_token='{token}'"
                    ),
                }
            )

        # --- EXECUTION GATE ---
        if not confirmation_token:
            return format_json(
                {
                    "error": "confirmation_token is required when confirm=True. "
                    "Call without confirm=True first to get a token."
                }
            )

        pending = _pending_confirmations.pop(confirmation_token, None)
        if pending is None:
            return format_json(
                {
                    "error": "Invalid or expired confirmation_token. "
                    "Call without confirm=True to get a fresh token."
                }
            )

        if time.time() > pending.get("expires_at", 0):
            return format_json(
                {
                    "error": "Confirmation token has expired (5-minute window). "
                    "Call without confirm=True to get a fresh token."
                }
            )

        if _issued_for_other_action(
            pending, "wazuh_run_active_response", agent_id, command, parsed_args
        ):
            return format_json({"error": _TOKEN_MISMATCH_ERROR})

        # --- EXECUTE ---
        result = await client.run_active_response(
            agent_id=agent_id,
            command=command,
            arguments=parsed_args,
        )

        # Record to immutable audit log
        record_action(
            "wazuh_run_active_response",
            action_desc,
            {"agent_id": agent_id, "command": command, "arguments": parsed_args},
            {"status": "EXECUTED", "result": str(result)[:500]},
        )

        response_result = {
            "status": "EXECUTED",
            "action": action_desc,
            "result": result,
            "warning": "Active response has been triggered. Monitor the agent for effects.",
        }
        if compact_output:
            response_result = compact(response_result)
        return format_json(response_result)

    @mcp.tool(
        name="wazuh_agent_command",
        description=(
            "⚠️ DESTRUCTIVE: Execute an arbitrary command on a remote Wazuh agent "
            "via the active-response infrastructure.\n\n"
            "🔒 SAFETY: Same confirmation flow as wazuh_run_active_response. "
            "You MUST confirm explicitly before the command runs."
        ),
    )
    @safe_tool("wazuh_agent_command")
    async def wazuh_agent_command(
        agent_id: str = types.Field(
            description="Target agent ID",
        ),
        command: str = types.Field(
            description="Full command string to execute on the agent (use with extreme caution)",
        ),
        confirm: bool = types.Field(
            default=False,
            description="🔒 SAFETY: Set to True only after reviewing the confirmation prompt.",
        ),
        confirmation_token: Optional[str] = types.Field(
            default=None,
            description="🔒 SAFETY: The token from the confirmation prompt.",
        ),
        compact_output: bool = types.Field(
            default=False,
            description="Return token-efficient compact output",
        ),
    ) -> str:
        # --- input validation ---
        validate_agent_id(agent_id)
        validate_soft_text(command, param_name="command")
        if confirmation_token is not None:
            validate_soft_text(confirmation_token, param_name="confirmation_token")

        action_desc = f"Agent command on {agent_id}: '{command}'"

        # --- CONFIRMATION GATE ---
        if not confirm:
            token = _generate_token(action_desc)
            _pending_confirmations[token] = {
                "tool": "wazuh_agent_command",
                "agent_id": agent_id,
                "command": command,
                "arguments": None,
                "created_at": time.time(),
                "expires_at": time.time() + 300,
            }

            return CONFIRMATION_WARNING.format(token=token) + format_json(
                {
                    "status": "AWAITING_CONFIRMATION",
                    "action": action_desc,
                    "confirmation_token": token,
                    "expires_in_seconds": 300,
                    "instructions": (
                        "Review the action above. If you intend to execute it, "
                        "call wazuh_agent_command again with "
                        f"confirm=True and confirmation_token='{token}'"
                    ),
                }
            )

        # --- EXECUTION GATE ---
        if not confirmation_token:
            return format_json(
                {"error": "confirmation_token is required when confirm=True."}
            )

        pending = _pending_confirmations.pop(confirmation_token, None)
        if pending is None or time.time() > pending.get("expires_at", 0):
            return format_json(
                {
                    "error": "Invalid or expired confirmation_token. "
                    "Call without confirm=True to get a fresh token."
                }
            )

        if _issued_for_other_action(
            pending, "wazuh_agent_command", agent_id, command, None
        ):
            return format_json({"error": _TOKEN_MISMATCH_ERROR})

        # --- EXECUTE ---
        result = await client.run_active_response(
            agent_id=agent_id,
            command=command,
            custom=True,
        )

        # Record to immutable audit log
        record_action(
            "wazuh_agent_command",
            action_desc,
            {"agent_id": agent_id, "command": command},
            {"status": "EXECUTED", "result": str(result)[:500]},
        )

        agent_result = {
            "status": "EXECUTED",
            "action": action_desc,
            "result": result,
            "warning": "Command sent to agent. Monitor for effects.",
        }
        if compact_output:
            agent_result = compact(agent_result)
        return format_json(agent_result)
