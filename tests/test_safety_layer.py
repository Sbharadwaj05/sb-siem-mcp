"""
Tests for the safety layer: confirmation gate, RBAC, rate limiting,
validators and the output sanitizer. Added October 2026.

Unlike most of the older tests, these run the real code. The destructive
tools are registered on a real FastMCP instance and invoked through
``FastMCP.call_tool``, so the ``safe_tool`` wrapper (RBAC, rate limiter),
FastMCP's argument handling and the tool body all execute. Only the Wazuh
client is mocked, and assertions are made on what the tool returned and on
how the client was called, never on a mock's own return value.

Tests marked ``xfail(strict=True)`` document real defects found while
writing this file. They are left unfixed on purpose and will start
failing (XPASS) once the defect is fixed, so the marker gets removed.
"""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from wazuh_mcp import audit, rate_limiter, rbac, safe_tool
from wazuh_mcp.client import WazuhClient
from wazuh_mcp.sanitizer import sanitize
from wazuh_mcp.tools import response
from wazuh_mcp.tools.response import register_response
from wazuh_mcp.validators import (
    validate_agent_id,
    validate_cve,
    validate_ip,
    validate_mitre_technique,
    validate_rule_id,
)

ACTIVE_RESPONSE = "wazuh_run_active_response"
AGENT_COMMAND = "wazuh_agent_command"
DESTRUCTIVE_TOOLS = [ACTIVE_RESPONSE, AGENT_COMMAND]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fresh_safety_state(monkeypatch, tmp_path):
    """Reset every module-level cache the safety layer keeps between calls."""
    for var in (
        "WAZUH_RBAC_ROLE",
        "WAZUH_RBAC_POLICY",
        "WAZUH_RATE_LIMIT_TOKENS",
        "WAZUH_RATE_LIMIT_PERIOD",
    ):
        monkeypatch.delenv(var, raising=False)
    # safe_tool caches the enforcer and limiter; rbac and rate_limiter keep
    # their own singletons behind those. All four must go.
    monkeypatch.setattr(safe_tool, "_rbac", None)
    monkeypatch.setattr(safe_tool, "_limiter", None)
    monkeypatch.setattr(rbac, "_rbac", None)
    monkeypatch.setattr(rate_limiter, "_rate_limiter", None)
    monkeypatch.setattr(audit, "AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    response._pending_confirmations.clear()
    yield
    response._pending_confirmations.clear()


@pytest.fixture
def client():
    c = AsyncMock(spec=WazuhClient)
    c.run_active_response.return_value = {"affected_items": ["001"]}
    return c


@pytest.fixture
def server(client):
    mcp = FastMCP("test")
    register_response(mcp, client)
    return mcp


def parse(text: str) -> dict:
    # The confirmation prompt prefixes the JSON with a text box (no braces).
    return json.loads(text[text.index("{") :])


async def call(server: FastMCP, tool: str, **arguments) -> dict:
    """Invoke a tool through FastMCP and return its JSON payload."""
    result = await server.call_tool(tool, arguments)
    blocks = result[0] if isinstance(result, tuple) else result
    return parse(blocks[0].text)


async def request_token(server, tool, agent_id="001", command="firewall-drop"):
    payload = await call(server, tool, agent_id=agent_id, command=command)
    assert payload["status"] == "AWAITING_CONFIRMATION"
    return payload["confirmation_token"]


def assert_executed_with(client, tool, agent_id, command):
    if tool == ACTIVE_RESPONSE:
        client.run_active_response.assert_awaited_once_with(
            agent_id=agent_id, command=command, arguments=None
        )
    else:
        client.run_active_response.assert_awaited_once_with(
            agent_id=agent_id, command=command, custom=True
        )


def audit_records() -> list[dict]:
    path = audit.AUDIT_LOG_PATH
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# A. Confirmation gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", DESTRUCTIVE_TOOLS)
class TestConfirmationGate:
    async def test_first_call_returns_token_and_does_not_execute(
        self, server, client, tool
    ):
        payload = await call(server, tool, agent_id="001", command="firewall-drop")

        assert payload["status"] == "AWAITING_CONFIRMATION"
        assert len(payload["confirmation_token"]) == 32
        assert payload["expires_in_seconds"] == 300
        client.run_active_response.assert_not_called()

    async def test_confirm_without_token_is_refused(self, server, client, tool):
        payload = await call(
            server, tool, agent_id="001", command="firewall-drop", confirm=True
        )

        assert "confirmation_token is required" in payload["error"]
        client.run_active_response.assert_not_called()

    async def test_unknown_token_is_refused(self, server, client, tool):
        payload = await call(
            server,
            tool,
            agent_id="001",
            command="firewall-drop",
            confirm=True,
            confirmation_token="0" * 32,
        )

        assert "Invalid or expired" in payload["error"]
        client.run_active_response.assert_not_called()

    async def test_valid_token_executes_stored_action_once(
        self, server, client, tool
    ):
        token = await request_token(server, tool, agent_id="003", command="host-deny")

        payload = await call(
            server,
            tool,
            agent_id="003",
            command="host-deny",
            confirm=True,
            confirmation_token=token,
        )

        assert payload["status"] == "EXECUTED"
        assert_executed_with(client, tool, "003", "host-deny")

    async def test_token_is_single_use(self, server, client, tool):
        token = await request_token(server, tool)
        args = dict(
            agent_id="001", command="firewall-drop", confirm=True, confirmation_token=token
        )

        first = await call(server, tool, **args)
        second = await call(server, tool, **args)

        assert first["status"] == "EXECUTED"
        assert "Invalid or expired" in second["error"]
        assert client.run_active_response.await_count == 1

    async def test_token_expires_after_300_seconds(
        self, server, client, tool, monkeypatch
    ):
        issued_at = time.time()
        monkeypatch.setattr(time, "time", lambda: issued_at)
        token = await request_token(server, tool)

        monkeypatch.setattr(time, "time", lambda: issued_at + 301)
        payload = await call(
            server,
            tool,
            agent_id="001",
            command="firewall-drop",
            confirm=True,
            confirmation_token=token,
        )

        assert "expired" in payload["error"]
        client.run_active_response.assert_not_called()

    async def test_token_for_agent_a_rejected_on_agent_b(self, server, client, tool):
        token = await request_token(server, tool, agent_id="001")

        payload = await call(
            server,
            tool,
            agent_id="002",
            command="firewall-drop",
            confirm=True,
            confirmation_token=token,
        )

        assert "different action" in payload["error"]
        client.run_active_response.assert_not_called()

    async def test_token_for_command_x_rejected_on_command_y(
        self, server, client, tool
    ):
        token = await request_token(server, tool, command="firewall-drop")

        payload = await call(
            server,
            tool,
            agent_id="001",
            command="restart-wazuh",
            confirm=True,
            confirmation_token=token,
        )

        assert "different action" in payload["error"]
        client.run_active_response.assert_not_called()

    async def test_rejected_attempt_still_consumes_token(self, server, client, tool):
        token = await request_token(server, tool, agent_id="001")
        await call(
            server,
            tool,
            agent_id="002",
            command="firewall-drop",
            confirm=True,
            confirmation_token=token,
        )

        # The original, correctly bound action can no longer use the token.
        payload = await call(
            server,
            tool,
            agent_id="001",
            command="firewall-drop",
            confirm=True,
            confirmation_token=token,
        )

        assert "Invalid or expired" in payload["error"]
        client.run_active_response.assert_not_called()

    async def test_successful_execution_writes_one_audit_record(
        self, server, client, tool
    ):
        token = await request_token(server, tool, agent_id="003")
        await call(
            server,
            tool,
            agent_id="003",
            command="firewall-drop",
            confirm=True,
            confirmation_token=token,
        )

        records = audit_records()
        assert len(records) == 1
        assert records[0]["tool"] == tool
        assert records[0]["parameters"]["agent_id"] == "003"
        assert records[0]["parameters"]["command"] == "firewall-drop"
        assert records[0]["result_summary"]["status"] == "EXECUTED"


@pytest.mark.asyncio
class TestConfirmationGateAcrossTools:
    @pytest.mark.parametrize(
        "issued_by, used_on",
        [(ACTIVE_RESPONSE, AGENT_COMMAND), (AGENT_COMMAND, ACTIVE_RESPONSE)],
    )
    async def test_token_rejected_on_the_other_tool(
        self, server, client, issued_by, used_on
    ):
        token = await request_token(server, issued_by)

        payload = await call(
            server,
            used_on,
            agent_id="001",
            command="firewall-drop",
            confirm=True,
            confirmation_token=token,
        )

        assert "different action" in payload["error"]
        client.run_active_response.assert_not_called()

    async def test_token_rejected_when_arguments_differ(self, server, client):
        # Called below FastMCP: see test_json_array_arguments_reach_the_tool
        # for why an arguments value cannot get through call_tool today.
        fn = server._tool_manager.get_tool(ACTIVE_RESPONSE).fn
        common = dict(agent_id="001", command="firewall-drop", compact_output=False)

        issued = parse(
            await fn(
                **common,
                arguments='["srcip", "10.0.0.50", "-"]',
                confirm=False,
                confirmation_token=None,
            )
        )
        payload = parse(
            await fn(
                **common,
                arguments='["srcip", "10.0.0.99", "-"]',
                confirm=True,
                confirmation_token=issued["confirmation_token"],
            )
        )

        assert "different action" in payload["error"]
        client.run_active_response.assert_not_called()

    @pytest.mark.xfail(
        strict=True,
        raises=ToolError,
        reason=(
            "FastMCP pre-parses any str argument whose annotation is not exactly "
            "`str`. `arguments` is Optional[str], so the documented JSON array "
            "string is turned into a list and then fails str validation. "
            "Active responses that need arguments (firewall-drop srcip) cannot "
            "be requested through MCP."
        ),
    )
    async def test_json_array_arguments_reach_the_tool(self, server, client):
        payload = await call(
            server,
            ACTIVE_RESPONSE,
            agent_id="001",
            command="firewall-drop",
            arguments='["srcip", "10.0.0.50", "-"]',
        )

        assert payload["status"] == "AWAITING_CONFIRMATION"


# ---------------------------------------------------------------------------
# B. RBAC
# ---------------------------------------------------------------------------


class TestRBAC:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool", DESTRUCTIVE_TOOLS)
    async def test_viewer_cannot_reach_destructive_tools(
        self, server, client, tool, monkeypatch
    ):
        monkeypatch.setenv("WAZUH_RBAC_ROLE", "viewer")

        payload = await call(server, tool, agent_id="001", command="firewall-drop")

        assert payload["error"]["type"] == "AccessDenied"
        assert response._pending_confirmations == {}
        client.run_active_response.assert_not_called()

    @pytest.mark.asyncio
    async def test_rbac_is_off_by_default(self, server):
        """No WAZUH_RBAC_ROLE and no WAZUH_RBAC_POLICY: every tool is allowed."""
        enforcer = rbac.get_rbac_enforcer()

        assert enforcer._enabled is False
        assert enforcer.is_allowed(ACTIVE_RESPONSE)
        payload = await call(server, AGENT_COMMAND, agent_id="001", command="id")
        assert payload["status"] == "AWAITING_CONFIRMATION"

    def test_policy_without_role_allows_everything(self, tmp_path, monkeypatch):
        """A policy file alone does not restrict anything; a role must be set."""
        policy = tmp_path / "rbac.json"
        policy.write_text(json.dumps({"viewer": ["wazuh_list_alerts"]}))
        monkeypatch.setenv("WAZUH_RBAC_POLICY", str(policy))

        enforcer = rbac.get_rbac_enforcer()

        assert enforcer._enabled is True
        assert enforcer.is_allowed(ACTIVE_RESPONSE)

    @pytest.mark.parametrize(
        "role, lower_tier_tool",
        [
            ("analyst", "wazuh_list_alerts"),
            ("admin", "wazuh_search_events"),
            ("soc", "wazuh_manager_stats"),
        ],
    )
    def test_built_in_roles_are_cumulative(self, role, lower_tier_tool, monkeypatch):
        monkeypatch.setenv("WAZUH_RBAC_ROLE", role)

        assert rbac.get_rbac_enforcer().is_allowed(lower_tier_tool)


# ---------------------------------------------------------------------------
# C. Rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRateLimit:
    @pytest.mark.parametrize("tool", DESTRUCTIVE_TOOLS)
    async def test_sixth_destructive_call_in_window_is_refused(self, server, tool):
        for _ in range(5):
            payload = await call(server, tool, agent_id="001", command="firewall-drop")
            assert payload["status"] == "AWAITING_CONFIRMATION"

        payload = await call(server, tool, agent_id="001", command="firewall-drop")

        assert payload["error"]["type"] == "RateLimited"


# ---------------------------------------------------------------------------
# D. Validators
# ---------------------------------------------------------------------------

VALIDATORS = [
    (validate_agent_id, "001"),
    (validate_ip, "10.0.0.50"),
    (validate_cve, "CVE-2024-3094"),
    (validate_mitre_technique, "T1059.001"),
    (validate_rule_id, "5710"),
]
SHELL_PAYLOADS = [";id", "|id", "`id`", "$(id)"]


class TestValidators:
    @pytest.mark.parametrize("validator, valid", VALIDATORS)
    def test_accepts_valid_value(self, validator, valid):
        assert validator(valid) == valid

    @pytest.mark.parametrize("payload", SHELL_PAYLOADS)
    @pytest.mark.parametrize("validator, valid", VALIDATORS)
    def test_rejects_shell_metacharacters(self, validator, valid, payload):
        with pytest.raises(ValueError):
            validator(valid + payload)

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Patterns use re.match with `$`, which also matches before a "
            "trailing newline, so '001\\n' passes. Newline is a shell command "
            "separator. re.fullmatch or `\\Z` would close it."
        ),
    )
    @pytest.mark.parametrize("validator, valid", VALIDATORS)
    def test_rejects_trailing_newline(self, validator, valid):
        with pytest.raises(ValueError):
            validator(valid + "\n")


# ---------------------------------------------------------------------------
# E. Sanitizer
# ---------------------------------------------------------------------------

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJ3YXp1aC13dWkiLCJpYXQiOjE3MDAwMDAwMDB9"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)


class TestSanitizer:
    def test_redacts_secrets_in_nested_dicts_and_lists(self):
        data = {
            "agent": {
                "id": "001",
                "config": [
                    {"user": "wazuh-wui", "password": "hunter2"},
                    {"note": f"session {JWT} reused"},
                ],
            },
            "integrations": [
                {"name": "virustotal", "api_key": "c0ffee"},
                ["nested", "key sk-" + "a" * 40],
            ],
        }

        out = sanitize(data)
        flat = json.dumps(out)

        assert out["agent"]["config"][0]["password"] == "***REDACTED***"
        assert out["integrations"][0]["api_key"] == "***REDACTED***"
        assert "JWT_REDACTED" in out["agent"]["config"][1]["note"]
        assert "API_KEY_REDACTED" in out["integrations"][1][1]
        for secret in ("hunter2", "c0ffee", JWT, "sk-" + "a" * 40):
            assert secret not in flat
        # Non-secret values survive.
        assert out["agent"]["id"] == "001"
        assert out["agent"]["config"][0]["user"] == "wazuh-wui"
        assert out["integrations"][0]["name"] == "virustotal"


# ---------------------------------------------------------------------------
# F. SSE entry point (localhost bind)
# ---------------------------------------------------------------------------


class TestSSEEntryPoint:
    @pytest.mark.xfail(
        strict=True,
        raises=TypeError,
        reason=(
            "main_sse() passes host= and port= to FastMCP.run(), which only "
            "accepts transport and mount_path in mcp 1.x. SSE mode, the Docker "
            "image's default entrypoint, raises TypeError on start, so "
            "WAZUH_MCP_HOST and WAZUH_MCP_PORT never take effect."
        ),
    )
    def test_main_sse_starts_bound_to_localhost(self, monkeypatch):
        from wazuh_mcp import metrics, server

        started = {}

        async def fake_run_sse_async(*args, **kwargs):
            started["host"] = server.mcp.settings.host

        monkeypatch.setattr(metrics, "start_metrics_server", lambda port: None)
        monkeypatch.setattr(server.mcp, "run_sse_async", fake_run_sse_async)
        monkeypatch.delenv("WAZUH_MCP_HOST", raising=False)

        server.main_sse()

        assert started["host"] == "127.0.0.1"
