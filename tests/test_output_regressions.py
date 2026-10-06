"""
Regression tests for issues #2, #3 and #7.

These exercise the real functions rather than a mocked client — both bugs
survived the existing suite because it asserts against AsyncMock return
values and never touches the serialisation or field-selection code.
"""

from __future__ import annotations

import json
from collections import Counter
from unittest.mock import AsyncMock

import pytest
from mcp.server.fastmcp import FastMCP

from wazuh_mcp.client import WazuhClient
from wazuh_mcp.output import (
    AGENT_SELECT_FIELDS,
    MODE_FIELDS,
    compact,
    filter_agent_select,
    get_agent_select_for_mode,
)
from wazuh_mcp.sanitizer import sanitize
from wazuh_mcp.tools.alerts import register_alerts
from wazuh_mcp.utils import format_json


class TestSanitizerNonStringKeys:
    """Issue #3 — 'int' object has no attribute 'lower'."""

    def test_sanitize_handles_int_keys(self):
        """Counters keyed on rule.level produce int keys; must not raise."""
        assert sanitize({12: 3, 7: 1}) == {12: 3, 7: 1}

    def test_format_json_handles_int_keys(self):
        """The exact shape wazuh_alert_summary built before the fix."""
        level_counts: Counter = Counter()
        for level in (12, 12, 7, 10, 12):
            level_counts[level] += 1
        summary = {"severity_distribution": dict(level_counts.most_common())}

        out = json.loads(format_json(summary))
        assert out["severity_distribution"] == {"12": 3, "7": 1, "10": 1}

    def test_sanitize_still_redacts_string_keys(self):
        """The non-string guard must not weaken redaction."""
        result = sanitize({"password": "hunter2", "agent": "web-1"})
        assert result["password"] == "***REDACTED***"
        assert result["agent"] == "web-1"

    def test_sanitize_mixed_key_types(self):
        result = sanitize({12: {"api_key": "abc"}, "name": "x"})
        assert result[12]["api_key"] == "***REDACTED***"
        assert result["name"] == "x"


class TestAgentSelectFields:
    """Issue #2 — alert fields sent to /agents produce a 400."""

    @pytest.mark.parametrize(
        "mode", ["triage", "detail", "fleet", "compliance", "hunting"]
    )
    def test_every_mode_yields_only_valid_agent_fields(self, mode):
        select = get_agent_select_for_mode(mode)
        assert select, f"mode {mode} produced an empty select"
        bad = [f for f in select.split(",") if f not in AGENT_SELECT_FIELDS]
        assert not bad, f"mode {mode} would 400 on: {bad}"

    def test_unknown_mode_falls_back_to_fleet(self):
        assert get_agent_select_for_mode("nonsense") == get_agent_select_for_mode(
            "fleet"
        )

    def test_alert_mode_fields_are_rejected_for_agents(self):
        """The regression itself: triage alert fields must not survive."""
        filtered = filter_agent_select(MODE_FIELDS["triage"])
        assert filtered is not None
        assert "rule.id" not in filtered
        assert "data.srcip" not in filtered
        assert "decoder.name" not in filtered

    def test_filter_drops_unknown_and_keeps_known(self):
        assert filter_agent_select("id,name,rule.level,bogus") == "id,name"

    def test_filter_returns_none_when_nothing_survives(self):
        assert filter_agent_select("rule.level,data.srcip") is None
        assert filter_agent_select(None) is None

    def test_fleet_mode_field_names_match_the_api(self):
        """These two were camelCase in the API and snake_case in the code."""
        fleet = MODE_FIELDS["fleet"]
        assert "lastKeepAlive" in fleet and "last_keepalive" not in fleet
        assert "configSum" in fleet and "config_summary" not in fleet


class TestCompactKeepsRequestedItems:
    """Issue #7 — compact_output cut items to 10 while count still said 50."""

    @pytest.mark.xfail(strict=True, reason="issue #7: compact() caps the envelope's items")
    @pytest.mark.asyncio
    async def test_list_alerts_compact_returns_every_requested_item(self):
        client = AsyncMock(spec=WazuhClient)
        client.list_alerts.return_value = {
            "affected_items": [{"id": str(i), "rule": {"level": 10}} for i in range(50)],
            "total_affected_items": 10000,
        }
        mcp = FastMCP("test")
        register_alerts(mcp, client)

        result = await mcp.call_tool(
            "wazuh_list_alerts", {"limit": 50, "compact_output": True}
        )
        blocks = result[0] if isinstance(result, tuple) else result
        out = json.loads(blocks[0].text)

        assert len(out["items"]) == 50
        assert out["count"] == len(out["items"])

    def test_compact_still_caps_nested_lists(self):
        """Token savings inside each item stay as they were."""
        envelope = {"items": [{"tags": list(range(30))}], "count": 1, "limit": 50}

        assert len(compact(envelope)["items"][0]["tags"]) == 10
