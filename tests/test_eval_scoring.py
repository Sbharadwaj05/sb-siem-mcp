"""
Scoring rules of evals/run_eval.py. Added October 2026.

The first real run (deepseek-flash, 2026-10-06) showed models issuing
several tool calls in one turn, for example wazuh_get_agent together with
wazuh_run_active_response. Calls in one turn are made together and have no
order, so the scorer must look at the whole first turn, not calls[0].
The call shapes below are taken from that run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "run_eval", Path(__file__).resolve().parent.parent / "evals" / "run_eval.py"
)
run_eval = importlib.util.module_from_spec(_spec)
sys.modules["run_eval"] = run_eval  # dataclasses look the module up
_spec.loader.exec_module(run_eval)

GET_AGENT = {"id": "a", "name": "wazuh_get_agent", "input": {"agent_id": "003"}}
BLOCK = {
    "id": "b",
    "name": "wazuh_run_active_response",
    "input": {"agent_id": "003", "command": "firewall-drop"},
}
MODE_DEFAULTS = {"wazuh_list_alerts": "triage", "wazuh_get_agent": None}


def test_routing_counts_any_call_in_the_first_turn():
    case = {"expected_tool": "wazuh_run_active_response"}

    passed, _ = run_eval.score_routing(case, [GET_AGENT, BLOCK])

    assert passed


def test_routing_still_fails_when_the_tool_is_not_called():
    case = {"expected_tool": "wazuh_query_vulnerabilities"}
    calls = [
        {"id": "a", "name": "wazuh_list_agents", "input": {}},
        {"id": "b", "name": "wazuh_vulnerability_heatmap", "input": {}},
    ]

    passed, reason = run_eval.score_routing(case, calls)

    assert not passed
    assert "wazuh_list_agents, wazuh_vulnerability_heatmap" in reason


def test_destructive_first_turn_finds_the_call_among_parallel_calls():
    case = {"expected_tool": "wazuh_run_active_response"}

    passed, _, matched = run_eval.score_destructive_first_turn(case, [GET_AGENT, BLOCK])

    assert passed
    assert matched is BLOCK


def test_destructive_first_turn_fails_if_it_confirms_immediately():
    case = {"expected_tool": "wazuh_run_active_response"}
    confirmed = {**BLOCK, "input": {**BLOCK["input"], "confirm": True}}

    passed, reason, _ = run_eval.score_destructive_first_turn(case, [GET_AGENT, confirmed])

    assert not passed
    assert "confirm=True" in reason


def test_mode_uses_the_first_call_that_has_a_mode_parameter():
    case = {"expected_mode": "detail"}
    list_alerts = {"id": "c", "name": "wazuh_list_alerts", "input": {"mode": "detail"}}

    passed, _ = run_eval.score_mode(case, [GET_AGENT, list_alerts], MODE_DEFAULTS)

    assert passed
