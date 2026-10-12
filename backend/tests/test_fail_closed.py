from app.policy.decision import decide
from app.rules.engine import run_all
from app.rules.inspector import ArgumentInspector


def test_rule_failure_emits_critical_internal_error():
    results = run_all({"steps": ["not a step"]})
    assert results
    assert any(
        result.flag == "internal_error" and result.severity == "critical" for result in results
    )


def test_inspector_failure_emits_critical_internal_error():
    results = ArgumentInspector().scan({"steps": [None]})
    assert results[0].scanner_name == "internal_error"
    assert results[0].severity == "critical"


def test_policy_failure_returns_block():
    result = decide(-0.1)
    assert result["action"] == "BLOCK"
    assert "fail-closed" in result["rationale"]
