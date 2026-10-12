import pytest
from app.policy.decision import (
    TAU_BLOCK,
    TAU_CONFIRM,
    TAU_HIGH,
    TAU_MEDIUM,
    decide,
    evaluate_policy,
)
from app.schemas import RuleResult


def _critical(rule_id="R1"):
    return RuleResult(
        rule_id=rule_id,
        rule_name="Test critical",
        triggered=True,
        severity="critical",
        flag=rule_id,
        step_triggered=0,
    )


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0.1, "ALLOW"), (0.5, "REVISE"), (0.8, "CONFIRM")],
)
def test_zero_critical_violation_score_paths(score, expected):
    assert decide(score)["action"] == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0.1, "REVISE"), (0.8, "CONFIRM"), (0.95, "BLOCK")],
)
def test_one_critical_violation_score_paths(score, expected):
    assert decide(score, [_critical()])["action"] == expected


def test_two_or_more_critical_violations_block_at_any_score():
    assert decide(0.05, [_critical("R1"), _critical("R2")])["action"] == "BLOCK"


def test_thresholds_loaded_from_json():
    assert (TAU_MEDIUM, TAU_HIGH, TAU_CONFIRM, TAU_BLOCK) == (0.4, 0.6, 0.75, 0.9)


def test_evaluate_policy_compatibility_alias_and_rationale():
    result = evaluate_policy(0.2, [_critical()], [])
    assert result["action"] == "REVISE"
    assert "critical violation" in result["rationale"]
    assert result["critical_violations"] == 1


def test_noncritical_high_severity_hits_are_conservative():
    high_hit = RuleResult(rule_id="R2", rule_name="High", triggered=True, severity="high")
    assert decide(0.1, [high_hit])["action"] == "REVISE"
    assert decide(0.8, [high_hit])["action"] == "CONFIRM"
    assert decide(0.1, [high_hit, high_hit])["action"] == "CONFIRM"


def test_policy_fails_closed_on_invalid_score():
    assert decide(float("nan"))["action"] == "BLOCK"
