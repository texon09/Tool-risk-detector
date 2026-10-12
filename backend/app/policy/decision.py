"""Policy decision layer combining calibrated risk and deterministic hits."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from app.fail_closed import fail_closed
from app.schemas import InspectorResult, RuleResult

THRESHOLDS_PATH = Path(__file__).with_name("thresholds.json")
with THRESHOLDS_PATH.open(encoding="utf-8") as thresholds_file:
    _thresholds = json.load(thresholds_file)

TAU_MEDIUM = float(_thresholds["t_medium"])
TAU_HIGH = float(_thresholds["t_high"])
TAU_CONFIRM = float(_thresholds["t_confirm"])
TAU_BLOCK = float(_thresholds["t_block"])
if not (0 <= TAU_MEDIUM < TAU_HIGH < TAU_CONFIRM < TAU_BLOCK <= 1):
    raise ValueError("Policy thresholds must be ordered values between 0 and 1")


def _field(hit: Any, name: str, default: Any = None) -> Any:
    if isinstance(hit, dict):
        return hit.get(name, default)
    return getattr(hit, name, default)


def _policy_error(exc: Exception) -> dict[str, Any]:
    return {
        "action": "BLOCK",
        "rationale": f"Policy engine error: fail-closed ({exc})",
        "critical_violations": 1,
        "rule_hits": ["internal_error"],
    }


@fail_closed(_policy_error)
def decide(
    risk_score: float,
    rule_results: list[RuleResult] | None = None,
    inspector_results: list[InspectorResult] | None = None,
) -> dict[str, Any]:
    """Choose an action from a [0, 1] risk score and rule/scanner results."""
    score = float(risk_score)
    if not math.isfinite(score) or not 0 <= score <= 1:
        raise ValueError("risk_score must be a finite number in [0, 1]")

    all_hits = list(rule_results or []) + list(inspector_results or [])
    critical = sum(
        1 for hit in all_hits if str(_field(hit, "severity", "")).casefold() == "critical"
    )
    high = sum(1 for hit in all_hits if str(_field(hit, "severity", "")).casefold() == "high")
    hit_names = [
        str(
            _field(hit, "flag")
            or _field(hit, "rule_id")
            or _field(hit, "scanner_name")
            or "unknown"
        )
        for hit in all_hits
    ]

    if critical >= 2:
        action = "BLOCK"
        rationale = f"Blocked due to {critical} critical violations (risk score {score:.2f})."
    elif critical == 1:
        if score > TAU_BLOCK:
            action = "BLOCK"
            rationale = (
                f"Blocked: one critical violation and risk score {score:.2f} "
                f"exceeds {TAU_BLOCK:.2f}."
            )
        elif score > TAU_CONFIRM:
            action = "CONFIRM"
            rationale = (
                f"Human confirmation required: one critical violation and risk score {score:.2f}."
            )
        else:
            action = "REVISE"
            rationale = (
                f"Revise the plan: one critical violation remains at risk score {score:.2f}."
            )
    elif score >= TAU_HIGH:
        action = "CONFIRM"
        rationale = f"Human confirmation required at risk score {score:.2f}."
    elif score >= TAU_MEDIUM:
        action = "REVISE"
        rationale = f"Revise the plan at risk score {score:.2f}."
    else:
        action = "ALLOW"
        rationale = f"No significant violations; risk score {score:.2f} is below {TAU_MEDIUM:.2f}."

    if critical == 0 and high >= 2 and action in {"ALLOW", "REVISE"}:
        action = "CONFIRM"
        rationale = f"Human confirmation required for {high} high-severity violations."
    elif critical == 0 and high == 1 and action == "ALLOW":
        action = "REVISE"
        rationale = "Revise the plan to address its high-severity violation."

    if hit_names:
        rationale += " Triggered checks: " + ", ".join(hit_names) + "."
    return {
        "action": action,
        "decision": action,
        "rationale": rationale,
        "critical_violations": critical,
        "rule_hits": hit_names,
    }


def evaluate_policy(
    ml_score: float,
    rule_results: list[RuleResult] | None = None,
    inspector_results: list[InspectorResult] | None = None,
) -> dict[str, Any]:
    """Compatibility alias retained for existing API callers."""
    return decide(ml_score, rule_results, inspector_results)
