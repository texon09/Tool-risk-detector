import pytest
from app.rules.engine import RULES, RuleEngine, run_all


def _step(**fields):
    defaults = {
        "tool_name": "file_read",
        "arguments": {},
        "side_effect_class": "read",
        "reversible": True,
    }
    return {**defaults, **fields}


def _rule(index, plan, context=None):
    return RULES[index - 1](plan, context)


@pytest.mark.parametrize(
    ("rule_index", "trigger", "safe"),
    [
        (
            1,
            {"tool_name": "file_read", "permissions_required": ["files:read"]},
            {"tool_name": "file_read", "permissions_required": ["files:read"]},
        ),
        (
            2,
            {"side_effect_class": "delete", "reversible": True},
            {"side_effect_class": "read", "reversible": True},
        ),
        (3, {"data_sensitivity": "restricted"}, {"data_sensitivity": "public"}),
        (4, None, None),
        (5, None, None),
        (6, None, None),
        (
            7,
            {"tool_name": "file_read", "arguments": {"path": "reports/*.csv"}},
            {"tool_name": "file_read", "arguments": {"path": "reports/annual.csv"}},
        ),
        (8, {"arguments": {"affected_records": 200}}, {"arguments": {"affected_records": 5}}),
        (9, None, None),
    ],
)
def test_each_rule_has_trigger_and_no_trigger_cases(rule_index, trigger, safe):
    trigger_context = {"granted_permissions": ["files:read"]}
    safe_context = trigger_context
    if rule_index == 4:
        triggered = {
            "steps": [_step(data_sensitivity="confidential"), _step(destination="external")]
        }
        clean = {"steps": [_step(data_sensitivity="public"), _step(destination="external")]}
    elif rule_index == 5:
        triggered = {"steps": [_step(estimated_cost=101)]}
        clean = {"steps": [_step(estimated_cost=1)]}
    elif rule_index == 6:
        triggered = {
            "steps": [
                _step(kill_chain_stage="recon"),
                _step(kill_chain_stage="access"),
                _step(kill_chain_stage="exfil"),
            ]
        }
        clean = {"steps": [_step(kill_chain_stage="recon"), _step(kill_chain_stage="access")]}
    elif rule_index == 9:
        triggered = {"steps": [_step(output_trust="untrusted"), _step(side_effect_class="execute")]}
        clean = {"steps": [_step(output_trust="trusted"), _step(side_effect_class="execute")]}
    elif rule_index == 1:
        triggered = {"steps": [_step(**trigger)]}
        clean = {"steps": [_step(**safe)]}
        trigger_context = {"granted_permissions": []}
        safe_context = {"granted_permissions": ["files:read"]}
    else:
        triggered = {"steps": [_step(**trigger)]}
        clean = {"steps": [_step(**safe)]}

    hit = _rule(rule_index, triggered, trigger_context)
    assert any(result.rule_id == f"R{rule_index}" for result in hit)
    assert not any(
        result.rule_id == f"R{rule_index}" for result in _rule(rule_index, clean, safe_context)
    )
    assert next(result for result in hit if result.rule_id == f"R{rule_index}").step_triggered >= 0


def test_rule_engine_runs_enabled_registry():
    plan = {
        "steps": [_step(data_sensitivity="restricted")],
        "session_context": {"granted_permissions": []},
    }
    assert any(result.rule_id == "R3" for result in RuleEngine().evaluate(plan))
    assert len(RULES) == 9
    assert run_all({"steps": "malformed"})[0].flag == "internal_error"
