"""Metadata-driven deterministic safety rules for planned tool calls."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from app.fail_closed import fail_closed
from app.schemas import RuleResult

DEFAULT_CONFIG: dict[str, Any] = {
    "rules_enabled": [f"R{i}" for i in range(1, 10)],
    "budget_threshold": 100.0,
    "broad_scope_threshold": 100,
    "r6": {"max_steps": 25, "max_repeat_calls": 3, "bulk_read_rows": 1000},
    "allowlist_domains": [],
    "sensitivity_levels": ["confidential", "restricted", "secret"],
}
ALLOWED_TOOLS = {
    "database_query",
    "file_read",
    "file_write",
    "http_post",
    "email_send",
    "shell_exec",
}
SENSITIVE_LEVELS = {"confidential", "restricted", "secret"}
PRIVILEGED_EFFECTS = {"write", "delete", "execute"}


def _load_config() -> dict[str, Any]:
    config_path = Path(__file__).with_name("rules.yaml")
    if not config_path.exists():
        return dict(DEFAULT_CONFIG)
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        return dict(DEFAULT_CONFIG)
    config = {**DEFAULT_CONFIG, **loaded}
    config["r6"] = {**DEFAULT_CONFIG["r6"], **(loaded.get("r6") or {})}
    return config


CONFIG = _load_config()


def _steps(plan: dict[str, Any]) -> list[dict[str, Any]]:
    steps = plan.get("steps", [])
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        raise TypeError("plan.steps must be a list of step objects")
    return steps


def _args(step: dict[str, Any]) -> dict[str, Any]:
    value = step.get("arguments", step.get("args", {}))
    if not isinstance(value, dict):
        raise TypeError("step arguments must be an object")
    return value


def _required_permissions(step: dict[str, Any]) -> set[str]:
    value = step.get("permissions_required", [])
    if isinstance(value, str):
        return {value}
    return {str(item) for item in value}


def _result(rule_id: str, name: str, severity: str, reason: str, step: int) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        rule_name=name,
        triggered=True,
        severity=severity,
        reason=reason,
        step_id=str(step),
        flag=rule_id,
        step_triggered=step,
    )


def _rule_error(exc: Exception) -> list[RuleResult]:
    return [_result("internal_error", "Internal rule error", "critical", str(exc), -1)]


@fail_closed(_rule_error)
def rule_1(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    context = session_context or plan.get("session_context", {}) or {}
    granted = context.get("granted_permissions", [])
    if isinstance(granted, str):
        granted = [granted]
    granted_set = {str(permission) for permission in granted}
    hits = []
    for index, step in enumerate(_steps(plan)):
        required = _required_permissions(step)
        missing = required - granted_set
        tool_name = str(step.get("tool_name", step.get("name", "")))
        if tool_name not in ALLOWED_TOOLS or missing:
            detail = (
                f"unregistered tool {tool_name}"
                if tool_name not in ALLOWED_TOOLS
                else f"missing permissions {sorted(missing)}"
            )
            hits.append(_result("R1", "Permission check", "critical", detail, index))
    return hits


@fail_closed(_rule_error)
def rule_2(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    hits = []
    for index, step in enumerate(_steps(plan)):
        effect = str(step.get("side_effect_class", "none")).casefold()
        if step.get("reversible") is False or effect in PRIVILEGED_EFFECTS:
            hits.append(
                _result(
                    "R2",
                    "Irreversibility check",
                    "high",
                    "Irreversible or side-effecting operation",
                    index,
                )
            )
    return hits


@fail_closed(_rule_error)
def rule_3(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    sensitive = {
        str(value).casefold() for value in CONFIG.get("sensitivity_levels", SENSITIVE_LEVELS)
    }
    hits = []
    for index, step in enumerate(_steps(plan)):
        level = str(step.get("data_sensitivity", "public")).casefold()
        if level in sensitive:
            hits.append(
                _result("R3", "Sensitivity check", "high", f"Step accesses {level} data", index)
            )
    return hits


def _is_sensitive_read(step: dict[str, Any]) -> bool:
    level = str(step.get("data_sensitivity", "public")).casefold()
    effect = str(step.get("side_effect_class", "")).casefold()
    tool = str(step.get("tool_name", step.get("name", ""))).casefold()
    return level in SENSITIVE_LEVELS and (
        effect == "read" or tool in {"file_read", "database_query"}
    )


def _is_external(step: dict[str, Any]) -> bool:
    destination = step.get("destination", "")
    if isinstance(destination, dict):
        destination = destination.get("type", destination.get("scope", ""))
    destination_text = str(destination).casefold()
    if destination_text in {"internal", "local"}:
        return False
    args = step.get("arguments", step.get("args", {}))
    url = args.get("url", "") if isinstance(args, dict) else ""
    url = str(url or (destination if "://" in destination_text else ""))
    host = (urlsplit(url).hostname or "").casefold()
    allowed = {str(domain).casefold() for domain in CONFIG.get("allowlist_domains", [])}
    if host and (host in allowed or any(host.endswith("." + domain) for domain in allowed)):
        return False
    if destination_text == "external":
        return True
    tool = str(step.get("tool_name", step.get("name", ""))).casefold()
    return tool in {"http_post", "email_send"} and (destination_text == "" or bool(host))


@fail_closed(_rule_error)
def rule_4(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    seen_sensitive_read = False
    for index, step in enumerate(_steps(plan)):
        if _is_external(step) and seen_sensitive_read:
            return [
                _result(
                    "R4",
                    "Egress check",
                    "critical",
                    "External destination follows a sensitive read",
                    index,
                )
            ]
        seen_sensitive_read = seen_sensitive_read or _is_sensitive_read(step)
    return []


@fail_closed(_rule_error)
def rule_5(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    threshold = float(CONFIG.get("budget_threshold", 100.0))
    total = 0.0
    for index, step in enumerate(_steps(plan)):
        total += float(step.get("estimated_cost", 0) or 0)
        if total > threshold:
            return [
                _result(
                    "R5",
                    "Budget check",
                    "medium",
                    f"Cumulative estimated cost {total:g} exceeds {threshold:g}",
                    index,
                )
            ]
    return []


def _stage(step: dict[str, Any]) -> str | None:
    explicit = str(step.get("kill_chain_stage", step.get("stage", ""))).casefold()
    if explicit in {"recon", "reconnaissance", "access", "exfil", "exfiltration"}:
        return (
            "recon"
            if explicit.startswith("recon")
            else "exfil"
            if explicit.startswith("exfil")
            else "access"
        )
    tool = str(step.get("tool_name", step.get("name", ""))).casefold()
    effect = str(step.get("side_effect_class", "")).casefold()
    if any(word in tool for word in ("search", "scan", "enumerate", "discover", "list")):
        return "recon"
    if _is_external(step) or tool in {"http_post", "email_send"}:
        return "exfil"
    if effect == "read" or tool in {"database_query", "file_read"}:
        return "access"
    return None


@fail_closed(_rule_error)
def rule_6(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    seen_recon = False
    seen_access = False
    for index, step in enumerate(_steps(plan)):
        stage = _stage(step)
        if stage == "recon":
            seen_recon = True
        elif stage == "access" and seen_recon:
            seen_access = True
        elif stage == "exfil" and seen_access:
            return [
                _result(
                    "R6",
                    "Suspicious pattern check",
                    "critical",
                    "Reconnaissance, access, and exfiltration sequence detected",
                    index,
                )
            ]
    return []


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in [str(key), *_flatten_strings(item)]]
    if isinstance(value, (list, tuple, set)):
        return [text for item in value for text in _flatten_strings(item)]
    return [str(value)]


def _bounded(args: dict[str, Any]) -> bool:
    keys = {str(key).casefold() for key, value in args.items() if value not in (None, "", [], {})}
    if keys & {
        "where",
        "filter",
        "filters",
        "id",
        "ids",
        "limit",
        "max_results",
        "max_records",
        "count",
    }:
        return True
    return any(
        isinstance(value, str) and re.search(r"(?i)\b(where|limit|top)\b", value)
        for value in args.values()
    )


@fail_closed(_rule_error)
def rule_7(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    hits = []
    for index, step in enumerate(_steps(plan)):
        args = _args(step)
        texts = _flatten_strings(args)
        wildcard = any("*" in text or "%" in text for text in texts)
        tool = str(step.get("tool_name", step.get("name", ""))).casefold()
        unbounded_query = tool == "database_query" and not _bounded(args)
        if wildcard or unbounded_query:
            hits.append(
                _result(
                    "R7",
                    "Scope ambiguity check",
                    "medium",
                    "Unbounded or wildcard operation scope",
                    index,
                )
            )
    return hits


@fail_closed(_rule_error)
def rule_8(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    threshold = int(
        CONFIG.get("broad_scope_threshold", CONFIG.get("r6", {}).get("bulk_read_rows", 1000))
    )
    count_keys = {
        "affected_records",
        "record_count",
        "num_records",
        "file_count",
        "num_files",
        "max_results",
        "limit",
        "count",
        "rows",
    }
    hits = []
    for index, step in enumerate(_steps(plan)):
        values = _args(step)
        count = max(
            (
                int(value)
                for key, value in values.items()
                if str(key).casefold() in count_keys and isinstance(value, (int, float))
            ),
            default=0,
        )
        if count > threshold:
            hits.append(
                _result(
                    "R8",
                    "Broad-scope check",
                    "high",
                    f"Operation affects {count} items; threshold is {threshold}",
                    index,
                )
            )
    return hits


def _untrusted(step: dict[str, Any]) -> bool:
    trust = str(step.get("output_trust", step.get("source_trust", ""))).casefold()
    args = step.get("arguments", step.get("args", {}))
    input_from = step.get("input_from", args.get("input_from") if isinstance(args, dict) else "")
    input_sources = " ".join(_flatten_strings(input_from)).casefold()
    return (
        trust == "untrusted"
        or step.get("trusted") is False
        or step.get("untrusted") is True
        or step.get("output_from_untrusted") is True
        or bool(step.get("tainted"))
        or any(marker in input_sources for marker in ("untrusted", "user_input", "external_input"))
    )


@fail_closed(_rule_error)
def rule_9(plan: dict[str, Any], session_context: dict[str, Any] | None = None) -> list[RuleResult]:
    prior_untrusted = False
    for index, step in enumerate(_steps(plan)):
        effect = str(step.get("side_effect_class", "")).casefold()
        permissions = _required_permissions(step)
        tool = str(step.get("tool_name", step.get("name", ""))).casefold()
        privileged = (
            effect in PRIVILEGED_EFFECTS
            or tool in {"file_write", "http_post", "email_send", "shell_exec"}
            or any(
                token in permission.casefold()
                for permission in permissions
                for token in ("admin", "write", "execute", "delete")
            )
        )
        if prior_untrusted and privileged:
            return [
                _result(
                    "R9",
                    "Untrusted-input check",
                    "critical",
                    "Privileged action follows untrusted output",
                    index,
                )
            ]
        prior_untrusted = prior_untrusted or _untrusted(step)
    return []


RULES = [rule_1, rule_2, rule_3, rule_4, rule_5, rule_6, rule_7, rule_8, rule_9]


@fail_closed(_rule_error)
def run_all(
    plan: dict[str, Any], session_context: dict[str, Any] | None = None
) -> list[RuleResult]:
    enabled = {
        str(rule).upper() for rule in CONFIG.get("rules_enabled", [f"R{i}" for i in range(1, 10)])
    }
    results: list[RuleResult] = []
    for index, rule in enumerate(RULES, start=1):
        rule_id = f"R{index}"
        if rule_id in enabled:
            results.extend(rule(plan, session_context))
    return results


class RuleEngine:
    """Backward-compatible object interface used by the API integration."""

    ALLOWED_TOOLS = sorted(ALLOWED_TOOLS)

    def evaluate(
        self, plan: dict[str, Any], session_context: dict[str, Any] | None = None
    ) -> list[RuleResult]:
        return run_all(plan, session_context)
