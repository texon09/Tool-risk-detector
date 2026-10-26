"""PlanGuard HTTP client and plan adapter for the chat demo.

Converts tool calls to the canonical PlanGuard plan schema and requests
risk analysis over HTTP. Enforces fail-closed behaviour: any unreachable,
malformed, or timed out request returns an audited synthetic BLOCK.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any
from urllib.parse import urlsplit

import requests

logger = logging.getLogger("chat_demo.guard_client")

# Static tool metadata registry following PlanGuard conventions
TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "file_read": {
        "permissions_required": ["filesystem:read"],
        "side_effect_class": "read",
        "reversible": True,
        "destination": "internal",
        "estimated_cost": 0.1,
    },
    "db_query": {
        "permissions_required": ["database:read"],
        "side_effect_class": "read",
        "reversible": True,
        "destination": "internal",
        "estimated_cost": 0.1,
    },
    "database_query": {
        "permissions_required": ["database:read"],
        "side_effect_class": "read",
        "reversible": True,
        "destination": "internal",
        "estimated_cost": 0.1,
    },
    "http_post": {
        "permissions_required": ["network:external"],
        "side_effect_class": "write",
        "reversible": False,
        "destination": "external",
        "estimated_cost": 0.5,
    },
    "email_send": {
        "permissions_required": ["email:send", "network:external"],
        "side_effect_class": "write",
        "reversible": False,
        "destination": "external",
        "estimated_cost": 0.2,
    },
    "shell_exec": {
        "permissions_required": ["admin", "system:execute"],
        "side_effect_class": "execute",
        "reversible": False,
        "destination": "internal",
        "estimated_cost": 1.0,
    },
}

RESTRICTED_PATTERNS = [
    r"id_rsa",
    r"\.env",
    r"password",
    r"secret",
    r"api[_-]?key",
    r"private[_-]?key",
    r"/etc/passwd",
    r"\.aws/credentials",
]
CONFIDENTIAL_PATTERNS = [
    r"customers?",
    r"clients?",
    r"users?",
    r"employees?",
    r"pii",
    r"accounts?",
    r"billing",
    r"orders?",
]


def derive_data_sensitivity(tool_name: str, arguments: dict[str, Any]) -> str:
    """Derive data sensitivity based on arguments content and tool target.

    Returns:
        'restricted' | 'confidential' | 'internal' | 'public'
    """
    args_str = json_str_flatten(arguments).lower()

    for pattern in RESTRICTED_PATTERNS:
        if re.search(pattern, args_str, re.IGNORECASE):
            return "restricted"

    for pattern in CONFIDENTIAL_PATTERNS:
        if re.search(pattern, args_str, re.IGNORECASE):
            return "confidential"

    if tool_name in {"http_post", "email_send"}:
        return "internal"
    return "internal"


def derive_destination(tool_name: str, arguments: dict[str, Any], default_dest: str) -> str:
    """Derive destination (internal vs external) dynamically."""
    if default_dest == "external":
        return "external"
    url = arguments.get("url") or arguments.get("destination") or ""
    if url:
        hostname = (urlsplit(str(url)).hostname or "").lower()
        if hostname and not (
            hostname in {"localhost", "127.0.0.1", "internal"}
            or hostname.endswith(".internal")
        ):
            return "external"
    return default_dest


def json_str_flatten(val: Any) -> str:
    """Flatten an argument structure to a string for scanning."""
    if isinstance(val, dict):
        return " ".join(f"{k} {json_str_flatten(v)}" for k, v in val.items())
    if isinstance(val, (list, tuple, set)):
        return " ".join(json_str_flatten(x) for x in val)
    return str(val)


def map_tool_call_to_step(tool_call: dict[str, Any]) -> dict[str, Any]:
    """Convert a LangChain AIMessage tool call to a PlanGuard plan step."""
    name = tool_call.get("name", "")
    args = tool_call.get("args", {})
    if not isinstance(args, dict):
        args = {"raw_arg": args}

    meta = TOOL_REGISTRY.get(name, {
        "permissions_required": ["system:execute"],
        "side_effect_class": "write",
        "reversible": False,
        "destination": "internal",
        "estimated_cost": 0.5,
    })

    sensitivity = derive_data_sensitivity(name, args)
    destination = derive_destination(name, args, meta.get("destination", "internal"))

    # Map tool name aliases if needed (e.g. db_query -> database_query for full R1 compatibility)
    plan_tool_name = "database_query" if name == "db_query" else name

    # Permissions calculation
    perms = list(meta.get("permissions_required", []))
    if sensitivity in {"confidential", "restricted"}:
        perms.append("customer_data:read" if "customer" in json_str_flatten(args).lower() else "sensitive:read")

    # If it's a customer query, add confidential flag
    step = {
        "tool_name": plan_tool_name,
        "arguments": args,
        "permissions_required": perms,
        "side_effect_class": meta.get("side_effect_class", "read"),
        "reversible": meta.get("reversible", True),
        "data_sensitivity": sensitivity,
        "destination": destination,
        "estimated_cost": meta.get("estimated_cost", 0.1),
    }
    return step


def to_plan(tool_calls: list[dict[str, Any]], session_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Convert a sequence of LangChain tool calls to a full PlanGuard plan payload."""
    steps = [map_tool_call_to_step(tc) for tc in tool_calls]
    # Default granted permissions to basic reads if not provided
    default_session = {
        "granted_permissions": ["filesystem:read", "database:read"]
    }
    return {
        "steps": steps,
        "session_context": session_context or default_session,
    }


class GuardClient:
    """HTTP client communicating with PlanGuard /api/analyze."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 10.0,
    ):
        self.base_url = (base_url or os.getenv("PLANGUARD_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.api_key = api_key or os.getenv("PLANGUARD_API_KEY", "")
        self.timeout = timeout

    def check(self, plan: dict[str, Any], trajectory_id: str | None = None) -> dict[str, Any]:
        """Send a plan to /api/analyze.

        Returns:
            dict containing: action, risk_score, rule_hits, rationale, audit_id, latency_ms.
            Fail-closed guarantee: any exception returns a synthetic BLOCK.
        """
        payload = {
            "plan": plan,
            "session_context": plan.get("session_context"),
            "context": {"trajectory_id": trajectory_id or "chat-session"},
        }
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        url = f"{self.base_url}/api/analyze"
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            return {
                "action": data.get("action", "BLOCK"),
                "risk_score": float(data.get("risk_score", 1.0)),
                "rule_hits": data.get("rule_hits", []),
                "rationale": data.get("rationale", "Plan evaluated by PlanGuard."),
                "audit_id": str(data.get("audit_id", "")),
                "latency_ms": float(data.get("latency_ms", 0.0)),
            }
        except Exception as exc:
            logger.error("PlanGuard check failed closed: %s", exc)
            return {
                "action": "BLOCK",
                "risk_score": 1.0,
                "rule_hits": ["guard_unavailable", "fail_closed"],
                "rationale": f"Blocked: PlanGuard guardrail is unreachable or encountered an error ({type(exc).__name__}: {exc}). Fail-closed policy enforced.",
                "audit_id": "fail-closed-client",
                "latency_ms": 0.0,
            }
