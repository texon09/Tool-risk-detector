"""MCP Proxy Guardrail intercepting tool calls and enforcing security decisions."""

from __future__ import annotations

import logging
from typing import Any
import httpx

from mcp_proxy.mock_servers import dispatch_to_mcp_server

logger = logging.getLogger("mcp.proxy")


class MCPProxy:
    """Proxy guardrail intercepting MCP tool calls before execution."""

    def __init__(self, api_base_url: str = "http://127.0.0.1:8000", client: Any = None):
        self.api_base_url = api_base_url.rstrip("/")
        self.client = client  # Optional custom httpx or TestClient

    def _call_analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send plan to /api/analyze."""
        if self.client is not None:
            response = self.client.post("/api/analyze", json=payload)
            return response.json()

        with httpx.Client(timeout=10.0) as client:
            response = client.post(f"{self.api_base_url}/api/analyze", json=payload)
            response.raise_for_status()
            return response.json()

    def handle_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        server_name: str | None = None,
        tool_schema: dict[str, Any] | None = None,
        resource_uris: list[str] | None = None,
        session_context: dict[str, Any] | None = None,
        trajectory_id: str | None = None,
    ) -> dict[str, Any]:
        """Intercept a tool call, query /api/analyze, and enforce the security decision.

        Enforcement semantics:
        - ALLOW: Forward call to mock MCP server and return executed result.
        - BLOCK: Refuse execution, return security error to agent.
        - CONFIRM: Pause execution, return human approval requirement.
        - REVISE: Reject execution, return guidance to agent to revise plan.
        """
        # Synthesize standard plan for the tool call
        perms_needed = ["admin"] if tool_name == "shell_exec" else (["filesystem:read"] if tool_name == "file_read" else [])
        plan = {
            "steps": [
                {
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "permissions_required": perms_needed,
                    "side_effect_class": "write" if tool_name in ["file_write", "http_post", "shell_exec", "email_send"] else "read",
                    "destination": "external" if tool_name in ["http_post", "email_send"] else "internal",
                    "reversible": tool_name not in ["file_write", "http_post", "shell_exec"],
                    "data_sensitivity": "restricted" if "id_rsa" in str(arguments) or "secret" in str(arguments) else "internal",
                    "estimated_cost": 0.1,
                }
            ],
            "session_context": session_context or {"granted_permissions": ["database:read", "filesystem:read"]},
        }


        mcp_meta = {
            "server_name": server_name or f"{tool_name}_server",
            "tool_schema": tool_schema or {"name": tool_name},
            "resource_uris": resource_uris or [],
        }

        request_payload = {
            "plan": plan,
            "context": {"trajectory_id": trajectory_id or "mcp-session"},
            "mcp_meta": mcp_meta,
        }

        try:
            analysis = self._call_analyze(request_payload)
        except Exception as exc:
            # Proxy fail-closed: if guardrail analysis is unreachable, BLOCK execution
            logger.error("Guardrail analysis unreachable, proxy failing closed: %s", exc)
            return {
                "status": "blocked",
                "action": "BLOCK",
                "error": f"Guardrail unavailable, fail-closed enforced: {exc}",
                "audit_id": "proxy-fail-closed",
            }

        action = analysis.get("action", "BLOCK")
        rationale = analysis.get("rationale", "")
        audit_id = analysis.get("audit_id", "")
        risk_score = analysis.get("risk_score", 1.0)

        logger.info("MCP Proxy decision: action=%s score=%.2f tool=%s", action, risk_score, tool_name)

        if action == "ALLOW":
            result = dispatch_to_mcp_server(tool_name, arguments)
            return {
                "status": "executed",
                "action": "ALLOW",
                "tool_name": tool_name,
                "result": result,
                "audit_id": audit_id,
                "risk_score": risk_score,
            }

        elif action == "BLOCK":
            return {
                "status": "blocked",
                "action": "BLOCK",
                "tool_name": tool_name,
                "error": f"Security Policy Violation: {rationale}",
                "audit_id": audit_id,
                "risk_score": risk_score,
                "rule_hits": analysis.get("rule_hits", []),
            }

        elif action == "CONFIRM":
            return {
                "status": "confirmation_required",
                "action": "CONFIRM",
                "tool_name": tool_name,
                "message": f"Human approval required: {rationale}",
                "audit_id": audit_id,
                "risk_score": risk_score,
            }

        elif action == "REVISE":
            return {
                "status": "revision_required",
                "action": "REVISE",
                "tool_name": tool_name,
                "message": f"Plan revision needed: {rationale}",
                "audit_id": audit_id,
                "risk_score": risk_score,
            }

        else:
            return {
                "status": "blocked",
                "action": "BLOCK",
                "error": f"Unknown action '{action}', failing closed.",
                "audit_id": audit_id,
            }
