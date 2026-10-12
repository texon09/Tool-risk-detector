"""API client connecting Streamlit and Python dashboards to the FastAPI backend."""

from __future__ import annotations

import os
from typing import Any
import requests

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


class RiskDetectorAPIClient:
    """Client for Risk Detection API endpoints."""

    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url.rstrip("/")

    def health_check(self) -> dict[str, Any]:
        """Check API service health."""
        try:
            resp = requests.get(f"{self.base_url}/api/health", timeout=3.0)
            return resp.json() if resp.status_code == 200 else {"status": "unhealthy"}
        except requests.RequestException as e:
            return {"status": "offline", "error": str(e)}

    def analyze_plan(
        self,
        plan: dict[str, Any],
        context: dict[str, Any] | None = None,
        mcp_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Analyze a tool-call plan."""
        payload = {"plan": plan, "context": context or {}, "mcp_meta": mcp_meta}
        try:
            resp = requests.post(f"{self.base_url}/api/analyze", json=payload, timeout=10.0)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            return {
                "action": "BLOCK",
                "decision": "BLOCK",
                "risk_score": 1.0,
                "critical_violations": 1,
                "rule_hits": ["api_connection_error"],
                "rationale": f"Fail-closed: Backend connection error ({e})",
                "feature_contributions": {},
                "model_votes": {},
                "latency_ms": 0.0,
                "audit_id": "",
            }

    def get_audit_logs(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Retrieve paginated audit records."""
        try:
            resp = requests.get(
                f"{self.base_url}/api/audit",
                params={"limit": limit, "offset": offset},
                timeout=5.0,
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict):
                return data.get("logs", [])
            return data if isinstance(data, list) else []
        except requests.RequestException:
            return []

    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify cryptographic integrity of the hash chain."""
        try:
            resp = requests.post(f"{self.base_url}/api/audit/verify", timeout=5.0)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            return {"valid": False, "reason": f"Connection error: {e}"}

    def get_metrics(self) -> dict[str, Any]:
        """Fetch model metrics evaluation results."""
        try:
            resp = requests.get(f"{self.base_url}/api/metrics", timeout=5.0)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            return {"available": False, "models": {}}

    def get_scenarios(self) -> list[dict[str, Any]]:
        """Fetch preset benchmark scenarios."""
        try:
            resp = requests.get(f"{self.base_url}/api/scenarios", timeout=5.0)
            resp.raise_for_status()
            return resp.json().get("scenarios", [])
        except requests.RequestException:
            return []
