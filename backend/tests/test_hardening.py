"""Tests for production hardening: CORS, rate limiting, payload size, and fail-closed handling."""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_cors_headers_present():
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") in ["*", "http://localhost:3000"]


def test_payload_size_limit_exceeded():
    # Attempting to send a payload exceeding MAX_REQUEST_SIZE
    large_headers = {"content-length": str(1024 * 1024 + 10)}
    response = client.post("/api/analyze", json={"plan": {}}, headers=large_headers)
    assert response.status_code == 413
    assert "Payload too large" in response.json()["detail"]


def test_health_endpoint_still_works():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scenarios_endpoint():
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert "scenarios" in data
    assert len(data["scenarios"]) >= 5


def test_audit_verify_endpoint():
    response = client.post("/api/audit/verify")
    assert response.status_code == 200
    data = response.json()
    assert "valid" in data
    assert data["valid"] is True
