"""Tests for user accounts, API keys, per-user audit filtering, and tamper resistance."""

from __future__ import annotations

import json
import sqlite3

import pytest
from app.audit.auth_store import AuthStore
from app.audit.store import AuditStore
from app.main import app
from fastapi.testclient import TestClient


@pytest.fixture
def test_client(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_auth_audit.sqlite3")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")

    # Re-initialize stores with test database
    from app.api import analyze, audit, auth
    test_audit_store = AuditStore(db_path=db_file)
    test_auth_store = AuthStore(db_path=db_file)

    orig_analyze_audit = analyze.audit_store
    orig_analyze_auth = analyze.auth_store
    orig_audit_audit = audit.audit_store
    orig_audit_auth = audit.auth_store
    orig_auth_auth = auth.auth_store

    analyze.audit_store = test_audit_store
    analyze.auth_store = test_auth_store
    audit.audit_store = test_audit_store
    audit.auth_store = test_auth_store
    auth.auth_store = test_auth_store

    client = TestClient(app)
    try:
        yield client, test_audit_store, test_auth_store
    finally:
        analyze.audit_store = orig_analyze_audit
        analyze.auth_store = orig_analyze_auth
        audit.audit_store = orig_audit_audit
        audit.auth_store = orig_audit_auth
        auth.auth_store = orig_auth_auth


def test_auth_signup_login_and_me(test_client):
    client, _, _ = test_client

    # 1. Signup
    signup_res = client.post("/api/auth/signup", json={"email": "agent@example.com", "password": "supersecretpassword"})
    assert signup_res.status_code == 200
    data = signup_res.json()
    assert "session_token" in data
    assert data["user"]["email"] == "agent@example.com"
    token = data["session_token"]

    # 2. Get Current User via /api/auth/me
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["user"]["email"] == "agent@example.com"

    # 3. Duplicate signup rejected
    dup_res = client.post("/api/auth/signup", json={"email": "agent@example.com", "password": "supersecretpassword"})
    assert dup_res.status_code == 400

    # 4. Login
    login_res = client.post("/api/auth/login", json={"email": "agent@example.com", "password": "supersecretpassword"})
    assert login_res.status_code == 200
    assert "session_token" in login_res.json()

    # 5. Invalid login
    bad_login = client.post("/api/auth/login", json={"email": "agent@example.com", "password": "wrongpassword"})
    assert bad_login.status_code == 401


def test_api_key_lifecycle(test_client):
    client, _, _ = test_client

    # Create user
    res = client.post("/api/auth/signup", json={"email": "dev@example.com", "password": "password123"})
    token = res.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create API key
    key_res = client.post("/api/keys", json={"label": "Production CLI"}, headers=headers)
    assert key_res.status_code == 200
    key_data = key_res.json()
    raw_key = key_data["api_key"]
    key_id = key_data["id"]
    assert raw_key.startswith("pg_")
    assert key_data["label"] == "Production CLI"

    # List keys
    list_res = client.get("/api/keys", headers=headers)
    assert list_res.status_code == 200
    keys = list_res.json()["keys"]
    assert len(keys) == 1
    assert keys[0]["id"] == key_id
    assert keys[0]["revoked"] == 0

    # Revoke key
    del_res = client.delete(f"/api/keys/{key_id}", headers=headers)
    assert del_res.status_code == 200

    # Verify key list shows revoked
    list_res2 = client.get("/api/keys", headers=headers)
    assert list_res2.json()["keys"][0]["revoked"] == 1


def test_analyze_with_api_key_stores_user_id(test_client):
    client, audit_store, _ = test_client

    # Create user and API key
    res = client.post("/api/auth/signup", json={"email": "keyuser@example.com", "password": "password123"})
    token = res.json()["session_token"]
    user_id = res.json()["user"]["id"]
    key_res = client.post("/api/keys", json={"label": "Test Key"}, headers={"Authorization": f"Bearer {token}"})
    raw_key = key_res.json()["api_key"]

    plan = {
        "steps": [
            {
                "tool_name": "file_read",
                "arguments": {"path": "report.txt"},
                "permissions_required": ["filesystem:read"],
                "side_effect_class": "read",
                "reversible": True,
                "data_sensitivity": "internal",
                "destination": "internal",
                "estimated_cost": 0.1,
            }
        ],
        "session_context": {"granted_permissions": ["filesystem:read"]},
    }

    # Analyze with X-API-Key
    analyze_res = client.post("/api/analyze", json={"plan": plan}, headers={"X-API-Key": raw_key})
    assert analyze_res.status_code == 200
    audit_id = analyze_res.json()["audit_id"]

    # Verify audit record has user_id and chain is intact
    logs = audit_store.get_logs(audit_id=audit_id)
    assert len(logs) == 1
    assert logs[0]["user_id"] == user_id
    assert audit_store.verify_chain()["valid"] is True


def test_analyze_anonymous_fallback_and_chain(test_client):
    client, audit_store, _ = test_client

    plan = {
        "steps": [
            {
                "tool_name": "file_read",
                "arguments": {"path": "report.txt"},
                "permissions_required": ["filesystem:read"],
                "side_effect_class": "read",
                "reversible": True,
                "data_sensitivity": "internal",
                "destination": "internal",
                "estimated_cost": 0.1,
            }
        ],
        "session_context": {"granted_permissions": ["filesystem:read"]},
    }

    # Anonymous request
    res = client.post("/api/analyze", json={"plan": plan})
    assert res.status_code == 200
    audit_id = res.json()["audit_id"]

    logs = audit_store.get_logs(audit_id=audit_id)
    assert len(logs) == 1
    assert logs[0]["user_id"] is None
    assert audit_store.verify_chain()["valid"] is True


def test_audit_logs_per_user_isolation_and_id_deep_link(test_client):
    client, audit_store, _ = test_client

    # User 1
    u1_signup = client.post("/api/auth/signup", json={"email": "user1@example.com", "password": "password123"}).json()
    token1 = u1_signup["session_token"]
    u1_id = u1_signup["user"]["id"]

    # User 2
    u2_signup = client.post("/api/auth/signup", json={"email": "user2@example.com", "password": "password123"}).json()
    token2 = u2_signup["session_token"]
    u2_id = u2_signup["user"]["id"]

    # Log entries directly
    id1 = audit_store.log_decision({"steps": []}, "ALLOW", "User 1 action", user_id=u1_id)
    id2 = audit_store.log_decision({"steps": []}, "ALLOW", "User 2 action", user_id=u2_id)
    audit_store.log_decision({"steps": []}, "ALLOW", "Anonymous action")

    # User 1 queries /api/audit
    res1 = client.get("/api/audit", headers={"Authorization": f"Bearer {token1}"})
    assert res1.status_code == 200
    user1_logs = res1.json()["logs"]
    assert len(user1_logs) == 1
    assert user1_logs[0]["audit_id"] == id1

    # User 2 queries /api/audit with deep link ?id=id2
    res2_deep = client.get(f"/api/audit?id={id2}", headers={"Authorization": f"Bearer {token2}"})
    assert res2_deep.status_code == 200
    assert len(res2_deep.json()["logs"]) == 1
    assert res2_deep.json()["logs"][0]["audit_id"] == id2

    # User 2 queries User 1's ID -> should return empty
    res2_forbidden = client.get(f"/api/audit?id={id1}", headers={"Authorization": f"Bearer {token2}"})
    assert res2_forbidden.status_code == 200
    assert len(res2_forbidden.json()["logs"]) == 0

    # Anonymous queries /api/audit -> sees public logs
    res_anon = client.get("/api/audit")
    assert res_anon.status_code == 200
    assert len(res_anon.json()["logs"]) == 3


def test_tampering_with_user_id_breaks_audit_chain(test_client):
    _, audit_store, _ = test_client

    audit_id = audit_store.log_decision({"steps": []}, "ALLOW", "Safe action", user_id="user-original")
    assert audit_store.verify_chain()["valid"] is True

    # Tamper with user_id in database
    with sqlite3.connect(audit_store.db_path) as conn:
        conn.execute("UPDATE audit_logs SET user_id = ? WHERE audit_id = ?", ("user-hacked", audit_id))

    verify_res = audit_store.verify_chain()
    assert verify_res["valid"] is False
    assert verify_res["broken_at_id"] == audit_id


def test_legacy_rows_without_user_id_still_verify(tmp_path):
    """Verify that rows without user_id verify cleanly and remain tamper-evident."""
    from app.audit.chain import GENESIS_HASH, link, verify_chain

    record1 = {
        "audit_id": "legacy-uuid-1",
        "trajectory_id": "traj-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "prev_hash": GENESIS_HASH,
        "payload": json.dumps({"steps": []}, sort_keys=True),
        "decision": "ALLOW",
        "rationale": "Legacy rationale.",
        "user_id": None,  # Legacy row without user_id
    }
    hash1 = link(GENESIS_HASH, record1)
    record1["current_hash"] = hash1

    record2 = {
        "audit_id": "new-uuid-2",
        "trajectory_id": "traj-2",
        "timestamp": "2026-01-01T00:01:00Z",
        "prev_hash": hash1,
        "payload": json.dumps({"steps": []}, sort_keys=True),
        "decision": "CONFIRM",
        "rationale": "New user action.",
        "user_id": "user-uuid-123",  # New row with user_id
    }
    hash2 = link(hash1, record2)
    record2["current_hash"] = hash2

    valid, errors = verify_chain([record1, record2])
    assert valid is True
    assert len(errors) == 0
