import hashlib
import json
import sqlite3
import uuid

from app.audit.store import AuditStore


def _store(tmp_path, name="audit.sqlite3"):
    return AuditStore(db_path=str(tmp_path / name))


def test_valid_chain(tmp_path):
    store = _store(tmp_path)
    store.log_decision({"steps": []}, "ALLOW", "Safe.", trajectory_id="traj-1")
    store.log_decision({"steps": [{"tool_name": "file_read"}]}, "CONFIRM", "Review.")

    assert store.verify_chain() == {
        "valid": True,
        "broken_at_id": None,
        "reason": "Chain intact",
    }


def test_rationale_tamper_breaks_chain(tmp_path):
    store = _store(tmp_path)
    audit_id = store.log_decision({"steps": []}, "ALLOW", "Original rationale")

    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE audit_logs SET rationale = ? WHERE audit_id = ?",
            ("Changed after logging", audit_id),
        )

    result = store.verify_chain()
    assert result["valid"] is False
    assert result["broken_at_id"] == audit_id


def test_decision_tamper_breaks_chain(tmp_path):
    store = _store(tmp_path)
    audit_id = store.log_decision({"steps": []}, "ALLOW", "Safe.")

    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE audit_logs SET decision = ? WHERE audit_id = ?",
            ("BLOCK", audit_id),
        )

    result = store.verify_chain()
    assert result["valid"] is False
    assert result["broken_at_id"] == audit_id


def test_restart_persistence(tmp_path):
    db_path = str(tmp_path / "persistent.sqlite3")
    first_store = AuditStore(db_path=db_path)
    first_store.log_decision({"steps": []}, "ALLOW", "Safe.", "trajectory-restart")

    reopened_store = AuditStore(db_path=db_path)
    assert reopened_store.verify_chain()["valid"] is True
    assert len(reopened_store.get_logs()) == 1


def test_audit_id_is_uuid(tmp_path):
    store = _store(tmp_path)
    audit_id = store.log_decision({"steps": []}, "ALLOW", "Safe.")

    assert str(uuid.UUID(audit_id)) == audit_id
    assert store.get_logs()[0]["audit_id"] == audit_id


def test_trajectory_id_persisted(tmp_path):
    store = _store(tmp_path)
    store.log_decision({"steps": []}, "ALLOW", "Safe.", trajectory_id="trajectory-42")

    assert store.get_logs()[0]["trajectory_id"] == "trajectory-42"


def test_database_url_environment_variable(tmp_path, monkeypatch):
    db_path = (tmp_path / "env.sqlite3").as_posix()
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    store = AuditStore()

    assert store.db_path == db_path
    store.log_decision({"steps": []}, "ALLOW", "Safe.")
    assert store.verify_chain()["valid"] is True


def test_legacy_schema_migrates_and_rechains(tmp_path):
    db_path = str(tmp_path / "legacy.sqlite3")
    timestamp = "2026-01-01T00:00:00"
    payload = json.dumps({"steps": []}, sort_keys=True)
    previous = "GENESIS"
    old_hash = hashlib.sha256(f"{previous}{timestamp}{payload}ALLOW".encode()).hexdigest()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                payload TEXT NOT NULL,
                decision TEXT NOT NULL,
                rationale TEXT NOT NULL
            )"""
        )
        conn.execute(
            """INSERT INTO audit_logs
            (timestamp, prev_hash, current_hash, payload, decision, rationale)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (timestamp, previous, old_hash, payload, "ALLOW", "legacy rationale"),
        )

    migrated = AuditStore(db_path=db_path)
    row = migrated.get_logs()[0]
    assert row["audit_id"]
    assert row["trajectory_id"] == "legacy-1"
    assert migrated.verify_chain()["valid"] is True
