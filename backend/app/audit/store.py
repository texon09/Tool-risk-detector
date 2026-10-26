"""SQLite persistence for the tamper-evident audit chain."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from app.audit.chain import GENESIS_HASH, link, verify_chain, verify_legacy_chain


class AuditMigrationError(RuntimeError):
    """Raised when a legacy audit chain cannot safely be migrated."""


def _resolve_database_path(database_url: str) -> str:
    """Convert a SQLite URL or plain path into a local database path."""
    if database_url.startswith("sqlite:///"):
        path = unquote(database_url[len("sqlite:///") :])
    elif "://" in database_url:
        raise ValueError("AuditStore supports SQLite DATABASE_URL values only")
    else:
        path = database_url
    if not path:
        raise ValueError("DATABASE_URL must include a SQLite database path")
    return path


class AuditStore:
    def __init__(self, db_path: str | None = None):
        configured_path = (
            db_path if db_path is not None else os.getenv("DATABASE_URL", "sqlite:///audit.db")
        )
        self.db_path = _resolve_database_path(configured_path)
        self.lock = threading.Lock()
        self.ensure_schema()

    def ensure_schema(self) -> None:
        """Create the current table or migrate the previous SQLite schema.

        Existing chains are verified using their legacy hash recipe before any
        changes. Migration assigns IDs and re-hashes each row using the current
        recipe, which includes rationale. Back up the database before migrating.
        """
        parent = Path(self.db_path).parent
        if self.db_path != ":memory:" and str(parent) not in {"", "."}:
            parent.mkdir(parents=True, exist_ok=True)

        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        audit_id TEXT NOT NULL UNIQUE,
                        trajectory_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        current_hash TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        rationale TEXT NOT NULL,
                        user_id TEXT
                    )"""
                )
                cursor.execute("PRAGMA table_info(audit_logs)")
                columns = {row[1] for row in cursor.fetchall()}
                if "user_id" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN user_id TEXT")
                    columns.add("user_id")

                if "audit_id" in columns and "trajectory_id" in columns:
                    return

                cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
                old_rows = [
                    dict(zip((c[0] for c in cursor.description), row, strict=False))
                    for row in cursor.fetchall()
                ]
                valid, errors = verify_legacy_chain(old_rows)
                if not valid:
                    raise AuditMigrationError(
                        f"Legacy audit chain failed verification; refusing migration: {errors[0]}"
                    )

                if "audit_id" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN audit_id TEXT")
                if "trajectory_id" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN trajectory_id TEXT")

                cursor.execute(
                    "SELECT id, audit_id, trajectory_id, payload FROM audit_logs ORDER BY id ASC"
                )
                rows = cursor.fetchall()
                for row_id, audit_id, trajectory_id, payload in rows:
                    try:
                        payload_trajectory = json.loads(payload).get("trajectory_id")
                    except (TypeError, json.JSONDecodeError):
                        payload_trajectory = None
                    cursor.execute(
                        "UPDATE audit_logs SET audit_id = ?, trajectory_id = ? WHERE id = ?",
                        (
                            audit_id or str(uuid.uuid4()),
                            trajectory_id or payload_trajectory or f"legacy-{row_id}",
                            row_id,
                        ),
                    )

                cursor.execute(
                    "SELECT id, audit_id, trajectory_id, timestamp, prev_hash, current_hash, "
                    "payload, decision, rationale FROM audit_logs ORDER BY id ASC"
                )
                migrated_rows = [
                    dict(zip((c[0] for c in cursor.description), row, strict=False))
                    for row in cursor.fetchall()
                ]
                previous = GENESIS_HASH
                for record in migrated_rows:
                    new_hash = link(previous, record)
                    cursor.execute(
                        "UPDATE audit_logs SET prev_hash = ?, current_hash = ? WHERE id = ?",
                        (previous, new_hash, record["id"]),
                    )
                    previous = new_hash
                cursor.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_audit_id "
                    "ON audit_logs(audit_id)"
                )

    def log_decision(
        self,
        payload: dict[str, Any],
        decision: str,
        rationale: str,
        trajectory_id: str | None = None,
        user_id: str | None = None,
    ) -> str:
        """Append a decision and return its UUID audit identifier."""
        with self.lock, closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                prev_hash = row[0] if row else GENESIS_HASH
                audit_id = str(uuid.uuid4())
                trajectory_id = trajectory_id or payload.get("trajectory_id") or str(uuid.uuid4())
                timestamp = datetime.now(timezone.utc).isoformat()
                record: dict[str, Any] = {
                    "audit_id": audit_id,
                    "trajectory_id": str(trajectory_id),
                    "timestamp": timestamp,
                    "prev_hash": prev_hash,
                    "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    "decision": decision,
                    "rationale": rationale,
                }
                if user_id is not None:
                    record["user_id"] = user_id

                current_hash = link(prev_hash, record)
                cursor.execute(
                    """INSERT INTO audit_logs
                    (audit_id, trajectory_id, timestamp, prev_hash, current_hash,
                     payload, decision, rationale, user_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        audit_id,
                        str(trajectory_id),
                        timestamp,
                        prev_hash,
                        current_hash,
                        record["payload"],
                        decision,
                        rationale,
                        user_id,
                    ),
                )
        return audit_id

    def _records(self) -> list[dict[str, Any]]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
            return [dict(row) for row in cursor.fetchall()]

    def verify_chain(self) -> dict[str, Any]:
        valid, errors = verify_chain(self._records())
        first_error = errors[0] if errors else None
        return {
            "valid": valid,
            "broken_at_id": first_error["audit_id"] if first_error else None,
            "reason": first_error["reason"] if first_error else "Chain intact",
        }

    def get_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        user_id: str | None = None,
        audit_id: str | None = None,
    ) -> list[dict[str, Any]]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            conditions: list[str] = []
            params: list[Any] = []
            if user_id is not None:
                conditions.append("user_id = ?")
                params.append(user_id)
            if audit_id is not None:
                conditions.append("audit_id = ?")
                params.append(audit_id)

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            query = f"SELECT * FROM audit_logs {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, tuple(params))
            return [dict(row) for row in cursor.fetchall()]
