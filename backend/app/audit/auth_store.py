"""User authentication and API key management store for PlanGuard."""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import bcrypt


def _resolve_database_path(database_url: str) -> str:
    """Convert a SQLite URL or plain path into a local database path."""
    if database_url.startswith("sqlite:///"):
        path = unquote(database_url[len("sqlite:///") :])
    elif "://" in database_url:
        raise ValueError("AuthStore supports SQLite DATABASE_URL values only")
    else:
        path = database_url
    if not path:
        raise ValueError("DATABASE_URL must include a SQLite database path")
    return path


def hash_api_key(raw_key: str) -> str:
    """Hash an API key using SHA-256."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


class AuthStore:
    """SQLite-backed store for users, sessions, and hashed API keys."""

    def __init__(self, db_path: str | None = None):
        configured_path = (
            db_path if db_path is not None else os.getenv("DATABASE_URL", "sqlite:///audit.db")
        )
        self.db_path = _resolve_database_path(configured_path)
        self.lock = threading.Lock()
        self.ensure_schema()

    def ensure_schema(self) -> None:
        parent = Path(self.db_path).parent
        if self.db_path != ":memory:" and str(parent) not in {"", "."}:
            parent.mkdir(parents=True, exist_ok=True)

        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )"""
                )
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS api_keys (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        key_hash TEXT UNIQUE NOT NULL,
                        key_prefix TEXT NOT NULL,
                        label TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        revoked INTEGER NOT NULL DEFAULT 0,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )"""
                )
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS sessions (
                        token TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )"""
                )

    def create_user(self, email: str, password: str) -> dict[str, Any]:
        """Create a new user with bcrypt-hashed password."""
        email_clean = email.strip().lower()
        if not email_clean or "@" not in email_clean:
            raise ValueError("Invalid email format.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters.")

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        user_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        with self.lock, closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                        (user_id, email_clean, password_hash, created_at),
                    )
                except sqlite3.IntegrityError as err:
                    raise ValueError(f"User with email '{email_clean}' already exists.") from err

        return {"id": user_id, "email": email_clean, "created_at": created_at}

    def authenticate_user(self, email: str, password: str) -> dict[str, Any] | None:
        """Verify user credentials and return user dict if valid."""
        email_clean = email.strip().lower()
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email_clean,))
            row = cursor.fetchone()
            if not row:
                return None
            user = dict(row)
            if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
                return {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}
            return None

    def create_session(self, user_id: str) -> str:
        """Create a session token."""
        token = secrets.token_urlsafe(32)
        created_at = datetime.now(timezone.utc).isoformat()
        # 7-day session
        expires_at = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() + 7 * 86400, tz=timezone.utc
        ).isoformat()

        with self.lock, closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                    (token, user_id, created_at, expires_at),
                )
        return token

    def get_user_by_session(self, token: str) -> dict[str, Any] | None:
        """Resolve session token to a user."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """SELECT u.id, u.email, u.created_at, s.expires_at
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?""",
                (token,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            # Expiry check
            if datetime.fromisoformat(data["expires_at"]) < datetime.now(timezone.utc):
                return None
            return {"id": data["id"], "email": data["email"], "created_at": data["created_at"]}

    def create_api_key(self, user_id: str, label: str = "Default Key") -> dict[str, Any]:
        """Generate a new API key, store its SHA-256 hash, and return raw key once."""
        raw_key = f"pg_{secrets.token_urlsafe(32)}"
        key_hash = hash_api_key(raw_key)
        key_id = str(uuid.uuid4())
        key_prefix = raw_key[:7] + "..."
        created_at = datetime.now(timezone.utc).isoformat()

        with self.lock, closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO api_keys
                    (id, user_id, key_hash, key_prefix, label, created_at, revoked)
                    VALUES (?, ?, ?, ?, ?, ?, 0)""",
                    (key_id, user_id, key_hash, key_prefix, label, created_at),
                )

        return {
            "id": key_id,
            "api_key": raw_key,  # Only shown once
            "key_prefix": key_prefix,
            "label": label,
            "created_at": created_at,
        }

    def list_api_keys(self, user_id: str) -> list[dict[str, Any]]:
        """List active and revoked API keys for a user."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, key_prefix, label, created_at, revoked FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def revoke_api_key(self, user_id: str, key_id: str) -> bool:
        """Revoke an API key belonging to a user."""
        with self.lock, closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?",
                    (key_id, user_id),
                )
                return cursor.rowcount > 0

    def get_user_by_api_key(self, raw_key: str) -> dict[str, Any] | None:
        """Resolve a raw API key to its user, if active and not revoked."""
        key_hash = hash_api_key(raw_key)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """SELECT u.id, u.email, u.created_at
                FROM api_keys k
                JOIN users u ON k.user_id = u.id
                WHERE k.key_hash = ? AND k.revoked = 0""",
                (key_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return dict(row)
