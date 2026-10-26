"""Canonical helpers for the append-only SHA-256 audit chain."""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "GENESIS"


def _canonical_json(record: dict[str, Any]) -> str:
    """Serialize a record deterministically, excluding derived database fields.

    For backward compatibility with legacy audit records, user_id is excluded
    when None or absent, and included when present.
    """
    fields = {
        key: value
        for key, value in record.items()
        if key not in {"current_hash", "id"} and not (key == "user_id" and value is None)
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(record: dict[str, Any]) -> str:
    """Return the SHA-256 digest for a complete record, including rationale."""
    return hashlib.sha256(_canonical_json(record).encode("utf-8")).hexdigest()


def link(prev_hash: str, record: dict[str, Any]) -> str:
    """Hash a record after binding it to its preceding record's digest."""
    linked_record = dict(record)
    linked_record["prev_hash"] = prev_hash
    return compute_hash(linked_record)


def verify_chain(records: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
    """Validate ordered records and return validity plus per-record errors."""
    expected_prev = GENESIS_HASH
    errors: list[dict[str, Any]] = []

    for position, record in enumerate(records):
        audit_id = record.get("audit_id", record.get("id", position))
        actual_prev = record.get("prev_hash")
        if actual_prev != expected_prev:
            errors.append({"audit_id": audit_id, "reason": "prev_hash mismatch"})
            expected_prev = str(record.get("current_hash", ""))
            continue

        expected_hash = link(expected_prev, record)
        if record.get("current_hash") != expected_hash:
            errors.append({"audit_id": audit_id, "reason": "current_hash mismatch"})
        expected_prev = str(record.get("current_hash", ""))

    return not errors, errors


def verify_legacy_chain(records: list[dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
    """Verify pre-migration hashes before assigning IDs and rehashing rows.

    Legacy hashes used ``prev_hash + timestamp + payload + decision`` and did
    not cover rationale. This compatibility verifier is migration-only; it
    cannot detect historical rationale edits made before migration.
    """
    expected_prev = GENESIS_HASH
    errors: list[dict[str, Any]] = []
    for record in records:
        audit_id = record.get("id")
        if record.get("prev_hash") != expected_prev:
            errors.append({"audit_id": audit_id, "reason": "legacy prev_hash mismatch"})
            expected_prev = str(record.get("current_hash", ""))
            continue
        legacy_input = (
            f"{record['prev_hash']}{record['timestamp']}{record['payload']}{record['decision']}"
        ).encode("utf-8")
        expected_hash = hashlib.sha256(legacy_input).hexdigest()
        if record.get("current_hash") != expected_hash:
            errors.append({"audit_id": audit_id, "reason": "legacy current_hash mismatch"})
        expected_prev = str(record.get("current_hash", ""))
    return not errors, errors
