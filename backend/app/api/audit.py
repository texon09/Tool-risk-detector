import os
from typing import Optional

from app.audit.auth_store import AuthStore
from app.audit.store import AuditStore
from fastapi import APIRouter, Header, Query

router = APIRouter()
audit_store = AuditStore(db_path=os.getenv("DATABASE_URL", "sqlite:///audit.db"))
auth_store = AuthStore(db_path=os.getenv("DATABASE_URL", "sqlite:///audit.db"))


@router.get("/audit")
async def get_audit_logs(
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    id: Optional[str] = Query(None, description="Optional audit UUID for single-record retrieval"),
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """Retrieve audit logs.

    When authenticated via session token (Authorization: Bearer <token>) or X-API-Key,
    returns logs belonging to the authenticated user.
    When anonymous, returns logs for public inspection (e.g. website manual analyzer).
    Supports ?id= to fetch a specific record.
    """
    user_id: Optional[str] = None

    # Check X-API-Key first
    if x_api_key:
        user_record = auth_store.get_user_by_api_key(x_api_key)
        if user_record:
            user_id = user_record["id"]

    # Check Authorization: Bearer <token>
    if not user_id and authorization:
        parts = authorization.split()
        token = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else authorization
        user_record = auth_store.get_user_by_session(token)
        if user_record:
            user_id = user_record["id"]

    logs = audit_store.get_logs(limit=limit, offset=offset, user_id=user_id, audit_id=id)
    return {"logs": logs}


@router.post("/audit/verify")
async def verify_audit_chain():
    result = audit_store.verify_chain()
    return result
