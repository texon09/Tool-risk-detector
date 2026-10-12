from app.audit.store import AuditStore
from fastapi import APIRouter, Query

router = APIRouter()
audit_store = AuditStore(db_path="audit.db")  # Use relative for now


@router.get("/audit")
async def get_audit_logs(limit: int = Query(50, le=100), offset: int = Query(0, ge=0)):
    logs = audit_store.get_logs(limit=limit, offset=offset)
    return {"logs": logs}


@router.post("/audit/verify")
async def verify_audit_chain():
    result = audit_store.verify_chain()
    return result
