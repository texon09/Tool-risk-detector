"""Authentication and API key management endpoints for PlanGuard."""

from __future__ import annotations

import os
from typing import Optional

from app.audit.auth_store import AuthStore
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

router = APIRouter()
auth_store = AuthStore(db_path=os.getenv("DATABASE_URL", "sqlite:///audit.db"))


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CreateKeyRequest(BaseModel):
    label: str = Field(default="Default Key", max_length=100)


def _get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    parts = authorization.split()
    token = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else authorization
    user = auth_store.get_user_by_session(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
        )
    return user


@router.post("/auth/signup")
async def signup(req: SignupRequest):
    """Register a new user account."""
    try:
        user = auth_store.create_user(email=req.email, password=req.password)
        token = auth_store.create_session(user["id"])
        return {
            "user": user,
            "session_token": token,
            "message": "User registered successfully.",
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/auth/login")
async def login(req: LoginRequest):
    """Authenticate and obtain a session token."""
    user = auth_store.authenticate_user(email=req.email, password=req.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    token = auth_store.create_session(user["id"])
    return {
        "user": user,
        "session_token": token,
        "message": "Login successful.",
    }


@router.get("/auth/me")
async def me(authorization: Optional[str] = Header(None)):
    """Return the currently authenticated user."""
    return {"user": _get_current_user(authorization)}


@router.post("/keys")
async def create_api_key(req: CreateKeyRequest, authorization: Optional[str] = Header(None)):
    """Create a new API key for the authenticated user.

    The raw secret key is returned ONCE and cannot be retrieved again.
    """
    user = _get_current_user(authorization)
    key_info = auth_store.create_api_key(user_id=user["id"], label=req.label)
    return key_info


@router.get("/keys")
async def list_api_keys(authorization: Optional[str] = Header(None)):
    """List all API keys for the authenticated user."""
    user = _get_current_user(authorization)
    keys = auth_store.list_api_keys(user_id=user["id"])
    return {"keys": keys}


@router.delete("/keys/{key_id}")
async def revoke_api_key(key_id: str, authorization: Optional[str] = Header(None)):
    """Revoke an API key."""
    user = _get_current_user(authorization)
    revoked = auth_store.revoke_api_key(user_id=user["id"], key_id=key_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key '{key_id}' not found or already revoked.",
        )
    return {"message": f"API key '{key_id}' revoked successfully."}
