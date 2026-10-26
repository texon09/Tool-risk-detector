"""FastAPI application for Risk Detection API with production hardening."""

from __future__ import annotations

import collections
import json
import logging
import os
import sys
import time

# Ensure backend directory is in sys.path so "app..." imports work seamlessly
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.api import analyze, audit, auth, health, metrics, scenarios
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Setup structured logger
logger = logging.getLogger("api.access")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

app = FastAPI(
    title="Risk Detection API",
    version="0.1.0",
    description="Proxy guardrail API intercepting and evaluating AI agent tool-call risk.",
)

# 1. CORS Middleware
cors_origins_raw = os.getenv("CORS_ORIGINS", "*")
if cors_origins_raw.strip() == "*":
    allow_origins = ["*"]
else:
    allow_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Rate Limiting State (Sliding window per IP)
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "120"))  # requests per window
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # window in seconds
RATE_LIMIT_DISABLED = os.getenv("RATE_LIMIT_DISABLED", "false").lower() in {"true", "1", "yes"}

_ip_request_history: dict[str, collections.deque] = collections.defaultdict(collections.deque)

# 3. Request Size Limit
MAX_REQUEST_SIZE = int(os.getenv("MAX_REQUEST_SIZE", str(1024 * 1024)))  # 1MB


@app.middleware("http")
async def production_hardening_middleware(request: Request, call_next):
    """Enforces request payload size limits, IP-based rate limiting, and structured logging."""
    start_time = time.perf_counter()
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    # A. Check Content-Length for Request Size Limit
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Payload too large. Maximum allowed size is {MAX_REQUEST_SIZE} bytes."},
                )
        except ValueError:
            pass

    # B. Enforce Rate Limiting
    if not RATE_LIMIT_DISABLED and client_ip != "testclient":
        history = _ip_request_history[client_ip]
        cutoff = now - RATE_LIMIT_WINDOW
        while history and history[0] < cutoff:
            history.popleft()

        if len(history) >= RATE_LIMIT_MAX:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded: max {RATE_LIMIT_MAX} requests per {RATE_LIMIT_WINDOW}s."},
            )
        history.append(now)

    # Process request
    response = await call_next(request)

    # C. Structured JSON Access Logging
    duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "client_ip": client_ip,
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "duration_ms": duration_ms,
    }
    logger.info(json.dumps(log_entry))

    return response


# 4. Global Fail-Closed Exception Handler
@app.exception_handler(Exception)
async def global_fail_closed_exception_handler(request: Request, exc: Exception):
    """Enforce fail-closed security: any unhandled error returns a valid BLOCK response."""
    logging.exception("Unhandled server exception caught; returning fail-closed BLOCK: %s", exc)
    return JSONResponse(
        status_code=500,
        content={
            "action": "BLOCK",
            "decision": "BLOCK",
            "risk_score": 1.0,
            "score": 1.0,
            "critical_violations": 1,
            "rule_hits": ["server_internal_error"],
            "rationale": f"Internal Security Error: fail-closed enforced ({type(exc).__name__})",
            "feature_contributions": {},
            "model_votes": {},
            "latency_ms": 0.0,
            "audit_id": "fail-closed-exception",
        },
    )


# 5. Route Registration for all 6 API Endpoints
app.include_router(health.router, prefix="/api")
app.include_router(analyze.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(metrics.router, prefix="/api")
app.include_router(scenarios.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
