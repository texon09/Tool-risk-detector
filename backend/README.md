# Risk Detection API (Backend Service)

The backend service is built with FastAPI and provides deterministic rule checks, argument inspection, ensemble ML risk scoring, policy decision logic, and tamper-evident audit logging.

---

## 🚀 API Endpoints Overview

| Method | Path | Summary | Description |
|---|---|---|---|
| `GET` | `/api/health` | Health Check | Returns service status and API version. |
| `POST`| `/api/analyze` | Analyze Plan | Intercepts a tool plan and returns a policy action (`ALLOW`, `CONFIRM`, `REVISE`, `BLOCK`). |
| `GET` | `/api/audit` | Audit Logs | Returns paginated list of logged security decisions. |
| `POST`| `/api/audit/verify` | Verify Audit Chain | Validates cryptographic SHA-256 hash chain integrity across all records. |
| `GET` | `/api/metrics` | Model Metrics | Returns per-model F1, precision, recall, auroc, and latency metrics. |
| `GET` | `/api/scenarios` | Demo Scenarios | Loads packaged test scenarios (benign, sensitive, credential theft, exfiltration). |

---

## 📋 Response Contract (`/api/analyze`)

Every response from `/api/analyze` strictly provides all 9 required fields:

```json
{
  "action": "BLOCK",
  "risk_score": 0.88,
  "critical_violations": 2,
  "rule_hits": ["R1", "Suspicious URLs", "SQL injection patterns"],
  "rationale": "Blocked due to 2 critical violations (risk score 0.88).",
  "feature_contributions": {
    "tool_shell_exec_count": 0.28,
    "perm_admin_count": 0.21,
    "dest_external_count": 0.12
  },
  "model_votes": {
    "rf_prob": 0.84,
    "xgb_prob": 0.89,
    "dt_prob": 0.80,
    "iso_flag": 1
  },
  "latency_ms": 3.45,
  "audit_id": "3f9c6d30-4e4b-4b2e-a0e2-658b16c87f32"
}
```

---

## 🔒 Security Hardening

- **Fail-Closed Protection**: In the event of an unhandled error, the system defaults to `BLOCK` with `critical_violations=1`.
- **IP Rate Limiting**: Defaults to 120 requests/minute per client IP.
- **Request Size Limitation**: Requests exceeding 1MB receive an HTTP 413.
- **Structured JSON Logging**: Every access attempt is logged with timestamp, duration, status, and client IP.
