# PlanGuard: Comprehensive Technical Architecture & Engineering Manual
**From Data Ingestion to Production Deployment**

---

## 1. Executive System Overview

**PlanGuard** is an industrial-grade, defense-in-depth safety and risk detection engine for autonomous AI agents. When an LLM agent plans or issues tool calls (e.g., executing SQL queries, reading filesystem blocks, invoking outbound webhooks, executing shell scripts), PlanGuard intercepts the execution plan **before runtime execution** and determines whether the plan is:
- **`ALLOW`**: Safe to execute autonomously without intervention.
- **`REVISE`**: The plan carries an elevated or ambiguous risk; the agent must adjust arguments or parameters according to security feedback.
- **`CONFIRM`**: The plan carries high impact or touches sensitive resources; explicit human-in-the-loop (HITL) approval is required.
- **`BLOCK`**: Malicious, destructive, or exfiltrative; execution is prohibited immediately.

PlanGuard employs a **hybrid architecture** pairing deterministic static security analysis (regular expressions, security heuristics, semantic argument inspectors) with an ensemble of four calibrated machine learning models.

```
                              [ AI Agent / User Prompt ]
                                          │
                                          ▼
                             [ Proposed Multi-Step Plan ]
                                          │
                ┌─────────────────────────┴─────────────────────────┐
                ▼                                                   ▼
   [ Deterministic Engine ]                                [ Machine Learning Engine ]
   • Deterministic Rules (R1–R9)                           • 38 Structured Features
   • Argument Inspector Scanners                           • Random Forest (40%)
     - Credential leaks                                    • XGBoost (40%)
     - Sensitive file paths                                • Decision Tree (10%)
     - SQL Injection patterns                              • Isolation Forest (10%)
     - Path traversal (../../)                                      │
     - PII & Credit Card verification                               ▼
     - Suspicious URLs & unknown TLDs                      [ Platt Scaling Calibrator ]
                │                                                   │
                └─────────────────────────┬─────────────────────────┘
                                          ▼
                            [ Policy & Decision Matrix ]
                            • Threshold Bands (0.40, 0.60, 0.75, 0.90)
                            • Critical & High Severity Escalation Rules
                            • Fail-Closed Safe Fallback
                                          │
                                          ▼
                      [ Final Action: ALLOW / REVISE / CONFIRM / BLOCK ]
                                          │
                                          ▼
                     [ Cryptographic SHA-256 Audit Blockchain ]
```

---

## 2. Database Importing, Schema & Cryptographic Persistence

### 2.1 Storage Engines
- **Database Engine**: SQLite 3 (configured via `DATABASE_URL`, e.g., `sqlite:////data/audit.db` or local `sqlite:///audit.db`).
- **Concurrency & Thread Safety**: Uses connection pooling, context management (`contextlib.closing`), and Python thread locks (`threading.Lock`) to prevent race conditions during high-concurrency evaluation requests.

### 2.2 Relational Tables

#### `audit_logs` (Tamper-Evident Ledger)
Every single decision evaluated by PlanGuard is recorded immutably:
```sql
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    plan TEXT NOT NULL,
    risk_score REAL NOT NULL,
    action TEXT NOT NULL,
    rationale TEXT NOT NULL,
    rule_hits TEXT NOT NULL,
    user_id TEXT,
    prev_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL
);
```

#### `users` & `api_keys` (Authentication & Access Control)
```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
```

### 2.3 The SHA-256 Cryptographic Hash Chain

#### Purpose & Significance
Prevents log tampering, repudiation, or internal log alterations. If an adversary or malicious administrator attempts to modify a prior risk assessment or alter the records of an exfiltration attempt, the mathematical integrity of subsequent block hashes is permanently broken.

#### Mathematical Formulation & Hash Linking
For record $i$, let $R_i$ represent the canonicalized dictionary of record fields:
$$R_i = \{ \text{action}, \text{audit\_id}, \text{plan}, \text{prev\_hash}, \text{rationale}, \text{risk\_score}, \text{rule\_hits}, \text{timestamp}, [\text{user\_id}] \}$$

1. **Canonical JSON Serialization**:
   $$\text{Canonical}(R_i) = \text{JSON}_{\text{sorted\_keys}}(\{ k: v \mid k \notin \{\text{"current\_hash"}, \text{"id"}\}, v \neq \text{None} \})$$
   Uses compact separators `(",", ":")` and `ensure_ascii=False` to guarantee deterministic bitwise byte ordering across heterogeneous operating systems.

2. **Digest Calculation**:
   $$H_0 = \text{"GENESIS"}$$
   $$H_i = \text{SHA256}(\text{Canonical}(R_i \cup \{ \text{"prev\_hash"}: H_{i-1} \}))$$

3. **Chain Verification Verification**:
   $$\text{Valid}(\text{Chain}) \iff \forall i \ge 1, \quad R_i.\text{prev\_hash} = H_{i-1} \quad \land \quad R_i.\text{current\_hash} = H_i$$

---

## 3. Data Processing & The 38 Feature Extraction Pipeline

Every incoming plan is converted into a 38-dimensional numerical feature vector $X \in \mathbb{R}^{38}$.

### 3.1 Feature Vector Index (`FEATURE_NAMES`)

| Feature Index | Name | Category | Description & Purpose |
|:---:|---|---|---|
| **0** | `step_count` | Complexity | Total number of discrete tool invocations in the plan. |
| **1** | `unique_tool_count` | Complexity | Number of distinct tools used (detects composite chain attacks). |
| **2** | `tool_db_query_count` | Tool Distribution | Frequency of database querying tools. |
| **3** | `tool_file_read_count` | Tool Distribution | Frequency of filesystem read tools. |
| **4** | `tool_file_write_count` | Tool Distribution | Frequency of filesystem write/modify tools. |
| **5** | `tool_http_post_count` | Tool Distribution | Outbound network data posting requests (primary vector for exfiltration). |
| **6** | `tool_email_send_count` | Tool Distribution | Outbound email dispatches (secondary exfiltration vector). |
| **7** | `tool_shell_exec_count` | Tool Distribution | Raw command-line or bash executions (highest blast radius). |
| **8** | `tool_directory_search_count` | Tool Distribution | Filesystem enumeration and reconnaissance tools. |
| **9** | `tool_unknown_count` | Tool Distribution | Tools not registered in canonical tool ontology. |
| **10** | `has_write_operation` | Impact / Mutability | Binary indicator (1 if any tool mutates state, 0 otherwise). |
| **11** | `write_step_count` | Impact / Mutability | Total count of state-mutating actions. |
| **12** | `has_irreversible_step` | Reversibility | Binary indicator (1 if an action cannot be rolled back or undone). |
| **13** | `irreversible_step_count`| Reversibility | Total count of irreversible operations. |
| **14** | `perm_required_count` | Permissions | Cardinality of all permissions claimed by plan steps. |
| **15** | `perm_admin_count` | Permissions | Number of privileged / root / admin permissions requested. |
| **16** | `perm_network_ext_count`| Permissions | Requests for outbound external Internet connectivity. |
| **17** | `perm_filesystem_count` | Permissions | Requests for local disk read/write permissions. |
| **18** | `dest_external_count` | Destination | Frequency of outbound destinations targeting non-internal entities. |
| **19** | `dest_has_ip_literal` | Destination | Binary/Count: destination uses raw IP literals (e.g. `http://203.0.113.7`) avoiding DNS. |
| **20** | `sens_count_public` | Sensitivity | Steps accessing publicly classified data. |
| **21** | `sens_count_internal` | Sensitivity | Steps accessing internal business data. |
| **22** | `sens_count_confidential`| Sensitivity | Steps accessing confidential organizational assets. |
| **23** | `sens_count_restricted` | Sensitivity | Steps accessing highly restricted assets (e.g., PII, financial). |
| **24** | `sens_count_secret` | Sensitivity | Steps accessing top-secret data (e.g., private keys, master auth tokens). |
| **25** | `has_sensitive_data` | Sensitivity | Binary: 1 if any step accesses confidential, restricted, or secret data. |
| **26** | `arg_sql_keyword_count` | Argument Pattern | Occurrences of dangerous SQL keywords (`DROP`, `UNION`, `DELETE`, etc.). |
| **27** | `arg_path_traversal_count`| Argument Pattern | Occurrences of directory escaping (`../`, `..\\`). |
| **28** | `arg_sensitive_path_count`| Argument Pattern | References to known credential paths (`~/.ssh`, `.env`, `/etc/passwd`). |
| **29** | `arg_suspicious_url_count`| Argument Pattern | Detection of known suspicious target domains or insecure protocols. |
| **30** | `arg_encoded_payload_count`| Argument Pattern | Occurrences of high-entropy strings or Base64 payload blobs. |
| **31** | `arg_credential_pattern_count`| Argument Pattern| Occurrences of API keys, bearer tokens, or password arguments. |
| **32** | `arg_pii_pattern_count` | Argument Pattern | Occurrences of SSNs, emails, or credit card numbers in tool parameters. |
| **33** | `kill_chain_recon_count`| Taint Analysis | Steps performing initial reconnaissance (directory listings, schema lookups). |
| **34** | `kill_chain_access_count`| Taint Analysis | Steps accessing privileged or secret target stores. |
| **35** | `kill_chain_exfil_count` | Taint Analysis | Steps transmitting retrieved data across outbound boundaries. |
| **36** | `mcp_server_count` | MCP Context | Number of Model Context Protocol (MCP) server instances involved. |
| **37** | `mcp_resource_uri_count`| MCP Context | Count of unique MCP resource URIs addressed by the plan. |

---

## 4. Machine Learning Algorithms, Formulas & Significance

PlanGuard combines supervised classification with unsupervised novelty detection.

### 4.1 Ensemble Architecture & Weights
The supervised risk score maps plans across 3 classes:
- Class 0: `SAFE`
- Class 1: `SUSPICIOUS`
- Class 2: `HIGH-RISK`

```
Plan -> Feature Vector X
         │
         ├──> Random Forest (200 trees) ─────────> p_rf  (Weight: 0.40)
         ├──> XGBoost (200 estimators) ──────────> p_xgb (Weight: 0.40)
         ├──> Decision Tree (max_depth=3) ───────> p_dt  (Weight: 0.10)
         └──> Isolation Forest (novelty) ────────> p_iso (Weight: 0.10)
                                                       │
                                                       ▼
                                            Weighted Linear Combine
                                                       │
                                                       ▼
                                            Platt Logistic Calibration
                                                       │
                                                       ▼
                                            Calibrated ML Score [0, 1]
```

### 4.2 Supervised Model Probability Aggregation
For each multi-class classifier $M \in \{\text{Random Forest}, \text{XGBoost}, \text{Decision Tree}\}$, the classifier outputs probability vector:
$$\mathbf{P}_M = [P_M(Y = \text{SAFE}), P_M(Y = \text{SUSPICIOUS}), P_M(Y = \text{HIGH-RISK})]$$

The continuous scalar risk projection $p_M \in [0.0, 1.0]$ is computed via linear expectation:
$$p_M = 0.0 \cdot P_M(\text{SAFE}) + 0.5 \cdot P_M(\text{SUSPICIOUS}) + 1.0 \cdot P_M(\text{HIGH-RISK})$$

### 4.3 Isolation Forest Anomaly Normalization
Isolation Forest computes anomaly scores based on tree path isolation depth.
- In `scikit-learn`, the decision function $s_{\text{raw}} = \text{decision\_function}(X)$ outputs positive values for nominal/inliers and negative values for anomalous outliers.
- We map $s_{\text{raw}}$ to an inverted continuous risk scale $s_{\text{iso}} \in [0.0, 1.0]$:

$$s_{\text{iso}} = \text{clip}\left( \frac{\text{max\_ref} - s_{\text{raw}}}{\text{max\_ref} - \text{min\_ref}}, 0.0, 1.0 \right)$$
*Reference anchors*: $\text{max\_ref} = 0.15$ (nominal baseline), $\text{min\_ref} = -0.25$ (extreme anomaly).
- When $s_{\text{raw}} \ge 0.15 \implies s_{\text{iso}} = 0.0$ (no novelty risk).
- When $s_{\text{raw}} \le -0.25 \implies s_{\text{iso}} = 1.0$ (maximum outlier/zero-day pattern).

### 4.4 Ensemble Linear Combination
The raw uncalibrated ensemble risk score $S_{\text{raw}}$ is calculated as:
$$S_{\text{raw}} = w_{\text{rf}} \cdot p_{\text{rf}} + w_{\text{xgb}} \cdot p_{\text{xgb}} + w_{\text{dt}} \cdot p_{\text{dt}} + w_{\text{iso}} \cdot s_{\text{iso}}$$
$$\text{Where: } w_{\text{rf}} = 0.40, \quad w_{\text{xgb}} = 0.40, \quad w_{\text{dt}} = 0.10, \quad w_{\text{iso}} = 0.10$$

#### Significance of Weight Choices:
- **Random Forest (0.40)**: Bagging prevents overfitting to specific argument combinations and yields robust variance reduction.
- **XGBoost (0.40)**: Gradient boosting captures non-linear feature interactions (e.g., `file_read` combined with `dest_external_count`).
- **Decision Tree (0.10)**: Fast shallow surrogate providing interpretable linear cutoffs.
- **Isolation Forest (0.10)**: Safety net against zero-day evasions or unusual feature distributions not present in training data.

---

## 5. Score Calibration: Platt Scaling

### 5.1 The Problem with Raw Ensemble Scores
Raw tree ensemble outputs often produce clustered or skewed probabilities near internal boundaries, leading to non-monotonic steps and poor threshold reliability.

### 5.2 Platt Scaling Formula
PlanGuard applies a fitted Logistic Regression model on top of $S_{\text{raw}}$ trained against validation ground truth:
$$P(\text{Risk} \mid S_{\text{raw}}) = \sigma(A \cdot S_{\text{raw}} + B) = \frac{1}{1 + e^{-(A \cdot S_{\text{raw}} + B)}}$$
- Optimized via binary cross-entropy with $L_2$ regularization parameter $C = 2.5$.
- Result: Transforms $S_{\text{raw}}$ into smooth, well-calibrated posterior probabilities $S_{\text{calibrated}} \in [0.0, 1.0]$.

---

## 6. Deterministic Rule Engine & Argument Inspector

Machine learning handles generalized probability, while **deterministic rules enforce absolute, non-negotiable security boundaries**.

### 6.1 The 9 Hard Safety Rules (`RuleEngine`)

| Rule ID | Rule Name | Severity | Condition / Trigger | Rationale |
|:---:|---|:---:|---|---|
| **R1** | Least Privilege Violation | Critical / High | Tool requires permissions not present in `session_context.granted_permissions`. | Prevents privilege escalation beyond user consent. |
| **R2** | Destructive File Operation | Critical | Irreversible file deletion or overwriting without explicit user confirmation. | Prevents silent data destruction. |
| **R3** | Confidential Data Read | High | Step accesses `confidential`, `restricted`, or `secret` sensitivity stores. | Protects proprietary and sensitive data assets. |
| **R4** | Data Exfiltration Chain | Critical | Step reads sensitive internal data followed by an outbound external transmission. | Stops classic cyber-kill-chain data theft. |
| **R5** | Unbounded Database Access | High | SQL query lacks `LIMIT` clause or fetches entire sensitive tables. | Mitigates data dump attempts and resource exhaustion. |
| **R6** | Shell Command Injection | Critical | Command execution contains chaining operators (`;`, `&&`, `\|`, backticks, `$()`). | Prevents arbitrary remote code execution (RCE). |
| **R7** | Unrestricted Network Mutation | High | External network mutation (HTTP PUT/POST/DELETE) with payload $> 100 \text{ KB}$. | Prevents massive exfiltration or DoS relay attacks. |
| **R8** | Critical Privilege Escalation | Critical | Requesting `admin:root`, `system:kernel`, or identity token assumption. | Blocks agent attempts to hijack system-level permissions. |
| **R9** | Recursive Directory Search | Medium | Deep filesystem traversal without path depth limits. | Prevents reconnaissance scanning of entire drive trees. |

### 6.2 Argument Inspector Scanners
Runs deep static analysis across all parameter values:
- **Credential Scanner** (`Critical`): Regex matches AWS keys (`AKIA...`), RSA private keys (`BEGIN RSA PRIVATE KEY`), JWT tokens, GitHub PATs (`ghp_...`).
- **Sensitive Path Scanner** (`High`): Detects accesses to `~/.ssh`, `/etc/shadow`, `.env`, `id_rsa`, `sam.db`.
- **SQL Injection Scanner** (`Critical`): Matches union-based and comment-based injection (`UNION SELECT`, `' OR 1=1 --`, `EXEC xp_cmdshell`).
- **Path Traversal Scanner** (`High`): Flags relative directory escapes (`../`, `..\`).
- **PII Scanner** (`High`): Validates Social Security Numbers (SSN), formatted email addresses, and Luhn-checked Credit Card numbers (Visa, Mastercard, Amex, Discover).
- **Suspicious URL & Host Scanner** (`High`): Scans URL-bearing fields and non-path parameters for unknown/unregistered TLDs, malicious schemes, or raw IP literatures while correctly ignoring local filesystem filenames (e.g. `notes.txt`, `report.pdf`).

---

## 7. Policy Decision Matrix & Thresholds

The policy engine (`backend/app/policy/decision.py`) evaluates the calibrated ML score along with the counts of critical and high-severity violations.

### 7.1 Threshold Parameters (`thresholds.json`)
$$\tau_{\text{medium}} = 0.40, \quad \tau_{\text{high}} = 0.60, \quad \tau_{\text{confirm}} = 0.75, \quad \tau_{\text{block}} = 0.90$$

### 7.2 Decision Truth Table

```
                         [ Inputs: Score S, Critical Count C, High Count H ]
                                                  │
                 ┌────────────────────────────────┴────────────────────────────────┐
                 ▼                                                                 ▼
             [ C >= 2 ]                                                        [ C == 1 ]
                 │                                                                 │
                 ▼                                             ┌───────────────────┼───────────────────┐
             >> BLOCK <<                                       ▼                   ▼                   ▼
                                                           [ S > 0.90 ]      [ S > 0.75 ]       [ S <= 0.75 ]
                                                               │                   │                   │
                                                               ▼                   ▼                   ▼
                                                          >> BLOCK <<        >> CONFIRM <<       >> REVISE <<

                 ┌─────────────────────────────────────────────────────────────────┐
                 ▼
             [ C == 0 ]
                 │
                 ├────────────────────────┬────────────────────────┬────────────────────────┐
                 ▼                        ▼                        ▼                        ▼
           [ S >= 0.60 ]            [ S >= 0.40 ]             [ S < 0.40 ]             [ S < 0.40 ]
                 │                        │                        │                        │
                 ▼                        ▼                  (and H == 0)             (and H == 1)
            >> CONFIRM <<            >> REVISE <<                  │                        │
                                                                   ▼                        ▼
                                                              >> ALLOW <<              >> REVISE <<
                                                                                            │
                                                                                    (if H >= 2 => CONFIRM)
```

### 7.3 Fail-Closed Safety Protocol
If any uncaught exception occurs (e.g., malformed plan, database lock, corrupted input vector, memory error), the decorator `@fail_closed` intercepts the failure and forces:
```python
{
    "action": "BLOCK",
    "rationale": "Blocked: internal security evaluation failed closed (Exception details)",
    "critical_violations": 1,
    "rule_hits": ["internal_error"]
}
```
**Significance**: An attacker cannot bypass security by sending crash-inducing inputs.

---

## 8. Deployment Architecture & Operations

### 8.1 Production Containerization (`Dockerfile`)
The service is containerized as a lightweight, secure image:
- **Base OS**: `python:3.11-slim`
- **Principle of Least Privilege**: A dedicated non-root user `appuser` (UID 1000) is created and owns the execution environment. The service never runs as root.
- **Port**: Exposed on port `8000`.

### 8.2 Deployment Blueprint (`render.yaml`)
- **Runtime**: Docker
- **Environment Variables**:
  - `PORT=8000`: HTTP listener port.
  - `DATABASE_URL=sqlite:////data/audit.db`: Persistent audit ledger path.
  - `MODEL_DIR=artifacts/models/v2`: Location of trained model binaries and manifest.
  - `RATE_LIMIT_MAX=120`: Maximum requests allowed per IP address per window.
  - `RATE_LIMIT_WINDOW=60`: 60-second sliding rate-limit window.
  - `MAX_REQUEST_SIZE=1048576`: Request payload limit (1 MB) to prevent buffer exhaustion.

### 8.3 Health & Diagnostic Probes
- `GET /api/health`: Liveness probe returning `{"status": "ok", "version": "1.0.0"}`.
- `GET /api/metrics`: Performance metrics including P50/P95/P99 latency, model votes, and recent rule hits.
- `GET /api/scenarios`: Returns pre-validated test scenarios for automated continuous integration verification.

---

## 9. Chat App Integration: How PlanGuard Works with Autonomous Agents

The interactive Chat Demo (`chat_demo/`) provides an end-to-end interface for users and autonomous AI agents. It demonstrates how PlanGuard acts as an **interception proxy** between LLM intention and actual runtime tool execution.

```
 [User Prompt in UI]
         │
         ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 1. Gemini LLM (LangChain)                                   │
 │    • Tool-binding (`bind_tools(ALL_TOOLS)`)                 │
 │    • Returns AIMessage with `tool_calls` (NO execution yet!)│
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 2. Plan Compilation (`to_plan` & `map_tool_call_to_step`)    │
 │    • Tool Metadata Registry lookup                          │
 │    • Data sensitivity classification (`restricted`, etc.)   │
 │    • Destination derivation (`internal` vs `external`)      │
 │    • Assembles canonical JSON schema                        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 3. PlanGuard Check (`POST /api/analyze`)                     │
 │    • Risk Score, Rule Hits, Rationale, and Action computed  │
 └──────────────────────────────┬──────────────────────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
    [ ALLOW ]              [ CONFIRM ]            [ REVISE / BLOCK ]
         │                      │                      │
         ▼                      ▼                      ▼
  Execute Tools            Pause in UI            Prevent execution;
  & Return LLM            Wait for Human          return security
  Summary Response           Approval             rationale to user
```

### 9.1 How the Canonical Plan JSON is Obtained from LLM Tool Calls

Autonomous LLMs (e.g., Google Gemini 3.5 Flash Lite) return raw tool calls in their API responses. The adapter (`chat_demo/guard_client.py`) transforms these raw invocations into the structured schema expected by the PlanGuard backend:

#### Step 1: Raw LLM Tool Call Interception
When the user submits `"Tell me the size of notes.txt"`, Gemini outputs an `AIMessage` containing structured tool calls:
```json
{
  "name": "file_read",
  "args": {"path": "notes.txt"},
  "id": "call_abcd1234"
}
```
*Crucially: the agent halts here and does NOT invoke the underlying Python function.*

#### Step 2: Metadata Registry Enrichment (`TOOL_REGISTRY`)
Every tool has a static security profile:
```python
TOOL_REGISTRY = {
    "file_read": {
        "permissions_required": ["filesystem:read"],
        "side_effect_class": "read",
        "reversible": True,
        "destination": "internal",
        "estimated_cost": 0.1,
    },
    "db_query": {
        "permissions_required": ["database:read"],
        "side_effect_class": "read",
        "reversible": True,
        "destination": "internal",
        "estimated_cost": 0.1,
    },
    "http_post": {
        "permissions_required": ["network:external"],
        "side_effect_class": "write",
        "reversible": False,
        "destination": "external",
        "estimated_cost": 0.5,
    },
    ...
}
```

#### Step 3: Dynamic Sensitivity & Destination Derivation
The adapter inspects the argument strings to derive data sensitivity:
- **`restricted`**: Triggered by patterns such as `id_rsa`, `.env`, `password`, `secret`, `private_key`, `/etc/passwd`.
- **`confidential`**: Triggered by patterns like `customers`, `clients`, `users`, `pii`, `billing`, `orders`.
- **`internal` / `public`**: Standard business operational files.

If a customer database query is detected, `customer_data:read` is dynamically appended to `permissions_required`. For network tools (`http_post`), destination URLs are parsed with `urllib.parse.urlsplit` to determine whether the target is `internal` (e.g. `localhost`, `*.internal`) or `external`.

#### Step 4: The Final PlanGuard JSON Payload (`to_plan()`)
The compiled JSON payload sent to `POST /api/analyze` is structured as:
```json
{
  "plan": {
    "steps": [
      {
        "tool_name": "file_read",
        "arguments": {
          "path": "notes.txt"
        },
        "permissions_required": [
          "filesystem:read"
        ],
        "side_effect_class": "read",
        "reversible": true,
        "data_sensitivity": "internal",
        "destination": "internal",
        "estimated_cost": 0.1
      }
    ],
    "session_context": {
      "granted_permissions": [
        "filesystem:read",
        "database:read"
      ]
    }
  },
  "session_context": {
    "granted_permissions": [
      "filesystem:read",
      "database:read"
    ]
  },
  "context": {
    "trajectory_id": "chat-session-uuid"
  }
}
```

### 9.2 Execution Control Flow in the Chat App

The chat application (`chat_demo/agent.py` and `chat_demo/app.py`) evaluates the returned action:

1. **`ALLOW`**:
   - The sandboxed tool is safely executed in Python via `execute_tools()`.
   - Tool outputs are appended to the conversation history as `ToolMessage(content=...)`.
   - Gemini is invoked one final time to summarize the findings for the user.
2. **`CONFIRM` (Human-in-the-Loop)**:
   - Tool execution is suspended immediately.
   - The UI presents an interactive card: *"The assistant wants your approval"*, detailing the tool names, sensitivity labels, and rationale.
   - **Approve**: Resumes execution of the exact pending plan without re-planning.
   - **Deny**: Cancels execution; no tools are run and no extra LLM tokens are spent.
3. **`REVISE` (Self-Correction Loop)**:
   - The plan is paused. The user sees: *"PlanGuard asked the assistant to change its plan"*.
   - The user can click *"Revise"* (or add an optional refinement note).
   - The security rationale and rule violations are injected back into Gemini as security feedback:
     ```text
     SECURITY WARNING from PlanGuard Guardrail:
     Action: REVISE
     Rationale: Unbounded query on sensitive table without LIMIT.
     Violations: R5
     Please reformulate a safer plan without unauthorized access or risky parameters.
     ```
   - Gemini plans a revised strategy up to a strict cap of 2 attempts before failing closed to `BLOCK`.
4. **`BLOCK`**:
   - Complete refusal. Execution is halted. A refusal explanation generated from the PlanGuard rationale is rendered immediately in the chat bubble without issuing a second LLM call.

---

## 10. Summary Formula Index

$$\begin{aligned}
\text{Normalized Anomaly Score:} \quad & s_{\text{iso}} = \text{clip}\left( \frac{0.15 - s_{\text{raw}}}{0.15 - (-0.25)}, 0.0, 1.0 \right) \\
\text{Raw Ensemble Score:} \quad & S_{\text{raw}} = 0.40\,p_{\text{rf}} + 0.40\,p_{\text{xgb}} + 0.10\,p_{\text{dt}} + 0.10\,s_{\text{iso}} \\
\text{Calibrated Risk Probability:} \quad & S_{\text{calibrated}} = \frac{1}{1 + e^{-(A \cdot S_{\text{raw}} + B)}} \\
\text{Cryptographic Hash Link:} \quad & H_i = \text{SHA256}(\text{Canonical}(R_i \cup \{ \text{"prev\_hash"}: H_{i-1} \})) \\
\text{Policy Bounds:} \quad & \text{ALLOW} < 0.40 \le \text{REVISE} < 0.60 \le \text{CONFIRM} < 0.90 \le \text{BLOCK}
\end{aligned}$$

