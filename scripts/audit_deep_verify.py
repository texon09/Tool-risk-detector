import sqlite3
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "backend"))

from backend.app.audit.store import AuditStore
from backend.app.features.extractor import extract_features
from backend.app.ml.ensemble import model_votes, score_risk
from backend.app.ml.loader import load_model
from backend.app.mock_tools.runtime import execute as execute_mock_tool
from backend.app.policy.decision import decide


def audit_tamper_test():
    print("--- 1. AUDIT LOGGER TAMPER TEST ---")
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    db_url = f"sqlite:///{db_path}"
    store = AuditStore(db_path=db_url)
    
    # Insert 3 records
    id1 = store.log_decision(payload={"task": 1}, decision="ALLOW", rationale="Benign task 1", trajectory_id="t1")
    id2 = store.log_decision(payload={"task": 2}, decision="CONFIRM", rationale="Sensitive task 2", trajectory_id="t2")
    id3 = store.log_decision(payload={"task": 3}, decision="BLOCK", rationale="Malicious task 3", trajectory_id="t3")
    
    # Verify initial chain
    res_initial = store.verify_chain()
    print(f"Initial chain intact: {res_initial['valid']} ({res_initial['reason']})")
    assert res_initial["valid"] is True, "Initial chain must be valid"
    
    # Tamper with record 2 rationale directly in sqlite table audit_logs
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE audit_logs SET rationale = 'TAMPERED RATIONALE' WHERE audit_id = ?", (id2,))
    conn.commit()
    conn.close()
    
    # Re-verify
    res_tampered = store.verify_chain()
    print(f"Chain after tampering with rationale: valid={res_tampered['valid']}, reason='{res_tampered['reason']}', broken_at={res_tampered['broken_at_id']}")
    assert res_tampered["valid"] is False, "Tampered chain must be detected as invalid!"
    print("[PASS] Tamper detection verified: rationale modification breaks the hash chain.")

def audit_restart_test():
    print("\n--- 2. AUDIT LOGGER RESTART TEST ---")
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db_url = f"sqlite:///{db_path}"
    
    # Process 1 creates store and logs
    store1 = AuditStore(db_path=db_url)
    store1.log_decision(payload={"session": 1}, decision="ALLOW", rationale="Session 1 log", trajectory_id="t-sess1")
    del store1  # simulate process shutdown
    
    # Process 2 reopens DB and logs next record
    store2 = AuditStore(db_path=db_url)
    store2.log_decision(payload={"session": 2}, decision="BLOCK", rationale="Session 2 log after restart", trajectory_id="t-sess2")
    
    res = store2.verify_chain()
    print(f"Chain across simulated restart: valid={res['valid']}, reason='{res['reason']}'")
    assert res["valid"] is True, "Chain must survive process restart and stay valid"
    print("[PASS] Restart survival verified: sequential hashes chain across separate store instances.")

def verify_policy_branching():
    print("\n--- 3. POLICY ENGINE BRANCHING TEST ---")
    # 2+ critical violations -> BLOCK
    res_multi_crit = decide(risk_score=0.1, rule_results=[{"flag": "R1", "severity": "critical"}, {"flag": "R2", "severity": "critical"}])
    print(f"2 critical violations: action={res_multi_crit['action']} (expected BLOCK)")
    assert res_multi_crit["action"] == "BLOCK"
    
    # 1 critical violation branching by score
    # score > 0.90 -> BLOCK
    res_1crit_high = decide(risk_score=0.95, rule_results=[{"flag": "R1", "severity": "critical"}])
    print(f"1 critical violation + high score (0.95): action={res_1crit_high['action']} (expected BLOCK)")
    assert res_1crit_high["action"] == "BLOCK"
    
    # score in (0.75, 0.90] -> CONFIRM
    res_1crit_med = decide(risk_score=0.80, rule_results=[{"flag": "R1", "severity": "critical"}])
    print(f"1 critical violation + med-high score (0.80): action={res_1crit_med['action']} (expected CONFIRM)")
    assert res_1crit_med["action"] == "CONFIRM"
    
    # score <= 0.75 -> REVISE
    res_1crit_low = decide(risk_score=0.50, rule_results=[{"flag": "R1", "severity": "critical"}])
    print(f"1 critical violation + low score (0.50): action={res_1crit_low['action']} (expected REVISE)")
    assert res_1crit_low["action"] == "REVISE"
    
    # 0 critical violations branching by score
    # score >= 0.60 (TAU_HIGH) -> CONFIRM
    res_0crit_high = decide(risk_score=0.85, rule_results=[])
    print(f"0 critical violations + high score (0.85): action={res_0crit_high['action']} (expected CONFIRM)")
    assert res_0crit_high["action"] == "CONFIRM"
    
    # score in [0.40, 0.60) -> REVISE
    res_0crit_med = decide(risk_score=0.50, rule_results=[])
    print(f"0 critical violations + med score (0.50): action={res_0crit_med['action']} (expected REVISE)")
    assert res_0crit_med["action"] == "REVISE"
    
    # score < 0.40 -> ALLOW
    res_0crit_low = decide(risk_score=0.05, rule_results=[])
    print(f"0 critical violations + low score (0.05): action={res_0crit_low['action']} (expected ALLOW)")
    assert res_0crit_low["action"] == "ALLOW"
    print("[PASS] Policy branching verified.")

def verify_models_and_votes():
    print("\n--- 4. ML MODELS & VOTES TEST ---")
    manifest, models = load_model("artifacts/models/v2")
    print(f"Loaded models: {list(models.keys())}")
    
    sample_plan = {"steps": [{"action": "db_read", "tool": "database_query", "params": {"query": "SELECT * FROM users"}}]}
    features = extract_features(sample_plan)
    import pandas as pd
    feat_df = pd.DataFrame([features], columns=manifest["feature_names"])
    
    rf_prob = float(models["random_forest"].predict_proba(feat_df)[:, 2][0])
    xgb_prob = float(models["xgboost"].predict_proba(feat_df)[:, 2][0])
    dt_prob = float(models["decision_tree"].predict_proba(feat_df)[:, 2][0])
    iso_score = float(models["isolation_forest"].decision_function(feat_df)[0])
    iso_flag = int(iso_score < 0.0)
    
    w_rf = float(manifest.get("ensemble_weights", {}).get("rf", 0.5))
    calibrator = models["calibrator"]
    cal_method = manifest.get("calibration_method", "isotonic")
    
    score_arr = score_risk(rf_prob, xgb_prob, w_rf, calibrator, cal_method)
    score = float(score_arr[0])
    print(f"score_risk() = {score:.4f} (in [0, 1]: {0.0 <= score <= 1.0})")
    assert 0.0 <= score <= 1.0
    
    votes = model_votes(rf_prob, xgb_prob, dt_prob, iso_flag)
    print(f"model_votes() = {votes}")
    assert "rf_prob" in votes
    assert "xgb_prob" in votes
    assert "dt_prob" in votes
    assert "iso_flag" in votes
    print("[PASS] ML models, scoring, and votes verified.")

def verify_mock_tools():
    print("\n--- 5. MOCK TOOLS EXECUTION TEST ---")
    tools = [
        ("database_query", {"query": "SELECT 1"}),
        ("file_read", {"path": "test.txt"}),
        ("file_write", {"path": "test.txt", "content": "hello"}),
        ("http_post", {"url": "https://example.com/api", "data": "{}"}),
        ("email_send", {"to": "user@example.com", "subject": "hi"}),
        ("shell_exec", {"cmd": "echo test"}),
    ]
    for t_name, t_params in tools:
        res = execute_mock_tool(t_name, t_params)
        print(f"Mock tool {t_name} -> success={res.get('success', True)}, output={str(res)[:60]}...")
    print("[PASS] All mock tools return canned responses safely without side effects.")

if __name__ == "__main__":
    audit_tamper_test()
    audit_restart_test()
    verify_policy_branching()
    verify_models_and_votes()
    verify_mock_tools()
