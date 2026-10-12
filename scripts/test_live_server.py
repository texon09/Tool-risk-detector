import json
import urllib.request

BASE_URL = "http://127.0.0.1:8000"

def test_endpoints():
    print("Testing 6 API endpoints against live server...")
    
    # 1. GET /api/health
    req = urllib.request.urlopen(f"{BASE_URL}/api/health")
    data = json.loads(req.read().decode("utf-8"))
    print(f"[OK] 1. GET /api/health -> status: {req.status}, response: {data}")
    assert data.get("status") in ["ok", "healthy"]

    # 2. GET /api/metrics
    req = urllib.request.urlopen(f"{BASE_URL}/api/metrics")
    data = json.loads(req.read().decode("utf-8"))
    print(f"[OK] 2. GET /api/metrics -> available: {data.get('available')}, models: {list(data.get('models', {}).keys())}")
    assert data.get("available") is True
    assert len(data.get("models", {})) == 4

    # 3. GET /api/scenarios
    req = urllib.request.urlopen(f"{BASE_URL}/api/scenarios")
    data = json.loads(req.read().decode("utf-8"))
    print(f"[OK] 3. GET /api/scenarios -> scenarios count: {len(data.get('scenarios', []))}")
    assert len(data.get("scenarios", [])) >= 5

    # 4. POST /api/analyze
    plan_payload = json.dumps({"plan": {"action": "search", "tool": "web_search", "query": "Tokyo weather"}}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/analyze",
        data=plan_payload,
        headers={"Content-Type": "application/json"}
    )
    resp = urllib.request.urlopen(req)
    analyze_data = json.loads(resp.read().decode("utf-8"))
    print(f"[OK] 4. POST /api/analyze -> Action: {analyze_data['action']}, Risk Score: {analyze_data['risk_score']}")
    assert analyze_data["action"] in ["ALLOW", "CONFIRM", "REVISE", "BLOCK"]

    # 5. GET /api/audit
    req = urllib.request.urlopen(f"{BASE_URL}/api/audit?limit=5")
    data = json.loads(req.read().decode("utf-8"))
    print(f"[OK] 5. GET /api/audit -> logs count: {len(data.get('logs', []))}")
    assert len(data.get("logs", [])) > 0

    # 6. POST /api/audit/verify
    v_req = urllib.request.Request(f"{BASE_URL}/api/audit/verify", data=b"", headers={"Content-Type": "application/json"})
    v_resp = urllib.request.urlopen(v_req)
    v_data = json.loads(v_resp.read().decode("utf-8"))
    print(f"[OK] 6. POST /api/audit/verify -> Valid: {v_data['valid']}, Reason: {v_data['reason']}")
    assert v_data["valid"] is True

    print("\nALL 6 ENDPOINTS VERIFIED AND RESPONDING SUCCESSFULLY!")

if __name__ == "__main__":
    test_endpoints()
