"""
Integration / Smoke Tests for Adaptive Honeypot
Run this after starting the backend with:
    python -m backend.app
"""

import requests, time, sys, json

BASE = "http://127.0.0.1:5000"

def _get_reason(r):
    """Helper to read reason from either top-level or decision."""
    if not isinstance(r, dict):
        return None
    if "reason" in r:
        return r["reason"]
    if "decision" in r and isinstance(r["decision"], dict):
        return r["decision"].get("reason")
    return None

def _get_ml_pred(r):
    if "decision" in r and isinstance(r["decision"], dict):
        return r["decision"].get("ml_pred")
    return None

def test_config():
    print("\n[1] Testing /config endpoint...")
    r = requests.get(BASE + "/config").json()
    assert "ml_conf_threshold" in r and "honeypot_enabled" in r
    print("   ✅ Config OK:", r)
    return r

def test_benign_request():
    print("\n[2] Testing benign request...")
    data = {"src_ip": "10.0.0.5", "payload": "hello world"}
    r = requests.post(BASE + "/simulate_traffic", json=data).json()
    print("   Response:", json.dumps(r, indent=2))
    # accept either top-level 'decision' dict or minimal response, but ensure ml_pred exists inside decision
    ml_pred = _get_ml_pred(r)
    assert r.get("route") == "normal"
    assert ml_pred == "BENIGN" or ("BENIGN" in str(r))
    print("   ✅ Benign route normal")

def test_sql_injection():
    print("\n[3] Testing SQL Injection...")
    data = {"src_ip": "10.0.0.6", "payload": "select * from users;"}
    r = requests.post(BASE + "/simulate_traffic", json=data).json()
    print("   Response:", json.dumps(r, indent=2))
    reason = _get_reason(r)
    assert r.get("route") == "honeypot"
    assert reason is not None and "rule_match" in reason
    print("   ✅ SQL Injection routed to honeypot")

def test_toggle_honeypot_off():
    print("\n[4] Disabling honeypot and re-testing...")
    requests.post(BASE + "/toggle_honeypot", json={"enabled": False})
    data = {"src_ip": "10.0.0.7", "payload": "select * from users;"}
    r = requests.post(BASE + "/simulate_traffic", json=data).json()
    print("   Response:", json.dumps(r, indent=2))
    # When honeypot disabled, reason will indicate that in decision or top-level
    reason = _get_reason(r)
    assert r.get("route") == "normal"
    assert reason is not None and ("honeypot_disabled" in reason or "honeypot_disabled" in str(r))
    print("   ✅ Honeypot disabled -> route normal")
    requests.post(BASE + "/toggle_honeypot", json={"enabled": True})  # reset

def test_ml_prediction():
    print("\n[5] Testing ML-based attack prediction...")
    data = {"src_ip": "10.0.0.8", "payload": "malicious_payload_123"}
    r = requests.post(BASE + "/simulate_traffic", json=data).json()
    print("   Response:", json.dumps(r, indent=2))
    # ensure probabilities exist inside decision (if decision present)
    probs = None
    if "decision" in r and isinstance(r["decision"], dict):
        probs = r["decision"].get("probs")
    assert probs is not None
    print("   ✅ ML probabilities present:", list(probs.keys())[:5])

def run_suite():
    print("\n=== Running Adaptive Honeypot Integration Suite ===")
    test_config()
    test_benign_request()
    test_sql_injection()
    test_toggle_honeypot_off()
    test_ml_prediction()
    print("\n✅ All integration tests passed!\n")

if __name__ == "__main__":
    try:
        run_suite()
    except AssertionError as e:
        print("\n❌ Test failed:", e)
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("\n❌ Backend not running. Start it with: python -m backend.app")
        sys.exit(2)
