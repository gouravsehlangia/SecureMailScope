#!/usr/bin/env python3
"""
SecureMailScope — Pipeline Integration Test
Tests the full PCAP-based pipeline (Stage 1 → 2 → 3 → 4) and FastAPI API endpoints.
Uses the test PCAP file at test_data/mock_email_traffic.pcap.
"""

import json
import os
import sys
import time
import subprocess

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from pipeline import app, run_pcap_pipeline, run_json_pipeline, save_to_history, get_history_list


def test_pcap_pipeline():
    """Test the full PCAP pipeline with the test data."""
    print("\n" + "=" * 75)
    print("       SECUREMAILSCOPE — FULL PIPELINE INTEGRATION TEST")
    print("=" * 75)

    pcap_file = os.path.join(PROJECT_ROOT, "test_data", "mock_email_traffic.pcap")
    keylog_file = os.path.join(PROJECT_ROOT, "test_data", "mock_session.keylog")

    # ── Test 1: Verify test PCAP file exists ──
    print("\n[TEST 1] Checking test data files...")
    assert os.path.exists(pcap_file), f"PCAP file not found: {pcap_file}"
    print(f"         ✓ PCAP file: {pcap_file}")
    if os.path.exists(keylog_file):
        print(f"         ✓ Keylog file: {keylog_file}")
    else:
        print(f"         ⚠ Keylog file not found (TLS 1.3 decryption will degrade gracefully)")
        keylog_file = None
    print("         → PASSED")

    # ── Test 2: Run full PCAP pipeline ──
    print("\n[TEST 2] Running full PCAP pipeline (Stage 1→2→3→4)...")
    enriched = run_pcap_pipeline(
        pcap_path=pcap_file,
        keylog_path=keylog_file,
    )
    assert len(enriched) > 0, "Pipeline produced no enriched sessions"
    print(f"         ✓ Pipeline produced {len(enriched)} enriched sessions → PASSED")

    # ── Test 3: Schema validation ──
    print("\n[TEST 3] Validating enriched session schema...")
    required_fields = [
        "session_id", "protocol", "starttls_used", "tls_version", "cipher_suite",
        "key_exchange", "forward_secrecy", "cert_key_length", "cert_expired",
        "cert_chain_valid", "handshake_duration_ms", "risk_score", "raw_score",
        "risk_level", "data_incomplete", "rule_violations", "anomaly_flag",
        "anomaly_score", "reasons", "ai_recommendation",
    ]
    sample = enriched[0]
    missing = [f for f in required_fields if f not in sample]
    assert not missing, f"Missing required fields: {missing}"
    print(f"         ✓ All {len(required_fields)} required fields present → PASSED")

    # ── Test 4: Display sample enriched records ──
    print("\n" + "=" * 75)
    print("       SAMPLE ENRICHED RECORDS")
    print("=" * 75)
    for i, rec in enumerate(enriched[:3]):
        print(f"\n--- Session {i+1}: {rec['session_id']} ---")
        print(f"  Protocol:     {rec['protocol']} | TLS: {rec['tls_version']}")
        print(f"  Cipher:       {rec['cipher_suite']}")
        print(f"  Key Exchange: {rec['key_exchange']} | PFS: {rec['forward_secrecy']}")
        print(f"  Risk Score:   {rec['risk_score']} ({rec['risk_level'].upper()})")
        print(f"  Anomaly:      {rec['anomaly_flag']} (score: {rec['anomaly_score']})")
        print(f"  Violations:   {len(rec['rule_violations'])} rules triggered")
        for v in rec['rule_violations'][:3]:
            print(f"    - {v}")
        print(f"  AI Advice:    {rec['ai_recommendation'][:100]}...")
    print("=" * 75)

    # ── Test 5: History management ──
    print("\n[TEST 5] Testing history management...")
    meta = save_to_history(enriched, source_filename="mock_email_traffic.pcap", pipeline_type="pcap")
    assert meta["run_id"], "History run_id missing"
    assert meta["session_count"] == len(enriched), "Session count mismatch"
    history = get_history_list()
    assert len(history) > 0, "History list is empty after save"
    print(f"         ✓ Saved run {meta['run_id']} ({meta['session_count']} sessions)")
    print(f"         ✓ History has {len(history)} entries → PASSED")

    # ── Test 6: FastAPI endpoint tests ──
    print("\n[TEST 6] Testing FastAPI endpoints via TestClient...")
    client = TestClient(app)

    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["version"] == "2.0.0"
    print(f"         GET / → {res_root.json()['service']} v{res_root.json()['version']} (HTTP 200) → PASSED")

    res_history = client.get("/api/history")
    assert res_history.status_code == 200
    print(f"         GET /api/history → {len(res_history.json())} entries (HTTP 200) → PASSED")

    if history:
        run_id = history[0]["run_id"]
        res_run = client.get(f"/api/history/{run_id}")
        assert res_run.status_code == 200
        run_data = res_run.json()
        assert "sessions" in run_data
        print(f"         GET /api/history/{run_id} → {len(run_data['sessions'])} sessions (HTTP 200) → PASSED")

    # Test PCAP upload endpoint
    print("\n[TEST 7] Testing POST /analyze endpoint...")
    with open(pcap_file, "rb") as f:
        res_analyze = client.post("/analyze", files={"file": ("test.pcap", f, "application/octet-stream")})
    assert res_analyze.status_code == 200
    analyze_data = res_analyze.json()
    assert analyze_data["status"] == "success"
    assert len(analyze_data["sessions"]) > 0
    print(f"         POST /analyze → {len(analyze_data['sessions'])} sessions enriched (HTTP 200) → PASSED")

    # ── Test 8: Real network test ──
    print("\n[TEST 8] REAL NETWORK TEST: Spawning Uvicorn subprocess on port 8000...")
    python_bin = sys.executable
    server_process = subprocess.Popen(
        [python_bin, "-m", "uvicorn", "pipeline:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        import requests
        ready = False
        print("         Waiting for server to accept connections...")
        for _ in range(25):
            try:
                res = requests.get("http://127.0.0.1:8000/", timeout=1)
                if res.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.3)

        assert ready, "Server failed to start within timeout."

        print("         Sending HTTP GET to http://127.0.0.1:8000/api/history ...")
        res = requests.get("http://127.0.0.1:8000/api/history", timeout=5)
        assert res.status_code == 200
        print(f"         RECEIVED {len(res.json())} history entries over REAL HTTP (Status: {res.status_code})")
        print("         REAL NETWORK TEST → PASSED")

    except Exception as e:
        print(f"         REAL NETWORK TEST → FAILED ({e})")
        raise e
    finally:
        server_process.terminate()
        try:
            server_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server_process.kill()
        print("         Uvicorn server shut down cleanly.")

    print("\n" + "=" * 75)
    print("         ALL TESTS PASSED!")
    print("=" * 75)


if __name__ == "__main__":
    test_pcap_pipeline()
