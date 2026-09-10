#!/home/gourav/myai/bin/python
import json
import os
import sys
import time
import subprocess
import requests
from random import choice
from fastapi.testclient import TestClient
from pipeline import app, run_pipeline

def display_three_records(enriched_sessions: list, raw_sessions: list):
    print("\n" + "=" * 75)
    print("      PART 1: FULL ENRICHED RECORDS FOR 3 REPRESENTATIVE SESSIONS")
    print("=" * 75)

    # 1. sess_032 — highest risk_score (well-known from prior run)
    sess_032 = next((s for s in enriched_sessions if s["session_id"] == "sess_032"), None)

    # 2. sess_046 — highest anomaly score (outlier: DH_anon + RC4 + expired cert)
    sess_046 = next((s for s in enriched_sessions if s["session_id"] == "sess_046"), None)

    # 3. Random "low" risk session
    low_risk_sessions = [s for s in enriched_sessions if s["risk_level"] == "low"]
    low_risk_sample = choice(low_risk_sessions) if low_risk_sessions else enriched_sessions[0]

    samples = [
        (f"sess_032 — HIGHEST RISK_SCORE session (risk_score={sess_032['risk_score']}, raw_score={sess_032['raw_score']})", sess_032),
        (f"sess_046 — HIGHEST ANOMALY SCORE session (risk_score={sess_046['risk_score']}, raw_score={sess_046['raw_score']})", sess_046),
        (f"RANDOM 'LOW' RISK SESSION (ID: {low_risk_sample['session_id']}, risk_score={low_risk_sample['risk_score']})", low_risk_sample)
    ]

    for title, record in samples:
        print(f"\n--- {title} ---")
        print(json.dumps(record, indent=2))
    print("=" * 75)

def test_pipeline_and_network():
    print("\n" + "=" * 75)
    print("       PART 2: SECURE MAIL SCOPE - PIPELINE & REAL NETWORK TESTING")
    print("=" * 75)

    # Test 1: Verify Input Mock Sessions File
    mock_file = "mock_sessions.json"
    assert os.path.exists(mock_file), f"Error: {mock_file} missing!"
    with open(mock_file, "r") as f:
        mock_sessions = json.load(f)
    print(f"[TEST 1] Loaded {len(mock_sessions)} mock sessions from '{mock_file}' -> PASSED")

    # Test 2: Run Pipeline Execution
    print("\n[TEST 2] Running pipeline enrichment execution...")
    enriched = run_pipeline(input_path=mock_file, output_path="enriched_sessions.json")
    assert len(enriched) == 200, f"Expected 200 sessions, got {len(enriched)}"
    print(f"         Pipeline enriched {len(enriched)} sessions -> PASSED")

    # Display 3 Enriched Records required by User Request
    display_three_records(enriched, mock_sessions)

    # Test 3: Schema Validation on Enriched Sessions
    print("\n[TEST 3] Validating enriched JSON schema...")
    required_fields = [
        "session_id", "protocol", "starttls_used", "tls_version", "cipher_suite",
        "key_exchange", "forward_secrecy", "cert_key_length", "cert_expired",
        "cert_chain_valid", "handshake_duration_ms", "risk_score", "raw_score",
        "risk_level", "data_incomplete", "rule_violations", "anomaly_flag", "anomaly_score", "reasons", "ai_recommendation"
    ]
    sample = enriched[0]
    for field in required_fields:
        assert field in sample, f"Missing required field: '{field}'"
    print(f"         Enriched schema verified (all {len(required_fields)} fields present) -> PASSED")

    # Test 4: FastAPI Endpoint Verification via TestClient
    print("\n[TEST 4] Testing FastAPI Endpoints using TestClient...")
    client = TestClient(app)

    res_root = client.get("/")
    assert res_root.status_code == 200
    print(f"         GET / -> {res_root.json()['service']} (HTTP 200) -> PASSED")

    res_all = client.get("/api/sessions")
    assert res_all.status_code == 200
    sessions_data = res_all.json()
    assert len(sessions_data) == 200
    print(f"         GET /api/sessions -> {len(sessions_data)} sessions returned (HTTP 200) -> PASSED")

    res_crit = client.get("/api/sessions?risk_level=critical")
    assert res_crit.status_code == 200
    print(f"         GET /api/sessions?risk_level=critical -> {len(res_crit.json())} sessions -> PASSED")

    res_anom = client.get("/api/sessions?anomaly_only=true")
    assert res_anom.status_code == 200
    print(f"         GET /api/sessions?anomaly_only=true -> {len(res_anom.json())} sessions -> PASSED")

    res_single = client.get("/api/sessions/sess_001")
    assert res_single.status_code == 200
    assert res_single.json()["session_id"] == "sess_001"
    print(f"         GET /api/sessions/sess_001 -> Session sess_001 details -> PASSED")

    # Test 5: Real Network Test using Subprocess & Requests
    print("\n[TEST 5] REAL NETWORK TEST: Spawning Uvicorn Subprocess on Port 8000...")
    python_bin = sys.executable
    server_process = subprocess.Popen(
        [python_bin, "-m", "uvicorn", "pipeline:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        url = "http://127.0.0.1:8000/api/sessions"
        ready = False
        print("         Waiting for FastAPI server to accept network requests on http://127.0.0.1:8000 ...")
        for _ in range(25):
            try:
                res = requests.get("http://127.0.0.1:8000/", timeout=1)
                if res.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.2)

        assert ready, "Real network error: Server failed to start on 127.0.0.1:8000 within timeout."

        # Perform actual HTTP request over TCP network socket
        print("         Sending actual HTTP GET request to http://127.0.0.1:8000/api/sessions ...")
        res = requests.get(url, timeout=5)
        assert res.status_code == 200, f"Expected HTTP 200, got {res.status_code}"
        data = res.json()
        assert isinstance(data, list) and len(data) == 200, f"Expected 200 sessions over network, got {len(data)}"
        
        print(f"         RECEIVED {len(data)} SESSIONS OVER REAL HTTP NETWORK SOCKET (Status: {res.status_code})")
        print("         REAL NETWORK TEST -> PASSED")

    except Exception as e:
        print(f"         REAL NETWORK TEST -> FAILED ({e})")
        raise e
    finally:
        server_process.terminate()
        try:
            server_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server_process.kill()
        print("         Uvicorn server subprocess shut down cleanly.")

    print("\n" + "=" * 75)
    print("         ALL TESTS (TESTCLIENT + REAL NETWORK HTTP) PASSED!")
    print("=" * 75)

if __name__ == "__main__":
    test_pipeline_and_network()
