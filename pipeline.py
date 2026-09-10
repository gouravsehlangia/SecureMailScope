#!/home/gourav/myai/bin/python
import json
import os
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import custom analysis modules
from risk_scoring import score_session
from anomaly_detection import detect_anomalies
from ai_recommendations import generate_recommendation

# Load environment variables securely from .env
load_dotenv()

# Initialize FastAPI App
app = FastAPI(
    title="SecureMailScope API",
    description="Email TLS Session Security, Risk Scoring, and Anomaly Detection Pipeline",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_pipeline(input_path: str = "mock_sessions.json", output_path: str = "enriched_sessions.json") -> List[Dict[str, Any]]:
    """
    Loads mock sessions, runs risk scoring, isolation forest anomaly detection,
    and AI recommendations, then writes enriched records to output_path.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file '{input_path}' not found.")

    with open(input_path, "r") as f:
        raw_sessions = json.load(f)

    # 1. Anomaly Detection
    anomaly_results = detect_anomalies(raw_sessions, contamination=0.05)
    anomaly_map = {item["session_id"]: (item["anomaly_flag"], item["anomaly_score"], item.get("reasons", [])) for item in anomaly_results}

    enriched_sessions = []

    for session in raw_sessions:
        sid = session.get("session_id", "")
        
        # 2. Risk Scoring
        score_res = score_session(session)
        risk_score = score_res.get("risk_score", 0)
        raw_score = score_res.get("raw_score", 0)
        risk_level = score_res.get("risk_level", "low")
        rule_violations = score_res.get("rule_violations", [])

        # Check for missing data fields and flag them
        data_incomplete = False
        expected_fields = [
            ("session_id", ""), ("protocol", ""), ("starttls_used", False),
            ("tls_version", ""), ("cipher_suite", ""), ("key_exchange", ""),
            ("forward_secrecy", False), ("cert_key_length", 0), ("cert_expired", False),
            ("cert_chain_valid", True), ("handshake_duration_ms", 0)
        ]
        
        for field, default in expected_fields:
            if field not in session:
                data_incomplete = True
                rule_violations.append(f"Incomplete session data — {field} missing, parsed with default")
                session[field] = default

        # Anomaly Status
        anomaly_flag, anomaly_score, reasons = anomaly_map.get(sid, (False, 0.0, []))

        # 3. AI Recommendation
        ai_rec = generate_recommendation(session, risk_score, risk_level, rule_violations, anomaly_flag)

        # Assemble final enriched session dictionary according to schema
        enriched_record = {
            "session_id": session.get("session_id", ""),
            "protocol": session.get("protocol", ""),
            "starttls_used": session.get("starttls_used", False),
            "tls_version": session.get("tls_version", ""),
            "cipher_suite": session.get("cipher_suite", ""),
            "key_exchange": session.get("key_exchange", ""),
            "forward_secrecy": session.get("forward_secrecy", False),
            "cert_key_length": session.get("cert_key_length", 0),
            "cert_expired": session.get("cert_expired", False),
            "cert_chain_valid": session.get("cert_chain_valid", True),
            "handshake_duration_ms": session.get("handshake_duration_ms", 0),
            "risk_score": risk_score,
            "raw_score": raw_score,
            "risk_level": risk_level,
            "data_incomplete": data_incomplete,
            "rule_violations": rule_violations,
            "anomaly_flag": anomaly_flag,
            "anomaly_score": anomaly_score,
            "reasons": reasons,
            "ai_recommendation": ai_rec
        }
        enriched_sessions.append(enriched_record)

    # Write output to JSON
    with open(output_path, "w") as f:
        json.dump(enriched_sessions, f, indent=2)

    print(f"[PIPELINE] Enriched {len(enriched_sessions)} sessions written to {output_path}")
    return enriched_sessions


# --- FastAPI Endpoints ---

@app.get("/")
def get_root():
    return {
        "service": "SecureMailScope API",
        "status": "active",
        "endpoints": ["/api/sessions"]
    }

@app.get("/api/sessions")
def get_sessions(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (low, medium, high, critical)"),
    anomaly_only: bool = Query(False, description="Filter to show only anomalous sessions")
):
    """
    Returns the enriched email TLS session security data.
    Automatically executes the pipeline if enriched_sessions.json does not exist.
    """
    output_file = "enriched_sessions.json"
    if not os.path.exists(output_file):
        run_pipeline(input_path="mock_sessions.json", output_path=output_file)

    with open(output_file, "r") as f:
        data = json.load(f)

    # Filtering logic
    if risk_level:
        data = [s for s in data if s.get("risk_level", "").lower() == risk_level.lower()]
    
    if anomaly_only:
        data = [s for s in data if s.get("anomaly_flag", False)]

    return data

@app.get("/api/sessions/{session_id}")
def get_session_by_id(session_id: str):
    output_file = "enriched_sessions.json"
    if not os.path.exists(output_file):
        run_pipeline(input_path="mock_sessions.json", output_path=output_file)

    with open(output_file, "r") as f:
        data = json.load(f)

    session = next((s for s in data if s["session_id"] == session_id), None)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    return session

if __name__ == "__main__":
    # Execute pipeline to generate enriched_sessions.json
    run_pipeline()

    # Start FastAPI server
    print("\nStarting SecureMailScope FastAPI server on http://0.0.0.0:8000 ...")
    uvicorn.run("pipeline:app", host="0.0.0.0", port=8000, reload=True)
