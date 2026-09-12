#!/usr/bin/env python3
"""
SecureMailScope — Unified Pipeline & API Server
================================================
Integrates all 5 SIH topic modules into a single end-to-end real-data pipeline:

  Stage 1: PCAP Parsing (Protocol ID, TCP reassembly, STARTTLS detection)
  Stage 2: TLS/Crypto Analysis (Handshake parsing, cipher evaluation, PFS)
  Stage 3: Certificate Analysis (X.509 parsing, chain validation, weak-crypto rules)
  Stage 4: AI/ML Engine (Risk scoring, Isolation Forest anomaly detection, AI recs)
  Stage 5: Dashboard API (FastAPI endpoints for frontend)

History: Each analysis run is saved to history/ (last 10 kept).
"""

import json
import os
import sys
import glob
import shutil
import logging
import tempfile
import base64
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Query, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ── Project root setup ──────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ── Import Stage 1: PCAP Parsing ────────────────────────────────────────────
# The original directory has special unicode characters in its name.
# A symlink 'pcap_parser' → 'Protocol ID (SMTP⁄IMAP⁄POP3) + TCP stream reassembly'
# is used for clean Python package imports.
from pcap_parser.extractor import parse_pcap, extract_tls_payloads_for_crypto_lead
from pcap_parser.models import PcapParseResult, EmailSession

# ── Import Stage 2: TLS/Crypto Analysis ─────────────────────────────────────
from backend.tls_analysis import CryptoAnalyzer, analyze_session_tls
from backend.tls_analysis.keylog_manager import SSLKeyLogManager
from backend.tls_analysis.models import Stage1SessionInput, TLSAnalysisResult

# ── Import Stage 3: Certificate Analysis ────────────────────────────────────
from cert_analysis import CertificateAnalyzer

# ── Import Stage 4: Risk Scoring, Anomaly Detection, AI Recommendations ────
from risk_scoring import score_session
from anomaly_detection import detect_anomalies
from ai_recommendations import generate_recommendation

# ── Load environment variables ──────────────────────────────────────────────
load_dotenv()

logger = logging.getLogger("securemailscope.pipeline")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s — %(message)s")

# ── History directory ───────────────────────────────────────────────────────
HISTORY_DIR = os.path.join(PROJECT_ROOT, "history")
MAX_HISTORY = 10

# ── Initialize FastAPI ──────────────────────────────────────────────────────
app = FastAPI(
    title="SecureMailScope API",
    description="Email TLS Cryptographic Security Posture Analysis — Full Pipeline",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════════════════════════════════════════
#  CORE PIPELINE: PCAP → Stage 1 → Stage 2 → Stage 3 → Stage 4 → Enriched
# ═══════════════════════════════════════════════════════════════════════════

def _bridge_stage1_to_stage2_input(session: EmailSession) -> Stage1SessionInput:
    """Convert a Stage 1 EmailSession into a Stage 2 Stage1SessionInput."""
    full_stream = session.tls_client_payload + session.tls_server_payload
    if not full_stream:
        # Fall back to concatenated plaintext payloads for protocol detection
        full_stream = b""

    return Stage1SessionInput(
        session_id=session.session_id,
        stream_id=session.stream_id,
        protocol=session.protocol.value,
        client_ip=session.client_ip,
        server_ip=session.server_ip,
        client_port=session.client_port,
        server_port=session.server_port,
        stream_bytes=full_stream,
        starttls_detected=(session.starttls.status.value == "NEGOTIATED_SUCCESS"),
        starttls_offered=session.starttls.advertised_by_server,
    )


def _bridge_stage2_to_flat(
    session: EmailSession,
    tls_result: TLSAnalysisResult,
    cert_findings: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Merge Stage 1 EmailSession + Stage 2 TLSAnalysisResult + Stage 3 cert findings
    into a flat dict matching the schema expected by risk_scoring.py / anomaly_detection.py.
    """
    # Determine cert_key_length from cert analysis or TLS key_length
    cert_key_length = tls_result.key_length or 0
    cert_expired = False
    cert_chain_valid = True

    if cert_findings and cert_findings.get("status") == "success":
        summary = cert_findings.get("summary", {})
        cert_key_length = summary.get("key_size", cert_key_length) or cert_key_length
        cert_expired = summary.get("is_expired", False)
        cert_chain_valid = summary.get("chain_valid", True)

    # Calculate handshake duration from session timestamps
    duration_s = max(0.0, session.end_time - session.start_time)
    handshake_duration_ms = int(duration_s * 1000)

    # Determine protocol string for the flat dict
    protocol = tls_result.protocol or session.protocol.value
    # Determine starttls_used
    starttls_used = tls_result.starttls_used or (
        session.starttls.status.value == "NEGOTIATED_SUCCESS"
    )

    # Map key_exchange to match risk_scoring expectations
    key_exchange = tls_result.key_exchange or ""
    # Strip group info parenthetical for risk scoring compatibility
    kex_base = key_exchange.split("(")[0].strip() if key_exchange else ""

    return {
        "session_id": session.session_id,
        "protocol": protocol,
        "starttls_used": starttls_used,
        "tls_version": tls_result.tls_version or "",
        "cipher_suite": tls_result.cipher_suite or "",
        "key_exchange": kex_base or key_exchange,
        "forward_secrecy": tls_result.forward_secrecy,
        "cert_key_length": cert_key_length,
        "cert_expired": cert_expired,
        "cert_chain_valid": cert_chain_valid,
        "handshake_duration_ms": handshake_duration_ms,
        # Carry over Stage 2 extras for richer dashboard display
        "tls_present": tls_result.tls_present,
        "security_rating": tls_result.security_rating.value if hasattr(tls_result.security_rating, 'value') else str(tls_result.security_rating),
        "starttls_stripped": tls_result.starttls_stripped,
        "is_aead": tls_result.is_aead,
        "encryption_algorithm": tls_result.encryption_algorithm,
        "mac_algorithm": tls_result.mac_algorithm,
        "sni": tls_result.sni,
        # Network metadata
        "client_ip": session.client_ip,
        "server_ip": session.server_ip,
        "client_port": session.client_port,
        "server_port": session.server_port,
        # Stage 2 rule violations (carried into enriched output)
        "_stage2_violations": tls_result.rule_violations,
        "_stage2_warnings": tls_result.warnings,
        # Stage 3 cert analysis summary
        "_cert_analysis": cert_findings if cert_findings else None,
    }


def run_pcap_pipeline(
    pcap_path: str,
    keylog_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Full pipeline: PCAP file → Stage 1 → Stage 2 → Stage 3 → Stage 4 → enriched JSON.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    logger.info("═══ SecureMailScope Full Pipeline ═══")
    logger.info(f"Input PCAP: {pcap_path}")

    # ── Stage 1: PCAP Parsing ──────────────────────────────────────────────
    logger.info("▶ STAGE 1: Parsing PCAP (Protocol ID, TCP reassembly, STARTTLS detection)...")
    pcap_result: PcapParseResult = parse_pcap(pcap_path)
    logger.info(
        f"  ✓ {pcap_result.total_packets_read} packets → "
        f"{pcap_result.total_streams_reassembled} TCP streams → "
        f"{len(pcap_result.email_sessions)} email sessions "
        f"({pcap_result.parse_duration_seconds:.3f}s)"
    )

    if not pcap_result.email_sessions:
        logger.warning("  ⚠ No email sessions detected in PCAP. Returning empty results.")
        return []

    # Load keylog manager for TLS 1.3 decryption
    keylog_mgr = SSLKeyLogManager()
    if keylog_path and os.path.exists(keylog_path):
        loaded = keylog_mgr.load_keylog_file(keylog_path)
        logger.info(f"  Keylog: loaded {loaded} entries from {keylog_path}")

    # ── Stage 2: TLS/Crypto Analysis ──────────────────────────────────────
    logger.info("▶ STAGE 2: TLS Handshake Reconstruction & Crypto Evaluation...")
    flat_sessions: List[Dict[str, Any]] = []

    for email_session in pcap_result.email_sessions:
        # Bridge Stage 1 → Stage 2 input
        stage2_input = _bridge_stage1_to_stage2_input(email_session)

        # Run Stage 2 analysis
        try:
            tls_result: TLSAnalysisResult = CryptoAnalyzer.analyze_session(
                stage2_input, keylog_manager=keylog_mgr
            )
        except Exception as exc:
            logger.warning(f"  ⚠ Stage 2 error for {email_session.session_id}: {exc}")
            # Create a minimal fallback result
            tls_result = TLSAnalysisResult(
                session_id=email_session.session_id,
                protocol=email_session.protocol.value,
                tls_present=email_session.is_tls_encrypted,
            )

        # ── Stage 3: Certificate Analysis ─────────────────────────────────
        cert_findings = None
        if tls_result.raw_certificates:
            try:
                # Pass DER certificates (base64 encoded) to cert analyzer
                cert_findings = CertificateAnalyzer.analyze(tls_result.raw_certificates)
                logger.info(
                    f"  📜 {email_session.session_id}: "
                    f"{len(tls_result.raw_certificates)} cert(s) analyzed — "
                    f"Score: {cert_findings.get('summary', {}).get('security_score', '?')}"
                )
            except Exception as exc:
                logger.warning(f"  ⚠ Stage 3 cert error for {email_session.session_id}: {exc}")

        # Bridge to flat dict for Stage 4
        flat = _bridge_stage2_to_flat(email_session, tls_result, cert_findings)
        flat_sessions.append(flat)

    logger.info(f"  ✓ {len(flat_sessions)} sessions analyzed through Stage 2+3")

    # ── Stage 4: Risk Scoring + Anomaly Detection + AI Recommendations ─────
    logger.info("▶ STAGE 4: Risk Scoring, Anomaly Detection & AI Recommendations...")

    # 4a. Anomaly Detection (needs all sessions for statistical model)
    try:
        anomaly_results = detect_anomalies(flat_sessions, contamination=0.05)
        anomaly_map = {
            item["session_id"]: (item["anomaly_flag"], item["anomaly_score"], item.get("reasons", []))
            for item in anomaly_results
        }
    except Exception as exc:
        logger.warning(f"  ⚠ Anomaly detection error: {exc}")
        anomaly_map = {}

    enriched_sessions: List[Dict[str, Any]] = []

    for session in flat_sessions:
        sid = session.get("session_id", "")

        # 4b. Risk Scoring
        score_res = score_session(session)
        risk_score = score_res.get("risk_score", 0)
        raw_score = score_res.get("raw_score", 0)
        risk_level = score_res.get("risk_level", "low")
        rule_violations = score_res.get("rule_violations", [])

        # Merge Stage 2 violations
        stage2_violations = session.get("_stage2_violations", [])
        for v in stage2_violations:
            if v not in rule_violations:
                rule_violations.append(v)

        # Check for missing data fields
        data_incomplete = False
        expected_fields = [
            ("session_id", ""), ("protocol", ""), ("starttls_used", False),
            ("tls_version", ""), ("cipher_suite", ""), ("key_exchange", ""),
            ("forward_secrecy", False), ("cert_key_length", 0), ("cert_expired", False),
            ("cert_chain_valid", True), ("handshake_duration_ms", 0),
        ]
        for field_name, default in expected_fields:
            if field_name not in session:
                data_incomplete = True
                rule_violations.append(f"Incomplete session data — {field_name} missing")
                session[field_name] = default

        # Anomaly results
        anomaly_flag, anomaly_score, reasons = anomaly_map.get(sid, (False, 0.0, []))

        # 4c. AI Recommendation
        ai_rec = generate_recommendation(
            session, risk_score, risk_level, rule_violations, anomaly_flag
        )

        # Assemble final enriched record
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
            "ai_recommendation": ai_rec,
            # Extra metadata for dashboard
            "tls_present": session.get("tls_present", False),
            "security_rating": session.get("security_rating", ""),
            "starttls_stripped": session.get("starttls_stripped", False),
            "is_aead": session.get("is_aead", False),
            "encryption_algorithm": session.get("encryption_algorithm", ""),
            "mac_algorithm": session.get("mac_algorithm", ""),
            "sni": session.get("sni"),
            "client_ip": session.get("client_ip", ""),
            "server_ip": session.get("server_ip", ""),
            "client_port": session.get("client_port", 0),
            "server_port": session.get("server_port", 0),
        }
        enriched_sessions.append(enriched_record)

    logger.info(f"  ✓ {len(enriched_sessions)} sessions fully enriched through Stage 4")

    # ── Save output ────────────────────────────────────────────────────────
    if output_path:
        with open(output_path, "w") as f:
            json.dump(enriched_sessions, f, indent=2)
        logger.info(f"  Output saved: {output_path}")

    logger.info("═══ Pipeline Complete ═══")
    return enriched_sessions


def run_json_pipeline(
    input_path: str,
    output_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Alternative pipeline for pre-parsed JSON session data (e.g., from ML engineer output).
    Runs Stage 4 only (risk scoring + anomaly + AI) on already-structured session dicts.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with open(input_path, "r") as f:
        raw_sessions = json.load(f)

    if not isinstance(raw_sessions, list):
        raw_sessions = [raw_sessions]

    logger.info(f"[JSON Pipeline] Loaded {len(raw_sessions)} sessions from {input_path}")

    # Run Stage 4 on the flat sessions
    try:
        anomaly_results = detect_anomalies(raw_sessions, contamination=0.05)
        anomaly_map = {
            item["session_id"]: (item["anomaly_flag"], item["anomaly_score"], item.get("reasons", []))
            for item in anomaly_results
        }
    except Exception as exc:
        logger.warning(f"Anomaly detection error: {exc}")
        anomaly_map = {}

    enriched_sessions = []
    for session in raw_sessions:
        sid = session.get("session_id", "")
        score_res = score_session(session)
        risk_score = score_res.get("risk_score", 0)
        raw_score = score_res.get("raw_score", 0)
        risk_level = score_res.get("risk_level", "low")
        rule_violations = score_res.get("rule_violations", [])

        data_incomplete = False
        expected_fields = [
            ("session_id", ""), ("protocol", ""), ("starttls_used", False),
            ("tls_version", ""), ("cipher_suite", ""), ("key_exchange", ""),
            ("forward_secrecy", False), ("cert_key_length", 0), ("cert_expired", False),
            ("cert_chain_valid", True), ("handshake_duration_ms", 0),
        ]
        for field_name, default in expected_fields:
            if field_name not in session:
                data_incomplete = True
                rule_violations.append(f"Incomplete session data — {field_name} missing")
                session[field_name] = default

        anomaly_flag, anomaly_score, reasons = anomaly_map.get(sid, (False, 0.0, []))
        ai_rec = generate_recommendation(session, risk_score, risk_level, rule_violations, anomaly_flag)

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
            "ai_recommendation": ai_rec,
        }
        enriched_sessions.append(enriched_record)

    if output_path:
        with open(output_path, "w") as f:
            json.dump(enriched_sessions, f, indent=2)
        logger.info(f"[JSON Pipeline] Output saved: {output_path}")

    return enriched_sessions


# ═══════════════════════════════════════════════════════════════════════════
#  HISTORY MANAGEMENT (Last 10 analysis runs)
# ═══════════════════════════════════════════════════════════════════════════

def _ensure_history_dir():
    os.makedirs(HISTORY_DIR, exist_ok=True)


def save_to_history(
    enriched_sessions: List[Dict[str, Any]],
    source_filename: str,
    pipeline_type: str = "pcap",
) -> Dict[str, Any]:
    """Save an analysis run to history. Returns the history metadata record."""
    _ensure_history_dir()

    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%d_%H%M%S")
    history_file = os.path.join(HISTORY_DIR, f"analysis_{run_id}.json")

    # Compute summary stats
    level_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    anomaly_count = 0
    for s in enriched_sessions:
        rl = s.get("risk_level", "low")
        if rl in level_counts:
            level_counts[rl] += 1
        if s.get("anomaly_flag"):
            anomaly_count += 1

    avg_score = 0
    if enriched_sessions:
        avg_score = round(
            sum(s.get("risk_score", 0) for s in enriched_sessions) / len(enriched_sessions), 1
        )

    meta = {
        "run_id": run_id,
        "timestamp": now.isoformat(),
        "source_filename": source_filename,
        "pipeline_type": pipeline_type,
        "session_count": len(enriched_sessions),
        "risk_summary": level_counts,
        "anomaly_count": anomaly_count,
        "avg_risk_score": avg_score,
    }

    record = {
        "metadata": meta,
        "sessions": enriched_sessions,
    }

    with open(history_file, "w") as f:
        json.dump(record, f, indent=2)

    # Prune old history beyond MAX_HISTORY
    _prune_history()

    logger.info(f"[HISTORY] Saved run {run_id} ({len(enriched_sessions)} sessions) → {history_file}")
    return meta


def _prune_history():
    """Keep only the last MAX_HISTORY analysis runs."""
    _ensure_history_dir()
    files = sorted(glob.glob(os.path.join(HISTORY_DIR, "analysis_*.json")))
    while len(files) > MAX_HISTORY:
        oldest = files.pop(0)
        try:
            os.remove(oldest)
            logger.info(f"[HISTORY] Pruned old run: {os.path.basename(oldest)}")
        except OSError:
            pass


def get_history_list() -> List[Dict[str, Any]]:
    """Returns metadata for all saved analysis runs, newest first."""
    _ensure_history_dir()
    files = sorted(glob.glob(os.path.join(HISTORY_DIR, "analysis_*.json")), reverse=True)
    history = []
    for fpath in files[:MAX_HISTORY]:
        try:
            with open(fpath, "r") as f:
                record = json.load(f)
            meta = record.get("metadata", {})
            meta["_filepath"] = fpath
            history.append(meta)
        except (json.JSONDecodeError, IOError):
            pass
    return history


def get_history_run(run_id: str) -> Optional[Dict[str, Any]]:
    """Load a specific history run by run_id."""
    fpath = os.path.join(HISTORY_DIR, f"analysis_{run_id}.json")
    if not os.path.exists(fpath):
        return None
    with open(fpath, "r") as f:
        return json.load(f)


def delete_history_run(run_id: str) -> bool:
    """Delete a specific history run."""
    fpath = os.path.join(HISTORY_DIR, f"analysis_{run_id}.json")
    if os.path.exists(fpath):
        os.remove(fpath)
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
#  In-memory latest results (for GET /api/sessions when no history exists)
# ═══════════════════════════════════════════════════════════════════════════

_latest_sessions: List[Dict[str, Any]] = []


# ═══════════════════════════════════════════════════════════════════════════
#  FASTAPI ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/")
def get_root():
    return {
        "service": "SecureMailScope API",
        "version": "2.0.0",
        "status": "active",
        "pipeline": "PCAP → Stage1 → Stage2 → Stage3 → Stage4 → Dashboard",
        "endpoints": [
            "/api/sessions",
            "/api/sessions/{session_id}",
            "/api/history",
            "/api/history/{run_id}",
            "/analyze",
        ],
    }


@app.get("/api/sessions")
def get_sessions(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (low, medium, high, critical)"),
    anomaly_only: bool = Query(False, description="Filter to anomalous sessions only"),
):
    """
    Returns the latest enriched email TLS session data.
    Loads from the most recent history run, or returns empty if no analysis has been performed.
    """
    global _latest_sessions

    # If we have in-memory results, use those
    if _latest_sessions:
        data = _latest_sessions
    else:
        # Try loading from most recent history
        history = get_history_list()
        if history:
            run = get_history_run(history[0]["run_id"])
            if run:
                data = run.get("sessions", [])
                _latest_sessions = data
            else:
                data = []
        else:
            data = []

    # Apply filters
    if risk_level:
        data = [s for s in data if s.get("risk_level", "").lower() == risk_level.lower()]
    if anomaly_only:
        data = [s for s in data if s.get("anomaly_flag", False)]

    return data


@app.get("/api/sessions/{session_id}")
def get_session_by_id(session_id: str):
    global _latest_sessions

    if not _latest_sessions:
        history = get_history_list()
        if history:
            run = get_history_run(history[0]["run_id"])
            if run:
                _latest_sessions = run.get("sessions", [])

    session = next((s for s in _latest_sessions if s["session_id"] == session_id), None)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return session


@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    """
    Upload a PCAP/PCAPNG file for full pipeline analysis.
    Returns enriched sessions JSON and saves to history.
    """
    global _latest_sessions

    filename = file.filename or "upload.pcap"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in ("pcap", "pcapng", "json"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '.{ext}'. Upload .pcap, .pcapng, or .json files.",
        )

    # Save uploaded file to temp location
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        if ext == "json":
            enriched = run_json_pipeline(tmp_path)
            pipeline_type = "json"
        else:
            enriched = run_pcap_pipeline(tmp_path)
            pipeline_type = "pcap"

        # Save to history
        meta = save_to_history(enriched, source_filename=filename, pipeline_type=pipeline_type)

        # Update in-memory cache
        _latest_sessions = enriched

        return {
            "status": "success",
            "metadata": meta,
            "sessions": enriched,
        }

    except Exception as exc:
        logger.error(f"Pipeline error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(exc)}")
    finally:
        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── History Endpoints ────────────────────────────────────────────────────

@app.get("/api/history")
def get_history():
    """Returns metadata for the last 10 analysis runs."""
    history = get_history_list()
    # Remove internal filepath from response
    for h in history:
        h.pop("_filepath", None)
    return history


@app.get("/api/history/{run_id}")
def get_history_by_id(run_id: str):
    """Load a specific past analysis run."""
    run = get_history_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"History run '{run_id}' not found.")
    return run


@app.delete("/api/history/{run_id}")
def delete_history(run_id: str):
    """Delete a specific history run."""
    if delete_history_run(run_id):
        return {"status": "deleted", "run_id": run_id}
    raise HTTPException(status_code=404, detail=f"History run '{run_id}' not found.")


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SecureMailScope Pipeline & API Server")
    parser.add_argument("--pcap", type=str, help="Path to PCAP file to analyze on startup")
    parser.add_argument("--json", type=str, help="Path to JSON sessions file to analyze on startup")
    parser.add_argument("--keylog", type=str, help="Path to SSLKEYLOGFILE for TLS 1.3 decryption")
    parser.add_argument("--output", type=str, help="Path to save enriched output JSON")
    parser.add_argument("--no-server", action="store_true", help="Run pipeline only, don't start API server")
    args = parser.parse_args()

    # Run pipeline if input provided
    if args.pcap:
        enriched = run_pcap_pipeline(args.pcap, keylog_path=args.keylog, output_path=args.output)
        meta = save_to_history(enriched, source_filename=os.path.basename(args.pcap), pipeline_type="pcap")
        _latest_sessions = enriched
        print(f"\n✓ Analyzed {len(enriched)} sessions from {args.pcap}")
    elif args.json:
        enriched = run_json_pipeline(args.json, output_path=args.output)
        meta = save_to_history(enriched, source_filename=os.path.basename(args.json), pipeline_type="json")
        _latest_sessions = enriched
        print(f"\n✓ Analyzed {len(enriched)} sessions from {args.json}")

    # Start API server
    if not args.no_server:
        print("\nStarting SecureMailScope API server on http://0.0.0.0:8000 ...")
        print("  Docs: http://localhost:8000/docs")
        print("  Sessions: http://localhost:8000/api/sessions")
        print("  History: http://localhost:8000/api/history")
        uvicorn.run("pipeline:app", host="0.0.0.0", port=8000, reload=True)
