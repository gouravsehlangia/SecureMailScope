#!/usr/bin/env python3
import json
from typing import Dict, List, Any

# Weak cipher keywords: RC4, DES, 3DES, EXPORT, NULL, anon
WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON"]

def is_weak_cipher(cipher_suite: str) -> bool:
    cipher_upper = cipher_suite.upper()
    return any(keyword in cipher_upper for keyword in WEAK_CIPHER_KEYWORDS)

def get_risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"

def score_session(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates a TLS email session record and returns risk_score (0-100 capped),
    raw_score (uncapped sum for ranking within cap), risk_level, and rule_violations.

    Rules applied:
    - TLS 1.0/1.1: +30
    - No forward secrecy: +20
    - cert_key_length < 2048: +25
    - cert_expired: +40
    - Weak cipher (RC4/DES/3DES/EXPORT/NULL/anon): +25
    - Certificate chain invalid: +20
    - Anonymous key exchange (DH_anon/ECDH_anon): +50  [NEW — own distinct rule]
    """
    score = 0
    rule_violations: List[str] = []

    # Rule 1: Deprecated TLS Version
    tls_version = session.get("tls_version", "")
    if tls_version in ["TLS 1.0", "TLS 1.1"]:
        score += 30
        rule_violations.append(f"Deprecated TLS version ({tls_version})")

    # Rule 2: Lack of Forward Secrecy
    if not session.get("forward_secrecy", False):
        score += 20
        rule_violations.append("Lack of Perfect Forward Secrecy (PFS)")

    # Rule 3: Weak Certificate Key Length (< 2048)
    cert_key_length = session.get("cert_key_length", 0)
    if cert_key_length < 2048:
        score += 25
        rule_violations.append(f"Weak certificate key length ({cert_key_length} bits < 2048)")

    # Rule 4: Expired Certificate
    if session.get("cert_expired", False):
        score += 40
        rule_violations.append("Expired TLS certificate")

    # Rule 5: Weak Cipher Suite
    cipher_suite = session.get("cipher_suite", "")
    if is_weak_cipher(cipher_suite):
        score += 25
        rule_violations.append(f"Weak or insecure cipher suite ({cipher_suite})")

    # Rule 6: Certificate Chain Invalidity (additional validation check)
    if not session.get("cert_chain_valid", True):
        score += 20
        rule_violations.append("Invalid certificate chain")

    # Rule 7: Anonymous Key Exchange — no server authentication, trivially MITM-exploitable
    key_exchange = session.get("key_exchange", "")
    if key_exchange in ["DH_anon", "ECDH_anon"]:
        score += 50
        rule_violations.append(
            "Anonymous key exchange — no server authentication, trivially exploitable via MITM"
        )

    raw_score = score  # Uncapped sum for ranking within the 100 cap
    final_score = min(100, score)
    risk_level = get_risk_level(final_score)

    return {
        "session_id": session.get("session_id"),
        "risk_score": final_score,
        "raw_score": raw_score,
        "risk_level": risk_level,
        "rule_violations": rule_violations
    }

if __name__ == "__main__":
    import os

    mock_file = "mock_sessions.json"
    if not os.path.exists(mock_file):
        print(f"Error: {mock_file} not found. Please run generate_mock_sessions.py first.")
        exit(1)

    with open(mock_file, "r") as f:
        sessions = json.load(f)

    results = [score_session(s) for s in sessions]

    # Summary statistics
    level_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for res in results:
        level_counts[res["risk_level"]] += 1

    print("=" * 65)
    print("                SECURE MAIL SCOPE - RISK SCORING SUMMARY")
    print("=" * 65)
    print(f"Total Sessions Processed: {len(results)}")
    print(f"  Critical Risk : {level_counts['critical']:3d} sessions")
    print(f"  High Risk     : {level_counts['high']:3d} sessions")
    print(f"  Medium Risk   : {level_counts['medium']:3d} sessions")
    print(f"  Low Risk      : {level_counts['low']:3d} sessions")
    print("-" * 65)

    print("\nSample Scored Sessions (First 5):")
    for r in results[:5]:
        print(f"\nSession ID: {r['session_id']}")
        print(f"  Score: {r['risk_score']} | Level: {r['risk_level'].upper()}")
        print(f"  Violations ({len(r['rule_violations'])}):")
        for v in r["rule_violations"]:
            print(f"    - {v}")

    print("\nSample Critical Risk Session:")
    critical_sample = next((r for r in results if r["risk_level"] == "critical"), None)
    if critical_sample:
        print(f"Session ID: {critical_sample['session_id']}")
        print(f"  Score: {critical_sample['risk_score']} | Level: {critical_sample['risk_level'].upper()}")
        print("  Violations:")
        for v in critical_sample["rule_violations"]:
            print(f"    - {v}")
    print("=" * 65)
