#!/usr/bin/env python3
"""
ai_recommendations.py

Generates per-session cybersecurity remediation recommendations using:
  1. Cerebras API (llama3.1-8b) — if CEREBRAS_API_KEY is set to a real value.
  2. Expert rule-engine fallback — if key is missing, invalid, or the API call fails.

The Cerebras prompt is structured to:
  - Present each violation as a numbered list
  - Instruct the model to NAME and address the single most severe issue FIRST
  - Keep the response to 2 sentences max

This produces noticeably different, violation-specific output for sessions that
have different dominant risks (e.g. anon key exchange vs. 3DES on old TLS).
"""

import os
from typing import List, Dict, Any

from dotenv import load_dotenv

load_dotenv()

_recommendation_cache: Dict[tuple, str] = {}


def _build_prompt(session: Dict[str, Any], risk_score: int, risk_level: str,
                  rule_violations: List[str], anomaly_flag: bool) -> str:
    """Build a structured, violation-specific prompt for the Cerebras LLM."""
    violations_numbered = "\n".join(
        f"  {i+1}. {v}" for i, v in enumerate(rule_violations)
    ) if rule_violations else "  None"

    severity_hint = ""
    # Give the model an explicit nudge toward the single worst issue
    if any("Anonymous key exchange" in v for v in rule_violations):
        severity_hint = "The single most severe issue is the ANONYMOUS KEY EXCHANGE — it nullifies all transport security."
    elif any("Expired TLS certificate" in v for v in rule_violations):
        severity_hint = "The single most severe issue is the EXPIRED CERTIFICATE — it invalidates the server's identity proof."
    elif any("Deprecated TLS" in v for v in rule_violations):
        severity_hint = "The single most severe issue is the DEPRECATED TLS VERSION — it exposes the session to known protocol-level attacks."
    elif any("Weak or insecure cipher" in v for v in rule_violations):
        severity_hint = "The single most severe issue is the INSECURE CIPHER SUITE — it can be cracked or decrypted offline."
    elif any("Weak certificate key length" in v for v in rule_violations):
        severity_hint = "The single most severe issue is the WEAK KEY LENGTH — it is computationally feasible to factor/break."

    return (
        f"You are a Cybersecurity Lead writing a remediation note for an email TLS session audit.\n\n"
        f"SESSION DETAILS:\n"
        f"  Protocol:      {session.get('protocol')} | TLS: {session.get('tls_version')}\n"
        f"  Cipher Suite:  {session.get('cipher_suite')}\n"
        f"  Key Exchange:  {session.get('key_exchange')} | PFS: {session.get('forward_secrecy')}\n"
        f"  Cert Key Len:  {session.get('cert_key_length')} bits | Expired: {session.get('cert_expired')}\n"
        f"  Risk Score:    {risk_score}/100 ({risk_level.upper()})\n"
        f"  Anomaly Flag:  {anomaly_flag}\n\n"
        f"SECURITY VIOLATIONS (ordered by detection):\n{violations_numbered}\n\n"
        f"{severity_hint}\n\n"
        f"INSTRUCTIONS:\n"
        f"- Begin your response by naming and addressing the single most severe violation above.\n"
        f"- Then briefly summarize remediation for any remaining violations in one additional sentence.\n"
        f"- Maximum 2 sentences total. Be specific and technical. Do not use generic advice."
    )


def generate_recommendation(
    session: Dict[str, Any],
    risk_score: int,
    risk_level: str,
    rule_violations: List[str],
    anomaly_flag: bool
) -> str:
    """
    Returns a tailored AI remediation recommendation for a TLS session.
    Results are cached by (risk_level, frozenset of violations, anomaly_flag)
    to avoid redundant API calls for sessions with identical risk profiles.
    """
    cache_key = (
        risk_level, 
        tuple(sorted(rule_violations)), 
        anomaly_flag,
        session.get("cipher_suite"),
        session.get("tls_version"),
        session.get("cert_key_length")
    )
    if cache_key in _recommendation_cache:
        return _recommendation_cache[cache_key]

    api_key = os.getenv("CEREBRAS_API_KEY", "")

    if api_key and api_key != "paste_my_actual_key_here":
        try:
            import requests as http_requests
            prompt = _build_prompt(session, risk_score, risk_level, rule_violations, anomaly_flag)
            response = http_requests.post(
                "https://api.cerebras.ai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama3.1-8b",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 120,
                    "temperature": 0.2
                },
                timeout=5
            )
            if response.status_code == 200:
                content = response.json()["choices"][0]["message"]["content"].strip()
                if content:
                    _recommendation_cache[cache_key] = content
                    return content
        except Exception:
            pass  # Fall through to rule engine

    # ---- Expert Rule Engine Fallback (used when API unavailable) ----
    # Priority-ordered: most severe violation drives the first sentence.
    parts: List[str] = []

    if any("Anonymous key exchange" in v for v in rule_violations):
        parts.append(
            "CRITICAL — Immediately disable anonymous key exchange (DH_anon/ECDH_anon): "
            "it provides zero server authentication and is trivially intercepted via MITM; "
            "replace with ECDHE or DHE with mutual certificate authentication."
        )
    elif any("Expired TLS certificate" in v for v in rule_violations):
        parts.append(
            "CRITICAL — Renew and deploy a valid TLS certificate immediately; "
            "an expired cert makes all identity assurances meaningless and will be rejected by compliant clients."
        )
    elif any("Deprecated TLS" in v for v in rule_violations):
        parts.append(
            "Disable TLS 1.0/1.1 on the mail gateway and enforce a minimum of TLS 1.2 with AEAD cipher suites "
            "to eliminate BEAST, POODLE, and related downgrade attacks."
        )
    elif any("Weak or insecure cipher" in v for v in rule_violations):
        parts.append(
            "Remove RC4/DES/3DES/NULL cipher suites from the server's cipher list "
            "and enforce AES-GCM or ChaCha20-Poly1305 AEAD suites only."
        )
    elif any("Weak certificate key length" in v for v in rule_violations):
        parts.append(
            "Re-issue the certificate with a minimum 2048-bit RSA or 256-bit ECDSA key; "
            "the current key length is within computational feasibility of modern factorization attacks."
        )

    # Secondary sentence covers remaining issues not already addressed
    secondary = []
    if any("Lack of Perfect Forward Secrecy" in v for v in rule_violations) and not any("Anonymous" in p for p in parts):
        secondary.append("prioritize ECDHE/DHE cipher suites to enable PFS")
    if any("Weak certificate key length" in v for v in rule_violations) and len(parts) > 0 and "Re-issue" not in parts[0]:
        secondary.append("re-issue the certificate with ≥2048-bit RSA or 256-bit ECDSA")
    if any("Invalid certificate chain" in v for v in rule_violations):
        secondary.append("fix the intermediate certificate chain on the mail server")
    if anomaly_flag and not parts:
        secondary.append("investigate session parameters for potential probing or infrastructure degradation")

    if secondary:
        parts.append("Additionally: " + ", and ".join(secondary) + ".")

    if not parts:
        rec_text = ("Session meets current security baseline standards — "
                    "maintain TLS 1.2+ with ECDHE and AES-GCM, and schedule routine certificate rotation.")
    else:
        rec_text = " ".join(parts)

    _recommendation_cache[cache_key] = rec_text
    return rec_text
