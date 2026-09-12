#!/usr/bin/env python3
"""
SecureMailScope — Full Stage 2 Pipeline Integration Test
Feeds all sessions from mock_email_traffic.pcap through the Stage 1 stub →
CryptoAnalyzer.analyze_session() and reports per-scenario results.

Usage:
    python3 test_data/run_pipeline.py
"""

import os
import sys
import json

CURRENT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

PCAP_PATH   = os.path.join(CURRENT_DIR, "mock_email_traffic.pcap")
KEYLOG_PATH = os.path.join(CURRENT_DIR, "mock_session.keylog")

from test_data.stage1_stub import reassemble_streams
from backend.tls_analysis import CryptoAnalyzer
from backend.tls_analysis.keylog_manager import SSLKeyLogManager

# ──────────────────────────────────────────────────────────────────────────────
# Expected outcomes per scenario (for PASS/FAIL assertion)
# ──────────────────────────────────────────────────────────────────────────────

EXPECTED = {
    1: {
        "description": "IMAP STARTTLS → TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256 (PFS)",
        "tls_present":     True,
        "tls_version":     "TLS 1.2",
        "forward_secrecy": True,
        "security_rating": "SECURE",
        "starttls_stripped": False,
    },
    2: {
        "description": "SMTP STARTTLS → TLS 1.3 TLS_AES_256_GCM_SHA384 (PFS, encrypted cert)",
        "tls_present":     True,
        "tls_version":     "TLS 1.3",
        "forward_secrecy": True,
        "security_rating": "SECURE",
        "starttls_stripped": False,
    },
    3: {
        "description": "POP3S implicit TLS 1.0 + RC4-MD5 (NO PFS, INSECURE)",
        "tls_present":     True,
        "tls_version":     "TLS 1.0",
        "forward_secrecy": False,
        "security_rating": "INSECURE",
        "starttls_stripped": False,
    },
    4: {
        "description": "SMTP STARTTLS offered, client never upgrades (downgrade)",
        "tls_present":     False,
        "forward_secrecy": False,
        "security_rating": "INSECURE",
        "starttls_stripped": True,
    },
    5: {
        "description": "IMAP/993 truncated ServerHello — error-handling test",
        "tls_present":     True,   # TLS records found, parser should not crash
        # version/cipher may be partial — we only verify no exception is raised
        "no_crash": True,
    },
}


def field(r, attr, default="—"):
    val = getattr(r, attr, default)
    return val if val is not None else default


def verdict(scenario_num: int, result) -> tuple[str, list[str]]:
    """Returns ('PASS'|'FAIL', list_of_failure_reasons)."""
    exp = EXPECTED[scenario_num]
    failures = []

    for key, expected_val in exp.items():
        if key in ("description", "no_crash"):
            continue
        actual_val = getattr(result, key, None)
        # security_rating is an Enum — compare .value
        if hasattr(actual_val, "value"):
            actual_val = actual_val.value
        if actual_val != expected_val:
            failures.append(
                f"  ✗ {key}: expected={expected_val!r}, got={actual_val!r}"
            )

    return ("PASS" if not failures else "FAIL"), failures


def print_result_block(scenario_num: int, session_desc: str, result, pass_fail: str, failures: list[str]):
    sep = "─" * 72
    icon = "✅" if pass_fail == "PASS" else "❌"
    print(f"\n{sep}")
    print(f"  SCENARIO {scenario_num}: {EXPECTED[scenario_num]['description']}")
    print(f"  Session  : {session_desc}")
    print(sep)
    print(f"  TLS Present        : {field(result, 'tls_present')}")
    print(f"  TLS Version        : {field(result, 'tls_version')}")
    print(f"  Cipher Suite       : {field(result, 'cipher_suite')}")
    print(f"  Cipher Code        : {field(result, 'cipher_code')}")
    print(f"  Key Exchange       : {field(result, 'key_exchange')}")
    print(f"  Key Exchange Group : {field(result, 'key_exchange_group')}")
    print(f"  Forward Secrecy    : {field(result, 'forward_secrecy')}")
    print(f"  Security Rating    : {field(result, 'security_rating')}")
    print(f"  Visibility         : {field(result, 'visibility')}")
    print(f"  Keylog Applied     : {field(result, 'keylog_applied')}")
    print(f"  STARTTLS Used      : {field(result, 'starttls_used')}")
    print(f"  STARTTLS Stripped  : {field(result, 'starttls_stripped')}")
    certs = getattr(result, "raw_certificates", [])
    print(f"  Certs for Stage 3  : {len(certs)} DER certificate(s)")
    violations = getattr(result, "rule_violations", [])
    if violations:
        print(f"  Rule Violations    :")
        for v in violations:
            print(f"    ⚠  {v}")
    warnings = getattr(result, "warnings", [])
    if warnings:
        print(f"  Warnings           :")
        for w in warnings:
            print(f"    ℹ  {w}")
    print(f"\n  {icon} VERDICT: {pass_fail}")
    for f in failures:
        print(f)


def main():
    print("=" * 72)
    print("  SecureMailScope — Stage 2 Full Pipeline Integration Test")
    print("  Stage 1 STUB → CryptoAnalyzer.analyze_session()")
    print("=" * 72)

    if not os.path.exists(PCAP_PATH):
        print(f"\nERROR: pcap not found at {PCAP_PATH}")
        print("Run:  python3 test_data/generate_mock_pcap.py  first.")
        sys.exit(1)

    # Load keylog manager for scenario 2
    keylog_mgr = SSLKeyLogManager()
    if os.path.exists(KEYLOG_PATH):
        loaded = keylog_mgr.load_keylog_file(KEYLOG_PATH)
        print(f"\nKeylog: loaded {KEYLOG_PATH!r} — {loaded} entries")
    else:
        print(f"\nKeylog: NOT FOUND at {KEYLOG_PATH} — TLS 1.3 cert decryption will degrade gracefully")

    # Reassemble TCP streams via Stage 1 stub
    print("\nRunning Stage 1 STUB (pcap TCP reassembly)...")
    sessions = reassemble_streams(PCAP_PATH)
    print(f"→ {len(sessions)} TCP sessions reassembled\n")

    if len(sessions) < 5:
        print(f"WARNING: expected 5 sessions, got {len(sessions)}. Some scenarios may be missing.\n")

    # Map sessions to scenarios by server port
    PORT_TO_SCENARIO = {143: 1, 587: 2, 995: 3, 25: 4, 993: 5}
    scenario_results = {}
    unmatched = []

    for session in sessions:
        sc_num = PORT_TO_SCENARIO.get(session.server_port)
        if sc_num is None:
            unmatched.append(session)
            continue
        if sc_num in scenario_results:
            # Already have this scenario mapped; skip duplicates
            continue

        # Run Stage 2
        try:
            result = CryptoAnalyzer.analyze_session(session, keylog_manager=keylog_mgr)
            scenario_results[sc_num] = (session, result, None)
        except Exception as exc:
            scenario_results[sc_num] = (session, None, exc)

    # Print per-scenario results
    summary_rows = []
    all_pass = True

    for sc_num in sorted(EXPECTED.keys()):
        if sc_num not in scenario_results:
            print(f"\n  SCENARIO {sc_num}: ⚠ NOT RUN — no matching session found in pcap")
            summary_rows.append((sc_num, EXPECTED[sc_num]["description"], "NOT RUN", []))
            all_pass = False
            continue

        session, result, exc = scenario_results[sc_num]
        session_desc = f"{session.protocol} {session.client_ip}:{session.client_port} → {session.server_ip}:{session.server_port}"

        if exc is not None:
            print(f"\n{'─'*72}")
            print(f"  SCENARIO {sc_num}: {EXPECTED[sc_num]['description']}")
            print(f"  ❌ EXCEPTION RAISED (Stage 2 CRASH):")
            import traceback
            traceback.print_exception(type(exc), exc, exc.__traceback__)
            pf = "FAIL"
            fails = [f"  ✗ Exception: {exc}"]
            summary_rows.append((sc_num, EXPECTED[sc_num]["description"], pf, fails))
            all_pass = False
            continue

        exp = EXPECTED[sc_num]
        if exp.get("no_crash") and result is not None and exc is None:
            # Scenario 5 — just verify no crash
            pf = "PASS"
            fails = []
        else:
            pf, fails = verdict(sc_num, result)

        if pf == "FAIL":
            all_pass = False
        print_result_block(sc_num, session_desc, result, pf, fails)
        summary_rows.append((sc_num, EXPECTED[sc_num]["description"], pf, fails))

    # Print summary table
    print("\n" + "=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"  {'#':<3}  {'Scenario':<47}  {'Result'}")
    print(f"  {'─'*3}  {'─'*47}  {'─'*6}")
    for sc_num, desc, pf, _ in summary_rows:
        icon = "✅" if pf == "PASS" else ("⚠️ " if pf == "NOT RUN" else "❌")
        print(f"  {sc_num:<3}  {desc[:47]:<47}  {icon} {pf}")
    print("=" * 72)
    print(f"\n  Overall: {'ALL PASS ✅' if all_pass else 'SOME FAILURES ❌'}")
    print()

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
