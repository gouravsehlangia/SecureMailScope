"""
backend.parser.cli
~~~~~~~~~~~~~~~~~~
Command-line interface for the PCAP Parsing module.
Use for standalone testing and SIH live demonstrations.

Usage:
  python -m backend.parser.cli <file.pcap>
  python -m backend.parser.cli <file.pcap> --json
  python -m backend.parser.cli <file.pcap> --export results.json
"""

import argparse
import sys
import json
from .extractor import parse_pcap, extract_tls_payloads_for_crypto_lead


# ANSI color codes for rich terminal formatting
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"


def color_severity(sev: str) -> str:
    if sev == "CRITICAL":
        return f"{RED}{BOLD}[CRITICAL]{RESET}"
    elif sev == "HIGH":
        return f"{RED}[HIGH]{RESET}"
    elif sev == "MEDIUM":
        return f"{YELLOW}[MEDIUM]{RESET}"
    elif sev == "LOW":
        return f"{CYAN}[LOW]{RESET}"
    return f"{RESET}[INFO]{RESET}"


def print_banner():
    print(f"""
{CYAN}{BOLD}========================================================================
   SMART INDIA HACKATHON - EMAIL SECURITY TRAFFIC ANALYZER
   Module 1: PCAP Ingestion, Stream Reassembly & STARTTLS Detector
========================================================================{RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        description="Smart India Hackathon - Email Traffic & STARTTLS Parser (Role #1)"
    )
    parser.add_argument("pcap_file", help="Path to .pcap or .pcapng file")
    parser.add_argument("--json", action="store_true", help="Print complete JSON output")
    parser.add_argument("--export", type=str, help="Export parsed JSON output to specified filepath")
    parser.add_argument("--crypto-handoff", action="store_true", help="Display TLS payload chunks prepared for Role #2")

    args = parser.parse_args()

    try:
        result = parse_pcap(args.pcap_file)
    except Exception as e:
        print(f"{RED}Error parsing PCAP file: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(result.to_json(indent=2))
        return

    if args.export:
        with open(args.export, "w", encoding="utf-8") as f:
            f.write(result.to_json(indent=2))
        print(f"{GREEN}[+] Results successfully exported to: {args.export}{RESET}")

    print_banner()

    summary = result.summary()
    print(f"{BOLD}File Analyzed:{RESET} {result.filepath}")
    print(f"{BOLD}Parse Duration:{RESET} {summary['parse_duration_seconds']:.4f}s")
    print(f"{BOLD}Packets Processed:{RESET} {summary['total_packets']} (TCP: {summary['tcp_packets']})")
    print(f"{BOLD}Total TCP Streams:{RESET} {summary['total_streams']}")
    print(f"{BOLD}Email Sessions Detected:{RESET} {summary['email_sessions_count']}")
    print("-" * 72)

    if not result.email_sessions:
        print(f"{YELLOW}No email (SMTP / IMAP / POP3) sessions found in this capture.{RESET}")
        return

    print(f"\n{BOLD}{CYAN}=== EMAIL SESSIONS SUMMARY ==={RESET}")
    for idx, sess in enumerate(result.email_sessions, 1):
        enc_status = f"{GREEN}YES (TLS Active){RESET}" if sess.is_tls_encrypted else f"{RED}NO (Plaintext Only){RESET}"
        stls_status = sess.starttls.status.value
        stls_color = GREEN if stls_status == "NEGOTIATED_SUCCESS" else (RED if "STRIPPED" in stls_status or "FAILED" in stls_status else YELLOW)

        print(f"\n{BOLD}[Session #{idx}] {sess.session_id}{RESET}")
        print(f"  * Protocol:        {MAGENTA}{sess.protocol.value}{RESET}")
        print(f"  * Endpoints:       {sess.client_ip}:{sess.client_port}  --->  {sess.server_ip}:{sess.server_port}")
        print(f"  * Packets:         {sess.packet_count}")
        print(f"  * STARTTLS Status: {stls_color}{stls_status}{RESET}")
        print(f"  * Encrypted:       {enc_status}")

        if sess.banner:
            print(f"  * Server Banner:   \"{sess.banner}\"")

        if sess.plaintext_commands:
            print(f"  * Plaintext Cmds:  {len(sess.plaintext_commands)} recorded (e.g. {', '.join(sess.plaintext_commands[:3])})")

        if sess.is_tls_encrypted:
            print(f"  * TLS Client Bytes: {len(sess.tls_client_payload)} bytes ready for Role #2 (TLS Handshake parser)")
            print(f"  * ClientHello:      {'Detected' if sess.client_hello_detected else 'None'}")

    if result.all_security_alerts:
        print(f"\n{BOLD}{RED}=== DETECTED SECURITY ALERTS & ANOMALIES ({len(result.all_security_alerts)}) ==={RESET}")
        for alert in result.all_security_alerts:
            print(f"\n{color_severity(alert.severity.value)} {BOLD}{alert.title}{RESET}")
            print(f"  * Alert Type:     {alert.alert_type}")
            print(f"  * Description:    {alert.description}")
            print(f"  * Evidence:       {alert.evidence}")
            print(f"  * Recommendation: {alert.recommendation}")
    else:
        print(f"\n{GREEN}[+] No critical cryptographic security alerts detected.{RESET}")

    if args.crypto_handoff:
        print(f"\n{BOLD}{MAGENTA}=== ROLE #2 (TLS/CRYPTO) HANDOFF PAYLOADS ==={RESET}")
        handoff = extract_tls_payloads_for_crypto_lead(result)
        for h in handoff:
            print(f"Session: {h['session_id']}")
            print(f"  Client TLS Payload (first 32 bytes hex): {h['tls_client_bytes'][:32].hex()}")
            print(f"  Server TLS Payload (first 32 bytes hex): {h['tls_server_bytes'][:32].hex()}")

    print("\n" + "=" * 72)


if __name__ == "__main__":
    main()
