#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  TEMPORARY STAGE 1 STUB — SecureMailScope                                  ║
║  replace with teammate's real Stage 1 module once merged.                  ║
║                                                                              ║
║  Purpose:  Read a .pcap file, reassemble per-TCP-stream byte sequences,     ║
║            detect STARTTLS negotiation and protocol type, and emit           ║
║            Stage1SessionInput objects that CryptoAnalyzer.analyze_session() ║
║            accepts as input.                                                 ║
║                                                                              ║
║  What this does NOT do (left to real Stage 1):                              ║
║    - IP fragmentation reassembly                                             ║
║    - Out-of-order segment reordering (assumes ascending seq from pcap)      ║
║    - Retransmission deduplication                                            ║
║    - Multi-packet segment merging beyond simple seq ordering                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
from typing import List, Dict, Tuple, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from scapy.all import rdpcap, TCP, IP, Raw
except ImportError:
    print("ERROR: scapy not installed. Run: pip install scapy", file=sys.stderr)
    sys.exit(1)

from backend.tls_analysis.models import Stage1SessionInput


# ──────────────────────────────────────────────────────────────────────────────
# Protocol detection by TCP port (per RFC / IANA assignments)
# ──────────────────────────────────────────────────────────────────────────────
PORT_PROTOCOL_MAP: Dict[int, str] = {
    25:   "SMTP",    # SMTP (plaintext / STARTTLS)
    465:  "SMTPS",   # SMTP over implicit TLS
    587:  "SMTP",    # SMTP submission (STARTTLS)
    110:  "POP3",    # POP3 (plaintext / STARTTLS)
    995:  "POP3S",   # POP3 over implicit TLS
    143:  "IMAP",    # IMAP (plaintext / STARTTLS)
    993:  "IMAPS",   # IMAP over implicit TLS
}

# STARTTLS command keywords per protocol
STARTTLS_CLIENT_CMDS = {
    "SMTP":  [b"starttls\r\n"],
    "IMAP":  [b"starttls\r\n"],         # e.g. "A002 STARTTLS\r\n" — match suffix
    "POP3":  [b"stls\r\n"],
}

# STARTTLS success response indicators per protocol
STARTTLS_SERVER_OK = {
    "SMTP":  [b"220 ", b"2.0.0"],
    "IMAP":  [b"ok begin", b" ok"],
    "POP3":  [b"+ok"],
}


def _detect_protocol(sport: int, dport: int) -> str:
    """Return protocol name by matching either endpoint port."""
    return (
        PORT_PROTOCOL_MAP.get(dport) or
        PORT_PROTOCOL_MAP.get(sport) or
        "SMTP"   # default fallback
    )


def _detect_starttls(
    client_stream: bytes,
    server_stream: bytes,
    protocol: str
) -> Tuple[bool, bool, bool]:
    """
    Returns (starttls_offered, starttls_negotiated, starttls_stripped).

    starttls_offered     : server capability line contained STARTTLS / STLS
    starttls_negotiated  : client sent STARTTLS cmd AND server replied OK, AND TLS records follow
    starttls_stripped    : STARTTLS offered, client sent auth/mail without upgrading
    """
    combined = (client_stream + server_stream).lower()
    srv_lower = server_stream.lower()
    cli_lower = client_stream.lower()

    offered = (
        b"250-starttls" in srv_lower or
        b"250 starttls" in srv_lower or
        b"starttls" in srv_lower or
        b"stls" in srv_lower
    )

    # Check if TLS records are present anywhere in the full stream
    full_stream = client_stream + server_stream
    has_tls = _has_tls_record(full_stream)

    # Check if client issued STARTTLS/STLS command
    issued_starttls = (
        b"starttls\r\n" in cli_lower or
        b"stls\r\n" in cli_lower
    )

    # Check server ack of STARTTLS (simplified — looks for 220 or +OK after stream boundary)
    server_acked = (
        b"220 " in srv_lower or
        b"ok begin" in srv_lower or
        b"+ok" in srv_lower
    )

    negotiated = issued_starttls and server_acked and has_tls

    # Stripping: offered but client sent credentials without upgrading
    stripped = (
        offered and not has_tls and (
            b"auth login" in cli_lower or
            b"auth plain" in cli_lower or
            b"mail from:" in cli_lower or
            b"pass " in cli_lower
        )
    )

    return offered, negotiated, stripped


def _has_tls_record(data: bytes) -> bool:
    """Quick scan for a valid TLS record header (content_type 0x14–0x17, version 0x03xx)."""
    for i in range(len(data) - 4):
        ct = data[i]
        if ct in (0x14, 0x15, 0x16, 0x17):
            ver_major = data[i + 1]
            ver_minor = data[i + 2]
            if ver_major == 0x03 and ver_minor in (0x00, 0x01, 0x02, 0x03, 0x04):
                rec_len = (data[i + 3] << 8) | data[i + 4]
                if rec_len > 0 and i + 5 + rec_len <= len(data):
                    return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# TCP Stream Reassembly (STUB — simple seq-ordered concatenation)
# ──────────────────────────────────────────────────────────────────────────────

class _TCPFlow:
    """Accumulates TCP payload bytes for one direction of a flow."""
    def __init__(self):
        self.segments: Dict[int, bytes] = {}   # seq_no → payload

    def add(self, seq: int, payload: bytes):
        if payload:
            self.segments[seq] = payload

    def reassemble(self) -> bytes:
        """Reassemble by ascending sequence number (no gap detection — STUB)."""
        return b"".join(v for _, v in sorted(self.segments.items()))


StreamKey = Tuple[str, str, int, int]   # (client_ip, server_ip, client_port, server_port)


def reassemble_streams(pcap_path: str) -> List[Stage1SessionInput]:
    """
    Reads a pcap file, reassembles TCP streams per 5-tuple, detects email
    protocols and STARTTLS, and returns a list of Stage1SessionInput objects.

    TEMPORARY STAGE 1 STUB — replace with teammate's real Stage 1 module once merged.
    """
    pkts = rdpcap(pcap_path)

    # Track client→server and server→client flows per TCP 4-tuple
    # Key: (client_ip, server_ip, sport, dport) where the 'client' is the SYN initiator
    connections: Dict[StreamKey, Dict[str, _TCPFlow]] = {}
    # Track which side is 'client' (sent SYN)
    syn_seen: Dict[frozenset, StreamKey] = {}

    for pkt in pkts:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        ip  = pkt[IP]
        tcp = pkt[TCP]

        flags = tcp.flags
        sport = tcp.sport
        dport = tcp.dport
        src   = ip.src
        dst   = ip.dst

        # Determine canonical flow key (always client→server ordering)
        pair = frozenset([(src, sport), (dst, dport)])
        if "S" in str(flags) and "A" not in str(flags):
            # SYN (without ACK) → this side is client
            key: StreamKey = (src, dst, sport, dport)
            syn_seen[pair] = key
        else:
            key = syn_seen.get(pair)
            if key is None:
                # Guess: lower port == server
                if dport in PORT_PROTOCOL_MAP:
                    key = (src, dst, sport, dport)
                elif sport in PORT_PROTOCOL_MAP:
                    key = (dst, src, dport, sport)
                else:
                    key = (src, dst, sport, dport)
                syn_seen[pair] = key

        if key not in connections:
            connections[key] = {
                "client": _TCPFlow(),
                "server": _TCPFlow(),
            }

        if not pkt.haslayer(Raw):
            continue
        payload = bytes(pkt[Raw])

        c_ip, s_ip, c_port, s_port = key
        if src == c_ip and sport == c_port:
            connections[key]["client"].add(tcp.seq, payload)
        else:
            connections[key]["server"].add(tcp.seq, payload)

    # Build Stage1SessionInput per connection
    sessions: List[Stage1SessionInput] = []
    for idx, (key, flows) in enumerate(connections.items()):
        c_ip, s_ip, c_port, s_port = key
        client_bytes = flows["client"].reassemble()
        server_bytes = flows["server"].reassemble()

        # Full reassembled stream: server bytes first (banner), then interleaved
        # For Stage 2's parser, we concatenate the full bidirectional stream
        full_stream = client_bytes + server_bytes

        protocol = _detect_protocol(c_port, s_port)
        offered, negotiated, stripped = _detect_starttls(client_bytes, server_bytes, protocol)

        session = Stage1SessionInput(
            session_id=f"pcap_sess_{idx + 1:03d}",
            stream_id=f"tcp_{c_ip}:{c_port}-{s_ip}:{s_port}",
            protocol=protocol,
            client_ip=c_ip,
            server_ip=s_ip,
            client_port=c_port,
            server_port=s_port,
            stream_bytes=full_stream,
            starttls_detected=negotiated,
            starttls_offered=offered,
        )
        sessions.append(session)

    return sessions


if __name__ == "__main__":
    # Quick self-test: dump detected sessions
    import argparse
    ap = argparse.ArgumentParser(description="Stage 1 STUB — PCAP TCP reassembler")
    ap.add_argument("pcap", help="Path to .pcap file")
    args = ap.parse_args()

    sessions = reassemble_streams(args.pcap)
    print(f"\nReassembled {len(sessions)} TCP sessions:\n")
    for s in sessions:
        print(
            f"  [{s.session_id}] {s.protocol:6s}  "
            f"{s.client_ip}:{s.client_port} → {s.server_ip}:{s.server_port} | "
            f"stream_bytes={len(s.stream_bytes)}B | "
            f"starttls_offered={s.starttls_offered} starttls_detected={s.starttls_detected}"
        )
