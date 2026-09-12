"""
backend.parser.extractor
~~~~~~~~~~~~~~~~~~~~~~~~
Master extraction pipeline tying together:
1. Packet ingestion (pcap_reader)
2. TCP stream reassembly (reassembler)
3. Protocol identification (protocol_detector)
4. STARTTLS state & anomaly analysis (starttls_detector)
5. Clean data handoff to Role #2 (TLS/Crypto), Role #5 (Frontend), and Role #6 (main.py).
"""

import time
import os
from typing import List, Dict, Any, Optional
from .models import (
    PcapParseResult,
    EmailSession,
    SecurityAlert,
    ProtocolType,
    StarttlsStatus,
)
from .pcap_reader import read_pcap
from .reassembler import TcpReassemblyEngine
from .protocol_detector import (
    ProtocolDetector,
    is_tls_record,
    is_tls_client_hello,
    is_tls_server_hello,
)
from .starttls_detector import StarttlsDetector


class EmailPcapParser:
    """
    High-level facade for PCAP parsing, protocol classification,
    and cryptographic transition analysis.
    """

    def __init__(self, prefer_scapy: bool = True):
        self.prefer_scapy = prefer_scapy

    def parse_file(self, filepath: str) -> PcapParseResult:
        """Parses a PCAP/PCAPNG file and returns a complete PcapParseResult."""
        start_wall_time = time.time()
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Target PCAP file does not exist: {filepath}")

        reassembly_engine = TcpReassemblyEngine()
        total_packets = 0
        tcp_packets = 0

        # Ingest packets through reassembly engine
        for pkt in read_pcap(filepath, prefer_scapy=self.prefer_scapy):
            total_packets += 1
            if pkt.ip_proto == "TCP":
                tcp_packets += 1
                reassembly_engine.process_packet(pkt)

        # Finalize all TCP streams
        tcp_streams = reassembly_engine.reassemble_all()

        email_sessions: List[EmailSession] = []
        all_alerts: List[SecurityAlert] = []
        session_idx = 0

        for stream in tcp_streams:
            proto, is_implicit_tls, banner = ProtocolDetector.identify(stream)

            # Filter out non-email streams unless they exhibit email-like behavior
            if proto == ProtocolType.UNKNOWN and not is_implicit_tls:
                continue

            session_idx += 1
            session_id = f"sess_{session_idx:03d}_{proto.value}_{stream.client_port}->{stream.server_port}"

            (
                starttls_info,
                alerts,
                tls_client_bytes,
                tls_server_bytes,
                plaintext_cmds,
                plaintext_resps,
            ) = StarttlsDetector.analyze(proto, stream, is_implicit_tls)

            has_tls = bool(is_implicit_tls or (starttls_info.status == StarttlsStatus.NEGOTIATED_SUCCESS and len(tls_client_bytes) > 0))
            client_hello_found = is_tls_client_hello(tls_client_bytes)
            server_hello_found = is_tls_server_hello(tls_server_bytes)

            session = EmailSession(
                session_id=session_id,
                protocol=proto,
                client_ip=stream.client_ip,
                client_port=stream.client_port,
                server_ip=stream.server_ip,
                server_port=stream.server_port,
                start_time=stream.start_time,
                end_time=stream.end_time,
                stream_id=stream.stream_id,
                packet_count=stream.packet_count,
                plaintext_commands=plaintext_cmds,
                plaintext_responses=plaintext_resps,
                starttls=starttls_info,
                is_tls_encrypted=has_tls,
                tls_client_payload=tls_client_bytes,
                tls_server_payload=tls_server_bytes,
                security_alerts=alerts,
                banner=banner,
                client_hello_detected=client_hello_found,
                server_hello_detected=server_hello_found,
            )

            email_sessions.append(session)
            all_alerts.extend(alerts)

        duration = time.time() - start_wall_time

        return PcapParseResult(
            filepath=os.path.abspath(filepath),
            parse_duration_seconds=duration,
            total_packets_read=total_packets,
            tcp_packets_processed=tcp_packets,
            total_streams_reassembled=len(tcp_streams),
            email_sessions=email_sessions,
            all_security_alerts=all_alerts,
            metadata={
                "parser_engine": "hybrid_pcap_reassembler",
                "team_role": "PCAP Parsing Lead (Role #1)",
                "sih_track": "Email Security & Cryptographic Traffic Inspection",
            },
        )


def parse_pcap(filepath: str, prefer_scapy: bool = True) -> PcapParseResult:
    """Primary programmatic entry point for the backend team."""
    parser = EmailPcapParser(prefer_scapy=prefer_scapy)
    return parser.parse_file(filepath)


def parse_pcap_to_dict(filepath: str, include_raw_bytes: bool = False) -> Dict[str, Any]:
    """Helper returning JSON-ready dictionary for Role #6 (main.py) and REST API."""
    result = parse_pcap(filepath)
    return result.to_dict(include_raw_bytes=include_raw_bytes)


def extract_tls_payloads_for_crypto_lead(result: PcapParseResult) -> List[Dict[str, Any]]:
    """
    Dedicated interface contract for Role #2 (TLS/Crypto Engineer).
    Extracts all reassembled TLS records ready for cipher suite / handshake analysis.
    """
    tls_payloads = []
    for s in result.email_sessions:
        if s.is_tls_encrypted and len(s.tls_client_payload) > 0:
            tls_payloads.append({
                "session_id": s.session_id,
                "protocol": s.protocol.value,
                "client": f"{s.client_ip}:{s.client_port}",
                "server": f"{s.server_ip}:{s.server_port}",
                "tls_client_bytes": s.tls_client_payload,
                "tls_server_bytes": s.tls_server_payload,
                "client_hello_present": s.client_hello_detected,
                "server_hello_present": s.server_hello_detected,
            })
    return tls_payloads
