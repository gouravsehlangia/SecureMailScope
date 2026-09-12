"""
backend.parser.models
~~~~~~~~~~~~~~~~~~~~~
Standardized data models and schemas for the PCAP Parsing module (Role #1).
These models provide the foundational contract with:
- Role #2: TLS/Crypto Engineer (tls_client_payload, tls_server_payload, tls_start_offset)
- Role #4: AI/ML Engineer (security_alerts, plaintext transcript, session metrics)
- Role #5: Frontend / Dashboard Lead (session tables, severity badges, timelines)
- Role #6: Integration & Reports Lead (JSON serializable via .to_dict())
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
import json


class ProtocolType(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    SMTPS = "SMTPS"      # Implicit TLS (port 465 or direct TLS handshake)
    IMAPS = "IMAPS"      # Implicit TLS (port 993)
    POP3S = "POP3S"      # Implicit TLS (port 995)
    UNKNOWN = "UNKNOWN"


class StarttlsStatus(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    OFFERED = "OFFERED"                             # Server advertised STARTTLS capability
    NEGOTIATED_SUCCESS = "NEGOTIATED_SUCCESS"       # Client sent STARTTLS, server accepted (220/OK)
    REJECTED_OR_FAILED = "REJECTED_OR_FAILED"       # Server rejected STARTTLS or error code returned
    STRIPPED_DOWNGRADE = "STRIPPED_DOWNGRADE"       # Server offered STARTTLS, but cleartext credentials sent without TLS
    PLAINTEXT_ONLY = "PLAINTEXT_ONLY"               # No STARTTLS offered or used; cleartext session


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityAlert:
    """Security alert emitted when anomalies, weak configs, or attacks are detected."""
    severity: AlertSeverity
    alert_type: str
    title: str
    description: str
    evidence: str
    recommendation: str
    timestamp: Optional[float] = None
    stream_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "alert_type": self.alert_type,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
            "stream_id": self.stream_id,
        }


@dataclass
class PacketRecord:
    """Normalized raw packet captured from PCAP/PCAPNG."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: Dict[str, bool]  # syn, ack, fin, rst, psh, urg
    payload: bytes
    ip_proto: str = "TCP"
    ip_version: int = 4
    packet_index: int = 0


@dataclass
class StreamEvent:
    """Represents an ordered chunk of communication in a TCP stream."""
    timestamp: float
    direction: str          # "client_to_server" or "server_to_client"
    payload: bytes
    seq: int
    is_tls: bool = False

    def payload_text(self, max_len: int = 200) -> str:
        """Safe printable representation of the payload."""
        try:
            txt = self.payload.decode("utf-8", errors="replace")
            return txt[:max_len]
        except Exception:
            return repr(self.payload[:max_len])


@dataclass
class TcpStream:
    """Reassembled bidirectional TCP stream with gap handling and reordering."""
    stream_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    start_time: float
    end_time: float
    client_payload: bytes = b""
    server_payload: bytes = b""
    events: List[StreamEvent] = field(default_factory=list)
    packet_count: int = 0
    client_packet_count: int = 0
    server_packet_count: int = 0
    retransmission_count: int = 0
    is_syn_seen: bool = False
    is_fin_seen: bool = False
    is_rst_seen: bool = False

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "client": f"{self.client_ip}:{self.client_port}",
            "server": f"{self.server_ip}:{self.server_port}",
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration, 4),
            "packet_count": self.packet_count,
            "client_bytes": len(self.client_payload),
            "server_bytes": len(self.server_payload),
            "retransmission_count": self.retransmission_count,
            "is_syn_seen": self.is_syn_seen,
            "is_fin_seen": self.is_fin_seen,
            "is_rst_seen": self.is_rst_seen,
        }


@dataclass
class StarttlsNegotiation:
    """Detailed record of STARTTLS protocol negotiation and cryptographic transition."""
    status: StarttlsStatus = StarttlsStatus.NOT_ATTEMPTED
    advertised_by_server: bool = False
    requested_by_client: bool = False
    accepted_by_server: bool = False
    client_command: Optional[str] = None
    server_response: Optional[str] = None
    command_timestamp: Optional[float] = None
    response_timestamp: Optional[float] = None
    client_tls_byte_offset: Optional[int] = None
    server_tls_byte_offset: Optional[int] = None
    downgrade_detected: bool = False
    credentials_leaked_in_clear: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "advertised_by_server": self.advertised_by_server,
            "requested_by_client": self.requested_by_client,
            "accepted_by_server": self.accepted_by_server,
            "client_command": self.client_command,
            "server_response": self.server_response,
            "command_timestamp": self.command_timestamp,
            "response_timestamp": self.response_timestamp,
            "client_tls_byte_offset": self.client_tls_byte_offset,
            "server_tls_byte_offset": self.server_tls_byte_offset,
            "downgrade_detected": self.downgrade_detected,
            "credentials_leaked_in_clear": self.credentials_leaked_in_clear,
        }


@dataclass
class EmailSession:
    """
    Consolidated email session identified from PCAP.
    This is the core object shared with the entire team.
    """
    session_id: str
    protocol: ProtocolType
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    start_time: float
    end_time: float
    stream_id: str
    packet_count: int
    
    # Plaintext conversation transcript before TLS negotiation
    plaintext_commands: List[str] = field(default_factory=list)
    plaintext_responses: List[str] = field(default_factory=list)
    
    # STARTTLS detection & state
    starttls: StarttlsNegotiation = field(default_factory=StarttlsNegotiation)
    
    # Flag indicating whether this session transitions into or is direct TLS
    is_tls_encrypted: bool = False
    
    # Binary TLS payload handed off directly to Role #2 (TLS/Crypto Engineer)
    # Starts exactly with TLS Record Header: 0x16 0x03 ... (Handshake / ClientHello)
    tls_client_payload: bytes = b""
    tls_server_payload: bytes = b""
    
    # Security alerts detected during parsing (stripping, weak auth, downgrade, etc.)
    security_alerts: List[SecurityAlert] = field(default_factory=list)
    
    # Additional protocol metadata
    banner: Optional[str] = None
    client_hello_detected: bool = False
    server_hello_detected: bool = False

    def to_dict(self, include_raw_bytes: bool = False) -> Dict[str, Any]:
        result = {
            "session_id": self.session_id,
            "protocol": self.protocol.value,
            "client": f"{self.client_ip}:{self.client_port}",
            "server": f"{self.server_ip}:{self.server_port}",
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(max(0.0, self.end_time - self.start_time), 3),
            "packet_count": self.packet_count,
            "stream_id": self.stream_id,
            "is_tls_encrypted": self.is_tls_encrypted,
            "banner": self.banner,
            "starttls": self.starttls.to_dict(),
            "plaintext_commands_count": len(self.plaintext_commands),
            "plaintext_commands_sample": self.plaintext_commands[:10],
            "security_alerts": [alert.to_dict() for alert in self.security_alerts],
            "tls_client_bytes_available": len(self.tls_client_payload),
            "tls_server_bytes_available": len(self.tls_server_payload),
            "client_hello_detected": self.client_hello_detected,
            "server_hello_detected": self.server_hello_detected,
        }
        if include_raw_bytes:
            result["tls_client_payload_hex"] = self.tls_client_payload.hex()
            result["tls_server_payload_hex"] = self.tls_server_payload.hex()
        return result


@dataclass
class PcapParseResult:
    """Master result container returned by the parser."""
    filepath: str
    parse_duration_seconds: float
    total_packets_read: int
    tcp_packets_processed: int
    total_streams_reassembled: int
    email_sessions: List[EmailSession] = field(default_factory=list)
    all_security_alerts: List[SecurityAlert] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        protocols_count = {}
        for s in self.email_sessions:
            p = s.protocol.value
            protocols_count[p] = protocols_count.get(p, 0) + 1

        alert_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for a in self.all_security_alerts:
            sev = a.severity.value
            alert_counts[sev] = alert_counts.get(sev, 0) + 1

        return {
            "filepath": self.filepath,
            "parse_duration_seconds": round(self.parse_duration_seconds, 4),
            "total_packets": self.total_packets_read,
            "tcp_packets": self.tcp_packets_processed,
            "total_streams": self.total_streams_reassembled,
            "email_sessions_count": len(self.email_sessions),
            "protocols_detected": protocols_count,
            "security_alert_counts": alert_counts,
        }

    def to_dict(self, include_raw_bytes: bool = False) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "sessions": [s.to_dict(include_raw_bytes=include_raw_bytes) for s in self.email_sessions],
            "security_alerts": [a.to_dict() for a in self.all_security_alerts],
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
