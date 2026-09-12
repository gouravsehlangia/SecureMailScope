"""
backend.parser
~~~~~~~~~~~~~~
Smart India Hackathon - Email Security Traffic Parser (Role #1)
Provides PCAP/PCAPNG ingestion, TCP stream reassembly, protocol identification
(SMTP/IMAP/POP3), and STARTTLS detection & downgrade attack auditing.
"""

from .models import (
    ProtocolType,
    StarttlsStatus,
    AlertSeverity,
    SecurityAlert,
    PacketRecord,
    TcpStream,
    StreamEvent,
    StarttlsNegotiation,
    EmailSession,
    PcapParseResult,
)
from .pcap_reader import read_pcap, PurePythonPcapReader, PcapReaderError
from .reassembler import TcpReassemblyEngine, DirectionalReassembler
from .protocol_detector import ProtocolDetector
from .starttls_detector import StarttlsDetector
from .extractor import (
    EmailPcapParser,
    parse_pcap,
    parse_pcap_to_dict,
    extract_tls_payloads_for_crypto_lead,
)

__all__ = [
    "ProtocolType",
    "StarttlsStatus",
    "AlertSeverity",
    "SecurityAlert",
    "PacketRecord",
    "TcpStream",
    "StreamEvent",
    "StarttlsNegotiation",
    "EmailSession",
    "PcapParseResult",
    "read_pcap",
    "PurePythonPcapReader",
    "PcapReaderError",
    "TcpReassemblyEngine",
    "DirectionalReassembler",
    "ProtocolDetector",
    "StarttlsDetector",
    "EmailPcapParser",
    "parse_pcap",
    "parse_pcap_to_dict",
    "extract_tls_payloads_for_crypto_lead",
]
