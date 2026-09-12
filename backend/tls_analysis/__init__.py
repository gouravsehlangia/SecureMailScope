"""
SecureMailScope - TLS / Crypto Analysis Module (Stage 2)
Provides TLS handshake reconstruction, cipher suite & version extraction,
Key Exchange & Perfect Forward Secrecy (PFS) verification, raw X.509 certificate extraction,
STARTTLS stripping attack detection, and SSLKEYLOGFILE decryption.
"""

from .models import (
    SecurityRating,
    VisibilityStatus,
    KeyExchangeAlgorithm,
    CipherSuiteInfo,
    ClientHelloData,
    ServerHelloData,
    CertificateHandshakeData,
    Stage1SessionInput,
    TLSAnalysisResult,
)
from .cipher_suites import CipherSuiteDB
from .handshake_parser import (
    TLSHandshakeParser,
    format_tls_version,
    HANDSHAKE_TYPE_CLIENT_HELLO,
    HANDSHAKE_TYPE_SERVER_HELLO,
    HANDSHAKE_TYPE_CERTIFICATE,
    HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
)
from .keylog_manager import SSLKeyLogManager
from .crypto_analyzer import CryptoAnalyzer, analyze_session_tls

__all__ = [
    "SecurityRating",
    "VisibilityStatus",
    "KeyExchangeAlgorithm",
    "CipherSuiteInfo",
    "ClientHelloData",
    "ServerHelloData",
    "CertificateHandshakeData",
    "Stage1SessionInput",
    "TLSAnalysisResult",
    "CipherSuiteDB",
    "TLSHandshakeParser",
    "format_tls_version",
    "SSLKeyLogManager",
    "CryptoAnalyzer",
    "analyze_session_tls",
]
