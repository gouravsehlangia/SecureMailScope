"""
SecureMailScope — TLS / Crypto Analysis Models  (Stage 2)
=========================================================
Defines every structured data contract used by Stage 2 and consumed by
Stage 3 (Certificate Engineer) and Stage 4 (Risk / AI Engine).

Enums
-----
  SecurityRating        — SECURE / ACCEPTABLE / WEAK / INSECURE
  VisibilityStatus      — full / decrypted_via_keylog / handshake_only_tls13_encrypted / plaintext_no_tls
  KeyExchangeAlgorithm  — ECDHE / DHE / X25519 / RSA / DH / DH_anon / ECDH_anon / PSK / UNKNOWN

Dataclasses (Stage 1 → Stage 2 handoff)
----------------------------------------
  Stage1SessionInput    — per-TCP-stream object provided by Stage 1 PCAP parser

Dataclasses (Stage 2 internal parsing)
---------------------------------------
  CipherSuiteInfo       — fully resolved properties of one cipher suite
  ClientHelloData       — parsed TLS ClientHello fields
  ServerHelloData       — parsed TLS ServerHello fields
  CertificateHandshakeData  — raw DER bytes + Base64 certs for Stage 3

Dataclasses (Stage 2 → Stage 3 / Stage 4 handoff)
---------------------------------------------------
  TLSAnalysisResult     — canonical Stage 2 output, serialised via .to_dict()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class SecurityRating(str, Enum):
    """Overall cryptographic security posture of a TLS session."""
    SECURE     = "SECURE"      # TLS 1.3 or TLS 1.2 with PFS + AEAD cipher
    ACCEPTABLE = "ACCEPTABLE"  # TLS 1.2 with PFS but CBC mode or SHA-1 MAC
    WEAK       = "WEAK"        # Missing PFS (static RSA) or weak key length
    INSECURE   = "INSECURE"    # Plaintext, deprecated TLS (≤1.1), RC4, 3DES,
                               # DES, NULL, EXPORT, MD5, or anonymous key exchange


class VisibilityStatus(str, Enum):
    """How much of the handshake could be reconstructed from the capture."""
    FULL                  = "full"
    # Full plaintext TLS 1.0–1.2 handshake, or TLS 1.3 decrypted via keylog.

    DECRYPTED_VIA_KEYLOG  = "decrypted_via_keylog"
    # TLS 1.3 encrypted Certificate record successfully decrypted using SSLKEYLOGFILE.

    HANDSHAKE_ONLY_TLS13  = "handshake_only_tls13_encrypted"
    # TLS 1.3 wire capture without keylog: ServerHello visible, Certificate encrypted.

    PLAINTEXT_NO_TLS      = "plaintext_no_tls"
    # No TLS negotiation found; session is in the clear.


class KeyExchangeAlgorithm(str, Enum):
    """Key exchange mechanism used in TLS negotiation."""
    ECDHE    = "ECDHE"       # Ephemeral Elliptic-Curve Diffie-Hellman (PFS ✅)
    DHE      = "DHE"         # Ephemeral finite-field Diffie-Hellman (PFS ✅)
    X25519   = "X25519"      # Modern ECDHE curve (TLS 1.3, PFS ✅)
    RSA      = "RSA"         # Static RSA key transport (NO forward secrecy ❌)
    DH       = "DH"          # Static finite-field DH (NO forward secrecy ❌)
    DH_ANON  = "DH_anon"     # Anonymous DH — NO authentication (MITM ❌)
    ECDH_ANON = "ECDH_anon"  # Anonymous ECDH — NO authentication (MITM ❌)
    PSK      = "PSK"         # Pre-shared key
    UNKNOWN  = "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 → Stage 2  (input contract)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Stage1SessionInput:
    """
    Per-TCP-stream object handed from Stage 1 (PCAP Parser) to Stage 2.

    Fields
    ------
    session_id        : Unique identifier for this stream/session.
    stream_id         : Human-readable TCP 5-tuple label (e.g. "tcp_10.0.0.1:587").
    protocol          : Application protocol detected from port/content
                        ("SMTP" | "SMTPS" | "IMAP" | "IMAPS" | "POP3" | "POP3S").
    client_ip / server_ip / client_port / server_port : Layer-3/4 metadata.
    stream_bytes      : Concatenated bidirectional TCP payload (server banner first,
                        then interleaved client/server data).
    starttls_detected : Stage 1 detected a successful STARTTLS upgrade.
    starttls_offered  : Server capability banner advertised STARTTLS/STLS.
    """
    session_id:        str
    stream_id:         str   = ""
    protocol:          str   = "SMTP"
    client_ip:         str   = ""
    server_ip:         str   = ""
    client_port:       int   = 0
    server_port:       int   = 0
    stream_bytes:      bytes = b""
    starttls_detected: bool  = False
    starttls_offered:  bool  = False


# ─────────────────────────────────────────────────────────────────────────────
# Internal parsing dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CipherSuiteInfo:
    """Fully resolved cryptographic properties of one TLS cipher suite."""
    hex_code:        int
    name:            str
    key_exchange:    str
    auth:            str
    encryption:      str
    key_bits:        int
    mac:             str
    forward_secrecy: bool
    rating:          SecurityRating
    description:     str = ""


@dataclass
class ClientHelloData:
    """Fields parsed from a TLS ClientHello handshake message."""
    record_version:      str
    client_version:      str
    random:              bytes
    session_id:          bytes
    cipher_suites:       List[str]  = field(default_factory=list)
    cipher_codes:        List[int]  = field(default_factory=list)
    compression_methods: List[int]  = field(default_factory=list)
    sni:                 Optional[str]        = None
    supported_versions:  List[str]  = field(default_factory=list)
    supported_groups:    List[str]  = field(default_factory=list)
    alpn_protocols:      List[str]  = field(default_factory=list)
    has_key_share:       bool = False
    raw_length:          int  = 0


@dataclass
class ServerHelloData:
    """Fields parsed from a TLS ServerHello handshake message."""
    record_version:      str
    server_version:      str
    negotiated_version:  str
    random:              bytes
    session_id:          bytes
    selected_cipher_code: int
    selected_cipher_name: str
    selected_compression: int
    selected_group:      Optional[str] = None
    raw_length:          int = 0


@dataclass
class CertificateHandshakeData:
    """
    Raw X.509 certificate data extracted from TLS Certificate (0x0B) message.
    Passed verbatim to Stage 3 (Certificate Engineer).
    """
    cert_count:         int         = 0
    raw_der_certs:      List[bytes] = field(default_factory=list)
    raw_base64_certs:   List[str]   = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 → Stage 3 / Stage 4  (output contract)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TLSAnalysisResult:
    """
    Canonical Stage 2 output document.

    Consumed by:
      - Stage 3 (Certificate Engineer): reads `raw_certificates` (Base64 DER list)
      - Stage 4 (Risk / AI Engine)    : reads all crypto posture fields +
                                        `rule_violations` + `security_rating`
      - Stage 6 (API / Reports)       : serialised via `to_dict()`
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    session_id:   str
    stream_id:    str = ""
    protocol:     str = "SMTP"
    client_ip:    str = ""
    server_ip:    str = ""
    client_port:  int = 0
    server_port:  int = 0

    # ── TLS / STARTTLS presence ───────────────────────────────────────────────
    tls_present:       bool = False
    starttls_used:     bool = False
    starttls_stripped: bool = False

    # ── Negotiated TLS parameters ─────────────────────────────────────────────
    tls_version:        Optional[str] = None   # e.g. "TLS 1.3"
    cipher_suite:       Optional[str] = None   # e.g. "ECDHE-RSA-AES128-GCM-SHA256"
    cipher_code:        Optional[str] = None   # e.g. "0xC02F"
    key_exchange:       Optional[str] = None   # e.g. "ECDHE (secp256r1)"
    key_exchange_group: Optional[str] = None   # e.g. "secp256r1 (NIST P-256)"
    forward_secrecy:    bool = False

    # ── Cryptographic properties ──────────────────────────────────────────────
    security_rating:      SecurityRating = SecurityRating.INSECURE
    encryption_algorithm: str = "NONE"
    key_length:           int = 0
    mac_algorithm:        str = "NONE"
    is_aead:              bool = False
    is_anonymous:         bool = False

    # ── Extension / application layer ─────────────────────────────────────────
    sni:  Optional[str] = None
    alpn: List[str]     = field(default_factory=list)

    # ── Visibility / keylog ───────────────────────────────────────────────────
    visibility:     VisibilityStatus = VisibilityStatus.PLAINTEXT_NO_TLS
    keylog_applied: bool = False

    # ── Certificate handoff (Stage 3) ─────────────────────────────────────────
    raw_certificates: List[str] = field(default_factory=list)
    # Base64-encoded DER-format certificates in chain order.

    # ── Violations, warnings, diagnostics ────────────────────────────────────
    rule_violations: List[str]       = field(default_factory=list)
    warnings:        List[str]       = field(default_factory=list)
    details:         Dict[str, Any]  = field(default_factory=dict)

    # ─────────────────────────────────────────────────────────────────────────
    # Serialisation helpers
    # ─────────────────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialises to a flat dict following the SecureMailScope schema.
        Used by Stage 6 (API + JSON/HTML/PDF report generators).
        """
        return {
            "session_id":           self.session_id,
            "stream_id":            self.stream_id,
            "protocol":             self.protocol,
            "client_ip":            self.client_ip,
            "server_ip":            self.server_ip,
            "client_port":          self.client_port,
            "server_port":          self.server_port,
            "tls_present":          self.tls_present,
            "starttls_used":        self.starttls_used,
            "starttls_stripped":    self.starttls_stripped,
            "tls_version":          self.tls_version,
            "cipher_suite":         self.cipher_suite,
            "cipher_code":          self.cipher_code,
            "key_exchange":         self.key_exchange,
            "key_exchange_group":   self.key_exchange_group,
            "forward_secrecy":      self.forward_secrecy,
            "security_rating":      self.security_rating.value,
            "encryption_algorithm": self.encryption_algorithm,
            "key_length":           self.key_length,
            "mac_algorithm":        self.mac_algorithm,
            "is_aead":              self.is_aead,
            "is_anonymous":         self.is_anonymous,
            "sni":                  self.sni,
            "alpn":                 self.alpn,
            "visibility":           self.visibility.value,
            "keylog_applied":       self.keylog_applied,
            "raw_certificates":     self.raw_certificates,
            "rule_violations":      self.rule_violations,
            "warnings":             self.warnings,
            "details":              self.details,
        }

    def to_session_dict(self) -> Dict[str, Any]:
        """
        Backward-compatible adapter for pipeline.py / risk_scoring.py.
        Merges Stage 2 output fields on top of the original session dict.
        """
        d = self.to_dict()
        # Guarantee non-null strings for downstream consumers
        d["tls_version"]  = self.tls_version  or ""
        d["cipher_suite"] = self.cipher_suite  or ""
        d["key_exchange"] = self.key_exchange  or ""
        d["forward_secrecy"] = self.forward_secrecy
        return d

    def severity_label(self) -> str:
        """Returns a short human-readable severity label for UI badges."""
        return {
            SecurityRating.SECURE:     "🟢 SECURE",
            SecurityRating.ACCEPTABLE: "🟡 ACCEPTABLE",
            SecurityRating.WEAK:       "🟠 WEAK",
            SecurityRating.INSECURE:   "🔴 INSECURE",
        }.get(self.security_rating, "⚪ UNKNOWN")

    def is_pfs_guaranteed(self) -> bool:
        """Convenience: True when forward secrecy is confirmed and version is modern."""
        return (
            self.forward_secrecy
            and self.tls_version in {"TLS 1.2", "TLS 1.3"}
        )

    def has_critical_violations(self) -> bool:
        """True when any rule violation contains the word CRITICAL."""
        return any("CRITICAL" in v.upper() for v in self.rule_violations)
