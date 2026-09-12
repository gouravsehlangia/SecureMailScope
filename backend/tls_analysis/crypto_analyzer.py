"""
SecureMailScope - Cryptographic & Forward Secrecy Analyzer (Stage 2)
Evaluates TLS versions, cipher suites, key exchange mechanisms, validates
Perfect Forward Secrecy (PFS), detects STARTTLS stripping, and handles TLS 1.3 keylog decryption.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from .models import (
    TLSAnalysisResult, SecurityRating, VisibilityStatus,
    ClientHelloData, ServerHelloData, CertificateHandshakeData,
    Stage1SessionInput
)
from .cipher_suites import CipherSuiteDB, WEAK_KEYWORDS
from .handshake_parser import (
    TLSHandshakeParser,
    HANDSHAKE_TYPE_CLIENT_HELLO,
    HANDSHAKE_TYPE_SERVER_HELLO,
    HANDSHAKE_TYPE_CERTIFICATE,
    HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
    CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_HANDSHAKE
)
from .keylog_manager import SSLKeyLogManager

logger = logging.getLogger("securemailscope.analyzer")


class CryptoAnalyzer:
    """
    Forensic cryptographic evaluation engine for SecureMailScope Stage 2.
    """

    DEPRECATED_VERSIONS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
    MODERN_VERSIONS = {"TLS 1.2", "TLS 1.3"}

    @classmethod
    def analyze_session(
        cls,
        session_input: Union[Stage1SessionInput, Dict[str, Any], bytes],
        keylog_manager: Optional[SSLKeyLogManager] = None
    ) -> TLSAnalysisResult:
        """
        Primary Stage 2 entrypoint. Ingests Stage 1 stream data or session dict,
        reconstructs TLS handshake, extracts certificates, and evaluates crypto posture.
        """
        # 1. Normalize input contract
        if isinstance(session_input, bytes):
            session = Stage1SessionInput(session_id="stream_direct", stream_bytes=session_input)
        elif isinstance(session_input, dict):
            session = Stage1SessionInput(
                session_id=session_input.get("session_id", "sess_unknown"),
                stream_id=session_input.get("stream_id", ""),
                protocol=session_input.get("protocol", "SMTP"),
                client_ip=session_input.get("client_ip", ""),
                server_ip=session_input.get("server_ip", ""),
                client_port=session_input.get("client_port", 0),
                server_port=session_input.get("server_port", 0),
                stream_bytes=session_input.get("stream_bytes") or session_input.get("raw_bytes") or b"",
                starttls_detected=session_input.get("starttls_detected", False),
                starttls_offered=session_input.get("starttls_offered", False)
            )
            # If session dict already has pre-parsed fields (e.g. from mock_sessions.json)
            if not session.stream_bytes and "cipher_suite" in session_input:
                return cls.evaluate_crypto(
                    tls_version=session_input.get("tls_version", "TLS 1.2"),
                    cipher_suite=session_input.get("cipher_suite", ""),
                    key_exchange_group=session_input.get("key_exchange_group"),
                    sni=session_input.get("sni"),
                    session_id=session.session_id,
                    stream_id=session.stream_id,
                    protocol=session.protocol
                )
        else:
            session = session_input

        # 2. Check for STARTTLS transition and stripping attack
        starttls_used, starttls_stripped, detected_proto = TLSHandshakeParser.check_starttls_transition(session.stream_bytes)
        protocol = session.protocol or detected_proto or "SMTP"

        # 3. Locate TLS records
        records = TLSHandshakeParser.find_tls_records_in_stream(session.stream_bytes)

        # 4. Handle pure plaintext session or active STARTTLS stripping
        if not records:
            rule_violations = []
            if starttls_stripped or session.starttls_offered:
                rule_violations.append(
                    "CRITICAL: STARTTLS Stripping / Downgrade Attack Detected — Plaintext email credentials transmitted despite server TLS capability"
                )
            else:
                rule_violations.append("Unencrypted plaintext email communication — vulnerable to eavesdropping and tampering")

            return TLSAnalysisResult(
                session_id=session.session_id,
                stream_id=session.stream_id,
                protocol=protocol,
                client_ip=session.client_ip,
                server_ip=session.server_ip,
                client_port=session.client_port,
                server_port=session.server_port,
                tls_present=False,
                starttls_used=starttls_used,
                starttls_stripped=starttls_stripped,
                security_rating=SecurityRating.INSECURE,
                visibility=VisibilityStatus.PLAINTEXT_NO_TLS,
                rule_violations=rule_violations,
                warnings=["Traffic sent in the clear; no TLS record frames found."]
            )

        # 5. Parse Handshake Messages across records
        client_hello: Optional[ClientHelloData] = None
        server_hello: Optional[ServerHelloData] = None
        raw_der_certs: List[bytes] = []
        raw_base64_certs: List[str] = []
        detected_group: Optional[str] = None
        encrypted_records: List[bytes] = []

        for content_type, version, payload in records:
            if content_type == CONTENT_TYPE_HANDSHAKE:
                # De-coalesce multi-handshake records (e.g. ServerHello + Certificate + ServerKeyExchange)
                messages = TLSHandshakeParser.parse_all_handshake_messages(payload)
                for msg_type, msg_body in messages:
                    if msg_type == HANDSHAKE_TYPE_CLIENT_HELLO and not client_hello:
                        client_hello = TLSHandshakeParser.parse_client_hello(msg_body, version)
                    elif msg_type == HANDSHAKE_TYPE_SERVER_HELLO and not server_hello:
                        server_hello = TLSHandshakeParser.parse_server_hello(msg_body, version)
                    elif msg_type == HANDSHAKE_TYPE_CERTIFICATE:
                        is_tls13 = server_hello and "1.3" in server_hello.negotiated_version
                        cert_data = TLSHandshakeParser.parse_certificate_message(msg_body, is_tls13=bool(is_tls13))
                        raw_der_certs.extend(cert_data.raw_der_certs)
                        raw_base64_certs.extend(cert_data.raw_base64_certs)
                    elif msg_type == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
                        kx_info = TLSHandshakeParser.parse_server_key_exchange(msg_body)
                        if kx_info and "group" in kx_info:
                            detected_group = kx_info["group"]

            elif content_type == CONTENT_TYPE_APPLICATION_DATA:
                # In TLS 1.3, encrypted handshake records are wrapped in Application Data (0x17)
                encrypted_records.append(payload)

        # Fallback if server_hello was not found in handshake frames
        negotiated_version = server_hello.negotiated_version if server_hello else "TLS 1.2"
        cipher_code = server_hello.selected_cipher_code if server_hello else 0x0000
        cipher_name = server_hello.selected_cipher_name if server_hello else "UNKNOWN_CIPHER"
        group = (server_hello.selected_group if server_hello and server_hello.selected_group else detected_group)

        # 6. TLS 1.3 Keylog Decryption Handling
        keylog = keylog_manager or SSLKeyLogManager()
        is_tls13 = "1.3" in negotiated_version
        visibility = VisibilityStatus.FULL
        keylog_applied = False
        warnings = []

        if is_tls13:
            client_random = client_hello.random if client_hello else b""
            if keylog.has_handshake_secret(client_random):
                # Attempt decryption of encrypted handshake records
                for enc_record in encrypted_records:
                    success, plaintext, status_msg = keylog.decrypt_tls13_record(
                        enc_record, client_random, cipher_code=cipher_code
                    )
                    if success and plaintext:
                        keylog_applied = True
                        visibility = VisibilityStatus.DECRYPTED_VIA_KEYLOG
                        # Parse decrypted handshake messages
                        dec_messages = TLSHandshakeParser.parse_all_handshake_messages(plaintext)
                        for msg_type, msg_body in dec_messages:
                            if msg_type == HANDSHAKE_TYPE_CERTIFICATE:
                                cert_data = TLSHandshakeParser.parse_certificate_message(msg_body, is_tls13=True)
                                raw_der_certs.extend(cert_data.raw_der_certs)
                                raw_base64_certs.extend(cert_data.raw_base64_certs)
                        break
                if not keylog_applied:
                    warnings.append("Matching entry found in SSLKEYLOGFILE, but payload decryption could not complete.")
                    visibility = VisibilityStatus.HANDSHAKE_ONLY_TLS13
            else:
                visibility = VisibilityStatus.HANDSHAKE_ONLY_TLS13
                warnings.append(
                    "TLS 1.3 wire capture without SSLKEYLOGFILE: Certificate handshake messages are encrypted on the wire; handshake metadata extracted at full confidence."
                )

        # 7. Evaluate cryptographic posture and PFS
        result = cls.evaluate_crypto(
            tls_version=negotiated_version,
            cipher_suite=cipher_name,
            key_exchange_group=group,
            sni=client_hello.sni if client_hello else None,
            client_supported_versions=client_hello.supported_versions if client_hello else None,
            session_id=session.session_id,
            stream_id=session.stream_id,
            protocol=protocol,
            client_ip=session.client_ip,
            server_ip=session.server_ip,
            client_port=session.client_port,
            server_port=session.server_port
        )

        result.tls_present = True
        result.starttls_used = starttls_used or session.starttls_detected
        result.starttls_stripped = starttls_stripped
        result.visibility = visibility
        result.keylog_applied = keylog_applied
        result.raw_certificates = raw_base64_certs
        result.alpn = client_hello.alpn_protocols if client_hello else []
        result.warnings.extend(warnings)

        return result

    @classmethod
    def evaluate_crypto(
        cls,
        tls_version: str,
        cipher_suite: str,
        key_exchange_group: Optional[str] = None,
        sni: Optional[str] = None,
        client_supported_versions: Optional[List[str]] = None,
        session_id: str = "",
        stream_id: str = "",
        protocol: str = "SMTP",
        client_ip: str = "",
        server_ip: str = "",
        client_port: int = 0,
        server_port: int = 0
    ) -> TLSAnalysisResult:
        """
        Evaluates cryptographic posture, PFS, and security rating.
        """
        cipher_info = CipherSuiteDB.classify_cipher(cipher_suite)

        rule_violations: List[str] = []
        warnings: List[str] = []

        # Version checks
        is_deprecated_version = tls_version in cls.DEPRECATED_VERSIONS
        if is_deprecated_version:
            rule_violations.append(f"Deprecated TLS version ({tls_version}) — vulnerable to POODLE/BEAST")

        # Forward Secrecy Check
        forward_secrecy = cipher_info.forward_secrecy
        key_exchange = cipher_info.key_exchange
        if key_exchange_group:
            key_exchange = f"{key_exchange} ({key_exchange_group})"

        if not forward_secrecy:
            rule_violations.append(
                "Lack of Perfect Forward Secrecy (PFS) — static RSA key exchange allows retroactive decryption if private key is compromised"
            )

        # Anonymous Key Exchange (MITM)
        is_anonymous = "ANON" in cipher_info.auth.upper() or "ANON" in cipher_suite.upper()
        if is_anonymous:
            rule_violations.append(
                "Anonymous key exchange detected (DH_anon/ECDH_anon) — vulnerable to active Man-in-the-Middle (MITM) attacks"
            )

        # Insecure Ciphers
        upper_cipher = cipher_suite.upper()
        if "RC4" in upper_cipher:
            rule_violations.append("Insecure RC4 stream cipher detected — vulnerable to statistical bias exploits")
        if "3DES" in upper_cipher or "DES-CBC3" in upper_cipher:
            rule_violations.append("3DES cipher detected — vulnerable to SWEET32 64-bit block collision attack")
        if "DES" in upper_cipher and "3DES" not in upper_cipher and "DES-CBC3" not in upper_cipher:
            rule_violations.append("Single DES cipher detected — trivially breakable with 56-bit key")
        if "EXPORT" in upper_cipher:
            rule_violations.append("Insecure EXPORT-grade cryptography detected — vulnerable to FREAK/Logjam attacks")
        if "NULL" in upper_cipher:
            rule_violations.append("Insecure NULL cipher suite detected — data transmitted in plaintext with zero encryption!")

        # MAC Checks
        if cipher_info.mac == "MD5":
            rule_violations.append("Broken MD5 message authentication code detected — collision vulnerable")
        elif cipher_info.mac == "SHA1":
            warnings.append("Legacy SHA-1 HMAC in use — recommend upgrading to SHA-256 or AEAD")

        # Overall Security Rating
        has_insecure = (
            is_deprecated_version or is_anonymous or 
            cipher_info.rating == SecurityRating.INSECURE or
            any(kw in upper_cipher for kw in ["RC4", "3DES", "EXPORT", "NULL"]) or
            cipher_info.mac == "MD5"
        )

        if has_insecure:
            rating = SecurityRating.INSECURE
        elif not forward_secrecy or cipher_info.rating == SecurityRating.WEAK:
            rating = SecurityRating.WEAK
        elif cipher_info.mac == "SHA1" or "CBC" in cipher_info.encryption:
            rating = SecurityRating.ACCEPTABLE
        else:
            rating = SecurityRating.SECURE

        details = {
            "key_exchange_raw": cipher_info.key_exchange,
            "authentication": cipher_info.auth,
            "key_exchange_group": key_exchange_group,
            "pfs_guaranteed": forward_secrecy,
            "symmetric_encryption": cipher_info.encryption,
            "key_bits": cipher_info.key_bits,
            "mac_algorithm": cipher_info.mac,
            "is_aead": cipher_info.mac == "AEAD",
            "rfc_description": cipher_info.description,
            "client_supported_versions": client_supported_versions or []
        }

        return TLSAnalysisResult(
            session_id=session_id,
            stream_id=stream_id,
            protocol=protocol,
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=client_port,
            server_port=server_port,
            tls_present=True,
            tls_version=tls_version,
            cipher_suite=cipher_info.name,
            cipher_code=f"0x{cipher_info.hex_code:04X}" if cipher_info.hex_code else None,
            key_exchange=key_exchange,
            key_exchange_group=key_exchange_group,
            forward_secrecy=forward_secrecy,
            security_rating=rating,
            encryption_algorithm=cipher_info.encryption,
            key_length=cipher_info.key_bits,
            mac_algorithm=cipher_info.mac,
            is_aead=cipher_info.mac == "AEAD",
            is_anonymous=is_anonymous,
            sni=sni,
            rule_violations=rule_violations,
            warnings=warnings,
            details=details
        )


def analyze_session_tls(session: Dict[str, Any], keylog_manager: Optional[SSLKeyLogManager] = None) -> Dict[str, Any]:
    """
    Standard pipeline adapter for pipeline.py, risk_scoring.py, and Stage 1 handoffs.
    Ingests session dictionary and updates it with Stage 2 outputs.
    """
    res = CryptoAnalyzer.analyze_session(session, keylog_manager=keylog_manager)
    output = session.copy()
    output.update(res.to_dict())
    return output
