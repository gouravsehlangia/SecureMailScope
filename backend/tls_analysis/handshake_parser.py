"""
SecureMailScope - TLS Handshake Parser (Stage 2)
High-performance parser for TLS Record Layer, Handshake Messages,
X.509 Certificate extraction, and STARTTLS protocol upgrades.
"""

import base64
import struct
import logging
from typing import Dict, List, Optional, Tuple, Any
from .models import (
    ClientHelloData, ServerHelloData, CertificateHandshakeData,
    VisibilityStatus
)
from .cipher_suites import CipherSuiteDB

logger = logging.getLogger("securemailscope.parser")

# TLS Content Types
CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14
CONTENT_TYPE_ALERT = 0x15
CONTENT_TYPE_HANDSHAKE = 0x16
CONTENT_TYPE_APPLICATION_DATA = 0x17

# TLS Handshake Types
HANDSHAKE_TYPE_HELLO_REQUEST = 0x00
HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
HANDSHAKE_TYPE_SERVER_HELLO = 0x02
HANDSHAKE_TYPE_NEW_SESSION_TICKET = 0x04
HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 0x08
HANDSHAKE_TYPE_CERTIFICATE = 0x0B
HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 0x0C
HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 0x0D
HANDSHAKE_TYPE_SERVER_HELLO_DONE = 0x0E
HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0F
HANDSHAKE_TYPE_FINISHED = 0x14

# Named Groups / Elliptic Curves
NAMED_GROUPS: Dict[int, str] = {
    0x0017: "secp256r1 (NIST P-256)",
    0x0018: "secp384r1 (NIST P-384)",
    0x0019: "secp521r1 (NIST P-521)",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
}

TLS_VERSION_MAP: Dict[int, str] = {
    0x0200: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def format_tls_version(version_int: int) -> str:
    """Converts 16-bit TLS version to human-readable string."""
    return TLS_VERSION_MAP.get(version_int, f"TLS Unknown (0x{version_int:04X})")


class TLSHandshakeParser:
    """
    Forensic parser for TLS records, multi-message handshake payloads,
    raw X.509 certificate extraction, and STARTTLS protocol upgrades.
    """

    @classmethod
    def find_tls_records_in_stream(cls, data: bytes) -> List[Tuple[int, int, bytes]]:
        """
        Scans a TCP reassembled stream payload to locate TLS record frames.
        Returns list of tuples: (content_type, version, record_payload).
        Optimized with bytes.find() for multi-megabyte stream efficiency.
        """
        records = []
        offset = 0
        data_len = len(data)

        while offset + 5 <= data_len:
            # Quick seek to potential TLS record header (0x14..0x17 followed by 0x03)
            # Find next occurrence of TLS Record starting byte
            content_type = data[offset]
            if content_type not in (CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_ALERT, 
                                    CONTENT_TYPE_HANDSHAKE, CONTENT_TYPE_APPLICATION_DATA):
                # Search ahead for next candidate
                cand = min(
                    [pos for ct in (0x14, 0x15, 0x16, 0x17) 
                     if (pos := data.find(bytes([ct, 0x03]), offset)) != -1] or [-1]
                )
                if cand == -1 or cand + 5 > data_len:
                    break
                offset = cand
                content_type = data[offset]

            version_int = struct.unpack("!H", data[offset+1:offset+3])[0]
            if version_int not in TLS_VERSION_MAP and not (0x0300 <= version_int <= 0x0304):
                offset += 1
                continue

            record_len = struct.unpack("!H", data[offset+3:offset+5])[0]
            if offset + 5 + record_len > data_len:
                # Incomplete / fragmented record at stream boundary
                break

            record_payload = data[offset+5 : offset+5+record_len]
            records.append((content_type, version_int, record_payload))
            offset += 5 + record_len

        return records

    @classmethod
    def parse_all_handshake_messages(cls, handshake_payload: bytes) -> List[Tuple[int, bytes]]:
        """
        De-coalesces multiple handshake messages packed within a single TLS record payload.
        Returns a list of tuples: (handshake_type, message_body).
        """
        messages = []
        offset = 0
        payload_len = len(handshake_payload)

        while offset + 4 <= payload_len:
            msg_type = handshake_payload[offset]
            msg_len = int.from_bytes(handshake_payload[offset+1:offset+4], byteorder="big")
            offset += 4

            if offset + msg_len > payload_len:
                # Truncated handshake message, capture remaining
                msg_body = handshake_payload[offset:]
                messages.append((msg_type, msg_body))
                break

            msg_body = handshake_payload[offset : offset + msg_len]
            messages.append((msg_type, msg_body))
            offset += msg_len

        return messages

    @classmethod
    def parse_client_hello(cls, payload: bytes, record_version: int = 0x0303) -> Optional[ClientHelloData]:
        """
        Parses a TLS ClientHello message payload.
        Handles both message-only payloads and full handshake frames.
        """
        if len(payload) < 34:
            return None

        offset = 0
        # Check if first byte is HANDSHAKE_TYPE_CLIENT_HELLO
        if payload[offset] == HANDSHAKE_TYPE_CLIENT_HELLO:
            offset += 1
            if len(payload) < offset + 3:
                return None
            msg_len = int.from_bytes(payload[offset:offset+3], byteorder="big")
            offset += 3

        if len(payload) < offset + 34:
            return None

        # 2-byte client version
        client_version_int = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        # 32-byte random
        random = payload[offset:offset+32]
        offset += 32

        # Session ID
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1
        session_id = payload[offset:offset+session_id_len]
        offset += session_id_len

        # Cipher Suites
        if offset + 2 > len(payload):
            return None
        cipher_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        cipher_codes = []
        cipher_names = []
        cipher_end = offset + cipher_len
        while offset + 2 <= cipher_end and offset + 2 <= len(payload):
            code = struct.unpack("!H", payload[offset:offset+2])[0]
            cipher_codes.append(code)
            info = CipherSuiteDB.classify_cipher(code)
            cipher_names.append(info.name)
            offset += 2
        offset = cipher_end

        # Compression Methods
        if offset >= len(payload):
            comp_methods = [0]
        else:
            comp_len = payload[offset]
            offset += 1
            comp_methods = list(payload[offset:offset+comp_len])
            offset += comp_len

        # Extensions
        sni = None
        supported_versions = []
        supported_groups = []
        alpn_protocols = []
        has_key_share = False

        if offset + 2 <= len(payload):
            ext_total_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
            ext_end = min(offset + ext_total_len, len(payload))

            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                ext_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
                offset += 4
                ext_data = payload[offset:offset+ext_len]
                offset += ext_len

                if ext_type == 0x0000 and len(ext_data) >= 5:
                    sni = cls._parse_sni_extension(ext_data)
                elif ext_type == 0x000A and len(ext_data) >= 2:
                    supported_groups = cls._parse_supported_groups(ext_data)
                elif ext_type == 0x0010 and len(ext_data) >= 2:
                    alpn_protocols = cls._parse_alpn_extension(ext_data)
                elif ext_type == 0x002B and len(ext_data) >= 1:
                    supported_versions = cls._parse_supported_versions(ext_data)
                elif ext_type == 0x0033:
                    has_key_share = True

        return ClientHelloData(
            record_version=format_tls_version(record_version),
            client_version=format_tls_version(client_version_int),
            random=random,
            session_id=session_id,
            cipher_suites=cipher_names,
            cipher_codes=cipher_codes,
            compression_methods=comp_methods,
            sni=sni,
            supported_versions=supported_versions,
            supported_groups=supported_groups,
            alpn_protocols=alpn_protocols,
            has_key_share=has_key_share,
            raw_length=len(payload)
        )

    @classmethod
    def parse_server_hello(cls, payload: bytes, record_version: int = 0x0303) -> Optional[ServerHelloData]:
        """
        Parses a TLS ServerHello message payload.
        Accurately extracts negotiated cipher suite, selected version (including TLS 1.3),
        and chosen key share / curve.
        """
        if len(payload) < 34:
            return None

        offset = 0
        if payload[offset] == HANDSHAKE_TYPE_SERVER_HELLO:
            offset += 1
            if len(payload) < offset + 3:
                return None
            msg_len = int.from_bytes(payload[offset:offset+3], byteorder="big")
            offset += 3

        if len(payload) < offset + 34:
            return None

        server_version_int = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        random = payload[offset:offset+32]
        offset += 32

        session_id_len = payload[offset]
        offset += 1
        session_id = payload[offset:offset+session_id_len]
        offset += session_id_len

        if offset + 2 > len(payload):
            return None

        selected_cipher_code = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2

        selected_compression = payload[offset] if offset < len(payload) else 0
        offset += 1

        cipher_info = CipherSuiteDB.classify_cipher(selected_cipher_code)
        negotiated_version_int = server_version_int
        selected_group = None

        # Extensions in ServerHello
        if offset + 2 <= len(payload):
            ext_total_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
            ext_end = min(offset + ext_total_len, len(payload))

            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                ext_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
                offset += 4
                ext_data = payload[offset:offset+ext_len]
                offset += ext_len

                # Extension 0x002B: Supported Versions (Server selected version for TLS 1.3)
                if ext_type == 0x002B and len(ext_data) >= 2:
                    negotiated_version_int = struct.unpack("!H", ext_data[0:2])[0]

                # Extension 0x0033: Key Share (Server selected key exchange group)
                elif ext_type == 0x0033 and len(ext_data) >= 2:
                    group_code = struct.unpack("!H", ext_data[0:2])[0]
                    selected_group = NAMED_GROUPS.get(group_code, f"Group 0x{group_code:04X}")

        return ServerHelloData(
            record_version=format_tls_version(record_version),
            server_version=format_tls_version(server_version_int),
            negotiated_version=format_tls_version(negotiated_version_int),
            random=random,
            session_id=session_id,
            selected_cipher_code=selected_cipher_code,
            selected_cipher_name=cipher_info.name,
            selected_compression=selected_compression,
            selected_group=selected_group,
            raw_length=len(payload)
        )

    @classmethod
    def parse_certificate_message(cls, payload: bytes, is_tls13: bool = False) -> CertificateHandshakeData:
        """
        Parses TLS Certificate (0x0B) handshake message.
        Extracts raw X.509 DER bytes for all certificates in the chain
        and provides base64-encoded representations for Stage 3 consumption.
        """
        offset = 0
        if len(payload) > 4 and payload[0] == HANDSHAKE_TYPE_CERTIFICATE:
            offset = 4  # Skip type (1 byte) + length (3 bytes)

        der_certs = []

        if is_tls13:
            # TLS 1.3 Certificate structure (RFC 8446 Section 4.4.2):
            # 1 byte: certificate_request_context length
            if offset >= len(payload):
                return CertificateHandshakeData()
            ctx_len = payload[offset]
            offset += 1 + ctx_len
            if offset + 3 > len(payload):
                return CertificateHandshakeData()
            certs_total_len = int.from_bytes(payload[offset:offset+3], byteorder="big")
            offset += 3
            certs_end = min(offset + certs_total_len, len(payload))

            while offset + 3 <= certs_end:
                cert_len = int.from_bytes(payload[offset:offset+3], byteorder="big")
                offset += 3
                if offset + cert_len > certs_end:
                    break
                der_bytes = payload[offset:offset+cert_len]
                der_certs.append(der_bytes)
                offset += cert_len

                # Skip certificate extensions in TLS 1.3
                if offset + 2 <= certs_end:
                    ext_len = struct.unpack("!H", payload[offset:offset+2])[0]
                    offset += 2 + ext_len
        else:
            # TLS 1.0 - 1.2 Certificate structure (RFC 5246 Section 7.4.2):
            # 3 bytes: certificates total length
            if offset + 3 > len(payload):
                return CertificateHandshakeData()
            certs_total_len = int.from_bytes(payload[offset:offset+3], byteorder="big")
            offset += 3
            certs_end = min(offset + certs_total_len, len(payload))

            while offset + 3 <= certs_end:
                cert_len = int.from_bytes(payload[offset:offset+3], byteorder="big")
                offset += 3
                if offset + cert_len > certs_end:
                    break
                der_bytes = payload[offset:offset+cert_len]
                der_certs.append(der_bytes)
                offset += cert_len

        b64_certs = [base64.b64encode(c).decode("ascii") for c in der_certs]
        return CertificateHandshakeData(
            cert_count=len(der_certs),
            raw_der_certs=der_certs,
            raw_base64_certs=b64_certs
        )

    @classmethod
    def parse_server_key_exchange(cls, payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Parses ServerKeyExchange (0x0C) for TLS 1.2 ECDHE/DHE parameters.
        Extracts named curve ID and public key parameters.
        """
        offset = 0
        if len(payload) > 4 and payload[0] == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
            offset = 4

        if offset >= len(payload):
            return None

        curve_type = payload[offset]
        offset += 1

        if curve_type == 0x03:  # named_curve
            if offset + 2 <= len(payload):
                named_curve_id = struct.unpack("!H", payload[offset:offset+2])[0]
                group_name = NAMED_GROUPS.get(named_curve_id, f"Curve_0x{named_curve_id:04X}")
                return {"type": "ECDHE", "curve_id": named_curve_id, "group": group_name}
        elif curve_type in (0x01, 0x02):  # explicit prime / char2
            return {"type": "DHE", "group": "explicit_dh_parameters"}

        return None

    @classmethod
    def check_starttls_transition(cls, raw_stream: bytes) -> Tuple[bool, bool, Optional[str]]:
        """
        Detects STARTTLS command exchange and evaluates whether STARTTLS stripping occurred.
        Returns: (starttls_used: bool, starttls_stripped: bool, matched_protocol: Optional[str])
        """
        # Look for typical SMTP, IMAP, and POP3 upgrade exchanges
        stream_lower = raw_stream[:4096].lower()

        is_smtp = b"smtp" in stream_lower or b"ehlo" in stream_lower or b"helo" in stream_lower
        is_imap = b"imap" in stream_lower or b"capability" in stream_lower
        is_pop3 = b"pop3" in stream_lower or b"+ok" in stream_lower

        proto = "SMTP" if is_smtp else ("IMAP" if is_imap else ("POP3" if is_pop3 else "SMTP"))

        # Capability advertised
        starttls_offered = (
            b"250-starttls" in stream_lower or 
            b"250 starttls" in stream_lower or 
            b"starttls" in stream_lower or 
            b"stls" in stream_lower
        )

        # Successful upgrade command and response
        starttls_negotiated = (
            (b"starttls\r\n" in stream_lower and (b"220" in stream_lower or b"2.0.0" in stream_lower)) or
            (b"stls\r\n" in stream_lower and b"+ok" in stream_lower) or
            (b"starttls" in stream_lower and b"ok begin" in stream_lower)
        )

        # Look for TLS record presence
        has_tls = bool(cls.find_tls_records_in_stream(raw_stream))

        if starttls_negotiated and has_tls:
            return True, False, proto
        
        # Stripping condition: STARTTLS offered in banner, but client sent AUTH / MAIL FROM / PASS in cleartext without TLS!
        is_stripped = False
        if starttls_offered and not has_tls:
            if b"auth login" in stream_lower or b"auth plain" in stream_lower or b"mail from:" in stream_lower or b"pass " in stream_lower:
                is_stripped = True

        return False, is_stripped, proto

    @classmethod
    def _parse_sni_extension(cls, ext_data: bytes) -> Optional[str]:
        try:
            offset = 2
            while offset + 3 <= len(ext_data):
                name_type = ext_data[offset]
                name_len = struct.unpack("!H", ext_data[offset+1:offset+3])[0]
                offset += 3
                if name_type == 0:
                    return ext_data[offset:offset+name_len].decode("utf-8", errors="replace")
                offset += name_len
        except Exception:
            return None
        return None

    @classmethod
    def _parse_supported_groups(cls, ext_data: bytes) -> List[str]:
        groups = []
        try:
            list_len = struct.unpack("!H", ext_data[0:2])[0]
            offset = 2
            while offset + 2 <= len(ext_data) and offset < 2 + list_len:
                group_id = struct.unpack("!H", ext_data[offset:offset+2])[0]
                groups.append(NAMED_GROUPS.get(group_id, f"Group_0x{group_id:04X}"))
                offset += 2
        except Exception:
            pass
        return groups

    @classmethod
    def _parse_alpn_extension(cls, ext_data: bytes) -> List[str]:
        protocols = []
        try:
            list_len = struct.unpack("!H", ext_data[0:2])[0]
            offset = 2
            while offset < 2 + list_len and offset < len(ext_data):
                proto_len = ext_data[offset]
                offset += 1
                proto_name = ext_data[offset:offset+proto_len].decode("ascii", errors="replace")
                protocols.append(proto_name)
                offset += proto_len
        except Exception:
            pass
        return protocols

    @classmethod
    def _parse_supported_versions(cls, ext_data: bytes) -> List[str]:
        versions = []
        try:
            list_len = ext_data[0]
            offset = 1
            while offset + 2 <= len(ext_data) and offset < 1 + list_len:
                ver_code = struct.unpack("!H", ext_data[offset:offset+2])[0]
                versions.append(format_tls_version(ver_code))
                offset += 2
        except Exception:
            pass
        return versions
