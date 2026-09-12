"""
backend.parser.protocol_detector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Protocol identification engine using Deep Packet Inspection (DPI) & port heuristics.
Accurately classifies:
- SMTP / ESMTP / SMTPS
- IMAP4 / IMAPS
- POP3 / POP3S
Distinguishes implicit TLS (direct TLS handshake) from explicit STARTTLS sessions.
"""

import re
from typing import Tuple, Optional
from .models import ProtocolType, TcpStream


# Common well-known email ports
PORT_SMTP = {25, 587, 2525}
PORT_SMTPS = {465}
PORT_IMAP = {143}
PORT_IMAPS = {993}
PORT_POP3 = {110}
PORT_POP3S = {995}

# Regex patterns for server greetings & banners
SMTP_BANNER_REGEX = re.compile(rb"^\s*220[- ]", re.IGNORECASE)
SMTP_KEYWORDS = [rb"esmtp", rb"smtp", rb"mail", rb"postfix", rb"sendmail", rb"exim", rb"exchange"]

IMAP_BANNER_REGEX = re.compile(rb"^\s*\* (OK|PREAUTH)\b", re.IGNORECASE)
POP3_BANNER_REGEX = re.compile(rb"^\s*\+OK\b", re.IGNORECASE)

# Regex patterns for client commands
SMTP_CLIENT_CMD_REGEX = re.compile(rb"^\s*(EHLO|HELO|MAIL FROM:|RCPT TO:|STARTTLS|AUTH\b|RSET|DATA|QUIT)", re.IGNORECASE | re.MULTILINE)
IMAP_CLIENT_CMD_REGEX = re.compile(rb"^\s*[A-Za-z0-9_\-\.]+\s+(CAPABILITY|LOGIN|AUTHENTICATE|STARTTLS|SELECT|EXAMINE|LOGOUT|NOOP)", re.IGNORECASE | re.MULTILINE)
POP3_CLIENT_CMD_REGEX = re.compile(rb"^\s*(USER\s+|PASS\s+|APOP\s+|STLS|CAPA|STAT|LIST|RETR|DELE|NOOP|RSET|QUIT)", re.IGNORECASE | re.MULTILINE)


def is_tls_record(data: bytes) -> bool:
    """Checks if raw data begins with a valid TLS Record layer header."""
    if len(data) < 5:
        return False
    # ContentType: 0x16 (Handshake), 0x15 (Alert), 0x14 (ChangeCipherSpec), 0x17 (ApplicationData)
    # Major version: 0x03 (SSLv3 / TLS 1.0, 1.1, 1.2, 1.3)
    # Minor version: 0x00 - 0x04
    content_type = data[0]
    major_ver = data[1]
    minor_ver = data[2]
    return (content_type in (0x16, 0x17, 0x15, 0x14) and major_ver == 0x03 and minor_ver in (0x00, 0x01, 0x02, 0x03, 0x04))


def is_tls_client_hello(data: bytes) -> bool:
    """Checks if raw data begins with TLS Handshake ClientHello."""
    if len(data) < 6:
        return False
    # 0x16 (Handshake) + 0x03 (TLS major) + minor + length (2 bytes) + 0x01 (ClientHello)
    return is_tls_record(data) and data[0] == 0x16 and len(data) > 5 and data[5] == 0x01


def is_tls_server_hello(data: bytes) -> bool:
    """Checks if raw data begins with TLS Handshake ServerHello."""
    if len(data) < 6:
        return False
    return is_tls_record(data) and data[0] == 0x16 and len(data) > 5 and data[5] == 0x02


class ProtocolDetector:
    """
    Analyzes TCP streams using combined Deep Packet Inspection (DPI)
    and transport layer port heuristics.
    """

    @classmethod
    def identify(cls, stream: TcpStream) -> Tuple[ProtocolType, bool, Optional[str]]:
        """
        Returns:
            (ProtocolType, is_implicit_tls, banner_text)
        """
        server_port = stream.server_port
        client_payload = stream.client_payload
        server_payload = stream.server_payload

        # 1. Direct / Implicit TLS Check (Client sends TLS ClientHello immediately at byte 0)
        if is_tls_client_hello(client_payload):
            if server_port in PORT_SMTPS or server_port in PORT_SMTP:
                return ProtocolType.SMTPS, True, None
            elif server_port in PORT_IMAPS or server_port in PORT_IMAP:
                return ProtocolType.IMAPS, True, None
            elif server_port in PORT_POP3S or server_port in PORT_POP3:
                return ProtocolType.POP3S, True, None
            else:
                # Direct TLS on other ports - check if port suggests mail
                return ProtocolType.UNKNOWN, True, None

        # 2. Extract Server Banner if present
        banner_text = None
        first_line = b""
        if server_payload:
            first_line = server_payload.split(b"\r\n")[0].split(b"\n")[0]
            try:
                banner_text = first_line.decode("utf-8", errors="replace").strip()
            except Exception:
                banner_text = None

        # 3. Deep Packet Inspection on Payloads
        
        # --- Check SMTP ---
        if SMTP_BANNER_REGEX.match(first_line):
            # Server responded with 220 banner
            return ProtocolType.SMTP, False, banner_text
        if SMTP_CLIENT_CMD_REGEX.search(client_payload):
            return ProtocolType.SMTP, False, banner_text

        # --- Check IMAP ---
        if IMAP_BANNER_REGEX.match(first_line):
            return ProtocolType.IMAP, False, banner_text
        if IMAP_CLIENT_CMD_REGEX.search(client_payload):
            return ProtocolType.IMAP, False, banner_text

        # --- Check POP3 ---
        if POP3_BANNER_REGEX.match(first_line):
            # Check if POP3 commands or port
            if server_port in PORT_POP3 or POP3_CLIENT_CMD_REGEX.search(client_payload):
                return ProtocolType.POP3, False, banner_text
            # Some FTP servers might have +OK? Rare, but verify keywords
            if b"pop" in first_line.lower() or POP3_CLIENT_CMD_REGEX.search(client_payload):
                return ProtocolType.POP3, False, banner_text

        # 4. Fallback to Port Heuristics
        if server_port in PORT_SMTP:
            return ProtocolType.SMTP, False, banner_text
        elif server_port in PORT_SMTPS:
            return ProtocolType.SMTPS, True, banner_text
        elif server_port in PORT_IMAP:
            return ProtocolType.IMAP, False, banner_text
        elif server_port in PORT_IMAPS:
            return ProtocolType.IMAPS, True, banner_text
        elif server_port in PORT_POP3:
            return ProtocolType.POP3, False, banner_text
        elif server_port in PORT_POP3S:
            return ProtocolType.POP3S, True, banner_text

        return ProtocolType.UNKNOWN, False, banner_text
