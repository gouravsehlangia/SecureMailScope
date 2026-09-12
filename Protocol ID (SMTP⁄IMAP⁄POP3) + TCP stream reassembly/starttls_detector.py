"""
backend.parser.starttls_detector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
STARTTLS transition detector and security audit engine.
- Detects STARTTLS command / response negotiation across SMTP, IMAP, and POP3.
- Splits the stream into plaintext command transcripts and raw TLS binary payload.
- Detects MITM STARTTLS stripping attacks, downgrade failures, and plaintext credential leaks.
"""

import re
import base64
from typing import Tuple, List, Optional
from .models import (
    ProtocolType,
    StarttlsStatus,
    StarttlsNegotiation,
    SecurityAlert,
    AlertSeverity,
    TcpStream,
)
from .protocol_detector import is_tls_record, is_tls_client_hello, is_tls_server_hello


# Regex patterns for STARTTLS advertisement
SMTP_STARTTLS_ADV = re.compile(rb"250[- ]STARTTLS\b", re.IGNORECASE)
IMAP_STARTTLS_ADV = re.compile(rb"\bSTARTTLS\b", re.IGNORECASE)
POP3_STLS_ADV = re.compile(rb"\bSTLS\b", re.IGNORECASE)

# Regex patterns for client STARTTLS commands
SMTP_STARTTLS_CMD = re.compile(rb"^\s*STARTTLS\r?\n", re.IGNORECASE | re.MULTILINE)
IMAP_STARTTLS_CMD = re.compile(rb"^[A-Za-z0-9_\-\.]+\s+STARTTLS\r?\n", re.IGNORECASE | re.MULTILINE)
POP3_STLS_CMD = re.compile(rb"^\s*STLS\r?\n", re.IGNORECASE | re.MULTILINE)

# Regex patterns for server STARTTLS positive responses
SMTP_STARTTLS_OK = re.compile(rb"^220[ -].*\r?\n", re.IGNORECASE | re.MULTILINE)
SMTP_STARTTLS_FAIL = re.compile(rb"^(454|501|503)[ -].*\r?\n", re.IGNORECASE | re.MULTILINE)
POP3_STLS_OK = re.compile(rb"^\+OK.*\r?\n", re.IGNORECASE | re.MULTILINE)
POP3_STLS_ERR = re.compile(rb"^-ERR.*\r?\n", re.IGNORECASE | re.MULTILINE)

# Plaintext credential patterns
SMTP_AUTH_PLAIN = re.compile(rb"AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
SMTP_AUTH_LOGIN = re.compile(rb"AUTH\s+LOGIN\b", re.IGNORECASE)
POP3_USER_PASS = re.compile(rb"USER\s+(\S+)\s*\r?\n.*?PASS\s+(\S+)", re.IGNORECASE | re.DOTALL)
IMAP_LOGIN_CMD = re.compile(rb"[A-Za-z0-9_\-\.]+\s+LOGIN\s+(\S+)\s+(\S+)", re.IGNORECASE)


class StarttlsDetector:
    """
    Examines stream payloads to detect STARTTLS exchange, performs stream splitting,
    and flags cryptographic security threats.
    """

    @classmethod
    def analyze(
        cls,
        protocol: ProtocolType,
        stream: TcpStream,
        is_implicit_tls: bool,
    ) -> Tuple[StarttlsNegotiation, List[SecurityAlert], bytes, bytes, List[str], List[str]]:
        """
        Returns:
            (negotiation, alerts, tls_client_payload, tls_server_payload, plaintext_cmds, plaintext_resps)
        """
        alerts: List[SecurityAlert] = []
        plaintext_cmds: List[str] = []
        plaintext_resps: List[str] = []
        client_raw = stream.client_payload
        server_raw = stream.server_payload

        # Case 1: Direct / Implicit TLS (SMTPS, IMAPS, POP3S)
        if is_implicit_tls or protocol in (ProtocolType.SMTPS, ProtocolType.IMAPS, ProtocolType.POP3S):
            neg = StarttlsNegotiation(
                status=StarttlsStatus.NEGOTIATED_SUCCESS,
                advertised_by_server=True,
                requested_by_client=True,
                accepted_by_server=True,
                client_tls_byte_offset=0,
                server_tls_byte_offset=0,
            )
            return neg, alerts, client_raw, server_raw, [], []

        # Case 2: Explicit STARTTLS candidate (SMTP, IMAP, POP3)
        advertised = False
        requested = False
        accepted = False
        client_tls_offset = None
        server_tls_offset = None
        client_cmd_text = None
        server_resp_text = None
        cmd_ts = None
        resp_ts = None

        # Check advertisement in server payload
        if protocol == ProtocolType.SMTP:
            advertised = bool(SMTP_STARTTLS_ADV.search(server_raw))
        elif protocol == ProtocolType.IMAP:
            advertised = bool(IMAP_STARTTLS_ADV.search(server_raw))
        elif protocol == ProtocolType.POP3:
            advertised = bool(POP3_STLS_ADV.search(server_raw))

        # Check client request
        cmd_match = None
        if protocol == ProtocolType.SMTP:
            cmd_match = SMTP_STARTTLS_CMD.search(client_raw)
        elif protocol == ProtocolType.IMAP:
            cmd_match = IMAP_STARTTLS_CMD.search(client_raw)
        elif protocol == ProtocolType.POP3:
            cmd_match = POP3_STLS_CMD.search(client_raw)

        if cmd_match:
            requested = True
            client_cmd_text = cmd_match.group(0).decode("utf-8", errors="replace").strip()
            # Everything after this command is expected to be TLS
            client_tls_offset = cmd_match.end()

        # Check server response following STARTTLS request
        if requested and client_tls_offset is not None:
            # Look for response in server_raw
            if protocol == ProtocolType.SMTP:
                # Look for 220 Ready
                match_ok = re.search(rb"\n220[ -].*?\r?\n", server_raw)
                if match_ok:
                    accepted = True
                    server_resp_text = match_ok.group(0).decode("utf-8", errors="replace").strip()
                    server_tls_offset = match_ok.end()
                else:
                    match_fail = re.search(rb"\n(454|501|503)[ -].*?\r?\n", server_raw)
                    if match_fail:
                        accepted = False
                        server_resp_text = match_fail.group(0).decode("utf-8", errors="replace").strip()
            elif protocol == ProtocolType.IMAP:
                match_ok = re.search(rb"\n[A-Za-z0-9_\-\.]+\s+OK.*?\r?\n", server_raw, re.IGNORECASE)
                if match_ok and (b"tls" in match_ok.group(0).lower() or b"begin" in match_ok.group(0).lower() or b"start" in match_ok.group(0).lower()):
                    accepted = True
                    server_resp_text = match_ok.group(0).decode("utf-8", errors="replace").strip()
                    server_tls_offset = match_ok.end()
            elif protocol == ProtocolType.POP3:
                match_ok = re.search(rb"\n\+OK.*?\r?\n", server_raw, re.IGNORECASE)
                if match_ok:
                    accepted = True
                    server_resp_text = match_ok.group(0).decode("utf-8", errors="replace").strip()
                    server_tls_offset = match_ok.end()
                else:
                    match_err = re.search(rb"\n-ERR.*?\r?\n", server_raw, re.IGNORECASE)
                    if match_err:
                        accepted = False
                        server_resp_text = match_err.group(0).decode("utf-8", errors="replace").strip()

        # Fallback heuristic: search directly for TLS ClientHello in client_raw
        if client_tls_offset is None:
            for idx in range(len(client_raw) - 5):
                if is_tls_client_hello(client_raw[idx:]):
                    client_tls_offset = idx
                    requested = True
                    break

        # Fallback heuristic: search directly for TLS ServerHello in server_raw
        if server_tls_offset is None and client_tls_offset is not None:
            for idx in range(len(server_raw) - 5):
                if is_tls_record(server_raw[idx:]):
                    server_tls_offset = idx
                    accepted = True
                    break

        # Extract plaintext phase vs TLS phase
        plaintext_client_bytes = client_raw[:client_tls_offset] if client_tls_offset is not None else client_raw
        plaintext_server_bytes = server_raw[:server_tls_offset] if server_tls_offset is not None else server_raw

        tls_client_bytes = client_raw[client_tls_offset:] if client_tls_offset is not None else b""
        tls_server_bytes = server_raw[server_tls_offset:] if server_tls_offset is not None else b""

        # Extract plaintext command lines
        for line in plaintext_client_bytes.splitlines():
            line_str = line.decode("utf-8", errors="replace").strip()
            if line_str:
                plaintext_cmds.append(line_str)

        for line in plaintext_server_bytes.splitlines():
            line_str = line.decode("utf-8", errors="replace").strip()
            if line_str:
                plaintext_resps.append(line_str)

        # Determine STARTTLS status
        if requested and accepted and is_tls_record(tls_client_bytes):
            status = StarttlsStatus.NEGOTIATED_SUCCESS
        elif requested and not accepted:
            status = StarttlsStatus.REJECTED_OR_FAILED
        elif advertised and not requested:
            # Server offered STARTTLS, but client never called it!
            # Check if client sent authentication or data
            has_credentials = cls._check_cleartext_credentials(plaintext_client_bytes)
            if has_credentials or len(plaintext_cmds) > 2:
                status = StarttlsStatus.STRIPPED_DOWNGRADE
            else:
                status = StarttlsStatus.OFFERED
        else:
            status = StarttlsStatus.PLAINTEXT_ONLY

        # Detect timestamps from events if available
        for ev in stream.events:
            if ev.direction == "client_to_server" and b"STARTTLS" in ev.payload.upper() and cmd_ts is None:
                cmd_ts = ev.timestamp
            if ev.direction == "server_to_client" and (b"220" in ev.payload or b"+OK" in ev.payload) and resp_ts is None:
                resp_ts = ev.timestamp

        # Check for credential leakage
        credentials_leaked = cls._check_cleartext_credentials(plaintext_client_bytes)

        negotiation = StarttlsNegotiation(
            status=status,
            advertised_by_server=advertised,
            requested_by_client=requested,
            accepted_by_server=accepted,
            client_command=client_cmd_text,
            server_response=server_resp_text,
            command_timestamp=cmd_ts,
            response_timestamp=resp_ts,
            client_tls_byte_offset=client_tls_offset,
            server_tls_byte_offset=server_tls_offset,
            downgrade_detected=(status == StarttlsStatus.STRIPPED_DOWNGRADE),
            credentials_leaked_in_clear=credentials_leaked,
        )

        # ----------------------------------------------------
        # SECURITY ALERT GENERATION (Rule Engine)
        # ----------------------------------------------------

        # Alert 1: MITM STARTTLS Stripping Attack
        if status == StarttlsStatus.STRIPPED_DOWNGRADE:
            alerts.append(SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                alert_type="STARTTLS_STRIPPING_ATTACK",
                title="STARTTLS Stripping / Downgrade Attack Detected",
                description=(
                    f"The server advertised STARTTLS capability, but the client proceeded to transmit "
                    f"commands/credentials in cleartext without initiating TLS. This is a signature "
                    f"of an active Man-In-The-Middle (MITM) downgrade or SSLstrip attack."
                ),
                evidence=f"Advertised STARTTLS in greeting. Client executed {len(plaintext_cmds)} commands in cleartext.",
                recommendation="Enforce MTA-STS (RFC 8461), DANE TLSA (RFC 7672), or require mandatory TLS encryption.",
                timestamp=stream.start_time,
                stream_id=stream.stream_id,
            ))

        # Alert 2: Plaintext Credentials in Cleartext
        if credentials_leaked:
            alerts.append(SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                alert_type="PLAINTEXT_CREDENTIALS_EXPOSED",
                title="Unencrypted Authentication Credentials Leaked",
                description="Plaintext user credentials (AUTH PLAIN, AUTH LOGIN, or USER/PASS) were transmitted over unencrypted TCP.",
                evidence="Plaintext authentication sequence found in client payload transcript.",
                recommendation="Configure mail client and server to reject authentication over non-TLS connections.",
                timestamp=stream.start_time,
                stream_id=stream.stream_id,
            ))

        # Alert 3: Server Rejection / Failure of STARTTLS
        if status == StarttlsStatus.REJECTED_OR_FAILED:
            alerts.append(SecurityAlert(
                severity=AlertSeverity.HIGH,
                alert_type="STARTTLS_NEGOTIATION_FAILED",
                title="STARTTLS Negotiation Failed or Rejected by Server",
                description="Client attempted STARTTLS upgrade, but server rejected the request with an error code.",
                evidence=f"Command: {client_cmd_text} -> Response: {server_resp_text}",
                recommendation="Check mail server TLS certificate and cipher suite configuration for compatibility.",
                timestamp=resp_ts or stream.start_time,
                stream_id=stream.stream_id,
            ))

        # Alert 4: Cleartext Email Transfer without Encryption
        if status == StarttlsStatus.PLAINTEXT_ONLY and len(plaintext_cmds) > 3:
            alerts.append(SecurityAlert(
                severity=AlertSeverity.MEDIUM,
                alert_type="UNENCRYPTED_EMAIL_SESSION",
                title="Entire Email Session Transmitted in Cleartext",
                description="The session did not utilize STARTTLS or TLS encryption; all messages and headers are vulnerable to wiretapping.",
                evidence=f"Transmitted {len(plaintext_cmds)} commands unencrypted on port {stream.server_port}.",
                recommendation="Enable opportunistic STARTTLS and configure strict TLS security policies.",
                timestamp=stream.start_time,
                stream_id=stream.stream_id,
            ))

        return negotiation, alerts, tls_client_bytes, tls_server_bytes, plaintext_cmds, plaintext_resps

    @staticmethod
    def _check_cleartext_credentials(payload: bytes) -> bool:
        """Inspects unencrypted bytes for authentication credentials."""
        if SMTP_AUTH_PLAIN.search(payload):
            return True
        if SMTP_AUTH_LOGIN.search(payload):
            return True
        if POP3_USER_PASS.search(payload):
            return True
        if IMAP_LOGIN_CMD.search(payload):
            return True
        return False
