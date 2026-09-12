"""
SecureMailScope - Stage 2 Comprehensive Test Suite
Validates TLS Handshake Parsing, Cipher Suite DB, Key Exchange & PFS Checks,
Raw Certificate Extraction for Stage 3, STARTTLS Stripping Detection,
and SSLKEYLOGFILE Ingestion.
"""

import os
import sys
import json
import base64
import struct
import tempfile
import unittest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.tls_analysis import (
    TLSHandshakeParser, CipherSuiteDB, CryptoAnalyzer,
    SecurityRating, VisibilityStatus, SSLKeyLogManager,
    Stage1SessionInput, analyze_session_tls
)


class TestCipherSuiteDB(unittest.TestCase):
    def test_tls13_cipher(self):
        info = CipherSuiteDB.get_by_code(0x1302)
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "TLS_AES_256_GCM_SHA384")
        self.assertTrue(info.forward_secrecy)
        self.assertEqual(info.rating, SecurityRating.SECURE)

    def test_ecdhe_pfs(self):
        info = CipherSuiteDB.get_by_code(0xC02F)
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "ECDHE-RSA-AES128-GCM-SHA256")
        self.assertTrue(info.forward_secrecy)
        self.assertEqual(info.key_exchange, "ECDHE")

    def test_static_rsa_lacks_pfs(self):
        info = CipherSuiteDB.get_by_code(0x009C)
        self.assertIsNotNone(info)
        self.assertFalse(info.forward_secrecy)
        self.assertEqual(info.key_exchange, "RSA")
        self.assertEqual(info.rating, SecurityRating.WEAK)

    def test_insecure_ciphers(self):
        rc4 = CipherSuiteDB.get_by_code(0x0005)
        self.assertEqual(rc4.rating, SecurityRating.INSECURE)
        des3 = CipherSuiteDB.get_by_code(0x000A)
        self.assertEqual(des3.rating, SecurityRating.INSECURE)
        null_cipher = CipherSuiteDB.get_by_code(0x0001)
        self.assertEqual(null_cipher.rating, SecurityRating.INSECURE)


class TestMultiMessageHandshakeAndCertExtraction(unittest.TestCase):
    """Tests coalesced handshake messages (ServerHello + Certificate + ServerKeyExchange)."""

    def _build_coalesced_server_handshake(self) -> bytes:
        # 1. ServerHello (TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256, 0xC02F)
        sh_body = (
            struct.pack("!H", 0x0303) +
            b"\x55" * 32 +
            bytes([0]) +
            struct.pack("!H", 0xC02F) +
            bytes([0]) +
            struct.pack("!H", 0)  # 0 extensions
        )
        sh_msg = bytes([0x02]) + struct.pack("!I", len(sh_body))[1:] + sh_body

        # 2. Certificate message (0x0B) with 2 fake DER certs
        cert1 = b"\x30\x82\x01\x00" + b"\x01" * 256  # Synthetic DER cert 1
        cert2 = b"\x30\x82\x01\x00" + b"\x02" * 256  # Synthetic DER cert 2
        cert_chain = (
            struct.pack("!I", len(cert1))[1:] + cert1 +
            struct.pack("!I", len(cert2))[1:] + cert2
        )
        cert_body = struct.pack("!I", len(cert_chain))[1:] + cert_chain
        cert_msg = bytes([0x0B]) + struct.pack("!I", len(cert_body))[1:] + cert_body

        # 3. ServerKeyExchange (0x0C) with secp256r1 (0x0017)
        ske_body = bytes([0x03]) + struct.pack("!H", 0x0017) + bytes([33]) + b"\x04" + b"\x77" * 32
        ske_msg = bytes([0x0C]) + struct.pack("!I", len(ske_body))[1:] + ske_body

        coalesced_handshake = sh_msg + cert_msg + ske_msg
        # Wrap in single TLS Record Layer header
        record_hdr = struct.pack("!BHH", 0x16, 0x0303, len(coalesced_handshake))
        return record_hdr + coalesced_handshake

    def test_parse_coalesced_handshake_and_certs(self):
        stream_bytes = self._build_coalesced_server_handshake()
        res = CryptoAnalyzer.analyze_session(
            Stage1SessionInput(
                session_id="test_coalesced_01",
                stream_bytes=stream_bytes,
                protocol="SMTPS"
            )
        )

        self.assertTrue(res.tls_present)
        self.assertEqual(res.tls_version, "TLS 1.2")
        self.assertEqual(res.cipher_suite, "ECDHE-RSA-AES128-GCM-SHA256")
        self.assertTrue(res.forward_secrecy)
        self.assertEqual(res.security_rating, SecurityRating.SECURE)
        self.assertIn("secp256r1", res.key_exchange_group)

        # Verify Certificate Extraction for Stage 3!
        self.assertEqual(len(res.raw_certificates), 2)
        # Check base64 decoding matches original synthetic cert bytes
        decoded_cert1 = base64.b64decode(res.raw_certificates[0])
        self.assertTrue(decoded_cert1.startswith(b"\x30\x82\x01\x00"))


class TestSTARTTLSEdgeCases(unittest.TestCase):
    def test_starttls_upgrade_success(self):
        # SMTP conversation before TLS record
        smtp_prefix = (
            b"220 mail.example.com ESMTP Postfix\r\n"
            b"EHLO client.local\r\n"
            b"250-mail.example.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 DSN\r\n"
            b"STARTTLS\r\n"
            b"220 2.0.0 Ready to start TLS\r\n"
        )
        # Followed by a TLS 1.3 ServerHello
        ext_data = struct.pack("!HHH", 0x002B, 2, 0x0304)  # type 0x002B, len 2, val 0x0304 (TLS 1.3)
        ext_bytes = struct.pack("!H", len(ext_data)) + ext_data
        sh_body = (
            struct.pack("!H", 0x0303) + b"\x11" * 32 + bytes([0]) +
            struct.pack("!H", 0x1302) + bytes([0]) +
            ext_bytes
        )
        sh_msg = bytes([0x02]) + struct.pack("!I", len(sh_body))[1:] + sh_body
        tls_record = struct.pack("!BHH", 0x16, 0x0303, len(sh_msg)) + sh_msg

        full_stream = smtp_prefix + tls_record

        res = CryptoAnalyzer.analyze_session(
            Stage1SessionInput(
                session_id="smtp_starttls_01",
                stream_bytes=full_stream,
                protocol="SMTP"
            )
        )

        self.assertTrue(res.tls_present)
        self.assertTrue(res.starttls_used)
        self.assertFalse(res.starttls_stripped)
        self.assertEqual(res.tls_version, "TLS 1.3")
        self.assertEqual(res.cipher_suite, "TLS_AES_256_GCM_SHA384")
        self.assertTrue(res.forward_secrecy)

    def test_starttls_stripping_attack(self):
        # Server advertises STARTTLS, but client sends AUTH over plaintext
        plaintext_stripped = (
            b"220 mail.bank.com ESMTP MailServer\r\n"
            b"EHLO user.victim\r\n"
            b"250-mail.bank.com\r\n"
            b"250-STARTTLS\r\n"
            b"250 PIPELINING\r\n"
            b"AUTH LOGIN\r\n"
            b"334 VXNlcm5hbWU6\r\n"
            b"dXNlckBiYW5rLmNvbQ==\r\n"
            b"MAIL FROM:<attacker@evil.com>\r\n"
        )

        res = CryptoAnalyzer.analyze_session(
            Stage1SessionInput(
                session_id="smtp_stripped_01",
                stream_bytes=plaintext_stripped,
                protocol="SMTP"
            )
        )

        self.assertFalse(res.tls_present)
        self.assertTrue(res.starttls_stripped)
        self.assertEqual(res.security_rating, SecurityRating.INSECURE)
        self.assertTrue(any("STARTTLS Stripping" in v for v in res.rule_violations))

    def test_plaintext_session(self):
        plaintext_stream = b"EHLO test\r\n250 OK\r\nMAIL FROM:<a@b.com>\r\n"
        res = CryptoAnalyzer.analyze_session(
            Stage1SessionInput(
                session_id="plain_01",
                stream_bytes=plaintext_stream,
                protocol="SMTP"
            )
        )
        self.assertFalse(res.tls_present)
        self.assertEqual(res.visibility, VisibilityStatus.PLAINTEXT_NO_TLS)
        self.assertEqual(res.security_rating, SecurityRating.INSECURE)
        self.assertTrue(any("Unencrypted plaintext" in v for v in res.rule_violations))


class TestTLS13AndSSLKeyLogHandling(unittest.TestCase):
    def test_tls13_without_keylog_graceful_degradation(self):
        # Synthetic TLS 1.3 Handshake without keylog
        client_random = b"\x44" * 32
        ch_body = struct.pack("!H", 0x0303) + client_random + bytes([0]) + struct.pack("!HH", 2, 0x1302) + bytes([1, 0])
        ch_msg = bytes([0x01]) + struct.pack("!I", len(ch_body))[1:] + ch_body
        ch_rec = struct.pack("!BHH", 0x16, 0x0301, len(ch_msg)) + ch_msg

        ext_data = struct.pack("!HHH", 0x002B, 2, 0x0304)
        ext_bytes = struct.pack("!H", len(ext_data)) + ext_data
        sh_body = (
            struct.pack("!H", 0x0303) + b"\x33" * 32 + bytes([0]) +
            struct.pack("!H", 0x1302) + bytes([0]) +
            ext_bytes
        )
        sh_msg = bytes([0x02]) + struct.pack("!I", len(sh_body))[1:] + sh_body
        sh_rec = struct.pack("!BHH", 0x16, 0x0303, len(sh_msg)) + sh_msg

        # Encrypted application data record (encrypted cert)
        enc_rec = struct.pack("!BHH", 0x17, 0x0303, 64) + b"\x99" * 64

        full_stream = ch_rec + sh_rec + enc_rec

        # Empty keylog manager
        keylog_mgr = SSLKeyLogManager()

        res = CryptoAnalyzer.analyze_session(
            Stage1SessionInput(
                session_id="tls13_no_keylog",
                stream_bytes=full_stream,
                protocol="SMTPS"
            ),
            keylog_manager=keylog_mgr
        )

        self.assertEqual(res.tls_version, "TLS 1.3")
        self.assertEqual(res.cipher_suite, "TLS_AES_256_GCM_SHA384")
        self.assertTrue(res.forward_secrecy)
        self.assertEqual(res.security_rating, SecurityRating.SECURE)
        self.assertEqual(res.visibility, VisibilityStatus.HANDSHAKE_ONLY_TLS13)
        self.assertFalse(res.keylog_applied)
        self.assertTrue(any("SSLKEYLOGFILE" in w for w in res.warnings))

    def test_keylog_file_loading_and_matching(self):
        client_random = b"\xab" * 32
        secret_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(f"# SSL Key Log File\n")
            f.write(f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random.hex()} {secret_hex}\n")
            temp_path = f.name

        try:
            mgr = SSLKeyLogManager(temp_path)
            self.assertTrue(mgr.has_handshake_secret(client_random))
            secrets = mgr.get_secrets_for_random(client_random)
            self.assertIsNotNone(secrets)
            self.assertIn("SERVER_HANDSHAKE_TRAFFIC_SECRET", secrets)
            self.assertEqual(secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"], bytes.fromhex(secret_hex))
        finally:
            os.remove(temp_path)


class TestPipelineCompatibility(unittest.TestCase):
    def test_mock_sessions_backward_compatibility(self):
        mock_path = os.path.join(PROJECT_ROOT, "mock_sessions.json")
        if not os.path.exists(mock_path):
            self.skipTest("mock_sessions.json not found")

        with open(mock_path, "r") as f:
            sessions = json.load(f)

        for sess in sessions[:100]:
            enriched = analyze_session_tls(sess)
            self.assertIn("tls_version", enriched)
            self.assertIn("cipher_suite", enriched)
            self.assertIn("key_exchange", enriched)
            self.assertIn("forward_secrecy", enriched)
            self.assertIn("security_rating", enriched)
            self.assertIn("raw_certificates", enriched)
            self.assertIn("rule_violations", enriched)


if __name__ == "__main__":
    unittest.main(verbosity=2)
