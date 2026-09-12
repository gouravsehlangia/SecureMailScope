"""
tests.test_parser
~~~~~~~~~~~~~~~~~
Comprehensive test suite for Task 1: PCAP Parsing Lead.
Verifies stream reassembly, protocol identification, STARTTLS extraction,
stripping attack detection, and integration contracts.
"""

import os
import unittest
import tempfile
from backend.parser import (
    parse_pcap,
    parse_pcap_to_dict,
    extract_tls_payloads_for_crypto_lead,
    ProtocolType,
    StarttlsStatus,
    AlertSeverity,
    DirectionalReassembler,
)
from tests.generate_test_pcaps import generate_pcap_files


class TestPcapParser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pcap_dir = os.path.join(tempfile.gettempdir(), "sih_test_pcaps")
        generate_pcap_files(cls.pcap_dir)
        cls.smtp_valid_pcap = os.path.join(cls.pcap_dir, "smtp_starttls_valid.pcap")
        cls.smtp_strip_pcap = os.path.join(cls.pcap_dir, "smtp_stripping_attack.pcap")
        cls.imap_pcap = os.path.join(cls.pcap_dir, "imap_starttls.pcap")
        cls.pop3_pcap = os.path.join(cls.pcap_dir, "pop3_stls.pcap")

    def test_out_of_order_tcp_reassembly(self):
        """Tests that DirectionalReassembler handles out-of-order packets and gaps."""
        reassembler = DirectionalReassembler(initial_seq=100)

        # Arrival order: Packet 2 (seq 105), Packet 1 (seq 100), Packet 3 (seq 110)
        c1 = reassembler.add_segment(seq=105, payload=b"WORLD", timestamp=1.2)
        # Should be buffered since seq 100 hasn't arrived
        self.assertEqual(len(c1), 0)

        # Packet 1 arrives
        c2 = reassembler.add_segment(seq=100, payload=b"HELLO", timestamp=1.1)
        # Now both HELLO (100) and WORLD (105) should be delivered in order
        assembled = bytes(reassembler.assembled_bytes)
        self.assertEqual(assembled, b"HELLOWORLD")

        # Duplicate packet arrives
        c3 = reassembler.add_segment(seq=100, payload=b"HELLO", timestamp=1.3)
        self.assertEqual(len(c3), 0)
        self.assertEqual(reassembler.retransmission_count, 1)

    def test_smtp_starttls_valid_session(self):
        """Tests standard SMTP negotiation with successful STARTTLS."""
        result = parse_pcap(self.smtp_valid_pcap)
        self.assertEqual(len(result.email_sessions), 1)

        sess = result.email_sessions[0]
        self.assertEqual(sess.protocol, ProtocolType.SMTP)
        self.assertEqual(sess.server_port, 25)
        self.assertTrue(sess.is_tls_encrypted)
        self.assertEqual(sess.starttls.status, StarttlsStatus.NEGOTIATED_SUCCESS)
        self.assertTrue(sess.starttls.advertised_by_server)
        self.assertTrue(sess.starttls.requested_by_client)
        self.assertTrue(sess.starttls.accepted_by_server)

        # Verify plaintext transcript contains pre-STARTTLS commands
        self.assertIn("EHLO mailclient.local", sess.plaintext_commands)
        self.assertIn("STARTTLS", sess.plaintext_commands)

        # Verify TLS payload was extracted and starts with ClientHello (0x16 0x03 0x01)
        self.assertTrue(sess.client_hello_detected)
        self.assertGreater(len(sess.tls_client_payload), 0)
        self.assertEqual(sess.tls_client_payload[0], 0x16)

        # Verify crypto lead handoff contract
        crypto_handoff = extract_tls_payloads_for_crypto_lead(result)
        self.assertEqual(len(crypto_handoff), 1)
        self.assertTrue(crypto_handoff[0]["client_hello_present"])

    def test_smtp_stripping_attack_detection(self):
        """Tests detection of MITM STARTTLS stripping and cleartext credentials leakage."""
        result = parse_pcap(self.smtp_strip_pcap)
        self.assertEqual(len(result.email_sessions), 1)

        sess = result.email_sessions[0]
        self.assertEqual(sess.protocol, ProtocolType.SMTP)
        self.assertFalse(sess.is_tls_encrypted)
        self.assertEqual(sess.starttls.status, StarttlsStatus.STRIPPED_DOWNGRADE)
        self.assertTrue(sess.starttls.downgrade_detected)
        self.assertTrue(sess.starttls.credentials_leaked_in_clear)

        # Verify security alerts
        alert_types = [a.alert_type for a in result.all_security_alerts]
        self.assertIn("STARTTLS_STRIPPING_ATTACK", alert_types)
        self.assertIn("PLAINTEXT_CREDENTIALS_EXPOSED", alert_types)

        # Verify critical severities
        critical_alerts = [a for a in result.all_security_alerts if a.severity == AlertSeverity.CRITICAL]
        self.assertGreaterEqual(len(critical_alerts), 2)

    def test_imap_starttls_session(self):
        """Tests IMAP protocol detection and STARTTLS upgrade on port 143."""
        result = parse_pcap(self.imap_pcap)
        self.assertEqual(len(result.email_sessions), 1)

        sess = result.email_sessions[0]
        self.assertEqual(sess.protocol, ProtocolType.IMAP)
        self.assertEqual(sess.server_port, 143)
        self.assertTrue(sess.is_tls_encrypted)
        self.assertEqual(sess.starttls.status, StarttlsStatus.NEGOTIATED_SUCCESS)
        self.assertTrue(sess.client_hello_detected)

    def test_pop3_stls_session(self):
        """Tests POP3 protocol detection and STLS upgrade on port 110."""
        result = parse_pcap(self.pop3_pcap)
        self.assertEqual(len(result.email_sessions), 1)

        sess = result.email_sessions[0]
        self.assertEqual(sess.protocol, ProtocolType.POP3)
        self.assertEqual(sess.server_port, 110)
        self.assertTrue(sess.is_tls_encrypted)
        self.assertEqual(sess.starttls.status, StarttlsStatus.NEGOTIATED_SUCCESS)
        self.assertTrue(sess.client_hello_detected)

    def test_json_export_structure(self):
        """Verifies JSON output compatibility for Frontend (Role #5) and API (Role #6)."""
        data = parse_pcap_to_dict(self.smtp_valid_pcap)
        self.assertIn("summary", data)
        self.assertIn("sessions", data)
        self.assertIn("security_alerts", data)
        self.assertEqual(data["summary"]["total_streams"], 1)


if __name__ == "__main__":
    unittest.main()
