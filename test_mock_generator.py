import unittest
from mock_generator import generate_mock_sessions, validate_session, calculate_risk, build_session

class TestMockGenerator(unittest.TestCase):

    def test_validation_layer_valid(self):
        valid_session = build_session("SMTPS", "modern", "secure")
        self.assertTrue(validate_session(valid_session))

    def test_invalid_port(self):
        invalid_port = build_session("SMTPS", "modern", "secure")
        invalid_port["server_port"] = 143
        with self.assertRaisesRegex(ValueError, "Invalid SMTPS port"):
            validate_session(invalid_port)

    def test_invalid_tls13_cipher(self):
        invalid_tls13_cipher = build_session("SMTPS", "modern", "secure")
        invalid_tls13_cipher["tls_version"] = "TLS 1.3"
        invalid_tls13_cipher["cipher_suite"] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        with self.assertRaisesRegex(ValueError, "Invalid TLS 1.3 cipher"):
            validate_session(invalid_tls13_cipher)

    def test_invalid_tls13_pfs(self):
        invalid_tls13_pfs = build_session("SMTPS", "modern", "secure")
        invalid_tls13_pfs["tls_version"] = "TLS 1.3"
        invalid_tls13_pfs["forward_secrecy"] = False
        with self.assertRaisesRegex(ValueError, "TLS 1.3 must have PFS"):
            validate_session(invalid_tls13_pfs)

    def test_invalid_pfs_rsa(self):
        invalid_pfs_rsa = build_session("SMTPS", "modern", "secure")
        invalid_pfs_rsa["key_exchange"] = "RSA"
        invalid_pfs_rsa["forward_secrecy"] = True
        with self.assertRaisesRegex(ValueError, "PFS = Yes with RSA key exchange"):
            validate_session(invalid_pfs_rsa)

    def test_invalid_no_pfs_ecdhe(self):
        invalid_no_pfs_ecdhe = build_session("SMTPS", "legacy", "secure")
        invalid_no_pfs_ecdhe["key_exchange"] = "ECDHE"
        invalid_no_pfs_ecdhe["forward_secrecy"] = False
        with self.assertRaisesRegex(ValueError, "PFS = No with ECDHE"):
            validate_session(invalid_no_pfs_ecdhe)

    def test_invalid_cert(self):
        invalid_cert = build_session("SMTPS", "modern", "secure")
        invalid_cert["cert_key_length"] = 128
        with self.assertRaisesRegex(ValueError, "Invalid cert key size"):
            validate_session(invalid_cert)
            
    def test_invalid_tls10_modern_cipher(self):
        invalid_tls10 = build_session("SMTPS", "legacy", "secure")
        invalid_tls10["tls_version"] = "TLS 1.0"
        invalid_tls10["cipher_suite"] = "TLS_AES_256_GCM_SHA384"
        with self.assertRaisesRegex(ValueError, "TLS 1.0 using modern cipher"):
            validate_session(invalid_tls10)

    def test_risk_scoring(self):
        # Plaintext IMAP
        s1 = build_session("IMAP", "none", "secure")
        self.assertEqual(s1["risk_level"], "critical")
        self.assertTrue(any("Unencrypted plaintext" in v for v in s1["rule_violations"]))

        # TLS 1.0
        s2 = build_session("SMTPS", "legacy", "secure")
        s2["tls_version"] = "TLS 1.0"
        s2["cipher_suite"] = "AES128-SHA"
        s2 = calculate_risk(s2)
        self.assertIn(s2["risk_level"], ["high", "critical"])
        self.assertTrue(any("Deprecated protocol TLS 1.0" in v for v in s2["rule_violations"]))

    def test_generate_profiles(self):
        for i in range(20):
            filename = f"test_file_{i}.pcap"
            sessions = generate_mock_sessions(filename)
            self.assertGreater(len(sessions), 0)
            for s in sessions:
                self.assertTrue(validate_session(s))

if __name__ == '__main__':
    unittest.main()
