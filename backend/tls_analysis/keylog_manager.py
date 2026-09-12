"""
SecureMailScope - TLS 1.3 SSLKEYLOGFILE Ingestion and Decryption Engine
Parses NSS keylog files, maps secrets to session randoms, and decrypts TLS 1.3
handshake traffic to expose encrypted X.509 Certificate messages.
"""

import os
import hashlib
import hmac
import struct
import logging
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("securemailscope.keylog")


class SSLKeyLogManager:
    """
    Manages NSS keylog files (RFC 8446 / Wireshark SSLKEYLOGFILE format).
    Enables forensic decryption of TLS 1.3 encrypted handshake messages.
    """

    def __init__(self, keylog_path: Optional[str] = None):
        self.keylog_path = keylog_path or os.environ.get("SSLKEYLOGFILE")
        # Maps client_random_hex -> dict of label -> secret_bytes
        self.secrets_by_client_random: Dict[str, Dict[str, bytes]] = {}
        if self.keylog_path and os.path.exists(self.keylog_path):
            self.load_keylog_file(self.keylog_path)

    def load_keylog_file(self, filepath: str) -> int:
        """Parses NSS keylog format entries."""
        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        label, client_random_hex, secret_hex = parts[0], parts[1].lower(), parts[2]
                        if client_random_hex not in self.secrets_by_client_random:
                            self.secrets_by_client_random[client_random_hex] = {}
                        try:
                            self.secrets_by_client_random[client_random_hex][label] = bytes.fromhex(secret_hex)
                            count += 1
                        except ValueError:
                            continue
            logger.info(f"Loaded {count} keys from SSLKEYLOGFILE: {filepath}")
        except Exception as e:
            logger.warning(f"Failed to read SSLKEYLOGFILE {filepath}: {e}")
        return count

    def get_secrets_for_random(self, client_random: bytes) -> Optional[Dict[str, bytes]]:
        """Returns secrets matching a 32-byte client_random."""
        if not client_random:
            return None
        return self.secrets_by_client_random.get(client_random.hex().lower())

    def has_handshake_secret(self, client_random: bytes) -> bool:
        """Checks if server handshake traffic secret exists for this session."""
        secrets = self.get_secrets_for_random(client_random)
        if not secrets:
            return False
        return "SERVER_HANDSHAKE_TRAFFIC_SECRET" in secrets or "CLIENT_RANDOM" in secrets

    @staticmethod
    def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int, hash_name: str = "sha256") -> bytes:
        """RFC 8446 Section 7.1 HKDF-Expand-Label."""
        full_label = b"tls13 " + label
        hkdf_label = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
        
        # HKDF-Expand implementation
        hash_fn = getattr(hashlib, hash_name)
        hash_len = hash_fn().digest_size
        n = (length + hash_len - 1) // hash_len
        t = b""
        okm = b""
        for i in range(1, n + 1):
            t = hmac.new(secret, t + hkdf_label + bytes([i]), hash_fn).digest()
            okm += t
        return okm[:length]

    def decrypt_tls13_record(
        self,
        encrypted_record_payload: bytes,
        client_random: bytes,
        cipher_code: int = 0x1302,
        seq_num: int = 0
    ) -> Tuple[bool, Optional[bytes], str]:
        """
        Decrypts a TLS 1.3 handshake record using SERVER_HANDSHAKE_TRAFFIC_SECRET.
        Returns: (success: bool, decrypted_plaintext: Optional[bytes], status_message: str)
        """
        secrets = self.get_secrets_for_random(client_random)
        if not secrets:
            return False, None, "No matching entry in SSLKEYLOGFILE for client_random"

        server_hs_secret = secrets.get("SERVER_HANDSHAKE_TRAFFIC_SECRET")
        if not server_hs_secret:
            return False, None, "Missing SERVER_HANDSHAKE_TRAFFIC_SECRET in keylog"

        hash_name = "sha384" if cipher_code == 0x1302 else "sha256"
        key_len = 32 if cipher_code == 0x1302 else 16
        iv_len = 12

        try:
            # Derive write key and IV
            write_key = self.hkdf_expand_label(server_hs_secret, b"key", b"", key_len, hash_name)
            write_iv = self.hkdf_expand_label(server_hs_secret, b"iv", b"", iv_len, hash_name)

            # Compute nonce: IV XOR seq_num (padded to 12 bytes)
            seq_padded = struct.pack("!Q", seq_num).rjust(12, b"\x00")
            nonce = bytes(a ^ b for a, b in zip(write_iv, seq_padded))

            # Attempt AES-GCM decryption using cryptography library if present
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(write_key)
                
                # In TLS 1.3, the 5-byte record header is the additional data (AAD)
                # Header format: ContentType=0x17, Version=0x0303, Length
                aad = struct.pack("!BHH", 0x17, 0x0303, len(encrypted_record_payload))
                decrypted = aesgcm.decrypt(nonce, encrypted_record_payload, aad)

                # Strip inner content type (trailing non-zero byte)
                inner_type = decrypted[-1]
                plaintext = decrypted[:-1].rstrip(b"\x00")
                return True, plaintext, f"Decrypted successfully (inner type {inner_type})"
            except ImportError:
                return False, None, "python-cryptography library not installed for AES-GCM decryption"
            except Exception as decrypt_err:
                return False, None, f"Decryption failed: {decrypt_err}"

        except Exception as err:
            return False, None, f"Key derivation failed: {err}"
