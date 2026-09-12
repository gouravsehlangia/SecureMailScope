"""
SecureMailScope - Cipher Suite Database and Evaluation Engine
Provides comprehensive IANA and OpenSSL cipher suite mapping, classification,
and Perfect Forward Secrecy (PFS) verification.
"""

import re
from typing import Dict, Optional, Tuple, Any
from .models import CipherSuiteInfo, SecurityRating, KeyExchangeAlgorithm

# Known weak and insecure keywords
WEAK_KEYWORDS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "ADH", "AECDH", "MD5"]


CIPHER_SUITE_DATABASE: Dict[int, CipherSuiteInfo] = {
    # ================= TLS 1.3 CIPHERS (RFC 8446) =================
    # In TLS 1.3, key exchange is decoupled and negotiated via Supported Groups / Key Share (PFS guaranteed)
    0x1301: CipherSuiteInfo(
        hex_code=0x1301,
        name="TLS_AES_128_GCM_SHA256",
        key_exchange="TLS1.3 (ECDHE/X25519)",
        auth="TLS1.3",
        encryption="AES-128-GCM",
        key_bits=128,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="Standard TLS 1.3 AEAD suite with Perfect Forward Secrecy"
    ),
    0x1302: CipherSuiteInfo(
        hex_code=0x1302,
        name="TLS_AES_256_GCM_SHA384",
        key_exchange="TLS1.3 (ECDHE/X25519)",
        auth="TLS1.3",
        encryption="AES-256-GCM",
        key_bits=256,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="High-security TLS 1.3 AEAD suite with Perfect Forward Secrecy"
    ),
    0x1303: CipherSuiteInfo(
        hex_code=0x1303,
        name="TLS_CHACHA20_POLY1305_SHA256",
        key_exchange="TLS1.3 (ECDHE/X25519)",
        auth="TLS1.3",
        encryption="CHACHA20-POLY1305",
        key_bits=256,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="Modern high-performance stream cipher with PFS"
    ),
    0x1304: CipherSuiteInfo(
        hex_code=0x1304,
        name="TLS_AES_128_CCM_SHA256",
        key_exchange="TLS1.3 (ECDHE/X25519)",
        auth="TLS1.3",
        encryption="AES-128-CCM",
        key_bits=128,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="TLS 1.3 CCM mode cipher suite"
    ),

    # ================= TLS 1.2 ECDHE (PFS + SECURE/ACCEPTABLE) =================
    0xC02F: CipherSuiteInfo(
        hex_code=0xC02F,
        name="ECDHE-RSA-AES128-GCM-SHA256",
        key_exchange="ECDHE",
        auth="RSA",
        encryption="AES-128-GCM",
        key_bits=128,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="TLS 1.2 standard GCM suite with ECDHE Forward Secrecy"
    ),
    0xC030: CipherSuiteInfo(
        hex_code=0xC030,
        name="ECDHE-RSA-AES256-GCM-SHA384",
        key_exchange="ECDHE",
        auth="RSA",
        encryption="AES-256-GCM",
        key_bits=256,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="TLS 1.2 high-security GCM suite with ECDHE Forward Secrecy"
    ),
    0xC02B: CipherSuiteInfo(
        hex_code=0xC02B,
        name="ECDHE-ECDSA-AES128-GCM-SHA256",
        key_exchange="ECDHE",
        auth="ECDSA",
        encryption="AES-128-GCM",
        key_bits=128,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="TLS 1.2 ECDSA + ECDHE Forward Secrecy"
    ),
    0xC02C: CipherSuiteInfo(
        hex_code=0xC02C,
        name="ECDHE-ECDSA-AES256-GCM-SHA384",
        key_exchange="ECDHE",
        auth="ECDSA",
        encryption="AES-256-GCM",
        key_bits=256,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="TLS 1.2 ECDSA + ECDHE 256-bit Forward Secrecy"
    ),
    0xCCA8: CipherSuiteInfo(
        hex_code=0xCCA8,
        name="ECDHE-RSA-CHACHA20-POLY1305",
        key_exchange="ECDHE",
        auth="RSA",
        encryption="CHACHA20-POLY1305",
        key_bits=256,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.SECURE,
        description="TLS 1.2 ChaCha20-Poly1305 with ECDHE Forward Secrecy"
    ),
    0xC027: CipherSuiteInfo(
        hex_code=0xC027,
        name="ECDHE-RSA-AES128-SHA256",
        key_exchange="ECDHE",
        auth="RSA",
        encryption="AES-128-CBC",
        key_bits=128,
        mac="SHA256",
        forward_secrecy=True,
        rating=SecurityRating.ACCEPTABLE,
        description="TLS 1.2 CBC cipher with ECDHE Forward Secrecy"
    ),
    0xC028: CipherSuiteInfo(
        hex_code=0xC028,
        name="ECDHE-RSA-AES256-SHA384",
        key_exchange="ECDHE",
        auth="RSA",
        encryption="AES-256-CBC",
        key_bits=256,
        mac="SHA384",
        forward_secrecy=True,
        rating=SecurityRating.ACCEPTABLE,
        description="TLS 1.2 CBC cipher with ECDHE Forward Secrecy"
    ),
    0xC013: CipherSuiteInfo(
        hex_code=0xC013,
        name="ECDHE-RSA-AES128-SHA",
        key_exchange="ECDHE",
        auth="RSA",
        encryption="AES-128-CBC",
        key_bits=128,
        mac="SHA1",
        forward_secrecy=True,
        rating=SecurityRating.ACCEPTABLE,
        description="Legacy ECDHE cipher with SHA1 MAC"
    ),
    0xC014: CipherSuiteInfo(
        hex_code=0xC014,
        name="ECDHE-RSA-AES256-SHA",
        key_exchange="ECDHE",
        auth="RSA",
        encryption="AES-256-CBC",
        key_bits=256,
        mac="SHA1",
        forward_secrecy=True,
        rating=SecurityRating.ACCEPTABLE,
        description="Legacy ECDHE 256-bit cipher with SHA1 MAC"
    ),

    # ================= DHE CIPHERS (PFS = TRUE) =================
    0x009E: CipherSuiteInfo(
        hex_code=0x009E,
        name="DHE-RSA-AES128-GCM-SHA256",
        key_exchange="DHE",
        auth="RSA",
        encryption="AES-128-GCM",
        key_bits=128,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.ACCEPTABLE,
        description="DHE with AES-GCM (PFS enabled)"
    ),
    0x009F: CipherSuiteInfo(
        hex_code=0x009F,
        name="DHE-RSA-AES256-GCM-SHA384",
        key_exchange="DHE",
        auth="RSA",
        encryption="AES-256-GCM",
        key_bits=256,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.ACCEPTABLE,
        description="DHE with AES-256-GCM (PFS enabled)"
    ),
    0x0033: CipherSuiteInfo(
        hex_code=0x0033,
        name="DHE-RSA-AES128-SHA",
        key_exchange="DHE",
        auth="RSA",
        encryption="AES-128-CBC",
        key_bits=128,
        mac="SHA1",
        forward_secrecy=True,
        rating=SecurityRating.ACCEPTABLE,
        description="DHE with AES-128 and SHA1"
    ),
    0x0039: CipherSuiteInfo(
        hex_code=0x0039,
        name="DHE-RSA-AES256-SHA",
        key_exchange="DHE",
        auth="RSA",
        encryption="AES-256-CBC",
        key_bits=256,
        mac="SHA1",
        forward_secrecy=True,
        rating=SecurityRating.ACCEPTABLE,
        description="DHE with AES-256 and SHA1"
    ),

    # ================= STATIC RSA (NO FORWARD SECRECY - WEAK) =================
    0x009C: CipherSuiteInfo(
        hex_code=0x009C,
        name="AES128-GCM-SHA256",
        key_exchange="RSA",
        auth="RSA",
        encryption="AES-128-GCM",
        key_bits=128,
        mac="AEAD",
        forward_secrecy=False,
        rating=SecurityRating.WEAK,
        description="Static RSA key exchange (Lacks Perfect Forward Secrecy)"
    ),
    0x009D: CipherSuiteInfo(
        hex_code=0x009D,
        name="AES256-GCM-SHA384",
        key_exchange="RSA",
        auth="RSA",
        encryption="AES-256-GCM",
        key_bits=256,
        mac="AEAD",
        forward_secrecy=False,
        rating=SecurityRating.WEAK,
        description="Static RSA key exchange (Lacks Perfect Forward Secrecy)"
    ),
    0x002F: CipherSuiteInfo(
        hex_code=0x002F,
        name="AES128-SHA",
        key_exchange="RSA",
        auth="RSA",
        encryption="AES-128-CBC",
        key_bits=128,
        mac="SHA1",
        forward_secrecy=False,
        rating=SecurityRating.WEAK,
        description="Static RSA with AES-CBC and SHA1 (No PFS)"
    ),
    0x0035: CipherSuiteInfo(
        hex_code=0x0035,
        name="AES256-SHA",
        key_exchange="RSA",
        auth="RSA",
        encryption="AES-256-CBC",
        key_bits=256,
        mac="SHA1",
        forward_secrecy=False,
        rating=SecurityRating.WEAK,
        description="Static RSA with AES-256 (No PFS)"
    ),
    0x003C: CipherSuiteInfo(
        hex_code=0x003C,
        name="AES128-SHA256",
        key_exchange="RSA",
        auth="RSA",
        encryption="AES-128-CBC",
        key_bits=128,
        mac="SHA256",
        forward_secrecy=False,
        rating=SecurityRating.WEAK,
        description="Static RSA with AES-128-SHA256 (No PFS)"
    ),
    0x003D: CipherSuiteInfo(
        hex_code=0x003D,
        name="AES256-SHA256",
        key_exchange="RSA",
        auth="RSA",
        encryption="AES-256-CBC",
        key_bits=256,
        mac="SHA256",
        forward_secrecy=False,
        rating=SecurityRating.WEAK,
        description="Static RSA with AES-256-SHA256 (No PFS)"
    ),

    # ================= INSECURE CIPHERS (3DES, RC4, DES, EXPORT, NULL) =================
    0x000A: CipherSuiteInfo(
        hex_code=0x000A,
        name="DES-CBC3-SHA",
        key_exchange="RSA",
        auth="RSA",
        encryption="3DES-EDE-CBC",
        key_bits=112,
        mac="SHA1",
        forward_secrecy=False,
        rating=SecurityRating.INSECURE,
        description="Triple-DES is vulnerable to SWEET32 collision attacks"
    ),
    0xC012: CipherSuiteInfo(
        hex_code=0xC012,
        name="ECDHE-RSA-DES-CBC3-SHA",
        key_exchange="ECDHE",
        auth="RSA",
        encryption="3DES-EDE-CBC",
        key_bits=112,
        mac="SHA1",
        forward_secrecy=True,
        rating=SecurityRating.INSECURE,
        description="Triple-DES cipher suite (vulnerable to SWEET32)"
    ),
    0x0005: CipherSuiteInfo(
        hex_code=0x0005,
        name="RC4-SHA",
        key_exchange="RSA",
        auth="RSA",
        encryption="RC4",
        key_bits=128,
        mac="SHA1",
        forward_secrecy=False,
        rating=SecurityRating.INSECURE,
        description="RC4 stream cipher (broken cryptographic biases)"
    ),
    0x0004: CipherSuiteInfo(
        hex_code=0x0004,
        name="RC4-MD5",
        key_exchange="RSA",
        auth="RSA",
        encryption="RC4",
        key_bits=128,
        mac="MD5",
        forward_secrecy=False,
        rating=SecurityRating.INSECURE,
        description="RC4 stream cipher with broken MD5 MAC"
    ),
    0x0009: CipherSuiteInfo(
        hex_code=0x0009,
        name="DES-CBC-SHA",
        key_exchange="RSA",
        auth="RSA",
        encryption="DES",
        key_bits=56,
        mac="SHA1",
        forward_secrecy=False,
        rating=SecurityRating.INSECURE,
        description="Single DES with 56-bit keys (trivially brute-forceable)"
    ),
    0x0001: CipherSuiteInfo(
        hex_code=0x0001,
        name="NULL-MD5",
        key_exchange="RSA",
        auth="RSA",
        encryption="NULL",
        key_bits=0,
        mac="MD5",
        forward_secrecy=False,
        rating=SecurityRating.INSECURE,
        description="Plaintext transmission (No encryption)"
    ),
    0x0002: CipherSuiteInfo(
        hex_code=0x0002,
        name="NULL-SHA",
        key_exchange="RSA",
        auth="RSA",
        encryption="NULL",
        key_bits=0,
        mac="SHA1",
        forward_secrecy=False,
        rating=SecurityRating.INSECURE,
        description="Plaintext transmission (No encryption)"
    ),

    # ================= ANONYMOUS KEY EXCHANGE (MITM VULNERABLE) =================
    0x00A6: CipherSuiteInfo(
        hex_code=0x00A6,
        name="ADH-AES128-GCM-SHA256",
        key_exchange="DH_anon",
        auth="None/Anonymous",
        encryption="AES-128-GCM",
        key_bits=128,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.INSECURE,
        description="Anonymous Diffie-Hellman (No server authentication - Man-in-the-Middle vuln)"
    ),
    0x00A7: CipherSuiteInfo(
        hex_code=0x00A7,
        name="ADH-AES256-GCM-SHA384",
        key_exchange="DH_anon",
        auth="None/Anonymous",
        encryption="AES-256-GCM",
        key_bits=256,
        mac="AEAD",
        forward_secrecy=True,
        rating=SecurityRating.INSECURE,
        description="Anonymous Diffie-Hellman (No server authentication - MITM vuln)"
    ),
    0xC018: CipherSuiteInfo(
        hex_code=0xC018,
        name="AECDH-AES128-SHA",
        key_exchange="ECDH_anon",
        auth="None/Anonymous",
        encryption="AES-128-CBC",
        key_bits=128,
        mac="SHA1",
        forward_secrecy=True,
        rating=SecurityRating.INSECURE,
        description="Anonymous ECDH (No authentication - MITM vuln)"
    )
}

# Lookup by name map
NAME_TO_CIPHER_MAP: Dict[str, CipherSuiteInfo] = {
    info.name.upper(): info for info in CIPHER_SUITE_DATABASE.values()
}

# Add common OpenSSL/RFC aliases
NAME_TO_CIPHER_MAP["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] = CIPHER_SUITE_DATABASE[0xC02F]
NAME_TO_CIPHER_MAP["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] = CIPHER_SUITE_DATABASE[0xC030]
NAME_TO_CIPHER_MAP["TLS_RSA_WITH_AES_128_GCM_SHA256"] = CIPHER_SUITE_DATABASE[0x009C]
NAME_TO_CIPHER_MAP["TLS_RSA_WITH_AES_256_GCM_SHA384"] = CIPHER_SUITE_DATABASE[0x009D]


class CipherSuiteDB:
    """Provides lookup, heuristic parsing, and security classification for TLS cipher suites."""

    @staticmethod
    def get_by_code(code: int) -> Optional[CipherSuiteInfo]:
        """Lookup cipher suite by 16-bit hex code."""
        return CIPHER_SUITE_DATABASE.get(code)

    @staticmethod
    def get_by_name(name: str) -> Optional[CipherSuiteInfo]:
        """Lookup cipher suite by standard name or alias."""
        clean_name = name.strip().upper().replace(" ", "_")
        if clean_name in NAME_TO_CIPHER_MAP:
            return NAME_TO_CIPHER_MAP[clean_name]
        return None

    @classmethod
    def classify_cipher(cls, name_or_code: Any) -> CipherSuiteInfo:
        """
        Classifies any cipher suite. If found in database, returns pre-computed info.
        Otherwise dynamically infers key exchange, encryption, forward secrecy, and security rating.
        """
        if isinstance(name_or_code, int):
            info = cls.get_by_code(name_or_code)
            if info:
                return info
            name = f"UNKNOWN_CIPHER_0x{name_or_code:04X}"
            code = name_or_code
        else:
            name = str(name_or_code).strip()
            info = cls.get_by_name(name)
            if info:
                return info
            code = 0x0000

        # Heuristic classification for uncatalogued ciphers
        return cls._infer_cipher_properties(name, code)

    @classmethod
    def _infer_cipher_properties(cls, name: str, code: int) -> CipherSuiteInfo:
        upper = name.upper()

        # 1. Key Exchange & Forward Secrecy
        if "TLS_AES" in upper or "TLS_CHACHA20" in upper:
            kx = "TLS1.3 (ECDHE/X25519)"
            auth = "TLS1.3"
            fs = True
        elif "ECDHE" in upper or "EDH" in upper:
            kx = "ECDHE"
            auth = "ECDSA" if "ECDSA" in upper else "RSA"
            fs = True
        elif "DHE" in upper:
            kx = "DHE"
            auth = "RSA" if "RSA" in upper else "DSS"
            fs = True
        elif "ADH" in upper or "ANON" in upper or "AECDH" in upper:
            kx = "DH_anon" if "AECDH" not in upper else "ECDH_anon"
            auth = "None/Anonymous"
            fs = True
        elif "RSA" in upper or upper.startswith("AES") or upper.startswith("DES"):
            kx = "RSA"
            auth = "RSA"
            fs = False
        else:
            kx = "UNKNOWN"
            auth = "UNKNOWN"
            fs = False

        # 2. Encryption & Key Bits
        if "CHACHA20" in upper:
            enc = "CHACHA20-POLY1305"
            bits = 256
            is_aead = True
        elif "AES_256" in upper or "AES256" in upper:
            enc = "AES-256-GCM" if "GCM" in upper else "AES-256-CBC"
            bits = 256
            is_aead = "GCM" in upper or "CCM" in upper
        elif "AES_128" in upper or "AES128" in upper:
            enc = "AES-128-GCM" if "GCM" in upper else "AES-128-CBC"
            bits = 128
            is_aead = "GCM" in upper or "CCM" in upper
        elif "3DES" in upper or "DES-CBC3" in upper:
            enc = "3DES"
            bits = 112
            is_aead = False
        elif "RC4" in upper:
            enc = "RC4"
            bits = 128
            is_aead = False
        elif "DES" in upper:
            enc = "DES"
            bits = 56
            is_aead = False
        elif "NULL" in upper:
            enc = "NULL"
            bits = 0
            is_aead = False
        else:
            enc = "UNKNOWN"
            bits = 128
            is_aead = False

        # 3. MAC
        if is_aead:
            mac = "AEAD"
        elif "SHA384" in upper:
            mac = "SHA384"
        elif "SHA256" in upper:
            mac = "SHA256"
        elif "SHA" in upper:
            mac = "SHA1"
        elif "MD5" in upper:
            mac = "MD5"
        else:
            mac = "UNKNOWN"

        # 4. Security Rating
        is_weak = any(kw in upper for kw in WEAK_KEYWORDS)
        is_anon = "ANON" in upper or "ADH" in upper or "AECDH" in upper

        if is_weak or is_anon or bits < 112:
            rating = SecurityRating.INSECURE
        elif not fs:
            rating = SecurityRating.WEAK
        elif is_aead and fs:
            rating = SecurityRating.SECURE
        else:
            rating = SecurityRating.ACCEPTABLE

        return CipherSuiteInfo(
            hex_code=code,
            name=name,
            key_exchange=kx,
            auth=auth,
            encryption=enc,
            key_bits=bits,
            mac=mac,
            forward_secrecy=fs,
            rating=rating,
            description=f"Inferred properties for {name}"
        )
