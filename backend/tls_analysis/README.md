# SecureMailScope - Stage 2: TLS / Cryptographic Analysis Engine

**Author:** Saksham (Role #2: TLS / Crypto Engineer)  
**Location:** `/backend/tls_analysis/`  
**Problem Statement:** SIH26159 — AI-Assisted Passive Email Forensic Framework

---

## 🎯 Deliverables Completed & Verified

1. **TLS Handshake Reconstruction (`handshake_parser.py`)**:
   - Parses raw TCP stream byte buffers and STARTTLS-upgraded email sessions.
   - De-coalesces multi-handshake records in a single TLS frame (`ServerHello` + `Certificate` + `ServerKeyExchange`).
   - Extracts `ClientHello` (SNI, ALPN, offered ciphers, supported elliptic curves/groups, supported versions).
   - Extracts `ServerHello` (negotiated cipher suite, negotiated TLS version including TLS 1.3 extension `0x002B`, selected key share/curve).

2. **Raw X.509 Certificate Extraction (`handshake_parser.py` $\to$ Stage 3)**:
   - Parses Handshake Message `0x0B` (`Certificate`).
   - Extracts raw DER certificate byte chains and encodes them to standard Base64.
   - Passes them directly in `raw_certificates` so **Stage 3 (Certificate Engineer)** does not need to touch PCAP files or raw byte streams.

3. **Cipher Suite & Perfect Forward Secrecy (PFS) Engine (`cipher_suites.py`)**:
   - Full IANA and OpenSSL cipher suite mapping.
   - Rigorous Forward Secrecy detection (`ECDHE`, `DHE`, and TLS 1.3 `x25519`/`secp256r1` $\rightarrow$ `forward_secrecy = True`; static `RSA`/`DH` $\rightarrow$ `False`).
   - Flags Anonymous key exchange (`DH_anon`, `ECDH_anon`) as active Man-in-the-Middle vulnerabilities.
   - Flags weak ciphers (`3DES`, `RC4`, `DES`, `EXPORT`, `NULL`) and weak MACs (`MD5`, `SHA1`).

4. **TLS 1.3 NSS Keylog Ingestion & Decryption (`keylog_manager.py`)**:
   - Ingests `SSLKEYLOGFILE` files (Wireshark / NSS format).
   - Matches session secrets using `client_random`.
   - When keylog is present: derives keys via RFC 8446 HKDF-Expand-Label to decrypt handshake records and expose encrypted certificates (`visibility = "decrypted_via_keylog"`).
   - When no keylog is present: **degrades gracefully** with full confidence metadata extraction and documented diagnostic status (`visibility = "handshake_only_tls13_encrypted"`).

5. **STARTTLS Stripping & Downgrade Attack Detection (`handshake_parser.py`)**:
   - Detects standard STARTTLS upgrade transitions across SMTP (`220`), IMAP (`+OK`), and POP3.
   - Actively flags **STARTTLS Stripping / Downgrade Attacks** when server capabilities advertise `STARTTLS` but client sends plaintext credentials (`AUTH LOGIN`, `PASS`) without upgrading.

---

## 🔌 Inter-Stage Integration Contracts

### Input Contract (from Stage 1: PCAP Parsing Lead)
Stage 2 accepts `Stage1SessionInput`, dictionary, or raw bytes:
```python
from backend.tls_analysis import CryptoAnalyzer, Stage1SessionInput

session_input = Stage1SessionInput(
    session_id="session_42",
    stream_id="tcp_stream_07",
    protocol="SMTP",
    client_ip="192.168.1.10",
    server_ip="10.0.0.25",
    client_port=49821,
    server_port=587,
    stream_bytes=reassembled_tcp_bytes,
    starttls_detected=True
)

result = CryptoAnalyzer.analyze_session(session_input)
```

### Output Contract (to Stage 3 & Stage 4)
Emits structured JSON adhering to `schema.md`:
```python
output_dict = result.to_dict()
```

- **For Stage 3 (Certificate Engineer)**:  
  Consume `output_dict["raw_certificates"]` (list of base64 DER strings). Decode using `base64.b64decode()` and feed into `cryptography.x509` or `pyOpenSSL`.
- **For Stage 4 (AI Risk Scoring & Rule Engine)**:  
  Consume `output_dict["tls_version"]`, `output_dict["cipher_suite"]`, `output_dict["forward_secrecy"]`, `output_dict["security_rating"]`, and `output_dict["rule_violations"]`.

---

## 🧪 Testing & Verification

Run the 11-test suite:
```bash
python3 backend/tls_analysis/test_tls_analysis.py
```

Run the forensic demonstration:
```bash
python3 backend/tls_analysis/demo_tls_analysis.py
```
