# Certificate Analysis Module (`/backend/cert_analysis`)

Role 3: Certificate Engineer Deliverable for TLS / Email Protocol Analyzer.

## Overview
This module extracts, inspects, and audits X.509 certificates and certificate chains exchanged during TLS / STARTTLS handshakes (SMTP, IMAP, POP3, HTTPS).

## Features
- **X.509 Extraction**: Subject, Issuer, SAN, Serial, Validity dates, Fingerprints (SHA-256, SHA-1).
- **Key & Signature Inspection**: Key algorithm (RSA, ECC, DSA), Key length, Signature algorithm, Hash algorithm.
- **Chain Validation**: Verifies hierarchy, parent-child links, cryptographic signatures, CA constraints, and self-signed status.
- **Weak-Crypto Rule Engine**:
  - `EXP-001`: Expired certificates (CRITICAL)
  - `EXP-002`: Not yet valid (HIGH)
  - `EXP-003`: Expiring in <= 7 days (HIGH)
  - `EXP-004`: Expiring in <= 30 days (MEDIUM)
  - `KEY-001` / `KEY-002`: Weak RSA (< 2048-bit) (CRITICAL)
  - `SIG-001` / `SIG-002`: Broken / Deprecated signatures (MD5, SHA-1) (CRITICAL / HIGH)
  - `AUTH-001`: Self-signed certificates (HIGH)
  - `SAN-001`: Missing Subject Alternative Name (MEDIUM)
  - `CHAIN-001`: Broken or incomplete certificate chain (HIGH)

## Quick Usage

```python
from backend.cert_analysis import analyze_certificate

# Input can be:
# - raw DER bytes (from TLS handshake)
# - PEM string
# - list of DER bytes / PEM strings (full chain: [leaf, intermediate, root])

result = analyze_certificate(cert_data)

print(result["summary"]["security_score"])  # e.g., 100
print(result["summary"]["risk_level"])      # "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
print(result["security_analysis"]["findings"])
```

## How to Test
Run the test suite from the root directory:
```bash
python test_cert_analysis.py
```
