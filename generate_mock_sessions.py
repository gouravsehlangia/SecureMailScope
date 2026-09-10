#!/usr/bin/env python3
import json
import random

def generate_mock_sessions(count=200):
    random.seed(42)

    # Standard cipher configurations: (cipher_suite, key_exchange, forward_secrecy, compatible_tls_versions)
    standard_ciphers = [
        ("TLS_AES_256_GCM_SHA384", "X25519", True, ["TLS 1.3"]),
        ("TLS_AES_128_GCM_SHA256", "ECDHE", True, ["TLS 1.3"]),
        ("TLS_CHACHA20_POLY1305_SHA256", "X25519", True, ["TLS 1.3"]),
        ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", True, ["TLS 1.2"]),
        ("ECDHE-RSA-AES256-GCM-SHA384", "ECDHE", True, ["TLS 1.2"]),
        ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE", True, ["TLS 1.2"]),
        ("DHE-RSA-AES128-GCM-SHA256", "DHE", True, ["TLS 1.2", "TLS 1.1"]),
        ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", False, ["TLS 1.2", "TLS 1.1"]),
        ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", False, ["TLS 1.2", "TLS 1.1"]),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", False, ["TLS 1.1", "TLS 1.0"]),
        ("TLS_RSA_WITH_RC4_128_SHA", "RSA", False, ["TLS 1.0"]),
        ("TLS_RSA_WITH_RC4_128_MD5", "RSA", False, ["TLS 1.0"]),
    ]

    # One-off or rare outlier cipher configurations
    outliers = [
        ("TLS_DH_anon_WITH_RC4_128_MD5", "DH_anon", False, "TLS 1.0", 512, True, False, 1250), # Unencrypted/anon + RC4 outlier
        ("TLS_RSA_WITH_NULL_SHA256", "RSA", False, "TLS 1.2", 1024, True, False, 980),        # Null encryption outlier
    ]

    # Specific designated indexes for outliers out of 200 records
    outlier_indices = {
        45: outliers[0],   # Extremely weak/anon cipher
        112: outliers[1],  # NULL cipher suite
    }

    sessions = []

    for i in range(count):
        session_id = f"sess_{i + 1:03d}"

        if i in outlier_indices:
            cipher, kex, fs, tls_ver, key_len, expired, chain_valid, handshake_ms = outlier_indices[i]
            protocol = "SMTP"
            starttls_used = True
        else:
            # TLS Version distribution (Realistic blend: TLS 1.3 and 1.2 dominant, older present)
            tls_version = random.choices(
                ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"],
                weights=[0.35, 0.45, 0.12, 0.08]
            )[0]

            # Filter ciphers valid for chosen TLS version
            valid_ciphers = [c for c in standard_ciphers if tls_version in c[3]]
            cipher_info = random.choice(valid_ciphers)
            cipher, kex, fs, _ = cipher_info
            tls_ver = tls_version

            # Protocol & STARTTLS
            protocol = random.choice(["SMTPS", "SMTP"])
            starttls_used = True if protocol == "SMTP" else random.choice([True, False])

            # Key length (RSA vs ECDHE/X25519)
            if kex in ["RSA", "DHE"]:
                # Some short RSA keys (1024 or 512 for legacy/weak), standard 2048/4096
                key_len = random.choices([512, 1024, 2048, 4096], weights=[0.05, 0.15, 0.65, 0.15])[0]
            else:
                # Elliptic curve key lengths (e.g. 256, 384, or standard RSA cert key length 2048/4096 behind ECDHE)
                key_len = random.choices([256, 384, 2048, 4096], weights=[0.30, 0.20, 0.40, 0.10])[0]

            # Certificate anomalies
            expired = random.choices([True, False], weights=[0.08, 0.92])[0]
            
            # If cert is expired or key length is 512, higher chance of chain invalidity
            if expired or key_len == 512:
                chain_valid = random.choices([True, False], weights=[0.40, 0.60])[0]
            else:
                chain_valid = random.choices([True, False], weights=[0.95, 0.05])[0]

            # Handshake duration ms (realistic normal distribution with potential spikes)
            base_duration = 30 if tls_ver == "TLS 1.3" else (80 if fs else 120)
            if random.random() < 0.05:  # Occasional high latency outlier
                handshake_ms = random.randint(600, 1800)
            else:
                handshake_ms = max(15, int(random.gauss(base_duration, 25)))

        session_record = {
            "session_id": session_id,
            "protocol": protocol,
            "starttls_used": starttls_used,
            "tls_version": tls_ver,
            "cipher_suite": cipher,
            "key_exchange": kex,
            "forward_secrecy": fs,
            "cert_key_length": key_len,
            "cert_expired": expired,
            "cert_chain_valid": chain_valid,
            "handshake_duration_ms": handshake_ms
        }
        sessions.append(session_record)

    return sessions

if __name__ == "__main__":
    data = generate_mock_sessions(200)
    output_filename = "mock_sessions.json"
    with open(output_filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Successfully generated {len(data)} mock TLS sessions in {output_filename}")
