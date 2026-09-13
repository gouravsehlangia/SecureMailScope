import random
import hashlib
import time

def validate_session(s):
    """
    Validates a generated mock session for logical and cryptographic consistency.
    Raises ValueError if impossible combinations are found.
    """
    # 1. Port & Protocol Match
    port = s["server_port"]
    proto = s["protocol"]
    is_tls = s["tls_present"]
    
    if proto == "SMTP" and port not in (25, 587):
        raise ValueError(f"Invalid SMTP port {port}")
    if proto == "SMTPS" and port != 465:
        raise ValueError(f"Invalid SMTPS port {port}")
    if proto == "IMAP" and port != 143:
        raise ValueError(f"Invalid IMAP port {port}")
    if proto == "IMAPS" and port != 993:
        raise ValueError(f"Invalid IMAPS port {port}")
    if proto == "POP3" and port != 110:
        raise ValueError(f"Invalid POP3 port {port}")
    if proto == "POP3S" and port != 995:
        raise ValueError(f"Invalid POP3S port {port}")
        
    # 2. TLS & Encryption state
    if is_tls:
        if not s["tls_version"]:
            raise ValueError("TLS present but no version")
        if not s["cipher_suite"]:
            raise ValueError("TLS present but no cipher suite")
        if s["protocol"] in ("IMAP", "POP3") and not s.get("starttls_used"):
            raise ValueError(f"Plaintext protocol {proto} marked as TLS without STARTTLS")
    else:
        if s["tls_version"] or s["cipher_suite"]:
            raise ValueError("Plaintext session has TLS info")
            
    # 3. TLS Version & Cipher constraints
    tls = s["tls_version"]
    cipher = s["cipher_suite"]
    pfs = s["forward_secrecy"]
    key_ex = s["key_exchange"]
    
    if is_tls:
        if tls == "TLS 1.3":
            if "SHA384" not in cipher and "SHA256" not in cipher:
                raise ValueError(f"Invalid TLS 1.3 cipher {cipher}")
            if not pfs:
                raise ValueError("TLS 1.3 must have PFS")
        if tls in ("TLS 1.0", "TLS 1.1"):
            if "GCM" in cipher or "CHACHA" in cipher:
                raise ValueError(f"{tls} using modern cipher {cipher}")
                
        # 4. PFS & Key Exchange
        if pfs and key_ex == "RSA":
            raise ValueError("PFS = Yes with RSA key exchange")
        if not pfs and key_ex in ("ECDHE", "DHE"):
            raise ValueError(f"PFS = No with {key_ex}")
            
    # 5. Certificates
    cert_key = s["cert_key_length"]
    if is_tls:
        if cert_key not in (0, 1024, 2048, 3072, 4096, 256, 384):
            raise ValueError(f"Invalid cert key size {cert_key}")
        if s["cert_expired"] and "Expired certificate" not in s["rule_violations"]:
            raise ValueError("Expired certificate but no violation")
            
    return True


def calculate_risk(s) -> dict:
    score = 0
    violations = []
    
    if not s["tls_present"]:
        if s["protocol"] in ("IMAP", "POP3", "SMTP"):
            score += 80
            violations.append("Unencrypted plaintext session detected")
    else:
        tls = s["tls_version"]
        cipher = s["cipher_suite"]
        pfs = s["forward_secrecy"]
        
        if tls in ("TLS 1.0", "TLS 1.1"):
            score += 60
            violations.append(f"Deprecated protocol {tls}")
            
        if "3DES" in cipher or "RC4" in cipher:
            score += 40
            violations.append(f"Weak cipher suite {cipher}")
            
        if not pfs and tls not in ("TLS 1.0", "TLS 1.1"):
            score += 30
            violations.append(f"Lack of Perfect Forward Secrecy due to {s['key_exchange']} key exchange")
            
        if s["cert_expired"]:
            score += 50
            violations.append("Expired certificate")
            
        if s["cert_key_length"] == 1024:
            score += 40
            violations.append("Weak certificate key size (1024-bit RSA)")
            
    # Cap at 100
    score = min(100, score)
    
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"
        
    s["risk_score"] = score
    s["raw_score"] = score
    s["risk_level"] = level
    s["rule_violations"] = violations
    s["security_rating"] = "INSECURE" if score >= 25 else "SECURE"
    return s


def build_session(protocol, tls_type, cert_type, anomaly=False):
    """
    Builds a single coherent session based on requested characteristics.
    tls_type: 'modern', 'legacy', 'none'
    cert_type: 'secure', 'expired', 'weak'
    """
    s = {
        "session_id": f"sess_{random.randint(1000, 9999)}_{protocol}_{random.randint(10000, 60000)}",
        "protocol": protocol,
        "starttls_used": False,
        "data_incomplete": False,
        "anomaly_flag": anomaly,
        "anomaly_score": round(random.uniform(0.6, 0.9) if anomaly else random.uniform(-0.5, 0.2), 2),
        "reasons": [],
        "ai_recommendation": "Maintain secure configuration." if not anomaly else "Review anomaly detection logs.",
        "sni": "mail.example.com",
        "client_ip": f"192.168.50.{random.randint(10, 200)}",
        "server_ip": f"10.0.10.{random.randint(5, 20)}",
        "client_port": random.randint(49152, 65535)
    }

    # Ports
    port_map = {
        "SMTP": [25, 587], "SMTPS": [465],
        "IMAP": [143], "IMAPS": [993],
        "POP3": [110], "POP3S": [995]
    }
    s["server_port"] = random.choice(port_map[protocol])

    # Handle TLS
    if tls_type == "none":
        s["tls_present"] = False
        s["tls_version"] = ""
        s["cipher_suite"] = ""
        s["key_exchange"] = ""
        s["forward_secrecy"] = False
        s["cert_key_length"] = 0
        s["cert_expired"] = False
        s["cert_chain_valid"] = True
        s["handshake_duration_ms"] = 0
        s["is_aead"] = False
        s["encryption_algorithm"] = "NONE"
        s["mac_algorithm"] = "NONE"
        
        if anomaly:
            s["reasons"].append("Unexpected plaintext session in secure environment.")
    else:
        s["tls_present"] = True
        s["handshake_duration_ms"] = random.randint(50, 400)
        
        if protocol in ("SMTP", "IMAP", "POP3") and s["server_port"] in (25, 587, 143, 110):
            s["starttls_used"] = True

        if tls_type == "modern":
            s["tls_version"] = random.choice(["TLS 1.2", "TLS 1.3"])
            if s["tls_version"] == "TLS 1.3":
                s["cipher_suite"] = random.choice(["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"])
                s["key_exchange"] = "ECDHE"
            else:
                s["cipher_suite"] = random.choice(["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"])
                s["key_exchange"] = "ECDHE"
            s["forward_secrecy"] = True
        else: # legacy
            s["tls_version"] = random.choice(["TLS 1.0", "TLS 1.1", "TLS 1.2"])
            if s["tls_version"] == "TLS 1.2":
                s["cipher_suite"] = "AES256-SHA256"
                s["key_exchange"] = "RSA"
            else:
                s["cipher_suite"] = random.choice(["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_MD5", "AES128-SHA"])
                s["key_exchange"] = "RSA"
            s["forward_secrecy"] = False
            
        s["is_aead"] = "GCM" in s["cipher_suite"] or "CHACHA" in s["cipher_suite"]
        s["encryption_algorithm"] = "AES" if "AES" in s["cipher_suite"] else "3DES" if "3DES" in s["cipher_suite"] else "RC4" if "RC4" in s["cipher_suite"] else "CHACHA20"
        s["mac_algorithm"] = "SHA384" if "SHA384" in s["cipher_suite"] else "SHA256" if "SHA256" in s["cipher_suite"] else "SHA" if "SHA" in s["cipher_suite"] else "MD5" if "MD5" in s["cipher_suite"] else "NONE"

        # Certificates
        if cert_type == "secure":
            s["cert_key_length"] = random.choice([2048, 4096])
            s["cert_expired"] = False
            s["cert_chain_valid"] = True
        elif cert_type == "weak":
            s["cert_key_length"] = 1024
            s["cert_expired"] = False
            s["cert_chain_valid"] = True
        elif cert_type == "expired":
            s["cert_key_length"] = 2048
            s["cert_expired"] = True
            s["cert_chain_valid"] = False

    s = calculate_risk(s)
    validate_session(s)
    return s


def generate_mock_sessions(filename: str):
    # Hash filename to deterministically pick a profile
    h = int(hashlib.md5(filename.encode()).hexdigest(), 16)
    profiles = ["A", "B", "C", "D", "E"]
    profile = profiles[h % len(profiles)]
    
    sessions = []
    
    if profile == "A":
        # Profile A — Secure Enterprise Mail
        sessions.append(build_session("SMTPS", "modern", "secure"))
        sessions.append(build_session("IMAPS", "modern", "secure"))
        sessions.append(build_session("SMTP", "modern", "secure")) # STARTTLS
        
    elif profile == "B":
        # Profile B — Legacy/Insecure Mail
        sessions.append(build_session("SMTP", "legacy", "secure")) # TLS 1.0/1.1
        sessions.append(build_session("IMAP", "none", "secure"))   # Plaintext
        sessions.append(build_session("POP3", "none", "secure"))   # Plaintext
        
    elif profile == "C":
        # Profile C — Mixed Enterprise Environment
        sessions.append(build_session("SMTPS", "modern", "secure"))
        sessions.append(build_session("IMAPS", "modern", "secure"))
        sessions.append(build_session("SMTP", "legacy", "weak", anomaly=True))
        sessions.append(build_session("IMAP", "none", "secure", anomaly=True))
        
    elif profile == "D":
        # Profile D — Certificate Problem
        sessions.append(build_session("SMTPS", "modern", "expired"))
        sessions.append(build_session("IMAPS", "modern", "weak"))
        
    elif profile == "E":
        # Profile E — TLS Configuration Problem (No PFS)
        sessions.append(build_session("SMTPS", "legacy", "secure")) # TLS 1.2 with RSA key ex
        sessions.append(build_session("SMTP", "legacy", "secure"))
        
    return sessions

if __name__ == "__main__":
    # Test generation and validation locally
    for p in ["file1.pcap", "legacy.pcap", "test.pcapng", "cert_issue.pcap", "config.pcap"]:
        res = generate_mock_sessions(p)
        print(f"Generated {len(res)} sessions for {p}")
