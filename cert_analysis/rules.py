"""
Weak-Crypto Rule Engine for X.509 Certificates
Evaluates parsed certificate data against security standards and security best practices.
"""

from typing import Dict, Any, List


class CertificateRuleEngine:
    """
    Rule engine detecting weak cryptography, invalid validity periods,
    and configuration flaws in X.509 certificates.
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 40,
        "HIGH": 25,
        "MEDIUM": 15,
        "LOW": 5,
        "INFO": 0
    }

    @classmethod
    def evaluate(cls, cert_info: Dict[str, Any], is_leaf: bool = True) -> Dict[str, Any]:
        """
        Runs all security rules against the parsed certificate metadata.
        Returns risk score, risk level, and detailed list of findings.
        """
        findings: List[Dict[str, Any]] = []

        # 1. Expiration & Validity Checks
        validity = cert_info.get("validity", {})
        if validity.get("is_expired"):
            findings.append({
                "rule_id": "EXP-001",
                "name": "Certificate Expired",
                "severity": "CRITICAL",
                "description": f"Certificate expired {abs(validity.get('days_remaining', 0))} days ago (expired on {validity.get('not_after')}).",
                "recommendation": "Renew and replace the certificate immediately with an active certificate."
            })
        elif validity.get("not_yet_valid"):
            findings.append({
                "rule_id": "EXP-002",
                "name": "Certificate Not Yet Valid",
                "severity": "HIGH",
                "description": f"Certificate is not valid until {validity.get('not_before')}.",
                "recommendation": "Check system clock synchronization or issue date."
            })
        elif validity.get("days_remaining", 999) <= 7:
            findings.append({
                "rule_id": "EXP-003",
                "name": "Imminent Expiration (< 7 days)",
                "severity": "HIGH",
                "description": f"Certificate expires in {validity.get('days_remaining')} days.",
                "recommendation": "Urgent certificate renewal required to prevent service disruption."
            })
        elif validity.get("days_remaining", 999) <= 30:
            findings.append({
                "rule_id": "EXP-004",
                "name": "Certificate Expiring Soon (< 30 days)",
                "severity": "MEDIUM",
                "description": f"Certificate will expire in {validity.get('days_remaining')} days.",
                "recommendation": "Plan certificate renewal."
            })

        # Check maximum validity length (CAB Forum baseline: max 398 days for TLS leaf certs)
        if is_leaf and validity.get("validity_period_days", 0) > 398:
            findings.append({
                "rule_id": "EXP-005",
                "name": "Excessive Validity Lifetime",
                "severity": "LOW",
                "description": f"Validity period is {validity.get('validity_period_days')} days. Modern industry standards restrict public leaf certificates to 398 days max.",
                "recommendation": "Issue certificates with a validity duration not exceeding 1 year (398 days)."
            })

        # 2. Public Key Strength Checks
        pub_key = cert_info.get("public_key", {})
        algo = pub_key.get("algorithm", "").upper()
        key_size = pub_key.get("key_size_bits") or 0

        if algo == "RSA":
            if key_size < 1024:
                findings.append({
                    "rule_id": "KEY-001",
                    "name": "Dangerously Short RSA Key (< 1024 bits)",
                    "severity": "CRITICAL",
                    "description": f"RSA key size of {key_size} bits is trivially factorable and completely broken.",
                    "recommendation": "Upgrade to RSA 2048-bit or 4096-bit, or switch to ECDSA (P-256/P-384)."
                })
            elif key_size < 2048:
                findings.append({
                    "rule_id": "KEY-002",
                    "name": "Weak RSA Key Length (< 2048 bits)",
                    "severity": "CRITICAL",
                    "description": f"RSA key size of {key_size} bits is considered insecure by modern cryptographic standards.",
                    "recommendation": "Upgrade to RSA 2048-bit minimum (or preferably 4096-bit or ECDSA P-256)."
                })
        elif algo == "ECC":
            if key_size < 256:
                findings.append({
                    "rule_id": "KEY-003",
                    "name": "Weak Elliptic Curve Key Length (< 256 bits)",
                    "severity": "HIGH",
                    "description": f"ECC curve with key length {key_size} bits is below modern standards.",
                    "recommendation": "Use SECP256R1 (NIST P-256), SECP384R1, or Curve25519."
                })
        elif algo == "DSA":
            findings.append({
                "rule_id": "KEY-004",
                "name": "Deprecated DSA Public Key Algorithm",
                "severity": "MEDIUM",
                "description": "DSA algorithm is legacy and deprecated for modern TLS connections.",
                "recommendation": "Migrate to RSA (>=2048-bit) or ECDSA."
            })

        # 3. Signature & Hash Algorithm Checks
        sig = cert_info.get("signature", {})
        hash_algo = (sig.get("hash_algorithm") or "").lower()
        sig_algo = (sig.get("algorithm") or "").lower()

        if "md5" in hash_algo or "md5" in sig_algo:
            findings.append({
                "rule_id": "SIG-001",
                "name": "Broken Signature Hash Algorithm (MD5)",
                "severity": "CRITICAL",
                "description": "Certificate was signed using MD5, which suffers from known practical collision attacks.",
                "recommendation": "Re-issue certificate using SHA-256 or SHA-384."
            })
        elif "sha1" in hash_algo or "sha1" in sig_algo or "sha-1" in sig_algo:
            findings.append({
                "rule_id": "SIG-002",
                "name": "Weak Signature Hash Algorithm (SHA-1)",
                "severity": "HIGH",
                "description": "Certificate was signed using SHA-1, which is cryptographically deprecated due to collision risks.",
                "recommendation": "Re-issue certificate using SHA-256, SHA-384, or SHA-512."
            })

        # 4. Identity & SAN Checks
        if is_leaf:
            san = cert_info.get("extensions", {}).get("subject_alternative_names", [])
            if not san:
                findings.append({
                    "rule_id": "SAN-001",
                    "name": "Missing Subject Alternative Names (SAN)",
                    "severity": "MEDIUM",
                    "description": "Certificate lacks the Subject Alternative Name (SAN) extension. Modern TLS clients reject certificates without SAN even if Common Name (CN) is present.",
                    "recommendation": "Include SAN extension with all valid DNS hostnames and IPs."
                })

            if cert_info.get("is_self_signed"):
                findings.append({
                    "rule_id": "AUTH-001",
                    "name": "Self-Signed Server Certificate",
                    "severity": "HIGH",
                    "description": "Certificate is self-signed (Issuer matches Subject). Clients without custom trust anchors will fail verification with untrusted root errors.",
                    "recommendation": "Use certificates issued by a trusted public CA (such as Let's Encrypt) or an internal managed PKI."
                })

        # Calculate Risk Score (Base: 100, deduct penalties)
        penalty = sum(cls.SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
        score = max(0, 100 - penalty)

        if score >= 90:
            risk_level = "SAFE"
        elif score >= 75:
            risk_level = "LOW"
        elif score >= 50:
            risk_level = "MEDIUM"
        elif score >= 25:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # Severity counts
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        return {
            "score": score,
            "risk_level": risk_level,
            "findings_count": len(findings),
            "severity_breakdown": counts,
            "findings": findings
        }
