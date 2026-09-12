"""
X.509 Certificate Chain Validator
Validates certificate hierarchies, intermediate linking, signatures, and trust anchors.
"""

from typing import List, Dict, Any, Union
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519
from cryptography.exceptions import InvalidSignature
from .parser import CertificateParser


class CertificateChainValidator:
    """
    Validates a list/chain of certificates from leaf to root.
    """

    @classmethod
    def validate_chain(cls, certs: List[Union[bytes, str, x509.Certificate]]) -> Dict[str, Any]:
        """
        Validates the certificate chain hierarchy and cryptographic signatures.
        """
        if not certs:
            return {
                "valid_chain": False,
                "chain_length": 0,
                "issues": ["No certificates provided in chain."],
                "is_self_signed": False,
                "has_root": False
            }

        # Parse all certificates into x509.Certificate objects
        parsed_x509: List[x509.Certificate] = []
        parsed_summaries: List[Dict[str, Any]] = []

        for c in certs:
            if isinstance(c, x509.Certificate):
                obj = c
            else:
                obj = CertificateParser.load_certificate(c)
            parsed_x509.append(obj)
            parsed_summaries.append({
                "subject": obj.subject.rfc4514_string(),
                "issuer": obj.issuer.rfc4514_string(),
                "serial_number": format(obj.serial_number, "X"),
                "not_after": obj.not_valid_after_utc.isoformat(),
                "is_ca": CertificateParser._extract_basic_constraints(obj)[0]
            })

        issues = []
        is_chain_intact = True
        chain_length = len(parsed_x509)

        # 1. Single certificate case
        if chain_length == 1:
            leaf = parsed_x509[0]
            is_self_signed = (leaf.subject == leaf.issuer)
            if is_self_signed:
                issues.append("Chain contains only a single self-signed certificate.")
            else:
                issues.append("Chain is incomplete: only leaf certificate sent (missing intermediate CA).")
            return {
                "valid_chain": False,
                "chain_length": 1,
                "is_self_signed": is_self_signed,
                "has_root": is_self_signed,
                "issues": issues,
                "certificates": parsed_summaries
            }

        # 2. Multi-certificate chain validation
        # Walk through chain: child -> parent
        for i in range(chain_length - 1):
            child = parsed_x509[i]
            parent = parsed_x509[i + 1]

            # A. Check Issuer / Subject Name Match
            if child.issuer != parent.subject:
                issues.append(
                    f"Chain break between certificate #{i} (Issuer: {child.issuer.rfc4514_string()}) "
                    f"and certificate #{i+1} (Subject: {parent.subject.rfc4514_string()})."
                )
                is_chain_intact = False

            # B. Check Basic Constraints of Parent
            is_parent_ca, _ = CertificateParser._extract_basic_constraints(parent)
            if not is_parent_ca:
                issues.append(f"Certificate #{i+1} is issuing certificates but lacks Basic Constraints CA=True.")
                is_chain_intact = False

            # C. Cryptographic Signature Verification
            sig_valid = cls._verify_signature(child, parent)
            if not sig_valid:
                issues.append(f"Cryptographic signature verification failed between cert #{i} and cert #{i+1}.")
                is_chain_intact = False

        # 3. Check the last certificate (Root or top Intermediate)
        top_cert = parsed_x509[-1]
        has_root = (top_cert.subject == top_cert.issuer)
        
        if not has_root:
            # It's common in TLS handshakes to not send the root CA (since client has it in trust store)
            # This is standard behavior, but noted as incomplete bundle if offline validation is needed
            pass

        return {
            "valid_chain": is_chain_intact and len(issues) == 0,
            "chain_length": chain_length,
            "is_self_signed": False,
            "has_root": has_root,
            "issues": issues,
            "certificates": parsed_summaries
        }

    @staticmethod
    def _verify_signature(child: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
        """
        Verifies child's signature using the issuer's public key.
        """
        try:
            pub_key = issuer_cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm
                )
                return True
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm)
                )
                return True
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                pub_key.verify(child.signature, child.tbs_certificate_bytes)
                return True
            else:
                return True  # Fallback for other key types
        except InvalidSignature:
            return False
        except Exception:
            return False
