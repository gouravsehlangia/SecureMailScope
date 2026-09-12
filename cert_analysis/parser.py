"""
X.509 Certificate Parser Module
Extracts detailed cryptographic and identity metadata from X.509 certificates (DER / PEM).
"""

import datetime
from typing import Dict, Any, List, Optional, Union
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID


class CertificateParser:
    """Parses X.509 certificates in PEM or DER format."""

    @staticmethod
    def load_certificate(cert_data: Union[bytes, str]) -> x509.Certificate:
        """
        Loads a certificate from bytes (DER or PEM) or string (PEM).
        """
        if isinstance(cert_data, str):
            cert_bytes = cert_data.strip().encode("utf-8")
        else:
            cert_bytes = cert_data

        # Try PEM first
        if b"-----BEGIN CERTIFICATE-----" in cert_bytes:
            return x509.load_pem_x509_certificate(cert_bytes)
        
        # Fallback to DER
        try:
            return x509.load_der_x509_certificate(cert_bytes)
        except Exception:
            # Maybe it is PEM without headers or base64
            import base64
            clean_b64 = b"".join(cert_bytes.split())
            der_bytes = base64.b64decode(clean_b64)
            return x509.load_der_x509_certificate(der_bytes)

    @classmethod
    def parse(cls, cert_input: Union[bytes, str, x509.Certificate]) -> Dict[str, Any]:
        """
        Parses an X.509 certificate into a comprehensive dictionary.
        """
        if isinstance(cert_input, x509.Certificate):
            cert = cert_input
        else:
            cert = cls.load_certificate(cert_input)

        # Subject & Issuer
        subject_dict = cls._name_to_dict(cert.subject)
        issuer_dict = cls._name_to_dict(cert.issuer)

        # Public Key Info
        public_key = cert.public_key()
        key_type, key_size_bits, curve_name = cls._extract_public_key_info(public_key)

        # Signature Algorithm & Hash
        sig_algo_name = cert.signature_algorithm_oid._name if cert.signature_algorithm_oid else "Unknown"
        hash_algo_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "None"

        # Validity Dates (timezone-aware UTC)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        days_remaining = (not_after - now).days
        is_expired = now > not_after
        not_yet_valid = now < not_before

        # Extensions: SAN, Key Usage, Basic Constraints
        san_list = cls._extract_san(cert)
        is_ca, path_length = cls._extract_basic_constraints(cert)
        key_usages = cls._extract_key_usage(cert)
        extended_key_usages = cls._extract_extended_key_usage(cert)

        # Is Self-Signed check (basic level: subject == issuer)
        is_self_signed = (cert.subject == cert.issuer)

        # Fingerprints
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()

        return {
            "serial_number": format(cert.serial_number, "X"),
            "version": cert.version.name,
            "subject": {
                "common_name": subject_dict.get("CN"),
                "organization": subject_dict.get("O"),
                "organizational_unit": subject_dict.get("OU"),
                "country": subject_dict.get("C"),
                "state": subject_dict.get("ST"),
                "locality": subject_dict.get("L"),
                "rfc4514_string": cert.subject.rfc4514_string(),
                "raw_attributes": subject_dict
            },
            "issuer": {
                "common_name": issuer_dict.get("CN"),
                "organization": issuer_dict.get("O"),
                "country": issuer_dict.get("C"),
                "rfc4514_string": cert.issuer.rfc4514_string(),
                "raw_attributes": issuer_dict
            },
            "validity": {
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": days_remaining,
                "is_expired": is_expired,
                "not_yet_valid": not_yet_valid,
                "validity_period_days": (not_after - not_before).days
            },
            "public_key": {
                "algorithm": key_type,
                "key_size_bits": key_size_bits,
                "curve": curve_name
            },
            "signature": {
                "algorithm": sig_algo_name,
                "hash_algorithm": hash_algo_name
            },
            "extensions": {
                "subject_alternative_names": san_list,
                "is_ca": is_ca,
                "path_length": path_length,
                "key_usage": key_usages,
                "extended_key_usage": extended_key_usages
            },
            "is_self_signed": is_self_signed,
            "fingerprints": {
                "sha256": fingerprint_sha256,
                "sha1": fingerprint_sha1
            }
        }

    @staticmethod
    def _name_to_dict(name: x509.Name) -> Dict[str, str]:
        mapping = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.LOCALITY_NAME: "L",
            NameOID.EMAIL_ADDRESS: "EMAIL"
        }
        res = {}
        for attr in name:
            key = mapping.get(attr.oid, attr.oid.dotted_string)
            res[key] = str(attr.value)
        return res

    @staticmethod
    def _extract_public_key_info(pub_key):
        if isinstance(pub_key, rsa.RSAPublicKey):
            return "RSA", pub_key.key_size, None
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            return "ECC", pub_key.key_size, pub_key.curve.name
        elif isinstance(pub_key, dsa.DSAPublicKey):
            return "DSA", pub_key.key_size, None
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256, "Ed25519"
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            return "Ed448", 448, "Ed448"
        return "Unknown", None, None

    @staticmethod
    def _extract_san(cert: x509.Certificate) -> List[str]:
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns = [str(x) for x in ext.value.get_values_for_type(x509.DNSName)]
            ips = [str(x) for x in ext.value.get_values_for_type(x509.IPAddress)]
            return dns + ips
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _extract_basic_constraints(cert: x509.Certificate):
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            return ext.value.ca, ext.value.path_length
        except x509.ExtensionNotFound:
            return False, None

    @staticmethod
    def _extract_key_usage(cert: x509.Certificate) -> List[str]:
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            usages = []
            val = ext.value
            for attr in [
                "digital_signature", "content_commitment", "key_encipherment",
                "data_encipherment", "key_agreement", "key_cert_sign",
                "crl_sign", "encipher_only", "decipher_only"
            ]:
                try:
                    if getattr(val, attr):
                        usages.append(attr)
                except ValueError:
                    pass
            return usages
        except x509.ExtensionNotFound:
            return []

    @staticmethod
    def _extract_extended_key_usage(cert: x509.Certificate) -> List[str]:
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            return [getattr(oid, "_name", str(oid)) for oid in ext.value]
        except x509.ExtensionNotFound:
            return []
