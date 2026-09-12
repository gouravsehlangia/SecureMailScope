"""
Certificate Analysis Module for TLS/SSL & Email Security Auditing.
"""

from .parser import CertificateParser
from .rules import CertificateRuleEngine
from .chain_validator import CertificateChainValidator
from .analyzer import CertificateAnalyzer

analyze_certificate = CertificateAnalyzer.analyze

__all__ = [
    "CertificateParser",
    "CertificateRuleEngine",
    "CertificateChainValidator",
    "CertificateAnalyzer",
    "analyze_certificate",
]
