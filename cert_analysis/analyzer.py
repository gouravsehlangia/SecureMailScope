"""
Main Certificate Analyzer Module
Unifies parsing, chain validation, and rule evaluation into a single entry-point.
"""

from typing import List, Dict, Any, Union
from .parser import CertificateParser
from .rules import CertificateRuleEngine
from .chain_validator import CertificateChainValidator


class CertificateAnalyzer:
    """
    Complete X.509 Certificate and Chain Analysis Suite.
    """

    @classmethod
    def analyze(cls, cert_input: Union[bytes, str, List[Union[bytes, str]]]) -> Dict[str, Any]:
        """
        Analyze a single certificate or a certificate chain.

        :param cert_input: DER/PEM bytes, string, or list of DER/PEM certificates (ordered Leaf -> Root).
        :return: Standardized JSON-ready dictionary of findings, metrics, and security assessment.
        """
        # Normalize input to a list of certs
        if isinstance(cert_input, list):
            cert_list = cert_input
        else:
            cert_list = [cert_input]

        if not cert_list:
            return {
                "status": "error",
                "message": "No certificate data provided."
            }

        # 1. Parse Leaf Certificate
        leaf_raw = cert_list[0]
        try:
            leaf_info = CertificateParser.parse(leaf_raw)
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to parse leaf certificate: {str(e)}"
            }

        # 2. Chain Validation
        chain_validation = CertificateChainValidator.validate_chain(cert_list)

        # 3. Rule Engine Analysis
        rule_results = CertificateRuleEngine.evaluate(leaf_info, is_leaf=True)

        # Incorporate chain issues into rule findings if any
        if not chain_validation["valid_chain"]:
            for issue in chain_validation["issues"]:
                # Check if it's already represented (e.g. self-signed)
                if "self-signed" in issue.lower() and leaf_info.get("is_self_signed"):
                    continue
                rule_results["findings"].append({
                    "rule_id": "CHAIN-001",
                    "name": "Invalid or Incomplete Certificate Chain",
                    "severity": "HIGH",
                    "description": issue,
                    "recommendation": "Configure the server to provide the full intermediate certificate chain."
                })
            # Recompute score penalty if new findings were added
            penalty = sum(CertificateRuleEngine.SEVERITY_WEIGHTS.get(f["severity"], 0) for f in rule_results["findings"])
            rule_results["score"] = max(0, 100 - penalty)
            if rule_results["score"] >= 90:
                rule_results["risk_level"] = "SAFE"
            elif rule_results["score"] >= 75:
                rule_results["risk_level"] = "LOW"
            elif rule_results["score"] >= 50:
                rule_results["risk_level"] = "MEDIUM"
            elif rule_results["score"] >= 25:
                rule_results["risk_level"] = "HIGH"
            else:
                rule_results["risk_level"] = "CRITICAL"

            rule_results["findings_count"] = len(rule_results["findings"])

        # 4. Assembling unified analysis payload
        return {
            "status": "success",
            "summary": {
                "subject_cn": leaf_info["subject"]["common_name"],
                "issuer_cn": leaf_info["issuer"]["common_name"],
                "key_algorithm": leaf_info["public_key"]["algorithm"],
                "key_size": leaf_info["public_key"]["key_size_bits"],
                "signature_algorithm": leaf_info["signature"]["algorithm"],
                "days_remaining": leaf_info["validity"]["days_remaining"],
                "is_expired": leaf_info["validity"]["is_expired"],
                "is_self_signed": leaf_info["is_self_signed"],
                "chain_length": chain_validation["chain_length"],
                "chain_valid": chain_validation["valid_chain"],
                "security_score": rule_results["score"],
                "risk_level": rule_results["risk_level"]
            },
            "leaf_certificate": leaf_info,
            "chain_validation": chain_validation,
            "security_analysis": rule_results
        }
