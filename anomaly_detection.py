#!/home/gourav/myai/bin/python
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, OrdinalEncoder
from typing import List, Dict, Any

def detect_anomalies(sessions: List[Dict[str, Any]], contamination: float = 0.05) -> List[Dict[str, Any]]:
    """
    Fits an IsolationForest model on TLS email session features and returns
    each session enriched with `anomaly_flag`, `anomaly_score`, and feature-level explanations.
    """
    df = pd.DataFrame(sessions)

    # 1. Feature Engineering & Numerical Encoding
    tls_map = {"TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}
    df["tls_version_num"] = df["tls_version"].map(tls_map).fillna(0)

    le_cipher = LabelEncoder()
    df["cipher_suite_num"] = le_cipher.fit_transform(df["cipher_suite"])

    le_kex = LabelEncoder()
    df["key_exchange_num"] = le_kex.fit_transform(df["key_exchange"])

    # Boolean & Protocol encoding
    df["protocol_num"] = (df["protocol"] == "SMTPS").astype(int)
    df["starttls_used_num"] = df["starttls_used"].astype(int)
    df["forward_secrecy_num"] = df["forward_secrecy"].astype(int)
    df["cert_expired_num"] = df["cert_expired"].astype(int)
    df["cert_chain_valid_num"] = df["cert_chain_valid"].astype(int)

    # Feature matrix for IsolationForest
    feature_cols = [
        "tls_version_num",
        "cipher_suite_num",
        "key_exchange_num",
        "protocol_num",
        "starttls_used_num",
        "forward_secrecy_num",
        "cert_key_length",
        "cert_expired_num",
        "cert_chain_valid_num",
        "handshake_duration_ms"
    ]

    X = df[feature_cols].copy()

    # 2. Fit IsolationForest Model
    model = IsolationForest(contamination=contamination, random_state=42)
    predictions = model.fit_predict(X)  # -1 for anomaly, 1 for normal
    raw_scores = model.decision_function(X) # lower score means more anomalous

    # Anomaly score calculation (inverted so higher positive value = higher anomaly)
    # Normalized score scale where higher = more anomalous
    scores = -raw_scores

    df["anomaly_flag"] = predictions == -1
    df["anomaly_score"] = np.round(scores, 4)

    # 3. Population Feature Statistics for Explanation Generation
    means = X.mean()
    stds = X.std().replace(0, 1)  # avoid div by zero
    cipher_counts = df["cipher_suite"].value_counts()
    kex_counts = df["key_exchange"].value_counts()

    enriched_sessions = []

    for idx, row in df.iterrows():
        session_id = row["session_id"]
        is_anomaly = bool(row["anomaly_flag"])
        score = float(row["anomaly_score"])
        reasons = []

        if is_anomaly:
            # Check Handshake Duration Z-score
            h_dur = row["handshake_duration_ms"]
            h_z = (h_dur - means["handshake_duration_ms"]) / stds["handshake_duration_ms"]
            if h_z > 2.0:
                reasons.append(f"Abnormally high handshake duration ({h_dur}ms, avg: {means['handshake_duration_ms']:.1f}ms, Z={h_z:.2f})")
            elif h_dur < 15:
                reasons.append(f"Unusually fast handshake duration ({h_dur}ms)")

            # Check Key Length
            key_len = row["cert_key_length"]
            if key_len < 1024:
                reasons.append(f"Extremely weak certificate key length ({key_len} bits)")

            # Check Cipher Suite Frequency / Outliers
            cipher_name = row["cipher_suite"]
            cipher_freq = cipher_counts[cipher_name]
            if cipher_freq <= 2:
                reasons.append(f"Rare/outlier cipher suite ('{cipher_name}' used only {cipher_freq} time(s))")

            # Check Key Exchange Frequency
            kex_name = row["key_exchange"]
            kex_freq = kex_counts[kex_name]
            if kex_freq <= 2:
                reasons.append(f"Unusual key exchange mechanism ('{kex_name}')")

            # Check Compound Legacy Security Attributes
            if row["tls_version"] in ["TLS 1.0", "TLS 1.1"] and not row["forward_secrecy"]:
                reasons.append(f"Legacy {row['tls_version']} protocol without Forward Secrecy")

            if row["cert_expired"] and not row["cert_chain_valid"]:
                reasons.append("Combined certificate failure (Expired AND Invalid Chain)")

            # Fallback if specific threshold missed
            if not reasons:
                reasons.append("Multi-attribute isolation anomaly in feature space")

        record = {
            "session_id": session_id,
            "anomaly_flag": is_anomaly,
            "anomaly_score": score,
            "reasons": reasons if is_anomaly else [],
            "raw_session": sessions[idx]
        }
        enriched_sessions.append(record)

    return enriched_sessions

if __name__ == "__main__":
    import os

    input_file = "mock_sessions.json"
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found. Please run generate_mock_sessions.py first.")
        exit(1)

    with open(input_file, "r") as f:
        sessions = json.load(f)

    results = detect_anomalies(sessions, contamination=0.05)
    anomalies = [r for r in results if r["anomaly_flag"]]

    print("=" * 70)
    print("           SECURE MAIL SCOPE - ISOLATION FOREST ANOMALY DETECTION")
    print("=" * 70)
    print(f"Total Sessions Analyzed : {len(results)}")
    print(f"Contamination Threshold : 0.05 (5%)")
    print(f"Anomalies Flagged       : {len(anomalies)} sessions")
    print("-" * 70)

    print("\n[FLAGGED ANOMALOUS SESSIONS]")
    for idx, item in enumerate(sorted(anomalies, key=lambda x: x["anomaly_score"], reverse=True), 1):
        s = item["raw_session"]
        print(f"\n{idx}. Session ID: {item['session_id']}")
        print(f"   Anomaly Score : {item['anomaly_score']:.4f}")
        print(f"   Protocol/TLS  : {s['protocol']} | {s['tls_version']} | Cipher: {s['cipher_suite']}")
        print(f"   Key Len / PFS : {s['cert_key_length']} bits | Forward Secrecy: {s['forward_secrecy']}")
        print(f"   Handshake Dur : {s['handshake_duration_ms']} ms")
        print(f"   Reasons Why Flagged:")
        for r in item["reasons"]:
            print(f"     * {r}")

    print("=" * 70)
