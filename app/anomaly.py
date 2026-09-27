"""
Unsupervised Anomaly Detection Module using Isolation Forest.
Operates on numeric session telemetry as an independent indicator.
Provides documented fallback (z-score / IQR) for small sample sizes.
"""

import numpy as np
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest


import hashlib

FEATURE_NAMES = [
    "handshake_duration_ms",
    "offered_cipher_count",
    "cipher_rarity_score",
    "payload_bytes_avg",
    "payload_bytes_var",
    "packet_count",
    "tls_version_encoded",
    "cipher_suite_encoded",
    "ja3_hash_encoded"
]


def encode_session_features(s: Dict[str, Any]) -> List[float]:
    """
    Deterministically extracts and encodes a 9-dimensional numeric feature vector for a session.
    
    Feature Specifications:
    1. handshake_duration_ms (Continuous float):
       - Source: Handshake latency (t_ServerHello - t_ClientHello) * 1000.0.
       - Missing-value: 0.0 (for unencrypted or aborted sessions).
       - Statistical meaning: Identifies network anomalies, slow reads, or proxy delays.
    2. offered_cipher_count (Discrete float):
       - Source: Length of client offered ciphersuite vector.
       - Missing-value: 0.0.
       - Statistical meaning: Differentiates standard browsers/MUAs (15-30 ciphers) from scanner bots (1-2 ciphers).
    3. cipher_rarity_score (Continuous float in [0.1, 0.95]):
       - Source: Negotiated cipher security class (0.95 broken, 0.60 CBC, 0.35 ChaCha, 0.15 AES-GCM).
       - Missing-value: 0.1.
       - Statistical meaning: Continuous heuristic proxy for cryptographic deprecation.
    4. payload_bytes_avg (Continuous float):
       - Source: Mean application-layer TCP payload bytes per packet.
       - Missing-value: 0.0.
       - Statistical meaning: Measures message volume and typical transaction density.
    5. payload_bytes_var (Continuous float):
       - Source: Variance of application-layer TCP payload bytes across stream frames.
       - Missing-value: 0.0.
       - Statistical meaning: Identifies bulk data transfer vs conversational handshakes.
    6. packet_count (Discrete float):
       - Source: Total frame count reassembled for this TCP stream.
       - Missing-value: 0.0.
       - Statistical meaning: Session duration and exchange complexity.
    7. tls_version_encoded (Ordinal float in [0.0, 5.0]):
       - Source: Negotiated TLS version string.
       - Encoding: Cleartext/None = 0.0, SSL 3.0 = 1.0, TLS 1.0 = 2.0, TLS 1.1 = 3.0, TLS 1.2 = 4.0, TLS 1.3 = 5.0.
       - Missing-value: 0.0.
       - Statistical meaning: Monotonic ordinal ranking reflecting protocol security progression.
    8. cipher_suite_encoded (Categorical tier float):
       - Source: Negotiated cipher suite standard name.
       - Encoding: Defensible security tier bins:
           0.0 = None / Cleartext
           1.0 = Broken / Prohibited primitive (RC4, 3DES, DES, NULL, EXPORT, MD5)
           2.0 = Non-AEAD CBC mode
           3.0 = Modern ChaCha20-Poly1305 AEAD
           4.0 = Modern AES-128-GCM AEAD
           5.0 = Modern AES-256-GCM AEAD
           Fallback = 10.0 + deterministic MD5 bucket (avoids process-level hash randomization)
       - Missing-value: 0.0.
       - Statistical meaning: Cryptographic capability tiering without arbitrary hash distances.
    9. ja3_hash_encoded (Continuous float in [0.0, 1.0]):
       - Source: Salesforce JA3 32-character hex MD5 digest.
       - Encoding: Upper 16-bit hex prefix normalized: int(ja3[:4], 16) / 65535.0.
       - Missing-value: 0.0.
       - Statistical meaning: Deterministic fingerprint category partitioning.
    """
    # 1. Handshake duration
    hs_dur = float(s.get("handshake_duration_ms") or 0.0)
    # 2. Offered ciphers count
    c_count = float(s.get("offered_cipher_count") or 0.0)
    # 3. Cipher rarity score
    c_rarity = float(s.get("cipher_rarity_score") or 0.1)
    # 4. Average payload size
    p_avg = float(s.get("payload_bytes_avg") or 0.0)
    # 5. Payload size variance
    p_var = float(s.get("payload_bytes_var") or 0.0)
    # 6. Packet count
    pkt_cnt = float(s.get("packet_count") or 0.0)

    # 7. Ordinal TLS Version encoding
    ver = s.get("tls_version") or ""
    if "1.3" in ver:
        v_code = 5.0
    elif "1.2" in ver:
        v_code = 4.0
    elif "1.1" in ver:
        v_code = 3.0
    elif "1.0" in ver:
        v_code = 2.0
    elif "3.0" in ver or "SSL" in ver:
        v_code = 1.0
    else:
        v_code = 0.0

    # 8. Deterministic cipher suite categorical tiering
    c_str = (s.get("cipher_suite") or "").upper().strip()
    if not c_str or c_str == "NONE":
        c_code = 0.0
    elif any(b in c_str for b in ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")):
        c_code = 1.0  # Prohibited / broken
    elif "CBC" in c_str:
        c_code = 2.0  # Legacy CBC
    elif "CHACHA20" in c_str:
        c_code = 3.0  # ChaCha20 AEAD
    elif "AES_128_GCM" in c_str:
        c_code = 4.0  # AES-128 AEAD
    elif "AES_256_GCM" in c_str:
        c_code = 5.0  # AES-256 AEAD
    else:
        # Deterministic MD5 hex bucket in range [10.0, 19.0]
        md5_int = int(hashlib.md5(c_str.encode("utf-8")).hexdigest()[:4], 16)
        c_code = 10.0 + float(md5_int % 10)

    # 9. Deterministic JA3 fingerprint category partition
    ja3 = s.get("ja3_hash") or ""
    if ja3:
        try:
            ja3_code = round(float(int(ja3[:4], 16)) / 65535.0, 4)
        except ValueError:
            ja3_code = 0.0
    else:
        ja3_code = 0.0

    return [hs_dur, c_count, c_rarity, p_avg, p_var, pkt_cnt, v_code, c_code, ja3_code]


class AnomalyDetector:
    """Detects statistical outliers on extracted session numeric features."""

    def __init__(self, contamination: float = 0.15, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state

    def detect_anomalies(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Calculates anomaly flags and normalized anomaly scores for a list of sessions.
        Attaches 'is_anomaly', 'anomaly_score', and 'top_deviating_features' to each session.
        """
        if not sessions:
            return sessions

        # If too few sessions (< 5), Isolation Forest cannot reliably estimate density.
        # Use statistical Z-Score threshold fallback.
        if len(sessions) < 5:
            return self._fallback_zscore_detection(sessions)

        # Extract numeric feature matrix
        matrix = [encode_session_features(s) for s in sessions]
        X = np.array(matrix, dtype=np.float64)

        # Fit Isolation Forest
        try:
            iso = IsolationForest(
                contamination=self.contamination,
                random_state=self.random_state,
                n_estimators=100
            )
            preds = iso.fit_predict(X)  # -1 for anomaly, 1 for normal
            decision_scores = iso.decision_function(X)  # lower = more abnormal

            # Normalize decision scores to [0.0, 1.0] where 1.0 is most anomalous
            min_score = np.min(decision_scores)
            max_score = np.max(decision_scores)
            if max_score > min_score:
                norm_scores = 1.0 - ((decision_scores - min_score) / (max_score - min_score))
            else:
                norm_scores = np.zeros(len(sessions))

            # Feature means and stds for explaining top deviations
            means = np.mean(X, axis=0)
            stds = np.std(X, axis=0)
            stds[stds == 0] = 1.0  # avoid division by zero

            for idx, s in enumerate(sessions):
                is_anom = bool(preds[idx] == -1)
                score = float(norm_scores[idx])

                # Determine which feature deviated most
                z_scores = np.abs((X[idx] - means) / stds)
                top_feat_idx = int(np.argmax(z_scores))
                top_feature = FEATURE_NAMES[top_feat_idx]

                s["is_anomaly"] = is_anom
                s["anomaly_score"] = round(score, 3)
                s["top_deviating_features"] = [f"{top_feature} (z={z_scores[top_feat_idx]:.2f})"] if is_anom else []

        except Exception as e:
            # Graceful fallback without failing the deterministic pipeline
            for s in sessions:
                s["is_anomaly"] = False
                s["anomaly_score"] = 0.0
                s["top_deviating_features"] = []

        return sessions

    def _fallback_zscore_detection(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fallback for small sample sizes using conservative feature thresholds."""
        for s in sessions:
            anom = False
            top_feats = []

            # Extreme handshake delay (> 450ms)
            hs_dur = s.get("handshake_duration_ms", 0.0)
            if hs_dur > 450.0:
                anom = True
                top_feats.append(f"handshake_duration_ms ({hs_dur}ms)")

            # Minimal single offered cipher (scanner/bot)
            c_cnt = s.get("offered_cipher_count", 0)
            if c_cnt == 1:
                anom = True
                top_feats.append(f"offered_cipher_count ({c_cnt})")

            s["is_anomaly"] = anom
            s["anomaly_score"] = 0.85 if anom else 0.05
            s["top_deviating_features"] = top_feats

        return sessions
