# SecureMailScope — Behavioral Anomaly Detection (Layer 2)

This document describes the design, feature engineering, mathematical foundation, and operational interpretation of Layer 2 in the SecureMailScope passive analysis engine.

---

## 1. Overview & Architectural Philosophy

SecureMailScope separates security evaluation into two decoupled layers:

1. **Layer 1: Deterministic Compliance Engine**
   - Rules based strictly on RFC specifications and NIST guidelines.
   - Evaluates violations such as expired certificates, plaintext credentials, and deprecated ciphers.
   - Computes deterministic **Maximum Severity** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`).

2. **Layer 2: Unsupervised Anomaly Detection**
   - Evaluates behavioral, structural, and statistical outliers across encrypted email traffic.
   - Uses an **Isolation Forest** ensemble algorithm.
   - Produces an independent **Anomaly Score** ($[0.0, 1.0]$) and an anomaly boolean flag (`is_anomaly`).

### Why Decouple Layer 1 and Layer 2?
A naive approach blends rule severity and anomaly score into an arbitrary composite number (e.g., $0.70 \times \text{rule} + 0.30 \times \text{anomaly}$). This is bad practice in security auditing:
- An expired certificate on an otherwise standard connection is an unambiguous **CRITICAL** compliance violation. Blending an anomaly score could dilute the severity.
- A connection using valid TLS 1.3 with an unusual handshake delay or rare cipher suite is **CLEAN** from an RFC compliance perspective, but anomalous from a network operations perspective.
- Decoupling preserves pure compliance audit trails while equipping analysts with an orthogonal behavioral radar.

---

## 2. The 9-Dimensional Feature Vector

For every reconstructed session, the extractor builds a standardized 9-dimensional numerical feature vector:

$$\mathbf{x} = [x_1, x_2, x_3, x_4, x_5, x_6, x_7, x_8, x_9] \in \mathbb{R}^9$$

| # | Feature Name | Type | Description | Rationale |
|---|---|---|---|---|
| 1 | `handshake_duration_ms` | Float | Milliseconds elapsed between TCP handshake completion / ClientHello and TLS negotiation completion. | Captures abnormal negotiation delays, network jitter, server CPU starvation, or interception proxies. |
| 2 | `offered_cipher_count` | Integer | Total number of cipher suites advertised by the client in `ClientHello`. | Fingerprints client TLS stack sophistication (minimal embedded clients offer 2–4; modern browsers offer 15–25). |
| 3 | `cipher_rarity_score` | Float | Empirical rarity / inverse frequency of the negotiated cipher suite relative to standard enterprise baselines ($[0.0, 1.0]$). | Flags obsolete, obscure, or non-standard cipher suites (e.g. 3DES, Camellia, SEED). |
| 4 | `payload_bytes_avg` | Float | Mean size of TCP application payload bytes across all stream packets. | Differentiates normal mail transactions from probing, brute-force bursts, or large automated exfiltration. |
| 5 | `payload_bytes_var` | Float | Variance of TCP application payload sizes across stream packets. | Characterizes protocol interaction dynamics (high variance indicates command/response plus bulk message transfers). |
| 6 | `packet_count` | Integer | Total count of TCP packets comprising the session stream. | Detects truncated sessions, abrupt aborts, or abnormally chatty sessions. |
| 7 | `tls_version_encoded` | Integer | Ordinal encoding of negotiated protocol: `0`=Cleartext, `1`=SSLv3, `2`=TLS 1.0, `3`=TLS 1.1, `4`=TLS 1.2, `5`=TLS 1.3. | Provides ordinal scale of cryptographic modernization. |
| 8 | `cipher_suite_encoded` | Integer | Deterministic hash/index of the negotiated IANA cipher suite identifier. | Enables clustering and partitioning based on cryptographic suite selection. |
| 9 | `ja3_hash_encoded` | Integer | Numerical representation derived from client JA3 fingerprint hash. | Identifies structural clustering of client software libraries (OpenSSL, Go, Python, Thunderbird). |

---

## 3. Algorithm: Isolation Forest

The model utilizes `sklearn.ensemble.IsolationForest`, an unsupervised tree ensemble designed for anomaly detection.

### Mathematical Mechanism
Instead of modeling the normal profile and measuring distance, Isolation Forest explicitly isolates anomalies by randomly partitioning feature space:
1. Subsamples of training/session vectors are recursively split along randomly selected features between their minimum and maximum values.
2. Anomalies (outliers) reside in low-density regions and require significantly fewer recursive splits to isolate than normal instances.
3. The anomaly score $s(x, n)$ for an instance $x$ given dataset size $n$ is defined by:
   $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
   where $h(x)$ is the path length in a isolation tree, $E(h(x))$ is the expectation across all trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree (BST):
   $$c(n) = 2 \left( \ln(n - 1) + 0.5772156649 \right) - \frac{2(n - 1)}{n}$$

### Normalization and Thresholding
The raw Isolation Forest decision function is calibrated and normalized into the range $[0.0, 1.0]$:
- Scores close to $0.0$: Deep in the core density distribution (normal).
- Scores around $0.5$: Indeterminate or standard baseline variations.
- Scores $> 0.70$: Significant behavioral outliers.

**Operational Decision Boundary:**
$$\text{is\_anomaly} = \begin{cases} \text{True} & \text{if } \text{Anomaly Score} \ge 0.70 \\ \text{False} & \text{if } \text{Anomaly Score} < 0.70 \end{cases}$$

---

## 4. Behavior in Demonstration Scenarios

In the verified synthetic test suite (`data/demo_mail_traffic.pcap`), the anomaly detector processes 9 distinct streams with the following notable flags:

- **Stream 6 (SMTP Port 587 - Handshake Failure / Fatal Alert)**:
  - **Score**: `0.958` (Flagged as Anomaly: `True`)
  - **Forensic Driver**: Handshake duration was intentionally delayed to 580 ms ($z = +2.82$ standard deviations above baseline mean), accompanied by an abrupt TLS fatal alert packet terminating the connection.
- **Stream 1 (SMTPS Port 465 - Deprecated TLS 1.0 + 3DES Broken Cipher)**:
  - **Score**: `1.000` (Flagged as Anomaly: `True`)
  - **Forensic Driver**: Extremely rare legacy cipher suite (`TLS_RSA_WITH_3DES_EDE_CBC_SHA`), low version encoding (`2`), and obsolete JA3 fingerprint.
- **Streams 0, 2, 3, 4, 5, 7, 8**:
  - Maintained anomaly scores below the $0.70$ threshold, reflecting statistical normality in packet structures and timing despite protocol-level RFC violations (e.g. Stream 2 is CRITICAL due to plaintext auth, but its timing and payload variance match typical SMTP interactions).

---

## 5. Scope & Boundary Clarifications

> [!IMPORTANT]
> - **NOT an Intrusion Detection System (IDS)**: Layer 2 does NOT inspect email bodies, scan for malware signatures, or inspect spam payloads.
> - **NOT an Attack Exploit Detector**: An anomaly score simply indicates that the cryptographic handshake or transport profile deviates statistically from expected baseline norms.
> - **Zero Cloud Dependencies**: The model trains and runs locally in pure Python/scikit-learn without external API calls.
