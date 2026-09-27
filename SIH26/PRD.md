# Product Requirements Document (PRD)
## Cryptographic Posture & TLS Anomaly Intelligence Dashboard

---

### 1. MVP Feature List
1. **Interactive TLS Session Ingestion & Inspection**:
   - Ingest TLS handshake records / session metadata via synthetic demo generator, JSON/CSV upload, or live query.
   - Session inspector highlighting negotiation parameters (TLS version, cipher suite, key exchange, certificate validity, SNI, latency).
2. **Deterministic Security Rule Engine**:
   - Instant cryptographic violation auditing against standard compliance baselines (NIST / PCI-DSS).
   - Flags deprecated protocols (SSLv3, TLS 1.0, TLS 1.1), broken ciphers (RC4, 3DES, EXPORT, NULL), weak keys (<2048-bit RSA, insecure curves), and expired/self-signed certs.
3. **Unsupervised Anomaly Detector**:
   - Scikit-learn `IsolationForest` model identifying statistical outliers unaddressed by static rules.
   - Evaluates numeric feature vectors: handshake duration (ms), offered cipher suite count, cipher rarity index, payload size variance.
4. **Unified Risk Scoring & Posture Dashboard**:
   - Session-level Risk Score (0-100) combining Rule Violations (deterministic severity) + Anomaly Score (statistical deviation).
   - High-level metrics: Compliance rate, High/Critical session count, Top policy violations, Outlier distribution.
5. **LLM Remediation & Explanation Layer (Optional/Enrichment)**:
   - Plain-language explanation and actionable config remediation (nginx/Apache/Caddy/OpenSSL snippets) strictly generated from verified findings in Layers 1 & 2.
   - Never hallucinates findings; strictly acts as a translation & remediation layer.
6. **Data Storage & Filtering**:
   - Lightweight SQLite storage for session histories, rule hits, anomaly scores, and audit tags.

---

### 2. Functional Requirements
- **FR-1 [Data Intake]**: Accept TLS session records with fields: `session_id`, `timestamp`, `client_ip`, `server_ip`, `sni`, `tls_version`, `cipher_suite`, `cert_days_to_expiry`, `cert_self_signed`, `handshake_duration_ms`, `offered_cipher_count`, `cipher_rarity_score`, `payload_bytes_avg`, `payload_bytes_var`.
- **FR-2 [Deterministic Evaluation]**: Evaluate each record against predefined rule table. Assign severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **FR-3 [Anomaly Model Execution]**: Fit/Predict with Isolation Forest. Output an anomaly decision (`-1` anomaly, `1` normal) and continuous anomaly score normalized to [0, 1].
- **FR-4 [Composite Risk Scoring]**:
  $$\text{Risk Score} = \min\left(100, \text{Max}(\text{Rule Severities}) \times 0.7 + (\text{Anomaly Score} \times 100) \times 0.3\right)$$
- **FR-5 [UI & Visualization]**: Streamlit multi-view dashboard:
  - Overview / Executive Cryptographic Posture
  - Session Explorer with filter by Risk Level / Anomaly flag
  - Model Insights & Anomaly Scatter Plots
  - Detailed Session Drill-down with remediation view.

---

### 3. System Architecture
Single Python process with modular components:

```
+-------------------------------------------------------------------+
|                        Streamlit Web UI                           |
|  (Metrics, Charts, Session Explorer, Risk Breakdown, Config Tips) |
+---------------------------------+---------------------------------+
                                  |
               +------------------+------------------+
               |                                     |
               v                                     v
+-------------------------------+   +-------------------------------+
|      Layer 1: Rule Engine     |   | Layer 2: Anomaly Detector     |
| (Deterministic Crypto Checks) |   | (IsolationForest Unsupervised)|
+---------------+---------------+   +---------------+---------------+
                |                                   |
                +-----------------+-----------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                   Composite Risk Synthesizer                      |
|           (Risk Score = 0.7 * RuleRisk + 0.3 * AnomalyRisk)       |
+---------------------------------+---------------------------------+
                                  |
         +------------------------+------------------------+
         v                                                 v
+-------------------------------+        +-------------------------------+
| Layer 3: LLM Explainer        |        | SQLite / In-Memory Database   |
| (Plain-language Remediation)  |        | (Sessions, Violations, Scores)|
+-------------------------------+        +-------------------------------+
```

---

### 4. Database Schema (SQLite)

```sql
CREATE TABLE IF NOT EXISTS tls_sessions (
    session_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    server_ip TEXT NOT NULL,
    sni TEXT NOT NULL,
    tls_version TEXT NOT NULL,
    cipher_suite TEXT NOT NULL,
    cert_valid BOOLEAN NOT NULL,
    cert_days_to_expiry INTEGER NOT NULL,
    cert_self_signed BOOLEAN NOT NULL,
    handshake_duration_ms REAL NOT NULL,
    offered_cipher_count INTEGER NOT NULL,
    cipher_rarity_score REAL NOT NULL,
    payload_bytes_avg REAL NOT NULL,
    payload_bytes_var REAL NOT NULL,
    is_anomaly BOOLEAN DEFAULT 0,
    anomaly_score REAL DEFAULT 0.0,
    rule_violations_count INTEGER DEFAULT 0,
    highest_severity TEXT DEFAULT 'CLEAN',
    composite_risk_score REAL DEFAULT 0.0,
    explanation_text TEXT
);

CREATE TABLE IF NOT EXISTS rule_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES tls_sessions(session_id)
);
```

---

### 5. Security-Rule Specification

| Rule ID | Condition | Severity | Description & Rationale |
|---|---|---|---|
| `RULE_TLS_LEGACY` | `tls_version` in `['SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1']` | **CRITICAL** | Deprecated protocol vulnerable to POODLE, BEAST, and lacking AEAD ciphers. |
| `RULE_CIPHER_BROKEN` | `cipher_suite` contains `['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']` | **CRITICAL** | Cryptographically broken cipher or hash prone to plaintext recovery. |
| `RULE_CIPHER_NON_AEAD` | `tls_version == 'TLS 1.2'` and cipher does not contain `['GCM', 'CHACHA20', 'CCM']` | **MEDIUM** | CBC mode ciphers susceptible to padding oracle attacks. |
| `RULE_CERT_EXPIRED` | `cert_days_to_expiry < 0` | **CRITICAL** | Expired X.509 certificate invalidating identity authentication. |
| `RULE_CERT_EXPIRING_SOON`| `0 <= cert_days_to_expiry <= 14` | **LOW** | Certificate expiring within 14 days; renewal required. |
| `RULE_CERT_SELF_SIGNED` | `cert_self_signed == True` | **HIGH** | Untrusted root / self-signed certificate subject to MitM. |

---

### 6. Risk Methodology
Composite Session Risk Score $R \in [0, 100]$:
1. **Rule Base Risk ($S_{\text{rule}}$)**:
   - `CRITICAL`: 95
   - `HIGH`: 75
   - `MEDIUM`: 50
   - `LOW`: 25
   - `CLEAN`: 0
   - Additive multi-hit penalty: $+5$ for each secondary violation (capped at 100).
2. **Anomaly Base Risk ($S_{\text{anomaly}}$)**:
   - Anomaly score transformed via min-max scaling of Isolation Forest decision function: $S_{\text{anomaly}} \in [0, 100]$.
3. **Composite Aggregation**:
   $$R = \text{clamp}\Big(0.70 \times S_{\text{rule}} + 0.30 \times S_{\text{anomaly}}, \, 0, \, 100\Big)$$
4. **Risk Tiers**:
   - `0 - 29`: Low (Compliant)
   - `30 - 59`: Medium (Attention Advised)
   - `60 - 79`: High (Action Required)
   - `80 - 100`: Critical (Immediate Remediation)

---

### 7. AI Architecture (Strictly Two + One Layers)

#### Layer 1: Deterministic Rule Engine
- Fixed boolean logic inspects protocol flags, cipher tokens, and certificate metadata.
- Zero stochasticity, deterministic verdict, instantaneous execution, 100% auditable.

#### Layer 2: Anomaly Detector (Unsupervised Isolation Forest)
- `sklearn.ensemble.IsolationForest` trained on normal baseline traffic.
- **Feature Vector $x \in \mathbb{R}^4$**:
  1. `handshake_duration_ms`: Outliers capture slow-read attacks, network MITM latency injection, or exotic negotiation.
  2. `offered_cipher_count`: Extremely low (fingerprinted bot/scanner) or abnormally high (probing).
  3. `cipher_rarity_score`: Frequency-weighted metric of unusual/rarely seen suites in enterprise traffic.
  4. `payload_bytes_var`: Irregular burst patterns indicative of C2 beaconing or exfiltration through TLS tunnels.
- Flags statistical outliers that pass standard protocol validation.

#### Layer 3 (Optional): LLM Explanation & Remediation Layer
- Strictly downstream from Layers 1 & 2.
- Input prompt contains verified findings (violated rule IDs, anomaly feature z-scores).
- Outputs plain English explanation and exact server config fixes.
- Safe fallback: Rule-based template remediation if LLM is disabled or offline.

---

### 8. Demo Dataset Specification
A realistic synthetic dataset of 250 TLS sessions spanning 5 realistic archetypes:
1. **Modern Standard Traffic (65%)**: TLS 1.3 / TLS 1.2 with ECDHE-RSA-AES128-GCM-SHA256, valid certs, normal handshake (20-60ms), typical cipher count (15-25).
2. **Legacy Protocol Violations (10%)**: TLS 1.0 / 1.1 sessions or 3DES/RC4 ciphers (triggers Layer 1 Critical).
3. **Certificate Faults (10%)**: Expired or self-signed internal certs (triggers Layer 1 High/Critical).
4. **Subtle Outliers / Tunneling / Scanners (10%)**: Valid TLS 1.3 / modern ciphers BUT aberrant handshake latency (450ms+), single offered cipher (custom C2 agent), or zero payload variance (triggers Layer 2 Anomaly without Layer 1 hits).
5. **Compound Threats (5%)**: Weak cipher + high anomaly latency.

---

### 9. Project Folder Structure
```
c:\SIH26\
├── PRD.md                       # This Product Requirements Document
├── requirements.txt             # Core dependencies (streamlit, scikit-learn, pandas, numpy)
└── app\
    ├── __init__.py
    ├── main.py                  # Streamlit entry point & dashboard views
    ├── database.py              # SQLite storage & session query layer
    ├── rules.py                 # Layer 1: Deterministic Rule Engine
    ├── anomaly.py               # Layer 2: Isolation Forest Anomaly Detector
    ├── explainer.py             # Layer 3: Plain-language & config remediation
    └── demo_data.py             # Realistic demo dataset generator
```
