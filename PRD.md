# Product Requirements Document (PRD)
## Cryptographic Posture & Mail Protocol (SMTP/IMAP/POP3) Anomaly Intelligence

---

### 1. MVP Feature List
- **PCAP / PCAPNG Upload & Ingestion**:
  - Accept uploaded `.pcap` or `.pcapng` capture files (or bundled demo PCAP captures).
  - Inspect actual raw packet captures across email protocols: **SMTP** (ports 25, 587, 465), **IMAP** (ports 143, 993), and **POP3** (ports 110, 995).
- **Two-Pass TShark & Deep Protocol Analysis**:
  - Reconstruct TCP conversations and extract both application-layer commands and cryptographic handshakes.
  - Track **STARTTLS Negotiation State**: `none`, `advertised`, `requested`, `completed`, `failed`.
  - Extract TLS negotiation parameters: protocol version, negotiated cipher suite, offered cipher list, client SNI, certificate validity/expiry, handshake latency, and packet sizing telemetry.
- **Layer 1: Deterministic Security Rule Engine**:
  - Hard compliance & cryptographic violation engine citing standard **RFC / NIST** benchmarks.
  - Detects plaintext authentication before TLS, un-enforced STARTTLS, deprecated SSL/TLS protocols, weak/broken ciphers, expired certificates, and untrusted/self-signed certs.
- **Layer 2: Unsupervised Anomaly Detector (Isolation Forest)**:
  - Scikit-learn `IsolationForest` flagging statistical outliers independent of fixed rules (e.g. anomalous handshake latency, abnormal cipher counts, rare cipher suites, abnormal payload variance/tunneling).
  - Reported as an **independent, separate indicator** (not merged into the severity rating).
- **Rule-Based Session Severity Assessment**:
  - Clear, unambiguous risk rating: **Session Severity = $\max(\text{fired rule severities})$** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`).
- **Layer 3: Plain-Language Explanation & Remediation (Downstream Only)**:
  - Translates verified Layer 1 violations and Layer 2 anomaly indicators into plain-English root causes and hardening configurations (Postfix/Exim/Dovecot/Nginx/OpenSSL). Never invents findings.
- **Interactive Streamlit Web Dashboard**:
  - Single Python process providing capture file ingestion, posture KPI cards, session data grid, anomaly scatter plots, and session drill-down views backed by SQLite.

---

### 2. Functional Requirements
- **FR-1 [PCAP / PCAPNG Ingestion & Parsing]**:
  - Ingest user-uploaded `.pcap`/`.pcapng` files or load bundled synthetic demo captures.
  - Execute TShark two-pass extraction (`tshark -2 -R "smtp || imap || pop || tls"`) with native Scapy fallback to extract sessions.
  - Track state across packets within each TCP stream:
    - Transport endpoints: `client_ip`, `client_port`, `server_ip`, `server_port`, `protocol` (`SMTP` / `IMAP` / `POP3`).
    - STARTTLS State Machine:
      - `none`: Direct implicit TLS or unencrypted stream without STARTTLS.
      - `advertised`: Server advertised STARTTLS capability (`250-STARTTLS`, `CAPABILITY STARTTLS`, `STLS`), but client never requested it.
      - `requested`: Client issued `STARTTLS` / `STLS` command.
      - `completed`: Server confirmed upgrade (`220 Ready`, `OK`, `+OK`) and TLS handshake completed.
      - `failed`: STARTTLS requested/advertised but negotiation aborted, fell back to cleartext, or failed handshake.
    - Plaintext credential leakage detection: scans for `AUTH PLAIN`, `AUTH LOGIN`, `LOGIN`, `USER`, `PASS` transmitted prior to TLS completion.
    - Cryptographic metrics: `tls_version`, `cipher_suite`, `cert_valid`, `cert_days_to_expiry`, `cert_self_signed`, `handshake_duration_ms`, `offered_cipher_count`, `cipher_rarity_score`, `payload_bytes_avg`, `payload_bytes_var`.
- **FR-2 [Deterministic Rule Evaluation]**:
  - Evaluate sessions against strict RFC/NIST cryptographic security policies.
  - Output violation records detailing `rule_id`, `rule_name`, `severity`, `source` (RFC/NIST standard), and `description`.
- **FR-3 [Unsupervised Anomaly Model Execution]**:
  - Fit/Predict using `sklearn.ensemble.IsolationForest` on numeric telemetry:
    $$x = [\text{handshake\_duration\_ms}, \text{offered\_cipher\_count}, \text{cipher\_rarity\_score}, \text{payload\_bytes\_var}]$$
  - Output `is_anomaly` boolean flag and normalized $[0.0, 1.0]$ continuous `anomaly_score` displayed as an independent indicator.
- **FR-4 [Session Severity Model]**:
  $$\text{Session Severity} = \max_{r \in \text{fired rules}}(\text{Severity}(r))$$
  - Hierarchy: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `CLEAN`.
- **FR-5 [Dashboard & Visualization]**:
  - Streamlit multi-tab interface:
    1. **Overview & Posture**: Total sessions, severity distribution, STARTTLS health breakdown, anomaly count.
    2. **Session Explorer**: Filterable data table with protocol filters, severity badges, and anomaly tags.
    3. **Threat & Anomaly Analytics**: Scatter plots ($x$: handshake duration, $y$: cipher count) highlighting statistical outliers.
    4. **Session Inspector & Remediation**: Deep dive into individual streams, displaying raw conversation flows, violated RFC standards, and targeted server remediation snippets.

---

### 3. System Architecture

```
                       +---------------------------------------+
                       |      Uploaded .pcap / .pcapng        |
                       |       (or Bundled Demo PCAP)          |
                       +-------------------+-------------------+
                                           |
                                           v
                       +---------------------------------------+
                       |   PCAP Parser (TShark 2-Pass / Scapy) |
                       | - TCP Stream Reassembly               |
                       | - STARTTLS State Machine Tracker      |
                       | - TLS Handshake & Cert Extractor      |
                       +-------------------+-------------------+
                                           |
                                           v
                       +---------------------------------------+
                       |        Extracted Session Records      |
                       +-------------------+-------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
     +------------------------------+             +-------------------------------+
     |  Layer 1: Rule Engine        |             |  Layer 2: Anomaly Detector    |
     |  (Deterministic Standards)   |             |  (Isolation Forest Outliers)  |
     |  - Plaintext auth before TLS |             |  - Handshake Latency Spikes   |
     |  - STARTTLS not enforced     |             |  - Cipher Count Fingerprints  |
     |  - Legacy TLS (1.0 / 1.1)    |             |  - Cipher Rarity Metric       |
     |  - Broken Ciphers (RC4/3DES) |             |  - Payload Variance           |
     |  - Expired / Self-Signed     |             |                               |
     +--------------+---------------+             +---------------+---------------+
                    |                                             |
                    | (Max Rule Severity)                         | (Independent Outlier Flag)
                    +----------------------+----------------------+
                                           |
                                           v
                       +---------------------------------------+
                       |   SQLite Storage (Sessions & Rules)   |
                       +-------------------+-------------------+
                                           |
                     +---------------------+---------------------+
                     |                                           |
                     v                                           v
+------------------------------------------+    +---------------------------------+
|          Streamlit Web Interface         |    | Layer 3: LLM Explainer Layer    |
| (KPIs, STARTTLS status, Explorer, Plots) |<---| (Plain-Text RFC Remediation)    |
+------------------------------------------+    +---------------------------------+
```

---

### 4. Database Schema (SQLite)

```sql
CREATE TABLE IF NOT EXISTS tls_sessions (
    session_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    client_port INTEGER NOT NULL,
    server_ip TEXT NOT NULL,
    server_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,                -- SMTP, IMAP, POP3
    starttls_state TEXT NOT NULL,          -- none, advertised, requested, completed, failed
    plaintext_auth_observed BOOLEAN NOT NULL DEFAULT 0,
    tls_version TEXT,                      -- TLS 1.3, TLS 1.2, TLS 1.0, etc. (NULL if cleartext)
    cipher_suite TEXT,                     -- Negotiated cipher
    cert_valid BOOLEAN,
    cert_days_to_expiry INTEGER,
    cert_self_signed BOOLEAN,
    handshake_duration_ms REAL,
    offered_cipher_count INTEGER,
    cipher_rarity_score REAL,
    payload_bytes_avg REAL,
    payload_bytes_var REAL,
    session_severity TEXT NOT NULL DEFAULT 'CLEAN', -- CRITICAL, HIGH, MEDIUM, LOW, CLEAN
    is_anomaly BOOLEAN NOT NULL DEFAULT 0,          -- Separate statistical indicator
    anomaly_score REAL NOT NULL DEFAULT 0.0,
    rule_violations_count INTEGER NOT NULL DEFAULT 0,
    explanation_text TEXT
);

CREATE TABLE IF NOT EXISTS rule_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,                -- CRITICAL, HIGH, MEDIUM, LOW
    source TEXT NOT NULL,                  -- e.g. "RFC 8314 Section 3", "NIST SP 800-52r2"
    description TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES tls_sessions(session_id)
);
```

---

### 5. Security-Rule Specification

| Rule ID | Condition | Severity | Source (Standard) | Description & Rationale |
|---|---|---|---|---|
| `RULE_PLAINTEXT_AUTH_BEFORE_TLS` | `plaintext_auth_observed == True` and `starttls_state != 'completed'` | **CRITICAL** | **RFC 8314 §3, NIST SP 800-45** | User credentials (`AUTH`, `LOGIN`, `PASS`) transmitted over cleartext connection before TLS handshake established. |
| `RULE_STARTTLS_NOT_ENFORCED` | `starttls_state == 'advertised'` and payload exchanged without upgrading | **HIGH** | **RFC 8314 §5.1, RFC 3207** | Server advertised STARTTLS capability, but client or server proceeded in cleartext without opportunistic encryption upgrade. |
| `RULE_TLS_LEGACY` | `tls_version` in `['SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1']` | **CRITICAL** | **RFC 8996, NIST SP 800-52r2 §3.1** | Deprecated cryptographic protocol susceptible to POODLE, BEAST, SWEET32, and padding oracle attacks. |
| `RULE_CIPHER_BROKEN` | `cipher_suite` contains `['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']` | **CRITICAL** | **RFC 7465, NIST SP 800-52r2 §3.3** | Negotiated cipher suite contains cryptographically broken primitives prone to plaintext extraction. |
| `RULE_CIPHER_NON_AEAD` | `tls_version == 'TLS 1.2'` and cipher does not contain `['GCM', 'CHACHA20', 'CCM']` | **MEDIUM** | **RFC 8446, NIST SP 800-52r2 §3.3.1** | CBC mode ciphers lack authenticated encryption (AEAD) and are susceptible to padding oracle attacks. |
| `RULE_CERT_EXPIRED` | `cert_days_to_expiry < 0` | **CRITICAL** | **RFC 5280 §4.1.2.5, NIST SP 800-52r2 §3.2** | Expired X.509 certificate breaches identity verification, leaving sessions vulnerable to impersonation. |
| `RULE_CERT_EXPIRING_SOON` | `0 <= cert_days_to_expiry <= 14` | **LOW** | **NIST SP 800-52r2 §3.2** | Certificate expires within 14 days; requires operational renewal. |
| `RULE_CERT_SELF_SIGNED` | `cert_self_signed == True` | **HIGH** | **RFC 8314 §4.1, NIST SP 800-52r2 §3.2** | Untrusted self-signed certificate violates PKI validation, exposing connection to Man-in-the-Middle (MitM). |

---

### 6. Risk Methodology
1. **Deterministic Session Severity**:
   $$\text{Session Severity} = \max_{r \in \text{fired rules}}(\text{Severity}(r))$$
   - Hierarchy: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `CLEAN`.
   - Clear, deterministic, and auditable — no black-box blending.
2. **Anomaly Indicator (Independent Layer)**:
   - Evaluated separately via Isolation Forest.
   - Outputs:
     - `is_anomaly`: Boolean (`True` / `False`).
     - `anomaly_score`: Normalized continuous distance $[0.0, 1.0]$.
   - Visualized as a distinct alert badge ("⚡ Statistical Outlier") alongside the session severity, preserving clarity between compliance failures and behavioral anomalies.

---

### 7. AI Architecture (Strictly Two + One Layers)

1. **Layer 1: Deterministic Rule Engine (Fixed Compliance Logic)**:
   - Inspects application protocol states (SMTP/IMAP/POP3 commands, STARTTLS lifecycle) and TLS metadata against exact RFC/NIST standards.
   - Emits structured rule violation records with exact standard citations.
2. **Layer 2: Unsupervised Anomaly Detector (Isolation Forest - Scikit-Learn)**:
   - Trained on baseline mail session telemetry.
   - Evaluates numeric feature vector:
     $$x = [\text{handshake\_duration\_ms}, \text{offered\_cipher\_count}, \text{cipher\_rarity\_score}, \text{payload\_bytes\_var}]$$
   - Isolates zero-day or non-rule-governed behavioral anomalies (e.g. scanner fingerprinted cipher lists, covert tunnel timing, abnormally high handshake delays).
3. **Layer 3 (Optional): LLM Explanation & Remediation Layer (Downstream Only)**:
   - Consumes verified findings emitted by Layer 1 & Layer 2.
   - Outputs plain-English analysis and copy-paste configuration directives for MTA servers (Postfix, Dovecot, Exim, Nginx mail proxy).
   - *Strict Guardrail*: The LLM never invents or classifies findings; it only translates verified engine outputs.

---

### 8. Demo Dataset Specification (Actual Synthetic PCAP Files)
The demo dataset will be generated as **actual binary `.pcap` files** using Python (`scapy` packet constructor):
- File: `data/demo_mail_traffic.pcap`
- Containing complete Ethernet / IP / TCP conversations across SMTP (ports 25, 587), IMAP (ports 143, 993), and POP3 (ports 110, 995) simulating:
  1. **Compliant Secure Sessions**: Clean STARTTLS upgrade to TLS 1.3 / TLS 1.2 AEAD with valid certs.
  2. **Plaintext Authentication Violations**: `AUTH LOGIN` / `USER ... PASS ...` commands sent in cleartext before STARTTLS.
  3. **Un-Enforced STARTTLS**: Server offers `250-STARTTLS` or `CAPABILITY STARTTLS`, but client sends `MAIL FROM:` or `LOGIN` without upgrading.
  4. **Deprecated TLS & Broken Ciphers**: Client and server negotiating TLS 1.0 or RC4/3DES suites.
  5. **Certificate Flaws**: Handshakes featuring expired or self-signed X.509 certificates.
  6. **Statistical Outlier Streams**: Compliant TLS version/cipher, but exhibiting extreme handshake delay ($>500\text{ ms}$), minimal single-cipher offering (bot fingerprint), or unusual burst variance.

---

### 9. Project Folder Structure
```
c:\SIH26\
├── PRD.md                       # Product Requirements Document
├── requirements.txt             # Dependencies (streamlit, scikit-learn, pandas, scapy)
├── data\
│   └── demo_mail_traffic.pcap   # Real synthetic binary PCAP demo dataset
└── app\
    ├── __init__.py
    ├── main.py                  # Streamlit entry point & dashboard views
    ├── pcap_parser.py           # TShark (2-pass) & Scapy PCAP ingestion & STARTTLS state tracker
    ├── database.py              # SQLite storage for sessions & rule violations
    ├── rules.py                 # Layer 1: Deterministic RFC/NIST Rule Engine
    ├── anomaly.py               # Layer 2: Isolation Forest Anomaly Detector
    ├── explainer.py             # Layer 3: Plain-language remediation & config tips
    └── pcap_generator.py        # Synthetic PCAP packet generator (Scapy)
```
