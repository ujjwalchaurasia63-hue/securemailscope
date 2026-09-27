# SecureMailScope — User & Operation Guide

This guide describes how to operate **SecureMailScope** via both the interactive Streamlit web interface and the headless CLI scanner.

---

## 1. Operating Modes

### A. Web Interface Mode
Launch via:
```powershell
python -m streamlit run main.py
```
Open `http://localhost:8501`.

### B. Headless CLI Scanner Mode
Run directly from terminal:
```powershell
python main.py <path_to_capture.pcap> [--json <output.json>]
```

---

## 2. Navigating the Streamlit Interface

The interface is structured into seven operational tabs:

### 1. 📊 Posture Overview
- **Executive Metrics**: Total sessions reassembled, STARTTLS upgrade percentage, overall capture severity, total rule violations, and statistical anomaly count.
- **Capture Metadata**: File size, packet count, execution latency, and unique analysis ID.
- **Protocol Distribution**: Breakdown of SMTP, IMAP, and POP3 traffic.
- **Severity Breakdown**: Distribution of maximum rule severities across streams.

### 2. 🔍 Session Explorer
- Reassembles bidirectional TCP flows into conversation records.
- **Table Overview**: Displays Stream ID, Protocol, Client/Server endpoints, STARTTLS state, negotiated TLS version and cipher, handshake latency, and severity.
- **Session Deep Dive**: Select any session from the dropdown to view its complete flow metadata and individual rule findings.

### 3. ⚖️ Rule Findings & Evidence
- Displays forensic findings categorized by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- For each finding, presents:
  - **Rule ID** (e.g. `RULE_PLAINTEXT_AUTH_BEFORE_TLS`)
  - **Governing Standard** (RFC and NIST SP 800-52 Rev. 2 citations)
  - **Forensic Packet Evidence** (Frame numbers and packet payload summaries)
  - **Why It Matters** (Cryptographic security impact)
  - **Remediation** (Technical fix)

### 4. 🔐 TLS & Passive Certificate Analysis
- Inspects cryptographic parameters per stream:
  - Negotiated TLS Version and Cipher Suite
  - Client SNI (Server Name Indication)
  - Offered Cipher Count & Cipher Rarity Metric
  - Salesforce JA3 (MD5 hash) and Cloudflare JA4 strings
  - OCSP Stapling Status (`present`, `absent`, `unknown`)
- **Passive X.509 Certificate Analysis**:
  - Subject and Issuer Distinguished Names
  - Validity window (`NotBefore`, `NotAfter`, days to expiration)
  - Subject Alternative Names (SANs) and hostname match
  - Public Key Algorithm and Key Size (bits)
  - Self-Signed Status (`True` / `False`)
- **TLS 1.3 Handling**: When TLS 1.3 is negotiated, status is labeled `not_extractable_tls1.3` (since RFC 8446 encrypts the Certificate handshake message).

### 5. ⚡ Anomaly Detector (Layer 2)
- Evaluates statistical outliers across 9 telemetry features using scikit-learn `IsolationForest`.
- Features include handshake duration, offered cipher count, rarity, payload metrics, packet count, TLS version ordinal, and cipher capability tier.
- **Score Interpretation**:
  > *The anomaly score indicates how unusual a session is relative to the analyzed behavioral baseline. It is not a probability that the session is malicious.*
- Completely separate from deterministic compliance severity.

### 6. 🛠️ Hardening & Remediation (Layer 3)
- Provides actionable, plain-language hardening directives for mail servers.
- Includes configuration snippets for:
  - **Postfix MTA** (`/etc/postfix/main.cf`)
  - **Dovecot IMAP/POP3** (`/etc/dovecot/conf.d/10-ssl.conf`, `10-auth.conf`)
- Clearly labeled as **Administrator Action** (Advisory Only).

### 7. 📄 Export Report
- Generates and downloads the complete machine-readable JSON analysis report.

---

## 3. Uploading Custom Network Captures

1. In the sidebar under **"Capture Ingestion"**, click **"Browse files"**.
2. Select any standard `.pcap` or `.pcapng` file.
3. SecureMailScope will automatically execute two-pass TShark analysis and refresh the dashboard with real results.
4. To reload the bundled 9-session demonstration dataset, click **"📁 Load Bundled Demo PCAP"**.
