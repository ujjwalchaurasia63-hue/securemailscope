# SecureMailScope — Demonstration Guide

This guide details how to verify SecureMailScope against the real synthetic demonstration dataset (`data/demo_mail_traffic.pcap`).

## 1. Generating the Demonstration Dataset
The demonstration PCAP is generated via Scapy and Cryptography using actual Ethernet, IP, TCP, and TLS frames:
```bash
python app/pcap_generator.py
```
This produces `data/demo_mail_traffic.pcap` containing 9 distinct real-world traffic sessions.

---

## 2. Demonstration Scenario Matrix

| Scenario | Protocol & Port | Expected Result | Rule Category Breakdown | Forensic Evidence Captured |
|---|---|---|---|---|
| **Modern TLS 1.3** | SMTP (587) | **CLEAN** | Compliant (Zero violations) | Handshake encrypted; `cert_visibility = not_extractable_tls1.3` |
| **Legacy TLS 1.0 & 3DES** | SMTP (25) | **HIGH** | Mandatory: `RULE_TLS_LEGACY`<br>Mandatory: `RULE_CIPHER_BROKEN` | Frame 23 ServerHello (`TLS 1.0`, `3DES`) |
| **SMTP Plaintext AUTH** | SMTP (587) | **CRITICAL** | Mandatory: `RULE_PLAINTEXT_AUTH_BEFORE_TLS` | Frame 31: Cleartext `AUTH` before TLS |
| **Expired Certificate** | IMAP (143) | **CRITICAL** | Mandatory: `RULE_CERT_EXPIRED`<br>Supporting: `RULE_CERT_SELF_SIGNED` | Frame 46: Visible DER cert expired 61 days ago |
| **POP3 Plaintext Auth** | POP3 (110) | **CRITICAL** | Mandatory: `RULE_PLAINTEXT_AUTH_BEFORE_TLS` | Frames 52 & 54: Cleartext `USER` / `PASS` |
| **STARTTLS Advertised / Ignored** | SMTP (25) | **MEDIUM** | Mandatory: `RULE_STARTTLS_NOT_ENFORCED` | Frame 64: `250-STARTTLS` offered, mail sent cleartext |
| **Behavioral Anomaly** | SMTP (587) | **Independent Anomaly** | Layer 1: CLEAN<br>Layer 2: `is_anomaly=True` (Score 0.958) | Abnormal 580ms handshake latency + single cipher |
| **Hostname / SAN Mismatch** | IMAP (143) | **CRITICAL** | Mandatory: `RULE_HOSTNAME_MISMATCH`<br>Supporting: `RULE_CERT_SELF_SIGNED` | Frame 89: SNI `mail.bank.corp` vs SAN `attacker.phishing.org` |
| **TLS Handshake Failure** | SMTP (587) | **HIGH** | Mandatory: `RULE_TLS_HANDSHAKE_FAILURE` | Frame 100: Fatal TLS Alert 40 (`handshake_failure`) |

---

## 3. Detailed Session Walkthrough

### Session 0: Compliant Modern SMTP (Port 587)
- **Flow**: Client initiates SMTP conversation with `EHLO`, requests `STARTTLS`, server confirms with `220 Ready to start TLS`.
- **TLS**: Upgrades to TLS 1.3 with `TLS_AES_256_GCM_SHA384`.
- **Expected Outcome**: `STARTTLS: COMPLETED`, `Severity: CLEAN`.
- **Cert Status**: `not_extractable_tls1.3` (explains that TLS 1.3 encrypts Certificate messages; avoids false positive errors).

### Session 1: Deprecated TLS 1.0 & Broken 3DES Cipher (Port 25)
- **Flow**: SMTP STARTTLS negotiation resulting in `TLS 1.0` and `TLS_RSA_WITH_3DES_EDE_CBC_SHA`.
- **Expected Outcome**:
  - `RULE_TLS_LEGACY` (HIGH)
  - `RULE_CIPHER_BROKEN` (HIGH)
  - `Session Severity: HIGH`.

### Session 2: Plaintext Credentials Transmitted Before TLS (Port 587)
- **Flow**: Client issues `AUTH LOGIN` and sends base64 credentials before completing TLS.
- **Expected Outcome**:
  - `RULE_PLAINTEXT_AUTH_BEFORE_TLS` (CRITICAL)
  - `Evidence`: Identifies Frame 31 with cleartext auth.
  - `Session Severity: CRITICAL`.

### Session 3: IMAP with Visible Expired & Self-Signed Certificate (Port 143)
- **Flow**: IMAP `STARTTLS` negotiation upgrading to TLS 1.2 with visible DER X.509 certificate.
- **Expected Outcome**:
  - Certificate parsed using Python `cryptography`.
  - `RULE_CERT_EXPIRED` (CRITICAL) — Certificate expired 60+ days ago.
  - `RULE_CERT_SELF_SIGNED` (HIGH) — Issuer equals Subject.
  - `Session Severity: CRITICAL`.

### Session 4: POP3 Cleartext Authentication (Port 110)
- **Flow**: Direct POP3 connection sending `USER` and `PASS` commands in cleartext without TLS.
- **Expected Outcome**:
  - `RULE_PLAINTEXT_AUTH_BEFORE_TLS` (CRITICAL)
  - `Session Severity: CRITICAL`.

### Session 5: STARTTLS Advertised but Ignored (Port 25)
- **Flow**: Server advertises `250-STARTTLS`, but client immediately sends `MAIL FROM:` in cleartext.
- **Expected Outcome**:
  - `RULE_STARTTLS_NOT_ENFORCED` (MEDIUM)
  - `Session Severity: MEDIUM`.

### Session 6: Statistical Anomaly (Handshake Latency 580ms + Scanner Fingerprint)
- **Flow**: Compliant TLS 1.3 protocol and modern cipher (no rule violations), but exhibits abnormal 580ms handshake delay and a single offered cipher suite.
- **Expected Outcome**:
  - `Rule Findings: None (Compliant)`
  - `Statistical Anomaly: YES` (Score: 0.958, Isolation Forest flags outlier independently).

### Session 7: Certificate Hostname / SAN Mismatch (Port 143 IMAP)
- **Flow**: Client connects with SNI `mail.bank.corp`, but server presents X.509 certificate with SAN `attacker.phishing.org`.
- **Expected Outcome**:
  - `RULE_HOSTNAME_MISMATCH` (CRITICAL) — Identifies SAN discrepancy.
  - `RULE_CERT_SELF_SIGNED` (HIGH)
  - `Session Severity: CRITICAL`.

### Session 8: TLS Handshake Failure / Alert (Port 587 SMTP)
- **Flow**: Client initiates STARTTLS and sends ClientHello; server aborts negotiation with TLS Alert Level 2 (Fatal), Description 40 (handshake_failure).
- **Expected Outcome**:
  - `STARTTLS: FAILED`
  - `RULE_TLS_HANDSHAKE_FAILURE` (HIGH) — Pinpoints Alert frame.
  - `Session Severity: HIGH`.

---

## 3. Verifying Results via CLI
```bash
python main.py data/demo_mail_traffic.pcap
```

## 4. Verifying Results via Streamlit
1. Navigate to `http://localhost:8501`.
2. Click **"Load Bundled Demo PCAP"** in the sidebar.
3. Explore the **Overview**, **Session Explorer**, **Rule Findings & Evidence**, **TLS & Certificates**, **Anomaly Detector**, and **Hardening & Remediation** tabs.

