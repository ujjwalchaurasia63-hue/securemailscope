# SecureMailScope — SIH Judge Demonstration Guide (3–5 Minute Walkthrough)

This guide provides a structured, presentation-tested demonstration flow designed for Smart India Hackathon 2026 evaluators and cybersecurity jury members.

---

## 1. Quick Demonstration Overview

- **Time Required**: 3 to 5 minutes
- **Artifacts Demonstrated**: Real PCAP packet processing, deterministic RFC rule matching, 9D Isolation Forest anomaly detection, packet-level evidence drill-down, remediation generation.
- **Launch Command**:
  ```powershell
  python -m streamlit run main.py
  ```
- **Access URL**: `http://localhost:8501`

---

## 2. Minute-by-Minute Presentation Script

### Minute 0:00 – 0:45: Problem Statement & Value Proposition
- **Key Talking Point**:
  > *"SecureMailScope addresses the passive, offline cryptographic assessment of email communications (SMTP, IMAP, POP3) from captured PCAP/PCAPNG network traffic without decrypting user payloads."*
- **Highlight**:
  - Offline / Air-Gapped capability: No live probes, no active traffic disruption.
  - Dual-layer assessment: Deterministic compliance (Layer 1) + Statistical anomaly detection (Layer 2).
  - Evidence-backed findings: Every finding links to precise packet frame numbers, RFC clauses, and byte offsets.

### Minute 0:45 – 1:30: Launching & Ingestion
1. Open the browser to `http://localhost:8501`.
2. Point out the **Sidebar**:
   - Environment check displays active `TShark` integration and Python runtime.
   - Click **"Load Bundled Demo PCAP"** (`data/demo_mail_traffic.pcap`).
3. Click **"Run Full Security Assessment"**.
4. Observe the real-time processing indicator:
   - TShark two-pass extraction completes across 9 TCP streams (101 packets).
   - Session table populates immediately with real stream metadata.

### Minute 1:30 – 2:45: Deep-Dive into Key Scenarios

Walk the judges through the **Session Explorer** tab:

1. **Stream 0 (Modern Clean Baseline)**:
   - SMTP Port 587, negotiated **TLS 1.3** (`TLS_AES_256_GCM_SHA384`).
   - Severity: `CLEAN`. Shows the ideal zero-violation posture.
   - Point out that X.509 certificate data is accurately reported as `encrypted_in_tls13` (RFC 8446 standard compliance, no fabricated certs).

2. **Stream 2 & Stream 8 (Plaintext Credential Exposure)**:
   - Severity: `CRITICAL` (`RULE_PLAINTEXT_AUTH_BEFORE_TLS`).
   - Show how the parser caught unencrypted `AUTH LOGIN` / `USER`/`PASS` before TLS was negotiated, violating RFC 8314 and exposing credentials to passive network sniffers.

3. **Stream 1 (Obsolete Protocol & Weak Ciphers)**:
   - Negotiated **TLS 1.0** with **3DES** (`TLS_RSA_WITH_3DES_EDE_CBC_SHA`).
   - Severity: `HIGH` (`RULE_TLS_LEGACY`, `RULE_CIPHER_BROKEN`).
   - Highlight that Layer 2 flagged this session as an **Anomaly** (`Score: 1.000`) due to rare cipher selection.

4. **Stream 4 & Stream 7 (PKI Violations in TLS 1.2)**:
   - Stream 4: `RULE_CERT_EXPIRED` (Certificate expired 15 days ago).
   - Stream 7: `RULE_HOSTNAME_MISMATCH` (Client SNI `mail.company.com` vs Certificate SAN `internal.corp.local`).

5. **Stream 6 (Handshake Abort & Latency Anomaly)**:
   - Severity: `HIGH` (`RULE_TLS_HANDSHAKE_FAILURE`).
   - TLS Fatal Alert frame detected.
   - Switch to the **Anomaly Radar** tab: Show how the 580 ms handshake delay ($z = +2.82$) triggered an anomaly score of `0.958`.

### Minute 2:45 – 3:30: Forensic Evidence & Remediation
1. Switch to the **Evidence Inspector** tab:
   - Expand any session finding to show the forensic audit card:
     - Exact packet frame number
     - Relative timestamp
     - Protocol and field name
     - Governing RFC citation (e.g., RFC 8996, RFC 8314, RFC 6125)
2. Switch to the **Remediation & Hardening** tab:
   - Show the auto-generated configuration blocks for Postfix (`main.cf`) and Dovecot (`dovecot.conf`).
   - Explain that all guidance is actionable and directly targets the detected vulnerabilities.

### Minute 3:30 – 4:00: Export & Closing
1. Demonstrate the **Export** feature:
   - Click **Download JSON Forensic Report** or locate `results/analysis_report.json`.
   - Show machine-readable output suitable for ingestion into SIEM platforms or incident ticketing systems.
2. Conclude:
   > *"SecureMailScope bridges the gap between passive packet capture and automated cryptographic auditability, delivering real evidence without breaking encryption or relying on brittle heuristics."*

---

## 3. Anticipated Judge Questions & Authoritative Answers

### Q1: *"Why can't your tool extract certificates from TLS 1.3 sessions?"*
> **Answer**: *"Under RFC 8446 (TLS 1.3), all handshake records following ServerHello—including the Certificate and CertificateVerify messages—are encrypted using ephemeral keys. Because SecureMailScope is a passive, non-intrusive analyzer, decrypting TLS 1.3 traffic without session keys (SSLKEYLOGFILE) is cryptographically impossible. Rather than faking data, SecureMailScope explicitly reports certificate status as `encrypted_in_tls13`."*

### Q2: *"Is this an Intrusion Detection System (IDS) like Snort or Suricata?"*
> **Answer**: *"No. SecureMailScope is a specialized Cryptographic Posture Assessment engine. Traditional IDSs look for attack signatures and malware payloads. SecureMailScope analyzes protocol negotiation hygiene, cipher deprecation, STARTTLS downgrade compliance, certificate validity, and TLS timing anomalies."*

### Q3: *"How does the anomaly detector work without labeled attack data?"*
> **Answer**: *"It uses an unsupervised Isolation Forest algorithm over a standardized 9-dimensional vector including handshake duration, cipher rarity, offered cipher counts, and payload variances. It partitions feature space to identify structural outliers without needing labeled threat datasets."*

### Q4: *"Can this analyze live network traffic?"*
> **Answer**: *"SecureMailScope's core pipeline is deliberately designed for passive, offline forensic analysis of PCAP files. In enterprise operations, live capture is performed upstream via TShark/dumpcap or SPAN/TAP ports, and PCAP rotations are fed into SecureMailScope for automated batch auditing."*
