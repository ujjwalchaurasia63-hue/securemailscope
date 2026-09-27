# SecureMailScope — End-to-End Analysis Pipeline

This document details the exact 15-step sequence by which an offline PCAP/PCAPNG capture file is processed into verified, evidence-linked cybersecurity findings.

```text
Raw PCAP File
      │
      ▼
[1. PCAP File Integrity & Format Validation] (app/pcap_validator.py)
      │
      ▼
[2. Two-Pass TShark Packet Dissection (-2)] (app/tshark_runner.py)
      │
      ▼
[3. Transport Stream Identification] (tcp.stream, endpoints)
      │
      ▼
[4. Bidirectional TCP Stream Reassembly] (app/stream_reassembler.py)
      │
      ▼
[5. Mail Protocol Identification] (app/protocol_detector.py)
      │
      ▼
[6. Application Banners & Command Parsing] (EHLO, HELO, AUTH, USER, PASS)
      │
      ▼
[7. STARTTLS 5-State Machine Tracking] (app/starttls_tracker.py)
      │
      ▼
[8. Cryptographic TLS Handshake Extraction] (app/tls_extractor.py)
      │
      ▼
[9. Passive X.509 Certificate Analysis] (app/tls_extractor.py via cryptography)
      │
      ▼
[10. Layer 1: Deterministic Compliance Rule Evaluation] (app/rules.py)
      │
      ▼
[11. Maximum Severity Aggregation] (CRITICAL > HIGH > MEDIUM > LOW > CLEAN)
      │
      ▼
[12. Layer 2: 9D Isolation Forest Anomaly Detection] (app/anomaly.py)
      │
      ▼
[13. Forensic Evidence Assembly & Frame Mapping] (app/analyzer.py)
      │
      ▼
[14. Machine-Readable Structured JSON Serialization] (main.py --json)
      │
      ▼
[15. Interactive Streamlit Visualization & Remediation] (app/main.py)
```

---

## Detailed Pipeline Phases

### Phase 1: Ingestion & Stream Reassembly
1. **PCAP Validation (`app/pcap_validator.py`)**:
   - Confirms file existence, valid extension (`.pcap`, `.pcapng`, `.cap`), non-zero byte size, and tests capture headers via TShark probe.
2. **Two-Pass TShark Dissection (`app/tshark_runner.py`)**:
   - Executes `tshark -r <file> -2 -R tcp -T fields ...` without shell injection.
   - Extracts frame numbers, epoch timestamps, source/destination IPs and ports, TCP stream IDs, application payloads, TLS record versions, handshake types, ciphersuites, SNI, alerts, and raw certificate DER hex.
3. **Stream Grouping & Boundary Detection (`app/stream_reassembler.py`)**:
   - Aggregates packets by `tcp.stream`. Identifies conversation boundaries (`first_frame`, `last_frame`), packet counts, conversation duration, and payload size statistics (average and variance).

### Phase 2: Protocol Identification & State Tracking
4. **Protocol Identification (`app/protocol_detector.py`)**:
   - Inspects application banners and command payloads (`EHLO`, `220`, `* OK`, `+OK`, `CAPABILITY`, `STLS`).
   - Validates across mail ports (25, 587, 465 for SMTP; 143, 993 for IMAP; 110, 995 for POP3).
   - If traffic on a mail port lacks mail grammar, it is classified as `unrecognized mail-port traffic`.
5. **STARTTLS State Machine (`app/starttls_tracker.py`)**:
   - Tracks 5 lifecycle states: `none`, `advertised`, `requested`, `completed`, `failed`.
   - Audits for cleartext authentication (`AUTH`, `LOGIN`, `USER`, `PASS`) occurring before TLS handshake completion.

### Phase 3: Cryptographic Parameter & Certificate Extraction
6. **TLS Metadata Extraction (`app/tls_extractor.py`)**:
   - Dissects ClientHello: extracts offered ciphers vector, Client SNI, and computes Salesforce JA3 (raw string + MD5) and Cloudflare JA4 strings (ignoring RFC 8701 GREASE values).
   - Dissects ServerHello: extracts negotiated TLS version and negotiated cipher suite.
   - Calculates handshake latency $\Delta t = (t_{\text{ServerHello}} - t_{\text{ClientHello}}) \times 1000$.
7. **Passive X.509 Certificate Analysis (`app/tls_extractor.py`)**:
   - **TLS 1.3 Handling**: When TLS 1.3 is negotiated, labels `cert_visibility = "not_extractable_tls1.3"` (since RFC 8446 encrypts the Certificate handshake message on the wire).
   - **TLS 1.2 & Lower**: Parses DER-encoded X.509 certificate bytes via Python `cryptography`. Extracts Subject, Issuer, Validity (`NotBefore`, `NotAfter`), SANs, Public Key Algorithm, Key Size, and checks for self-signed certificates (Issuer equals Subject) and SNI hostname match.
   - Operates strictly offline without outbound network calls.

### Phase 4: Security Rules & Anomaly Detection
8. **Layer 1 Deterministic Rule Engine (`app/rules.py`)**:
   - Evaluates compliance against 7 mandatory baseline rules plus additional supporting checks.
   - Maps each violation to exact forensic packet frame numbers and cites governing RFCs and NIST SP 800-52 Rev. 2.
9. **Maximum Severity Aggregation (`app/rules.py`)**:
   - Calculates session severity as $\max(\text{fired rule severities})$:
     $$\text{CRITICAL} > \text{HIGH} > \text{MEDIUM} > \text{LOW} > \text{CLEAN}$$
10. **Layer 2 Isolation Forest Anomaly Detection (`app/anomaly.py`)**:
    - Converts session telemetry into a 9-dimensional numeric vector:
      `[handshake_duration_ms, offered_cipher_count, cipher_rarity_score, payload_bytes_avg, payload_bytes_var, packet_count, tls_version_encoded, cipher_suite_encoded, ja3_hash_encoded]`.
    - Fits scikit-learn `IsolationForest(contamination=0.15, random_state=42)`.
    - Generates independent `is_anomaly` flag and normalized `anomaly_score` $[0.0, 1.0]$.
    - Identifies top deviating features using standardized z-scores.
    - Never elevates deterministic compliance severity.

### Phase 5: Output & Remediation
11. **Forensic Evidence Assembly (`app/analyzer.py`)**:
    - Compiles capture metadata, reassembled session records, rule findings, and anomaly flags into a unified structured Python dictionary.
12. **Serialization & Presentation (`main.py`, `app/main.py`)**:
    - Serializes to machine-readable JSON for automated ingestion.
    - Renders interactive Streamlit dashboard with session deep dives, forensic finding cards, and advisory Postfix/Dovecot hardening guides.
