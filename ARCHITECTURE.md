# SecureMailScope — Technical Architecture

## 1. Design Philosophy: Analysis Engine First
SecureMailScope is architected as an **engine-first security analysis tool**. The user interface (Streamlit) is strictly a presentation layer consuming the outputs of the underlying analysis engine. The engine operates independently and deterministically from the CLI (`python main.py <pcap>`).

## 2. Pipeline Stages

### Stage 1: TShark Ingestion & Two-Pass Parsing (`app/tshark_runner.py`)
- Discovers system TShark binary (`C:\Program Files\Wireshark\tshark.exe` or PATH).
- Executes two-pass analysis (`-2`) to allow Wireshark dissectors to resolve stream-dependent protocol state.
- Dissects frame numbers, epoch timestamps, transport endpoints (IP/port), TCP stream IDs, frame lengths, and mail protocol fields.

### Stage 2: Protocol Detection & Stream Reassembly (`app/protocol_detector.py`, `app/stream_reassembler.py`)
- Reassembles raw packet sequences into bidirectional TCP conversations.
- Identifies protocol by inspecting application-layer banners and commands (`EHLO`, `STARTTLS`, `* OK Dovecot`, `+OK POP3`, `CAPABILITY`, `STLS`) backed by standard ports (25, 587, 465, 143, 993, 110, 995).

### Stage 3: STARTTLS State Tracking & Plaintext Auth Detection (`app/starttls_tracker.py`)
- Maintains explicit state transitions:
  - `none`: Direct implicit TLS or unencrypted stream without STARTTLS.
  - `advertised`: Server offered STARTTLS capability (`250-STARTTLS`, `CAPABILITY STARTTLS`, `STLS`), but client never requested it.
  - `requested`: Client sent `STARTTLS` / `STLS` command.
  - `completed`: Server confirmed upgrade (`220 Ready`, `OK`, `+OK`) and TLS handshake packets followed.
  - `failed`: STARTTLS requested or advertised but session aborted or fell back to cleartext.
- Forensic audit for cleartext credentials: scans client packets prior to TLS completion for `AUTH PLAIN`, `AUTH LOGIN`, `LOGIN`, `USER`, `PASS`. Records exact frame numbers without logging credential contents.

### Stage 4: TLS & Passive Certificate Analysis (`app/tls_extractor.py`, `app/ja3_fingerprint.py`)
- Extracts ClientHello and ServerHello parameters: TLS version, negotiated cipher suite, offered ciphers list, client SNI, and handshake latency.
- Extracts Salesforce JA3 (raw string + MD5) and JA4 fingerprints from ClientHello, ignoring RFC 8701 GREASE values.
- Checks OCSP status request (extension type 5) and OCSP stapling response (`present`, `absent`, `unknown`).
- **TLS 1.3 Handling**: Correctly classifies certificate visibility as `not_extractable_tls1.3` (since TLS 1.3 encrypts the relevant certificate handshake information on the wire). Avoids false positive certificate missing errors.
- **Passive X.509 Certificate Analysis**: Parses DER X.509 certificate bytes via Python `cryptography` to extract Subject, Issuer, Validity NotBefore/NotAfter, SANs, Public Key Algorithm, Key Size, and self-signed status. Intentionally operates offline without outbound OCSP/CRL lookups.

### Stage 5: Layer 1 Deterministic Rule Engine (`app/rules.py`)
- Enforces **seven mandatory baseline rules** (Plaintext Auth, Deprecated TLS, Broken Ciphers, Expired Cert, Hostname/SAN Mismatch, STARTTLS Not Enforced, TLS Handshake Alerts) plus **additional supporting certificate checks** (Self-Signed, Non-AEAD, Expiring Soon).
- Evaluates rule violations with traceable frame-level evidence citing RFC and NIST SP 800-52 Rev. 2 standards.
- Calculates Session Severity as:
  $$\text{Session Severity} = \max(\text{fired rule severities})$$
  Hierarchy: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `CLEAN`.

### Stage 6: Layer 2 Unsupervised Anomaly Detector (`app/anomaly.py`)
- Scikit-learn `IsolationForest` operating on a defensible 9-dimensional numeric telemetry vector:
  $$x = [\text{handshake\_duration\_ms}, \text{offered\_cipher\_count}, \text{cipher\_rarity\_score}, \text{payload\_bytes\_avg}, \text{payload\_bytes\_var}, \text{packet\_count}, \text{tls\_version\_encoded}, \text{cipher\_suite\_encoded}, \text{ja3\_hash\_encoded}]$$
- **Feature Vector Justification**:
  1. `handshake_duration_ms` (Continuous): Exact timing latency $\Delta t = (t_{ServerHello} - t_{ClientHello}) \times 1000$. Distinguishes network delays and scanner timeouts.
  2. `offered_cipher_count` (Discrete): Length of ClientHello cipher suite vector. Distinguishes standard MUAs (15–30 ciphers) from scanner bots (1–2 ciphers).
  3. `cipher_rarity_score` (Continuous in $[0.1, 0.95]$): Heuristic metric representing cipher obsolescence.
  4. `payload_bytes_avg` (Continuous): Mean application TCP payload bytes per frame.
  5. `payload_bytes_var` (Continuous): Variance of application TCP payload bytes across stream frames.
  6. `packet_count` (Discrete): Total frames in the reassembled TCP stream.
  7. `tls_version_encoded` (Ordinal in $[0.0, 5.0]$): Monotonic ordinal ranking representing protocol security progression (Cleartext=0.0, SSL 3.0=1.0, TLS 1.0=2.0, TLS 1.1=3.0, TLS 1.2=4.0, TLS 1.3=5.0).
  8. `cipher_suite_encoded` (Categorical Tiers in $[0.0, 5.0]$): Rather than treating arbitrary hash integers as continuous distances (which is statistically unsound), cipher suites are partitioned into defensible cryptographic capability tiers (0=Cleartext, 1=Broken/prohibited, 2=Legacy CBC, 3=ChaCha20, 4=AES-128-GCM, 5=AES-256-GCM).
  9. `ja3_hash_encoded` (Continuous in $[0.0, 1.0]$): Normalized deterministic partition of JA3 ClientHello fingerprint.
- **Terminology & Boundary**:
  - The anomaly result is strictly an **Anomaly Score / Behavioral Outlier Indicator**.
  - It is **NOT** an attack probability or malicious likelihood.
  - *The anomaly score indicates how unusual a session is relative to the analyzed behavioral baseline. It is not a probability that the session is malicious.*
  - The anomaly indicator remains completely separate from deterministic rule severity.

### Stage 7: Layer 3 Downstream Hardening & Remediation (`app/explainer.py`, `app/main.py`)
- Strictly downstream and recommendation-only: Translates verified findings into actionable Postfix and Dovecot configuration directives.
- Labeled as **Administrator Action** (Advisory Only). SecureMailScope never automatically modifies production mail servers.
- Machine-readable JSON output and interactive Streamlit visualization of offline PCAP analysis results.
