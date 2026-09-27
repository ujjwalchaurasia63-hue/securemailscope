# SecureMailScope — Technical Limitations & Operational Scope

This document specifies the operational boundaries, technical limitations, and scope of SecureMailScope.

---

## 1. Environment Baseline & Runtime Verification

- **Reference Baseline**: Python 3.11 (per Handbook specification).
- **Verified Runtime**: Python 3.14.7 on Windows 11 with TShark 4.6.8.
- *Note*: The test suite and pipeline are fully verified under the Python 3.14.7 runtime. If deploying in a strict Python 3.11 production environment, dependencies in `requirements.txt` are pin-compatible with Python 3.11+.

---

## 2. Implemented & Verified Capabilities (What Works)
- **Real Two-Pass TShark Ingestion**: Operates directly on `.pcap` and `.pcapng` packet capture files without synthetic mocking.
- **Protocol Identification**: Detects SMTP (ports 25, 587, 465), IMAP (ports 143, 993), and POP3 (ports 110, 995) based on both payload signatures and port numbers. Non-matching traffic is labeled `unrecognized mail-port traffic`.
- **STARTTLS State Machine**: Full tracking of `none`, `advertised`, `requested`, `completed`, and `failed` negotiation lifecycles.
- **Plaintext Authentication Detection**: Audits and traces `AUTH`, `LOGIN`, `USER`, and `PASS` commands occurring prior to TLS establishment without logging sensitive credentials.
- **Cryptographic Parameter Extraction**: Negotiated TLS version, cipher suite, offered ciphers count, client SNI, and handshake latency.
- **Client Fingerprinting**: Derives Salesforce JA3 (raw string and MD5 hash) and JA4 string with RFC 8701 GREASE stripping.
- **Passive X.509 Certificate Analysis (TLS 1.2 and lower)**: Subject, Issuer, NotBefore, NotAfter, SANs, Public Key Algorithm, Key Size, and self-signed status extracted via Python `cryptography`.
- **Deterministic Rule Engine (Layer 1)**: Enforces seven mandatory baseline rules plus additional supporting certificate checks with frame-level evidence.
- **Maximum Severity Hierarchy**: Evaluates session severity as $\max(\text{fired rules})$: $\text{CRITICAL} > \text{HIGH} > \text{MEDIUM} > \text{LOW} > \text{CLEAN}$.
- **Unsupervised Anomaly Detection (Layer 2)**: Identifies statistical outliers using Isolation Forest across a defensible 9D feature vector without merging into rule severity.
- **Dual Interfaces**: Headless CLI and Streamlit dashboard consume the identical analysis engine pipeline.

---

## 3. Operational Boundaries & Threat Scope (Passive Analysis)

### Offline / Passive Scope (Not an Inline IDS or Gateway)
- SecureMailScope is an **offline, passive network capture analysis tool**.
- It is **NOT** an inline SMTP proxy, a live intrusion detection system (IDS), a real-time network sniffer, or a packet manipulation framework.
- It operates read-only on captured PCAP/PCAPNG files and never transmits packets, interferes with mail delivery, or alters production servers.

### Passive TLS 1.3 Certificate Visibility
- **Limitation**: In TLS 1.3 (RFC 8446), the server `Certificate` message is transmitted after the encrypted key exchange and is therefore encrypted on the wire.
- **Handling**: SecureMailScope explicitly labels this condition as `not_extractable_tls1.3` with the explanation:
  > *TLS 1.3 encrypts the relevant certificate handshake information in a passive capture, so certificate details may not be available without appropriate decryption keys.*
- It strictly refrains from misclassifying this condition as "Certificate Missing", "Certificate Invalid", or a parser defect.

### No Live Online Revocation Checking (OCSP / CRL)
- **Limitation**: Because SecureMailScope operates offline in an air-gapped/passive analysis posture, it does not send outbound network requests to query live OCSP responders or download Certificate Revocation Lists (CRLs).
- **Handling**: Performs passive inspection for OCSP Stapling extensions (`present`, `absent`, `unknown`) and evaluates certificate validity windows (`NotBefore`, `NotAfter`) and self-signed status.

### Encrypted Application Content
- **Limitation**: Once a TLS session completes handshake, subsequent application payloads are encrypted. SecureMailScope does not possess server private keys or perform TLS decryption.
- **Handling**: Audits protocol negotiation, pre-TLS commands, and cryptographic handshake parameters.

### Anomaly Score vs Attack Probability
- **Limitation**: The Isolation Forest anomaly detector identifies statistical deviations in session telemetry.
- **Handling**: Clearly designated as an **Anomaly Score / Behavioral Outlier Indicator**. It is **not** an attack probability or proof of compromise.

---

## 4. Proposed Future Capabilities (Intentionally Unsupported in Current PoC)
- Hardware-accelerated packet capture processing (e.g. DPDK / native C bindings).
- Live packet capture sniffing interface (e.g., Npcap / WinPcap driver integration).
- Offline LLM assistant integration for narrative posture briefings.
- Automated Ansible playbook generation for server remediation.

