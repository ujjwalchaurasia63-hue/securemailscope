# SecureMailScope — Final Source-Code & Evidence Consistency Audit Report

This report documents the final source-code, telemetry, and evidence consistency audit for **SecureMailScope** (Smart India Hackathon 2026 / NTRO prototype for passive, offline cryptographic security posture assessment of email traffic).

---

## A. Environment Verification

- **Reference Baseline**: Python 3.11 (per Handbook specification)
- **Verified Host Runtime**: Python 3.14.7 (64-bit) on Windows 11
- **Packet Dissection Engine**: TShark (Wireshark) 4.6.8 (v4.6.8-0-ge677bf052328) at `C:\Program Files\Wireshark\tshark.exe`
- **Verified Package Manifest**:
  - `streamlit`: 1.64.0
  - `scikit-learn`: 1.9.1
  - `pandas`: 3.0.6
  - `numpy`: 2.5.1
  - `scapy`: 2.7.0
  - `cryptography`: 50.0.1
- **Diagnostic Execution**: `python main.py --check-env` passes with all components validated.

---

## B. Automated Test Suite Results

Command: `python -m pytest tests -v`

```text
============================= test session starts =============================
platform win32 -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\SIH26
collected 33 items

tests/test_analyzer_integration.py::test_analyzer_on_demo_pcap PASSED    [  3%]
tests/test_compliance_suite.py::test_tls_version_normalization PASSED    [  6%]
tests/test_compliance_suite.py::test_cipher_suite_normalization PASSED   [  9%]
tests/test_compliance_suite.py::test_max_severity_rules PASSED           [ 12%]
tests/test_compliance_suite.py::test_smtp_protocol_detection_from_payload PASSED [ 15%]
tests/test_compliance_suite.py::test_imap_protocol_detection_from_payload PASSED [ 18%]
tests/test_compliance_suite.py::test_pop3_protocol_detection_from_payload PASSED [ 21%]
tests/test_compliance_suite.py::test_unrecognized_mail_port_traffic PASSED [ 24%]
tests/test_compliance_suite.py::test_starttls_completed_flow PASSED      [ 27%]
tests/test_compliance_suite.py::test_starttls_advertised_but_not_upgraded PASSED [ 30%]
tests/test_compliance_suite.py::test_plaintext_auth_detected PASSED      [ 33%]
tests/test_compliance_suite.py::test_tls13_certificate_visibility_guard PASSED [ 36%]
tests/test_compliance_suite.py::test_ja3_and_ja4_computation PASSED      [ 39%]
tests/test_compliance_suite.py::test_client_hello_fingerprint_extraction PASSED [ 42%]
tests/test_compliance_suite.py::test_anomaly_feature_vector_encoding PASSED [ 45%]
tests/test_compliance_suite.py::test_anomaly_detector_execution PASSED   [ 48%]
tests/test_compliance_suite.py::test_certificate_analysis_valid_and_expired PASSED [ 51%]
tests/test_compliance_suite.py::test_certificate_san_mismatch PASSED     [ 54%]
tests/test_compliance_suite.py::test_certificate_malformed_handling PASSED [ 57%]
tests/test_compliance_suite.py::test_environment_check PASSED            [ 60%]
tests/test_failure_cases.py::test_missing_pcap_raises_file_not_found PASSED [ 63%]
tests/test_failure_cases.py::test_invalid_extension_raises_error PASSED  [ 66%]
tests/test_failure_cases.py::test_empty_pcap_raises_value_error PASSED   [ 69%]
tests/test_failure_cases.py::test_no_email_traffic_pcap PASSED           [ 72%]
tests/test_rules.py::test_max_severity_hierarchy PASSED                  [ 75%]
tests/test_rules.py::test_rule_plaintext_auth_before_tls PASSED          [ 78%]
tests/test_rules.py::test_rule_legacy_tls PASSED                         [ 81%]
tests/test_rules.py::test_rule_broken_cipher PASSED                      [ 84%]
tests/test_rules.py::test_rule_expired_certificate PASSED                [ 87%]
tests/test_rules.py::test_rule_starttls_not_enforced PASSED              [ 90%]
tests/test_rules.py::test_tls13_visibility_does_not_trigger_cert_failure PASSED [ 93%]
tests/test_rules.py::test_rule_hostname_mismatch PASSED                  [ 96%]
tests/test_rules.py::test_rule_tls_handshake_failure PASSED              [100%]

======================== 33 passed, 1 warning in 3.32s ========================
```
- **Tests Collected**: 33
- **Tests Passed**: 33
- **Tests Failed**: 0
- **Tests Skipped**: 0
- **Warnings**: 1 (Non-blocking: Scapy internal DH group deprecation notice under Python 3.14)

---

## C. Demonstration PCAP Statistics

File: `data/demo_mail_traffic.pcap`
- **Total Packet Count**: 101 packets
- **Total Reassembled Sessions**: 9 sessions (Stream 0 through Stream 8)
- **Distinct Traffic Scenarios**: 9 scenarios
- **Overall Capture Severity**: **CRITICAL**

---

## D. Mandatory Rules Verification

| Rule ID | Severity | Verification Status | Offending Session | Evidence Frame | Standard Citation |
|---|---|---|---|---|---|
| `RULE_TLS_LEGACY` | **HIGH** | `VERIFIED` | Stream 1 (SMTP:25) | Frame 23 | NIST SP 800-52 Rev. 2 §3.1, RFC 8996 |
| `RULE_CIPHER_BROKEN` | **HIGH** | `VERIFIED` | Stream 1 (SMTP:25) | Frame 23 | RFC 7465, RFC 7590, NIST SP 800-52 Rev. 2 §3.3 |
| `RULE_PLAINTEXT_AUTH_BEFORE_TLS` | **CRITICAL** | `VERIFIED` | Stream 2 (SMTP:587)<br>Stream 4 (POP3:110) | Frame 31 (`AUTH`)<br>Frames 52 & 54 (`USER`, `PASS`) | RFC 2595 §3.2, RFC 8314 §3, NIST SP 800-45 |
| `RULE_STARTTLS_NOT_ENFORCED` | **MEDIUM** | `VERIFIED` | Stream 5 (SMTP:25) | Frame 64 (`250-STARTTLS`) | RFC 3207 §4.1, RFC 8314 §5.1 |
| `RULE_CERT_EXPIRED` | **CRITICAL** | `VERIFIED` | Stream 3 (IMAP:143) | Frame 46 | RFC 5280 §4.1.2.5, NIST SP 800-52 Rev. 2 §3.2 |
| `RULE_HOSTNAME_MISMATCH` | **CRITICAL** | `VERIFIED` | Stream 7 (IMAP:143) | Frame 89 | RFC 6125 |
| `RULE_TLS_HANDSHAKE_FAILURE` | **HIGH** | `VERIFIED` | Stream 8 (SMTP:587) | Frame 100 | RFC 8446 §6 |

*Supporting Rule Verified*:
- `RULE_CERT_SELF_SIGNED` (HIGH): Verified in Stream 3 (Frame 46) and Stream 7 (Frame 89).

---

## E. Nine Scenario Audit Matrix (Actual JSON Evidence)

Derived directly from `data/demo_result.json` produced by `python main.py data/demo_mail_traffic.pcap --json data/demo_result.json`:

| Stream | Protocol & Port | STARTTLS State | Negotiated TLS & Cipher | Session Severity (Max Rule) | Anomaly Indicator | Anomaly Score | Rule Findings & Offending Frames |
|---|---|---|---|---|---|---|---|
| **0** | SMTP:587 | `completed` | TLS 1.3 / `TLS_AES_256_GCM_SHA384` | **CLEAN** | False | 0.829 | None (Compliant). `cert_visibility = not_extractable_tls1.3` |
| **1** | SMTP:25 | `completed` | TLS 1.0 / `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | **HIGH** | **True** | 1.000 | `RULE_TLS_LEGACY` (Frame 23)<br>`RULE_CIPHER_BROKEN` (Frame 23) |
| **2** | SMTP:587 | `advertised` | None (Cleartext) | **CRITICAL** | False | 0.558 | `RULE_PLAINTEXT_AUTH_BEFORE_TLS` (Frame 31) |
| **3** | IMAP:143 | `completed` | TLS 1.2 / `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | **CRITICAL** | False | 0.804 | `RULE_CERT_EXPIRED` (Frame 46)<br>`RULE_CERT_SELF_SIGNED` (Frame 46) |
| **4** | POP3:110 | `none` | None (Cleartext) | **CRITICAL** | False | 0.243 | `RULE_PLAINTEXT_AUTH_BEFORE_TLS` (Frames 52, 54) |
| **5** | SMTP:25 | `advertised` | None (Cleartext) | **MEDIUM** | False | 0.000 | `RULE_STARTTLS_NOT_ENFORCED` (Frame 64) |
| **6** | SMTP:587 | `completed` | TLS 1.3 / `TLS_AES_128_GCM_SHA256` | **CLEAN** | **True** | **0.958** | **Zero Rule Violations (CLEAN)**.<br>Layer 2 Outlier: 580 ms latency (`z=2.82`) |
| **7** | IMAP:143 | `completed` | TLS 1.2 / `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | **CRITICAL** | False | 0.714 | `RULE_HOSTNAME_MISMATCH` (Frame 89)<br>`RULE_CERT_SELF_SIGNED` (Frame 89) |
| **8** | SMTP:587 | `failed` | TLS 1.2 / None | **HIGH** | False | 0.232 | `RULE_TLS_HANDSHAKE_FAILURE` (Frame 100 Fatal Alert 40) |

---

## F. Session 6 Anomaly Verification & Score Discrepancy Resolution

### 1. Actual 9-Dimensional Feature Vector
Extracted from `tcp_stream_6`:
```python
[
    580.0,    # 1. handshake_duration_ms (Continuous: 580 ms injected delay)
    1.0,      # 2. offered_cipher_count (Discrete: 1 cipher suite offered)
    0.15,     # 3. cipher_rarity_score (Continuous: modern AES-GCM class)
    40.43,    # 4. payload_bytes_avg (Continuous: mean TCP payload)
    492.53,   # 5. payload_bytes_var (Continuous: payload variance)
    11.0,     # 6. packet_count (Discrete: 11 frames in stream)
    5.0,      # 7. tls_version_encoded (Ordinal: TLS 1.3 = 5.0)
    4.0,      # 8. cipher_suite_encoded (Categorical tier: AES-128 AEAD = 4.0)
    0.8197    # 9. ja3_hash_encoded (Normalized 16-bit hex prefix: 0.8197)
]
```

### 2. Verified Anomaly Output
- `is_anomaly`: **`True`**
- `anomaly_score`: **`0.958`**
- `top_deviating_features`: `['handshake_duration_ms (z=2.82)']`

### 3. Two-Run Determinism Proof
- Run 1 Vector: `[580.0, 1.0, 0.15, 40.43, 492.53, 11.0, 5.0, 4.0, 0.8197]` | Score: `0.958` | Flag: `True`
- Run 2 Vector: `[580.0, 1.0, 0.15, 40.43, 492.53, 11.0, 5.0, 4.0, 0.8197]` | Score: `0.958` | Flag: `True`
- **Result**: Exactly identical. The model uses `random_state=42` and deterministic categorical encoding.

### 4. Root Cause of Previous 1.0 vs 0.958 Discrepancy
- In the earlier prototype stage, the capture dataset contained **7 sessions** and used Python's randomized hash modulo for cipher encoding. In that 7-session set, Session 6 was the sole outlier, which by min-max normalization ($1.0 - \frac{d - d_{min}}{d_{max} - d_{min}}$) evaluated to exactly $1.0 - 0.0 = 1.0$.
- In the complete **9-session** specification, Stream 1 (3DES, cipher rarity $0.95$) and Stream 6 (handshake delay $580$ ms) are both isolated by the Isolation Forest ($N=9, \text{contamination}=0.15 \implies 2$ outliers). Stream 1 achieves the lowest decision score (normalized to $1.000$), and Stream 6 achieves $0.958$.
- **Authoritative Value**: **0.958** is the verified deterministic score across all current artifacts.

---

## G. Evidence Traceability Audit

| Evidence Point | Offending PCAP Frame | TShark Dissected Field | Rule Engine Evidence String | JSON Path | Streamlit UI Element |
|---|---|---|---|---|---|
| **Legacy TLS & 3DES** | Frame 23 | `tls.handshake.version = 0x0301`, `tls.handshake.ciphersuite = 0x000a` | `"Negotiated TLS 1.0 in ServerHello (Frame 23)."` | `findings[0].evidence` | Findings Expander: `[HIGH] Deprecated TLS Protocol Version` |
| **Cleartext AUTH** | Frame 31 | `smtp.req.command = AUTH`, `tcp.payload` | `"Observed cleartext authentication in unencrypted SMTP stream: Frame 31: Cleartext AUTH command from 10.0.2.12"` | `findings[2].evidence` | Findings Expander: `[CRITICAL] Plaintext Credentials Transmitted` |
| **Expired Certificate** | Frame 46 | `tls.handshake.certificate`, `x509af.utcTime` | `"Certificate presented in Frame 46 expired 61 days ago."` | `findings[3].evidence` | Findings Expander: `[CRITICAL] Expired X.509 Certificate` |
| **POP3 Plaintext Auth** | Frames 52, 54 | `pop.request = USER`, `pop.request = PASS` | `"Observed cleartext authentication in unencrypted POP3 stream: Frame 52: Cleartext USER... Frame 54: Cleartext PASS..."` | `findings[5].evidence` | Findings Expander: `[CRITICAL] Plaintext Credentials Transmitted` |
| **STARTTLS Not Enforced** | Frame 64 | `tcp.payload = 250-STARTTLS` | `"Server advertised STARTTLS capability in Frame 64, but client proceeded in cleartext."` | `findings[6].evidence` | Findings Expander: `[MEDIUM] STARTTLS Advertised But Not Utilized` |
| **SAN Mismatch** | Frame 89 | `tls.handshake.extensions_server_name`, `x509ce.dNSName` | `"Client SNI 'mail.bank.corp' does not match certificate SANs [attacker.phishing.org] in Frame 89."` | `findings[7].evidence` | Findings Expander: `[CRITICAL] Certificate Hostname / SAN Mismatch` |
| **Handshake Alert** | Frame 100 | `tls.alert_message.level = 2`, `tls.alert_message.desc = 40` | `"TLS Alert (Level: 2, Description: 40) in Frame 100."` | `findings[9].evidence` | Findings Expander: `[HIGH] TLS Handshake Alert Encountered (40)` |

All frame numbers and evidence strings displayed in Streamlit originate directly from the analyzer model output. No frame numbers or findings are hard-coded in the UI.

---

## H. TLS 1.3 Handling Verification

- **Extraction State**: Recorded as `cert_visibility = "not_extractable_tls1.3"`.
- **Explanatory String**: `"TLS 1.3 encrypts the relevant certificate handshake information in a passive capture, so certificate details may not be available without appropriate decryption keys."`
- **Rule Engine Protection**: `app/rules.py` explicitly evaluates `cert_vis == "visible"` before checking certificate dates, self-signed status, or SAN matches. When `cert_vis == "not_extractable_tls1.3"`, certificate rules are bypassed, ensuring Stream 0 and Stream 6 produce **zero false-positive certificate violations**.
- **Terminology**: Labeled strictly as **Passive X.509 Certificate Analysis**.

---

## I. Known Limitations & Threat Scope

1. **Passive TLS 1.3 Encrypted Handshakes**: TLS 1.3 server certificates are encrypted on the wire; passive analysis cannot inspect certificate details without private keys or SSLKEYLOGFILE.
2. **No Live Online Revocation**: System operates strictly offline; live OCSP queries and CRL lookups are intentionally not performed. Passive OCSP Stapling visibility is tracked.
3. **Tested Runtime**: Verified under Python 3.14.7 runtime with TShark 4.6.8. Reference baseline remains Python 3.11 per handbook.
4. **Anomaly Score Interpretation**: The Isolation Forest anomaly score is an independent behavioral outlier indicator, not an attack probability or proof of compromise.
5. **Offline Scope**: SecureMailScope is an offline packet capture inspection tool; it does not operate as an inline gateway, live IDS, or real-time packet manipulator.

---

## J. Final Technical Classification

- **Core PoC**: **COMPLETE**
- **Technical Demo**: **READY**
- **Judge Demonstration**: **READY**
- **Production Deployment**: **NOT CLAIMED**

> **Defect Statement**: No known blocking defects were identified during the executed validation suite. The verified environment and remaining limitations are documented above.
