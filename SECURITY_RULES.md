# SecureMailScope — Security Rule Specifications

Deterministic compliance and cryptographic posture rules enforced by Layer 1.

The engine implements **seven mandatory baseline rules** from the project specification plus **additional supporting certificate and security checks**.

---

## 1. Mandatory Baseline Rules (7 Rules)

| Rule ID | Severity | Governing Standards | Trigger Condition | Forensic Evidence Captured |
|---|---|---|---|---|
| `RULE_TLS_LEGACY` | **HIGH** | NIST SP 800-52 Rev. 2 §3.1, RFC 8996 | Negotiated protocol version is SSL 2.0, SSL 3.0, TLS 1.0, or TLS 1.1. | Frame number of ServerHello, negotiated version string. |
| `RULE_CIPHER_BROKEN` | **HIGH** | RFC 7465, RFC 7590, NIST SP 800-52 Rev. 2 §3.3 | Negotiated cipher suite contains broken primitives (RC4, 3DES, DES, NULL, EXPORT, MD5). | Frame number of ServerHello, cipher suite name, matched broken algorithm. |
| `RULE_PLAINTEXT_AUTH_BEFORE_TLS` | **CRITICAL** | RFC 2595 §3.2, RFC 8314 §3, NIST SP 800-45 | Plaintext authentication command (`AUTH`, `LOGIN`, `USER`, `PASS`) transmitted before TLS completion. | Frame number, client IP, detected authentication command name. |
| `RULE_STARTTLS_NOT_ENFORCED` | **MEDIUM** | RFC 3207 §4.1, RFC 8314 §5.1 | Server advertised STARTTLS capability (`starttls_state == 'advertised'`), but communication proceeded unencrypted. | Frame number of STARTTLS advertisement, subsequent unencrypted commands. |
| `RULE_CERT_EXPIRED` | **CRITICAL** | RFC 5280 §4.1.2.5, NIST SP 800-52 Rev. 2 §3.2 | Visible X.509 certificate has `cert_days_to_expiry < 0`. | Certificate frame number, expiration timestamp, elapsed days since expiration. |
| `RULE_HOSTNAME_MISMATCH` | **CRITICAL** | RFC 6125 | Visible X.509 certificate Subject/SAN does not match client SNI. | Certificate frame number, client SNI, presented SAN list. |
| `RULE_TLS_HANDSHAKE_FAILURE` | **HIGH / MEDIUM** | RFC 8446 §6 | TLS Alert message observed during handshake negotiation (Fatal=HIGH, Warning=MEDIUM). | Alert frame number, alert level, alert description code. |

---

## 2. Additional Supporting Rules

| Rule ID | Severity | Governing Standards | Trigger Condition | Forensic Evidence Captured |
|---|---|---|---|---|
| `RULE_CERT_SELF_SIGNED` | **HIGH** | RFC 8314 §4.1, NIST SP 800-52 Rev. 2 §3.2 | Visible X.509 certificate Issuer equals Subject. | Certificate frame number, Issuer DN, Subject DN. |
| `RULE_CIPHER_NON_AEAD` | **LOW** | RFC 8446, NIST SP 800-52 Rev. 2 §3.3.1 | TLS 1.2 negotiated with CBC-mode cipher lacking authenticated encryption. | ServerHello frame number, cipher suite name. |
| `RULE_CERT_EXPIRING_SOON` | **LOW** | NIST SP 800-52 Rev. 2 §3.2 | Visible certificate expires within 14 days (`0 <= days <= 14`). | Certificate frame number, remaining days to expiration. |

---

## 3. Severity Hierarchy & Aggregation

Final Session Severity is the **MAXIMUM** severity across all fired rules:
$$\text{Session Severity} = \max(\text{fired rule severities})$$
Hierarchy:
$$\text{CRITICAL} > \text{HIGH} > \text{MEDIUM} > \text{LOW} > \text{CLEAN}$$

*Note: The Anomaly Detector (Layer 2) provides an independent behavioral outlier indicator and is never merged into the deterministic compliance severity score.*

