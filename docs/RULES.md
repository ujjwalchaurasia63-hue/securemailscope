# SecureMailScope — Security Rule Specifications

This document details the deterministic compliance and cryptographic posture rules implemented in Layer 1 of the SecureMailScope analysis engine.

The engine implements **seven mandatory baseline rules** along with **three supporting cryptographic and certificate hygiene checks**, strictly mapped to authoritative Internet Standards (RFCs) and NIST Special Publications.

---

## 1. Severity Hierarchy & Aggregation

SecureMailScope uses a deterministic **Maximum-Severity Aggregation Model**:

$$\text{Session Severity} = \max(\{ \text{severity}(r) \mid r \in \text{FiredRules} \} \cup \{ \text{CLEAN} \})$$

### Severity Precedence
$$\text{CRITICAL} > \text{HIGH} > \text{MEDIUM} > \text{LOW} > \text{CLEAN}$$

- **CRITICAL**: Immediate exposure of credentials, unauthorized interception, or completely invalid trust anchors.
- **HIGH**: Severely weakened cryptography, deprecated protocols vulnerable to known attacks (POODLE, BEAST, SWEET32), or fatal handshake aborts.
- **MEDIUM**: Protocol downgrades, opportunistic encryption bypassed, or handshake warnings.
- **LOW**: Sub-optimal configurations (e.g. non-AEAD ciphers in TLS 1.2, impending certificate expiration).
- **CLEAN**: Strict compliance with modern cryptographic baselines (TLS 1.2/1.3, AEAD cipher, valid certificates).

*Note: Behavioral Anomaly Detection (Layer 2) operates independently and produces an orthogonal outlier score ($[0.0, 1.0]$). It is intentionally NEVER mixed into the deterministic severity rating.*

---

## 2. Mandatory Baseline Rules (7 Rules)

### 2.1 `RULE_TLS_LEGACY`
- **Severity**: `HIGH`
- **Governing RFCs / Standards**: NIST SP 800-52 Rev. 2 §3.1, RFC 8996 (Deprecating TLS 1.0 and TLS 1.1), RFC 7568 (Deprecating SSL 3.0).
- **Rationale**: SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 lack modern cryptographic defenses and are vulnerable to POODLE, BEAST, and downgrade attacks. RFC 8996 formally prohibits their use.
- **Trigger Condition**: Negotiated TLS version is `SSLv2`, `SSLv3`, `TLSv1.0`, or `TLSv1.1`.
- **Forensic Evidence Captured**: ServerHello frame number, negotiated protocol version string.
- **Remediation**: Deprecate legacy protocol versions on mail server configurations. Enforce TLS 1.2 as minimum, TLS 1.3 preferred (`ssl_protocols TLSv1.2 TLSv1.3;`).

### 2.2 `RULE_CIPHER_BROKEN`
- **Severity**: `HIGH`
- **Governing RFCs / Standards**: RFC 7465 (Prohibiting RC4), RFC 7590 (TLS in Email), NIST SP 800-52 Rev. 2 §3.3.1.
- **Rationale**: Ciphers based on RC4, 3DES, DES, EXPORT, NULL, or MD5 integrity primitives have been proven insecure (e.g. Sweet32 attack on 64-bit block ciphers like 3DES; keystream biases in RC4).
- **Trigger Condition**: Negotiated cipher suite contains any of: `RC4`, `3DES`, `DES`, `NULL`, `EXPORT`, `MD5`.
- **Forensic Evidence Captured**: ServerHello frame number, cipher suite name, matched broken cryptographic primitive.
- **Remediation**: Remove legacy ciphers from the server cipher suite string. Enforce AEAD ciphers (AES-GCM, CHACHA20-POLY1305).

### 2.3 `RULE_PLAINTEXT_AUTH_BEFORE_TLS`
- **Severity**: `CRITICAL`
- **Governing RFCs / Standards**: RFC 2595 §3.2 (Using TLS with IMAP, POP3 and ACAP), RFC 8314 §3 (Cleartext Considered Obsolete: Use of Transport Layer Security for Email), NIST SP 800-45.
- **Rationale**: Transmitting user credentials (`USER`, `PASS`, `AUTH`, `LOGIN`) prior to establishing a secure TLS tunnel allows passive network eavesdroppers to harvest cleartext authentication credentials.
- **Trigger Condition**: An authentication command (`AUTH`, `LOGIN`, `USER`, `PASS`) is observed in the TCP stream prior to TLS handshake completion or when `starttls_state != 'completed'`.
- **Forensic Evidence Captured**: Frame number of authentication command, client IP, detected authentication keyword.
- **Remediation**: Reconfigure mail server to reject authentication before STARTTLS (`smtpd_tls_auth_only = yes` in Postfix; `disable_plaintext_auth = yes` in Dovecot). Prefer implicit TLS ports (Submission 465, IMAPS 993, POP3S 995).

### 2.4 `RULE_STARTTLS_NOT_ENFORCED`
- **Severity**: `MEDIUM`
- **Governing RFCs / Standards**: RFC 3207 §4.1 (SMTP Service Extension for Secure SMTP over TLS), RFC 8314 §5.1.
- **Rationale**: Opportunistic encryption allows passive downgrade or interception if the client ignores the STARTTLS announcement and proceeds in cleartext.
- **Trigger Condition**: Server advertises STARTTLS capability (`starttls_state == 'advertised'`), but the client continues session commands (`MAIL FROM`, `RCPT TO`, `DATA`, etc.) without issuing `STARTTLS` or completing TLS.
- **Forensic Evidence Captured**: Frame number of STARTTLS advertisement banner, subsequent unencrypted command frame numbers.
- **Remediation**: Configure MTA-STS (RFC 8461) and DANE (RFC 7672) for domain-to-domain SMTP. For submission, mandate implicit TLS (port 465) or require STARTTLS before processing mail.

### 2.5 `RULE_CERT_EXPIRED`
- **Severity**: `CRITICAL`
- **Governing RFCs / Standards**: RFC 5280 §4.1.2.5 (Validity), NIST SP 800-52 Rev. 2 §3.2.
- **Rationale**: An expired X.509 certificate fails the basic validity requirements of Public Key Infrastructure, signaling lack of operational maintenance or potential compromise.
- **Trigger Condition**: Visible X.509 certificate has `cert_days_to_expiry < 0`.
- **Forensic Evidence Captured**: Frame number carrying Certificate, expiration timestamp (`not_after`), elapsed days since expiration.
- **Remediation**: Renew the X.509 certificate immediately using automated issuance tools (e.g., Certbot / ACME protocol) and update mail service bindings.

### 2.6 `RULE_HOSTNAME_MISMATCH`
- **Severity**: `CRITICAL`
- **Governing RFCs / Standards**: RFC 6125 (Representation and Verification of Domain-Based Application Service Identity), RFC 8314 §4.1.
- **Rationale**: If the Subject Alternative Name (SAN) or Common Name (CN) does not match the client's Server Name Indication (SNI) or target hostname, traffic is vulnerable to Man-in-the-Middle (MitM) impersonation.
- **Trigger Condition**: Client SNI is present and does not match any DNS entry in the SAN list or CN of the presented server certificate.
- **Forensic Evidence Captured**: Certificate frame number, SNI hostname, list of SANs presented in certificate.
- **Remediation**: Reissue certificate to include all required fully qualified domain names (FQDNs) in the Subject Alternative Name extension.

### 2.7 `RULE_TLS_HANDSHAKE_FAILURE`
- **Severity**: `HIGH` (Fatal Alert) / `MEDIUM` (Warning Alert)
- **Governing RFCs / Standards**: RFC 8446 §6 (Alert Protocol), RFC 5246 §7.2.
- **Rationale**: Unhandled TLS alerts indicate protocol failure, cipher mismatch, untrusted CA, or abnormal session termination, causing disruption and fallback risks.
- **Trigger Condition**: A TLS Alert record is observed during or immediately following the handshake.
- **Forensic Evidence Captured**: Alert packet frame number, alert level (`fatal` or `warning`), alert description code (e.g. `handshake_failure`, `bad_certificate`).
- **Remediation**: Investigate server/client cipher compatibility and trust store configurations.

---

## 3. Supporting Rules (3 Rules)

### 3.1 `RULE_CERT_SELF_SIGNED`
- **Severity**: `HIGH`
- **Governing RFCs / Standards**: RFC 8314 §4.1, NIST SP 800-52 Rev. 2 §3.2.
- **Rationale**: Self-signed certificates lack third-party trust validation, creating a high risk of undetected MITM interception unless pinned across all clients.
- **Trigger Condition**: Certificate Issuer Distinguished Name (DN) equals Subject Distinguished Name (DN) without an external trust anchor.
- **Forensic Evidence Captured**: Certificate frame number, Issuer DN, Subject DN.
- **Remediation**: Replace self-signed certificates with certificates issued by a trusted public Certificate Authority (e.g. Let's Encrypt).

### 3.2 `RULE_CIPHER_NON_AEAD`
- **Severity**: `LOW`
- **Governing RFCs / Standards**: RFC 8446 (Deprecation of non-AEAD ciphers), NIST SP 800-52 Rev. 2 §3.3.1.
- **Rationale**: TLS 1.2 CBC-mode ciphers without Authenticated Encryption with Associated Data (AEAD) require encrypt-then-mac extensions or are vulnerable to padding oracle attacks (e.g. Lucky Thirteen).
- **Trigger Condition**: TLS 1.2 is negotiated with a CBC-mode cipher lacking AEAD (e.g. `TLS_RSA_WITH_AES_128_CBC_SHA256`).
- **Forensic Evidence Captured**: ServerHello frame number, cipher suite name.
- **Remediation**: Prioritize GCM or CHACHA20-POLY1305 ciphers in mail server cipher preferences.

### 3.3 `RULE_CERT_EXPIRING_SOON`
- **Severity**: `LOW`
- **Governing RFCs / Standards**: NIST SP 800-52 Rev. 2 §3.2.
- **Rationale**: Certificates expiring within 14 days pose an operational continuity risk if renewal automation fails.
- **Trigger Condition**: Visible X.509 certificate has `0 <= cert_days_to_expiry <= 14`.
- **Forensic Evidence Captured**: Certificate frame number, days remaining until expiration.
- **Remediation**: Trigger early renewal cycle in certificate management pipeline.

---

## 4. Rule-to-Scenario Verification Matrix

Verified against the 9 synthetic test scenarios in `data/demo_mail_traffic.pcap`:

| Stream # | Protocol | Scenario Description | Expected Rules Fired | Expected Severity |
|---|---|---|---|---|
| Stream 0 | SMTP (587) | Modern TLS 1.3 / AES-GCM (Clean) | *(None)* | **CLEAN** |
| Stream 1 | SMTPS (465) | TLS 1.0 + 3DES Broken Cipher | `RULE_TLS_LEGACY`, `RULE_CIPHER_BROKEN`, `RULE_CIPHER_NON_AEAD` | **HIGH** |
| Stream 2 | SMTP (25) | Plaintext Auth Before TLS | `RULE_PLAINTEXT_AUTH_BEFORE_TLS` | **CRITICAL** |
| Stream 3 | IMAP (143) | STARTTLS Advertised, Ignored | `RULE_STARTTLS_NOT_ENFORCED` | **MEDIUM** |
| Stream 4 | IMAPS (993) | Expired Certificate (TLS 1.2) | `RULE_CERT_EXPIRED`, `RULE_CIPHER_NON_AEAD` | **CRITICAL** |
| Stream 5 | POP3S (995) | Self-Signed Certificate | `RULE_CERT_SELF_SIGNED`, `RULE_CIPHER_NON_AEAD` | **HIGH** |
| Stream 6 | SMTP (587) | Handshake Failure (Fatal Alert) | `RULE_TLS_HANDSHAKE_FAILURE` | **HIGH** |
| Stream 7 | IMAPS (993) | SAN Hostname Mismatch | `RULE_HOSTNAME_MISMATCH`, `RULE_CIPHER_NON_AEAD` | **CRITICAL** |
| Stream 8 | POP3 (110) | Unencrypted Plaintext Auth | `RULE_PLAINTEXT_AUTH_BEFORE_TLS` | **CRITICAL** |
