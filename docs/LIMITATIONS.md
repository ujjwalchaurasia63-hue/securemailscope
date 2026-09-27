# SecureMailScope — Technical Scope & Limitations

This document explicitly defines the boundaries, technical constraints, and operating assumptions of SecureMailScope.

---

## 1. Passive & Offline Operational Paradigm

SecureMailScope is engineered strictly for **passive, offline cryptographic posture assessment**.

- **No Active Probing**: The tool does not send probe packets, handshake SYN requests, or fuzzing payloads across the network.
- **No Man-in-the-Middle (MITM) Decryption**: SecureMailScope does not intercept, terminate, or decrypt TLS application sessions.
- **Air-Gapped Friendly**: The analysis pipeline requires zero internet connectivity and zero cloud API integrations. All rule evaluations, certificate inspections, and anomaly inferences execute locally.

---

## 2. TLS 1.3 Certificate Visibility Handling

A fundamental architectural distinction exists between TLS 1.2 and TLS 1.3 regarding public key infrastructure inspection:

### In TLS 1.2 (RFC 5246):
The server transmits the `Certificate` handshake message in the clear immediately following `ServerHello`. As a result, passive observers can extract and inspect:
- Subject Alternative Names (SAN)
- Common Name (CN)
- Issuer Organization & DN
- Validity Period (`notBefore`, `notAfter`)
- Signature Algorithm

### In TLS 1.3 (RFC 8446):
The TLS 1.3 handshake encrypts all handshake messages following `ServerHello`, including `EncryptedExtensions`, `Certificate`, and `CertificateVerify`, using ephemeral handshake traffic keys derived from ECDHE.
- **Consequence for Passive Observers**: Without access to the client/server ephemeral private keys or an out-of-band `SSLKEYLOGFILE`, the X.509 certificate payload is completely opaque ciphertext.
- **SecureMailScope Behavior**: The system **never fabricates or guesses** certificate metadata for TLS 1.3 sessions. Instead, it accurately reports:
  ```json
  {
    "cert_status": "encrypted_in_tls13",
    "cert_issuer": null,
    "cert_subject": null,
    "cert_days_to_expiry": null
  }
  ```
  Rules relying on certificate contents (`RULE_CERT_EXPIRED`, `RULE_HOSTNAME_MISMATCH`, `RULE_CERT_SELF_SIGNED`) are skipped gracefully for TLS 1.3 sessions.

---

## 3. Certificate Revocation & PKI Constraints

- **No Online OCSP Queries**: SecureMailScope operates offline and therefore does not perform real-time OCSP (RFC 6960) lookups or download Certificate Revocation Lists (CRLs) via HTTP/LDAP.
- **OCSP Stapling**: If the server presents a stapled OCSP response in the TLS handshake (RFC 6066), it is extracted passively.
- **Root Store Trust Anchor**: Passive evaluation of self-signed status evaluates structural identity (`Issuer == Subject`). Full hierarchical path validation to an operating system root CA bundle is not enforced offline.

---

## 4. Anomaly Detection Boundaries

- **Statistical Deviation vs. Malicious Intent**: An anomaly score above 0.70 flags that a session's timing, cipher suite, packet sizes, or JA3 fingerprint deviates from the baseline statistical distribution. It does **not** constitute proof of malicious activity or network intrusion.
- **No Payload Inspection**: The anomaly engine does not inspect unencrypted email bodies or message contents for spam, phishing, or malware.
- **Baseline Dependency**: Isolation Forest scores are relative to the reference feature distribution. In production, models should be calibrated against organization-specific baseline traffic.

---

## 5. Advisory Remediation Guidance

- **Advisory Only**: SecureMailScope generates configuration snippets (for Postfix, Dovecot, Exim, Nginx) as educational and operational guidance.
- **No Direct System Modification**: SecureMailScope does **not** write to `/etc/postfix/`, restart systemd services, or mutate network firewall configurations. System administrators remain responsible for auditing and applying configuration changes.

---

## 6. Real vs. Synthetic PCAPs

- The bundled demonstration PCAP (`data/demo_mail_traffic.pcap`) is synthetically generated via Scapy to provide safe, reproducible, testable edge-case scenarios without exposing private organizational credentials or real-world PII.
- The pipeline processes both synthetic and real-world enterprise captures identically through TShark and TCP reassembly.
