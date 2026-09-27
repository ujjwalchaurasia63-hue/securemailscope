"""
Layer 3: Plain-Language Explanation and Remediation Layer.
Consumes verified findings from Layer 1 (Rule Engine) and Layer 2 (Anomaly Detector)
to generate actionable mail server hardening directives (Postfix, Dovecot, Exim).
Strictly downstream: never invents or classifies findings.
"""

from typing import List, Dict, Any


REMEDIATION_TEMPLATES = {
    "RULE_PLAINTEXT_AUTH_BEFORE_TLS": {
        "title": "Plaintext Credentials Transmitted Before TLS",
        "plain_explanation": (
            "During this email conversation, user authentication credentials (username and password) "
            "were transmitted in cleartext before an encrypted TLS tunnel was established. Anyone on the "
            "local network, Wi-Fi, or upstream internet provider could capture these credentials."
        ),
        "postfix_snippet": """# /etc/postfix/main.cf
# Disallow plaintext authentication over unencrypted connections
smtpd_tls_auth_only = yes
smtpd_tls_security_level = may
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
""",
        "dovecot_snippet": """# /etc/dovecot/conf.d/10-auth.conf
# Prohibit cleartext authentication unless TLS is established
disable_plaintext_auth = yes
ssl = required
"""
    },
    "RULE_STARTTLS_NOT_ENFORCED": {
        "title": "STARTTLS Advertised But Not Utilized",
        "plain_explanation": (
            "The email server advertised opportunistic encryption (STARTTLS), but the client or server "
            "proceeded to transmit email data in cleartext without issuing the STARTTLS command. This "
            "leaves email contents readable and exposes the session to STRIPTLS downgrade attacks."
        ),
        "postfix_snippet": """# /etc/postfix/main.cf
# Enforce mandatory TLS on client submission port 587
smtpd_enforce_tls = yes
smtpd_tls_mandatory_ciphers = high
""",
        "dovecot_snippet": """# /etc/dovecot/conf.d/10-ssl.conf
# Enforce STARTTLS before permitting mail access
ssl = required
"""
    },
    "RULE_TLS_LEGACY": {
        "title": "Deprecated TLS Protocol Version Negotiated",
        "plain_explanation": (
            "The server negotiated a deprecated cryptographic protocol (SSLv3, TLS 1.0, or TLS 1.1). "
            "These protocols lack modern authenticated encryption (AEAD) and are vulnerable to well-known "
            "attacks such as POODLE, BEAST, and SWEET32. NIST SP 800-52 Rev. 2 and RFC 8996 mandate deprecation."
        ),
        "postfix_snippet": """# /etc/postfix/main.cf
# Disable legacy protocols; permit TLS 1.2 and TLS 1.3 only
smtpd_tls_protocols = >=TLSv1.2
smtpd_tls_mandatory_protocols = >=TLSv1.2
smtp_tls_protocols = >=TLSv1.2
""",
        "dovecot_snippet": """# /etc/dovecot/conf.d/10-ssl.conf
ssl_min_protocol = TLSv1.2
"""
    },
    "RULE_CIPHER_BROKEN": {
        "title": "Insecure or Broken Cipher Suite Negotiated",
        "plain_explanation": (
            "The server agreed to use a legacy cipher suite containing cryptographically broken primitives "
            "(such as 3DES, RC4, or MD5). 3DES is vulnerable to SWEET32 collision attacks, and RC4 is prone to "
            "statistical plaintext recovery. Modern standards require AEAD ciphers (AES-GCM or ChaCha20-Poly1305)."
        ),
        "postfix_snippet": """# /etc/postfix/main.cf
# Modern High-Security Cipher Suites
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, 3DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA
smtpd_tls_ciphers = high
""",
        "dovecot_snippet": """# /etc/dovecot/conf.d/10-ssl.conf
ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
ssl_prefer_server_ciphers = yes
"""
    },
    "RULE_CERT_EXPIRED": {
        "title": "Expired X.509 Certificate",
        "plain_explanation": (
            "The server presented an expired digital certificate during the TLS handshake. Mail clients "
            "will display security warnings or reject the connection, and legitimate server identity cannot be verified."
        ),
        "postfix_snippet": """# Renew certificate using Certbot / ACME:
certbot certonly --standalone -d mail.yourdomain.com

# Update Postfix configuration:
smtpd_tls_cert_file = /etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/mail.yourdomain.com/privkey.pem
""",
        "dovecot_snippet": """# /etc/dovecot/conf.d/10-ssl.conf
ssl_cert = </etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem
ssl_key = </etc/letsencrypt/live/mail.yourdomain.com/privkey.pem
"""
    },
    "RULE_CERT_SELF_SIGNED": {
        "title": "Self-Signed Certificate Presented",
        "plain_explanation": (
            "The presented certificate was self-signed rather than signed by a recognized Certificate Authority. "
            "Unless connecting clients have manually pre-installed the certificate in their trust stores, "
            "it cannot prevent Man-in-the-Middle attacks."
        ),
        "postfix_snippet": """# Replace self-signed cert with automated Let's Encrypt CA certificate
certbot certonly --standalone -d mail.yourdomain.com
""",
        "dovecot_snippet": """# Ensure Dovecot references CA-signed certificate chain
ssl_cert = </etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem
"""
    },
    "RULE_HOSTNAME_MISMATCH": {
        "title": "Certificate Hostname / SAN Mismatch",
        "plain_explanation": (
            "The hostname requested by the client (via Server Name Indication / SNI) does not match any DNS Name "
            "listed in the certificate's Subject Alternative Name (SAN) extension. This indicates server misconfiguration "
            "or an active domain spoofing attempt."
        ),
        "postfix_snippet": """# Ensure certificate SAN covers all mail hostnames / MX records:
# Example: mail.yourdomain.com, smtp.yourdomain.com
certbot certonly --standalone -d mail.yourdomain.com -d smtp.yourdomain.com
""",
        "dovecot_snippet": """# /etc/dovecot/conf.d/10-ssl.conf
# Configure SNI-based certificate matching if serving multiple virtual domains:
local_name mail.bank.corp {
  ssl_cert = </etc/ssl/certs/mail.bank.corp.pem
  ssl_key = </etc/ssl/private/mail.bank.corp.key
}
"""
    },
    "RULE_TLS_HANDSHAKE_FAILURE": {
        "title": "TLS Handshake Failure / Alert Encountered",
        "plain_explanation": (
            "A fatal TLS alert was exchanged during the cryptographic handshake, prematurely terminating the connection. "
            "This typically results from protocol version incompatibility, unsupported cipher suites, or client certificate rejection."
        ),
        "postfix_snippet": """# /etc/postfix/main.cf
# Increase TLS logging verbosity to inspect handshake failure reasons
smtpd_tls_loglevel = 2
smtp_tls_loglevel = 2
""",
        "dovecot_snippet": """# /etc/dovecot/conf.d/10-logging.conf
# Enable detailed TLS negotiation error logging
auth_verbose = yes
mail_debug = yes
"""
    }
}


class RemediationExplainer:
    """Translates verified rule findings and anomalies into plain language and hardening guides."""

    def __init__(self):
        pass

    def explain_finding(self, rule_id: str) -> Dict[str, str]:
        """Provides explanatory and remediation details for a specific rule ID."""
        if rule_id in REMEDIATION_TEMPLATES:
            return REMEDIATION_TEMPLATES[rule_id]

        return {
            "title": rule_id,
            "plain_explanation": f"Policy check triggered for rule {rule_id}.",
            "postfix_snippet": "# Consult NIST SP 800-52 Rev. 2 for server hardening guidelines.",
            "dovecot_snippet": "# Refer to RFC 8314 for email encryption requirements."
        }
