"""
Deterministic Security Rule Engine for Email Protocols & Cryptographic Posture.
Evaluates RFC and NIST standards against parsed session telemetry.
Calculates session severity as the MAXIMUM severity across all fired rules.
"""

from typing import List, Dict, Any, Optional

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "CLEAN": 0
}

SEVERITY_REVERSE = {v: k for k, v in SEVERITY_ORDER.items()}


def get_max_severity(severities: List[str]) -> str:
    """Returns the highest severity from a list of severity strings."""
    if not severities:
        return "CLEAN"
    max_rank = max(SEVERITY_ORDER.get(s.upper(), 0) for s in severities)
    return SEVERITY_REVERSE.get(max_rank, "CLEAN")


class RuleEngine:
    """Deterministic rule evaluator with RFC / NIST source citations."""

    def __init__(self):
        pass

    def evaluate_session(self, session: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs all deterministic security rules against an extracted session.
        Returns a list of structured finding dictionaries.
        """
        findings: List[Dict[str, Any]] = []
        session_id = session.get("session_id", "unknown")
        proto = session.get("protocol", "UNKNOWN")
        tls_ver = session.get("tls_version")
        cipher = session.get("cipher_suite")
        starttls_state = session.get("starttls_state", "none")
        plaintext_auth = session.get("plaintext_auth_observed", False)
        auth_evidence = session.get("plaintext_auth_evidence", [])
        cert_vis = session.get("cert_visibility", "not_captured")
        cert_expiry = session.get("cert_days_to_expiry")
        cert_self_signed = session.get("cert_self_signed")
        cert_hostname_match = session.get("cert_hostname_match")
        sni = session.get("sni")
        alert_observed = session.get("alert_observed", False)
        alert_desc = session.get("alert_desc")
        alert_frame = session.get("alert_frame")

        finding_counter = 1

        # -----------------------------------------------------------------
        # RULE 3: Plaintext Authentication Before TLS (RFC 2595 §3.2, RFC 8314 §3)
        # -----------------------------------------------------------------
        if plaintext_auth and starttls_state != "completed":
            ev_str = "; ".join(auth_evidence) if auth_evidence else f"Session {session_id}"
            findings.append({
                "finding_id": f"{session_id}_F{finding_counter}",
                "session_id": session_id,
                "rule_id": "RULE_PLAINTEXT_AUTH_BEFORE_TLS",
                "title": "Plaintext Credentials Transmitted Before TLS",
                "severity": "CRITICAL",
                "evidence": f"Observed cleartext authentication in unencrypted {proto} stream: {ev_str}",
                "why_it_matters": (
                    "User credentials (usernames/passwords) were transmitted in plain text over "
                    "the network without TLS encryption, exposing them to interception and credential theft."
                ),
                "recommendation": (
                    "Enforce TLS before permitting authentication. In Postfix configure "
                    "'smtpd_tls_auth_only = yes'; in Dovecot configure 'disable_plaintext_auth = yes'."
                ),
                "source": "RFC 2595 §3.2, RFC 8314 §3, NIST SP 800-45"
            })
            finding_counter += 1

        # -----------------------------------------------------------------
        # RULE 4: STARTTLS Advertised but Not Used (RFC 3207 §4.1, RFC 8314 §5.1)
        # -----------------------------------------------------------------
        if starttls_state == "advertised" and not plaintext_auth:
            adv_frame = session.get("advertised_frame")
            findings.append({
                "finding_id": f"{session_id}_F{finding_counter}",
                "session_id": session_id,
                "rule_id": "RULE_STARTTLS_NOT_ENFORCED",
                "title": "STARTTLS Advertised But Not Utilized",
                "severity": "MEDIUM",
                "evidence": f"Server advertised STARTTLS capability in Frame {adv_frame}, but client proceeded in cleartext.",
                "why_it_matters": (
                    "The mail server offered opportunistic TLS upgrade, but communication remained in cleartext. "
                    "This leaves traffic vulnerable to passive eavesdropping or STRIPTLS downgrade attacks."
                ),
                "recommendation": (
                    "Require TLS for client submissions on port 587/465. For inter-server mail, deploy "
                    "MTA-STS (RFC 8461) and DANE (RFC 7672) to enforce encryption."
                ),
                "source": "RFC 3207 §4.1, RFC 8314 §5.1"
            })
            finding_counter += 1

        # -----------------------------------------------------------------
        # RULE 1: Legacy TLS Version (NIST SP 800-52 Rev. 2 §3.1, RFC 8996)
        # -----------------------------------------------------------------
        if tls_ver in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]:
            sh_frame = session.get("server_hello_frame") or session.get("tls_started_frame")
            findings.append({
                "finding_id": f"{session_id}_F{finding_counter}",
                "session_id": session_id,
                "rule_id": "RULE_TLS_LEGACY",
                "title": f"Deprecated TLS Protocol Version ({tls_ver})",
                "severity": "HIGH",
                "evidence": f"Negotiated {tls_ver} in ServerHello (Frame {sh_frame}).",
                "why_it_matters": (
                    f"{tls_ver} is formally deprecated by RFC 8996 and NIST SP 800-52 Rev. 2. "
                    "It lacks modern authenticated encryption (AEAD) and is vulnerable to attacks such as BEAST and POODLE."
                ),
                "recommendation": (
                    "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 across all mail services. "
                    "Enforce TLS 1.2 and TLS 1.3 only (e.g., 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1')."
                ),
                "source": "NIST SP 800-52 Rev. 2 §3.1, RFC 8996"
            })
            finding_counter += 1

        # -----------------------------------------------------------------
        # RULE 2: Weak / Broken Cipher Suite (RFC 7465, RFC 7590, NIST SP 800-52 Rev. 2 §3.3)
        # -----------------------------------------------------------------
        if cipher:
            broken_ciphers = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]
            matched_broken = [b for b in broken_ciphers if b in cipher.upper()]
            if matched_broken:
                sh_frame = session.get("server_hello_frame") or session.get("tls_started_frame")
                findings.append({
                    "finding_id": f"{session_id}_F{finding_counter}",
                    "session_id": session_id,
                    "rule_id": "RULE_CIPHER_BROKEN",
                    "title": f"Insecure / Broken Cipher Suite ({cipher})",
                    "severity": "HIGH",
                    "evidence": f"Negotiated cipher suite '{cipher}' contains broken primitive ({', '.join(matched_broken)}) in Frame {sh_frame}.",
                    "why_it_matters": (
                        f"Cipher suite contains {', '.join(matched_broken)}, which is cryptographically broken "
                        "and prohibited by NIST SP 800-52 Rev. 2 and RFC 7465/7590 due to plaintext recovery vulnerabilities."
                    ),
                    "recommendation": (
                        "Remove broken ciphers from server configuration. Enforce modern AEAD suites "
                        "such as ECDHE-RSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384, or ChaCha20-Poly1305."
                    ),
                    "source": "RFC 7465, RFC 7590, NIST SP 800-52 Rev. 2 §3.3"
                })
                finding_counter += 1

        # -----------------------------------------------------------------
        # RULE 5: Expired Certificate (RFC 5280 §4.1.2.5, NIST SP 800-52 Rev. 2 §3.2)
        # -----------------------------------------------------------------
        if cert_vis == "visible" and cert_expiry is not None:
            c_frame = session.get("cert_frame")
            if cert_expiry < 0:
                findings.append({
                    "finding_id": f"{session_id}_F{finding_counter}",
                    "session_id": session_id,
                    "rule_id": "RULE_CERT_EXPIRED",
                    "title": "Expired X.509 Certificate",
                    "severity": "CRITICAL",
                    "evidence": f"Certificate presented in Frame {c_frame} expired {abs(cert_expiry)} days ago.",
                    "why_it_matters": (
                        "An expired certificate invalidates cryptographic trust in server identity, "
                        "triggering client security warnings and enabling man-in-the-middle impersonation."
                    ),
                    "recommendation": (
                        "Immediately renew and deploy a valid TLS certificate from an authorized CA or automated ACME service."
                    ),
                    "source": "RFC 5280 §4.1.2.5, NIST SP 800-52 Rev. 2 §3.2"
                })
                finding_counter += 1
            elif 0 <= cert_expiry <= 14:
                # PRD Extra rule: Expiring soon
                findings.append({
                    "finding_id": f"{session_id}_F{finding_counter}",
                    "session_id": session_id,
                    "rule_id": "RULE_CERT_EXPIRING_SOON",
                    "title": "X.509 Certificate Expiring Soon",
                    "severity": "LOW",
                    "evidence": f"Certificate presented in Frame {c_frame} will expire in {cert_expiry} days.",
                    "why_it_matters": "Imminent expiration requires operational attention before client failures occur.",
                    "recommendation": "Renew the certificate before expiration date.",
                    "source": "NIST SP 800-52 Rev. 2 §3.2"
                })
                finding_counter += 1

        # -----------------------------------------------------------------
        # RULE 6: Hostname / SAN Mismatch (RFC 6125)
        # -----------------------------------------------------------------
        if cert_vis == "visible" and cert_hostname_match is False and sni:
            c_frame = session.get("cert_frame")
            sans_str = ", ".join(session.get("cert_sans", [])) or "None"
            findings.append({
                "finding_id": f"{session_id}_F{finding_counter}",
                "session_id": session_id,
                "rule_id": "RULE_HOSTNAME_MISMATCH",
                "title": "Certificate Hostname / SAN Mismatch",
                "severity": "CRITICAL",
                "evidence": f"Client SNI '{sni}' does not match certificate SANs [{sans_str}] in Frame {c_frame}.",
                "why_it_matters": (
                    "RFC 6125 mandates that the presented certificate must match the target domain. "
                    "A mismatch indicates server misconfiguration or an active domain spoofing attempt."
                ),
                "recommendation": (
                    f"Update server certificate to include '{sni}' in the Subject Alternative Name (SAN) extension."
                ),
                "source": "RFC 6125"
            })
            finding_counter += 1

        # -----------------------------------------------------------------
        # Extra PRD: Self-Signed Certificate (RFC 8314 §4.1, NIST SP 800-52 Rev. 2 §3.2)
        # -----------------------------------------------------------------
        if cert_vis == "visible" and cert_self_signed is True:
            c_frame = session.get("cert_frame")
            findings.append({
                "finding_id": f"{session_id}_F{finding_counter}",
                "session_id": session_id,
                "rule_id": "RULE_CERT_SELF_SIGNED",
                "title": "Self-Signed Certificate Presented",
                "severity": "HIGH",
                "evidence": f"Certificate in Frame {c_frame} is self-signed (Issuer equals Subject).",
                "why_it_matters": (
                    "Self-signed certificates cannot be validated by standard public trust anchors, "
                    "making communication vulnerable to interception."
                ),
                "recommendation": "Replace self-signed certificate with one signed by a trusted Public or Enterprise CA.",
                "source": "RFC 8314 §4.1, NIST SP 800-52 Rev. 2 §3.2"
            })
            finding_counter += 1

        # -----------------------------------------------------------------
        # RULE 7: TLS Handshake Failure / Alert (RFC 8446 §6)
        # -----------------------------------------------------------------
        if alert_observed:
            severity = "HIGH" if session.get("alert_level") in ("2", "fatal") else "MEDIUM"
            findings.append({
                "finding_id": f"{session_id}_F{finding_counter}",
                "session_id": session_id,
                "rule_id": "RULE_TLS_HANDSHAKE_FAILURE",
                "title": f"TLS Handshake Alert Encountered ({alert_desc or 'Alert'})",
                "severity": severity,
                "evidence": f"TLS Alert (Level: {session.get('alert_level')}, Description: {alert_desc}) in Frame {alert_frame}.",
                "why_it_matters": "A TLS alert indicates negotiation failure or connection termination during handshake.",
                "recommendation": "Investigate client-server cipher and protocol compatibility and inspect mail server logs.",
                "source": "RFC 8446 §6"
            })
            finding_counter += 1

        # -----------------------------------------------------------------
        # PRD Extra: Non-AEAD Cipher in TLS 1.2 (RFC 8446, NIST SP 800-52 Rev. 2 §3.3.1)
        # -----------------------------------------------------------------
        if tls_ver == "TLS 1.2" and cipher and "CBC" in cipher.upper() and not any(w in cipher for w in ("RC4", "3DES", "DES")):
            sh_frame = session.get("server_hello_frame") or session.get("tls_started_frame")
            findings.append({
                "finding_id": f"{session_id}_F{finding_counter}",
                "session_id": session_id,
                "rule_id": "RULE_CIPHER_NON_AEAD",
                "title": f"Non-AEAD Cipher Suite in TLS 1.2 ({cipher})",
                "severity": "LOW",
                "evidence": f"CBC mode cipher suite '{cipher}' negotiated in Frame {sh_frame}.",
                "why_it_matters": "CBC ciphers lack authenticated encryption (AEAD) and are susceptible to padding oracle timing attacks.",
                "recommendation": "Configure mail server to prefer AEAD cipher suites (GCM or CHACHA20-POLY1305).",
                "source": "RFC 8446, NIST SP 800-52 Rev. 2 §3.3.1"
            })
            finding_counter += 1

        return findings
