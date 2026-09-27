"""
Unit Tests for SecureMailScope Security Rules and Severity Calculation.
"""

import pytest
from app.rules import RuleEngine, get_max_severity


def test_max_severity_hierarchy():
    assert get_max_severity([]) == "CLEAN"
    assert get_max_severity(["LOW"]) == "LOW"
    assert get_max_severity(["LOW", "MEDIUM"]) == "MEDIUM"
    assert get_max_severity(["MEDIUM", "HIGH", "LOW"]) == "HIGH"
    assert get_max_severity(["MEDIUM", "CRITICAL", "HIGH"]) == "CRITICAL"


def test_rule_plaintext_auth_before_tls():
    engine = RuleEngine()
    session = {
        "session_id": "test_s1",
        "protocol": "SMTP",
        "starttls_state": "advertised",
        "plaintext_auth_observed": True,
        "plaintext_auth_evidence": ["Frame 12: Cleartext AUTH command"],
    }
    findings = engine.evaluate_session(session)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_PLAINTEXT_AUTH_BEFORE_TLS" in rule_ids
    auth_f = next(f for f in findings if f["rule_id"] == "RULE_PLAINTEXT_AUTH_BEFORE_TLS")
    assert auth_f["severity"] == "CRITICAL"
    assert "RFC 2595" in auth_f["source"]


def test_rule_legacy_tls():
    engine = RuleEngine()
    session = {
        "session_id": "test_s2",
        "protocol": "SMTP",
        "tls_version": "TLS 1.0",
        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "starttls_state": "completed",
    }
    findings = engine.evaluate_session(session)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_TLS_LEGACY" in rule_ids
    f = next(f for f in findings if f["rule_id"] == "RULE_TLS_LEGACY")
    assert f["severity"] == "HIGH"
    assert "NIST SP 800-52" in f["source"]


def test_rule_broken_cipher():
    engine = RuleEngine()
    session = {
        "session_id": "test_s3",
        "protocol": "SMTP",
        "tls_version": "TLS 1.2",
        "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "starttls_state": "completed",
    }
    findings = engine.evaluate_session(session)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_CIPHER_BROKEN" in rule_ids
    f = next(f for f in findings if f["rule_id"] == "RULE_CIPHER_BROKEN")
    assert f["severity"] == "HIGH"
    assert "RFC 7465" in f["source"]


def test_rule_expired_certificate():
    engine = RuleEngine()
    session = {
        "session_id": "test_s4",
        "protocol": "IMAP",
        "cert_visibility": "visible",
        "cert_days_to_expiry": -15,
        "cert_self_signed": False,
        "starttls_state": "completed",
    }
    findings = engine.evaluate_session(session)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_CERT_EXPIRED" in rule_ids
    f = next(f for f in findings if f["rule_id"] == "RULE_CERT_EXPIRED")
    assert f["severity"] == "CRITICAL"
    assert "RFC 5280" in f["source"]


def test_rule_starttls_not_enforced():
    engine = RuleEngine()
    session = {
        "session_id": "test_s5",
        "protocol": "SMTP",
        "starttls_state": "advertised",
        "plaintext_auth_observed": False,
        "advertised_frame": 18,
    }
    findings = engine.evaluate_session(session)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_STARTTLS_NOT_ENFORCED" in rule_ids
    f = next(f for f in findings if f["rule_id"] == "RULE_STARTTLS_NOT_ENFORCED")
    assert f["severity"] == "MEDIUM"
    assert "RFC 3207" in f["source"]


def test_tls13_visibility_does_not_trigger_cert_failure():
    engine = RuleEngine()
    session = {
        "session_id": "test_s6",
        "protocol": "SMTP",
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cert_visibility": "not_extractable_tls1.3",
        "starttls_state": "completed",
    }
    findings = engine.evaluate_session(session)
    # Ensure no false positive cert errors are raised for TLS 1.3
    cert_rules = [f["rule_id"] for f in findings if "CERT" in f["rule_id"]]
    assert len(cert_rules) == 0


def test_rule_hostname_mismatch():
    engine = RuleEngine()
    session = {
        "session_id": "test_s7",
        "protocol": "IMAP",
        "cert_visibility": "visible",
        "cert_hostname_match": False,
        "sni": "mail.bank.corp",
        "cert_sans": ["attacker.phishing.org"],
        "cert_frame": 89,
    }
    findings = engine.evaluate_session(session)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_HOSTNAME_MISMATCH" in rule_ids
    f = next(f for f in findings if f["rule_id"] == "RULE_HOSTNAME_MISMATCH")
    assert f["severity"] == "CRITICAL"
    assert "RFC 6125" in f["source"]


def test_rule_tls_handshake_failure():
    engine = RuleEngine()
    session = {
        "session_id": "test_s8",
        "protocol": "SMTP",
        "alert_observed": True,
        "alert_level": "2",
        "alert_desc": "40",
        "alert_frame": 100,
    }
    findings = engine.evaluate_session(session)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_TLS_HANDSHAKE_FAILURE" in rule_ids
    f = next(f for f in findings if f["rule_id"] == "RULE_TLS_HANDSHAKE_FAILURE")
    assert f["severity"] == "HIGH"
    assert "RFC 8446" in f["source"]

