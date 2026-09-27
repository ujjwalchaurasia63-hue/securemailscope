"""
Integration Tests for SecureMailScope PCAP Ingestion and Analysis Pipeline.
Runs against real synthetic demo PCAP.
"""

import os
import pytest
from app.analyzer import MailSecurityAnalyzer


def test_analyzer_on_demo_pcap():
    pcap_path = "data/demo_mail_traffic.pcap"
    assert os.path.exists(pcap_path), "Demo PCAP must exist before integration test"

    analyzer = MailSecurityAnalyzer()
    res = analyzer.analyze_pcap(pcap_path)

    # 1. Structure assertions
    assert "analysis_id" in res
    assert "summary" in res
    assert "sessions" in res
    assert "findings" in res

    summary = res["summary"]
    assert summary["total_sessions"] == 9
    assert summary["overall_severity"] == "CRITICAL"

    # Protocols detected
    proto_counts = summary["protocol_counts"]
    assert proto_counts.get("SMTP", 0) >= 6
    assert proto_counts.get("IMAP", 0) >= 2
    assert proto_counts.get("POP3", 0) >= 1

    # Findings verified
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "RULE_PLAINTEXT_AUTH_BEFORE_TLS" in rule_ids
    assert "RULE_TLS_LEGACY" in rule_ids
    assert "RULE_CIPHER_BROKEN" in rule_ids
    assert "RULE_CERT_EXPIRED" in rule_ids
    assert "RULE_STARTTLS_NOT_ENFORCED" in rule_ids
    assert "RULE_HOSTNAME_MISMATCH" in rule_ids
    assert "RULE_TLS_HANDSHAKE_FAILURE" in rule_ids

    # Verify TLS 1.3 cert handling in Session 0
    s0 = next(s for s in res["sessions"] if s["stream_id"] == 0)
    assert s0["tls_version"] == "TLS 1.3"
    assert s0["cert_visibility"] == "not_extractable_tls1.3"
    assert s0["session_severity"] == "CLEAN"

    # Verify Session 1 (Legacy TLS 1.0 & 3DES)
    s1 = next(s for s in res["sessions"] if s["stream_id"] == 1)
    assert s1["tls_version"] == "TLS 1.0"
    assert "3DES" in s1["cipher_suite"]
    assert s1["session_severity"] == "HIGH"

    # Verify Session 3 (IMAP with Expired Cert)
    s3 = next(s for s in res["sessions"] if s["stream_id"] == 3)
    assert s3["protocol"] == "IMAP"
    assert s3["cert_visibility"] == "visible"
    assert s3["cert_days_to_expiry"] < 0
    assert s3["session_severity"] == "CRITICAL"

    # Verify Session 7 (Scenario F: Hostname / SAN Mismatch)
    s7 = next(s for s in res["sessions"] if s["stream_id"] == 7)
    assert s7["protocol"] == "IMAP"
    assert s7["cert_visibility"] == "visible"
    assert s7["cert_hostname_match"] is False
    assert s7["session_severity"] == "CRITICAL"
    assert any(f["rule_id"] == "RULE_HOSTNAME_MISMATCH" for f in s7["findings"])

    # Verify Session 8 (Scenario G: TLS Handshake Failure)
    s8 = next(s for s in res["sessions"] if s["stream_id"] == 8)
    assert s8["protocol"] == "SMTP"
    assert s8["alert_observed"] is True
    assert s8["session_severity"] == "HIGH"
    assert any(f["rule_id"] == "RULE_TLS_HANDSHAKE_FAILURE" for f in s8["findings"])
