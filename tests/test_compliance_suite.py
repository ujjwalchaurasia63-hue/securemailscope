"""
Technical Compliance & Verification Test Suite for SecureMailScope.
Covers all mandatory verification areas specified in the Project Handbook & PRD:
1. TLS version classification
2. Cipher classification
3. Certificate validation (valid, expired, self-signed, SAN mismatch, malformed)
4. Risk max severity hierarchy
5. SMTP detection (standard, non-standard, unrecognized)
6. IMAP detection
7. POP3 detection
8. STARTTLS state machine transitions
9. Plaintext AUTH detection
10. TLS 1.3 certificate visibility handling (not_extractable_tls1.3)
11. JA3 and JA4 fingerprint extraction
12. Anomaly detector Isolation Forest & feature encoding
13. TShark error handling & environment check
"""

import os
import pytest
from app.rules import RuleEngine, get_max_severity
from app.protocol_detector import detect_protocol_from_stream
from app.starttls_tracker import StarttlsTracker
from app.tls_extractor import normalize_tls_version, normalize_cipher_suite, TlsExtractor
from app.ja3_fingerprint import compute_ja3, compute_ja4, extract_client_hello_fingerprints
from app.anomaly import AnomalyDetector, encode_session_features
from app.env_check import check_environment


# -----------------------------------------------------------------------------
# 1. TLS Version & Cipher Classification Tests
# -----------------------------------------------------------------------------
def test_tls_version_normalization():
    assert normalize_tls_version("0x0304") == "TLS 1.3"
    assert normalize_tls_version("0x0303") == "TLS 1.2"
    assert normalize_tls_version("0x0302") == "TLS 1.1"
    assert normalize_tls_version("0x0301") == "TLS 1.0"
    assert normalize_tls_version("0x0300") == "SSL 3.0"
    assert normalize_tls_version("772") == "TLS 1.3"
    assert normalize_tls_version("771") == "TLS 1.2"


def test_cipher_suite_normalization():
    assert normalize_cipher_suite("0x1301") == "TLS_AES_128_GCM_SHA256"
    assert normalize_cipher_suite("0xc02f") == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert normalize_cipher_suite("0x000a") == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assert normalize_cipher_suite("0x0005") == "TLS_RSA_WITH_RC4_128_SHA"


# -----------------------------------------------------------------------------
# 2. Risk Max Severity Hierarchy Tests
# -----------------------------------------------------------------------------
def test_max_severity_rules():
    assert get_max_severity([]) == "CLEAN"
    assert get_max_severity(["LOW"]) == "LOW"
    assert get_max_severity(["LOW", "MEDIUM"]) == "MEDIUM"
    assert get_max_severity(["MEDIUM", "HIGH", "LOW"]) == "HIGH"
    assert get_max_severity(["LOW", "CRITICAL", "HIGH"]) == "CRITICAL"
    assert get_max_severity(["CLEAN", "CLEAN"]) == "CLEAN"


# -----------------------------------------------------------------------------
# 3. Protocol Detection Tests (Actual Traffic vs Unrecognized Mail Port)
# -----------------------------------------------------------------------------
def test_smtp_protocol_detection_from_payload():
    pkts = [{"payload_bytes": b"220 mail.corp.org ESMTP Postfix\r\n", "protocol_col": "SMTP"}]
    proto = detect_protocol_from_stream(pkts, sport=54321, dport=587)
    assert proto == "SMTP"


def test_imap_protocol_detection_from_payload():
    pkts = [{"payload_bytes": b"* OK [CAPABILITY IMAP4rev1] Server ready\r\n", "protocol_col": "IMAP"}]
    proto = detect_protocol_from_stream(pkts, sport=44321, dport=143)
    assert proto == "IMAP"


def test_pop3_protocol_detection_from_payload():
    pkts = [{"payload_bytes": b"+OK POP3 server ready\r\n", "protocol_col": "POP3"}]
    proto = detect_protocol_from_stream(pkts, sport=34321, dport=110)
    assert proto == "POP3"


def test_unrecognized_mail_port_traffic():
    # Packets on port 587 but containing random HTTP or binary without SMTP signatures
    pkts = [{"payload_bytes": b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", "protocol_col": "HTTP"}]
    proto = detect_protocol_from_stream(pkts, sport=54321, dport=587)
    assert proto == "unrecognized mail-port traffic"


# -----------------------------------------------------------------------------
# 4. STARTTLS State Machine & Plaintext Authentication Tests
# -----------------------------------------------------------------------------
def test_starttls_completed_flow():
    tracker = StarttlsTracker("SMTP")
    pkts = [
        {"frame_number": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "payload_bytes": b"250-STARTTLS\r\n", "tls_handshake_type": ""},
        {"frame_number": 2, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "payload_bytes": b"STARTTLS\r\n", "tls_handshake_type": ""},
        {"frame_number": 3, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "payload_bytes": b"220 2.0.0 Ready to start TLS\r\n", "tls_handshake_type": ""},
        {"frame_number": 4, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "payload_bytes": b"", "tls_handshake_type": "1"},
        {"frame_number": 5, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "payload_bytes": b"", "tls_handshake_type": "2"}
    ]
    res = tracker.analyze_stream_packets(pkts, client_ip="10.0.0.2", server_ip="10.0.0.1", server_port=587)
    assert res["starttls_state"] == "completed"
    assert res["plaintext_auth_observed"] is False


def test_starttls_advertised_but_not_upgraded():
    tracker = StarttlsTracker("SMTP")
    pkts = [
        {"frame_number": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "payload_bytes": b"250-STARTTLS\r\n", "tls_handshake_type": ""},
        {"frame_number": 2, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "payload_bytes": b"MAIL FROM:<sender@test.org>\r\n", "tls_handshake_type": ""}
    ]
    res = tracker.analyze_stream_packets(pkts, client_ip="10.0.0.2", server_ip="10.0.0.1", server_port=25)
    assert res["starttls_state"] == "advertised"
    assert res["plaintext_auth_observed"] is False


def test_plaintext_auth_detected():
    tracker = StarttlsTracker("SMTP")
    pkts = [
        {"frame_number": 1, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "payload_bytes": b"AUTH LOGIN\r\n", "tls_handshake_type": ""}
    ]
    res = tracker.analyze_stream_packets(pkts, client_ip="10.0.0.2", server_ip="10.0.0.1", server_port=587)
    assert res["plaintext_auth_observed"] is True
    assert 1 in res["plaintext_auth_frames"]


# -----------------------------------------------------------------------------
# 5. TLS 1.3 Certificate Visibility Guard Test
# -----------------------------------------------------------------------------
def test_tls13_certificate_visibility_guard():
    extractor = TlsExtractor()
    cert_info = extractor._analyze_certificate(
        raw_cert_hex=None,
        tls_version="TLS 1.3",
        sni="mail.example.com",
        cert_frame=None
    )
    assert cert_info["cert_visibility"] == "not_extractable_tls1.3"
    assert cert_info["cert_valid"] is None
    assert "TLS 1.3 encrypts" in cert_info["cert_explanation"]

    # Ensure rule engine does not fire false positive certificate errors for TLS 1.3
    engine = RuleEngine()
    session = {
        "session_id": "test_tls13",
        "protocol": "SMTP",
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cert_visibility": "not_extractable_tls1.3",
        "starttls_state": "completed"
    }
    findings = engine.evaluate_session(session)
    cert_violations = [f for f in findings if "CERT" in f["rule_id"]]
    assert len(cert_violations) == 0


# -----------------------------------------------------------------------------
# 6. JA3 and JA4 Fingerprinting Tests
# -----------------------------------------------------------------------------
def test_ja3_and_ja4_computation():
    # TLS 1.2 with 2 ciphers and 1 extension
    ja3_raw, ja3_hash = compute_ja3(
        tls_version_code=771,
        ciphers=[49199, 49200],
        extensions=[0, 43],
        curves=[29, 23],
        point_formats=[0]
    )
    assert ja3_raw == "771,49199-49200,0-43,29-23,0"
    assert len(ja3_hash) == 32  # standard MD5 hex digest

    ja4_str = compute_ja4(
        tls_version_str="TLS 1.3",
        has_sni=True,
        ciphers=[0x1302, 0x1301],
        extensions=[0, 43]
    )
    assert ja4_str.startswith("t13d020200_")
    assert len(ja4_str.split("_")) == 3


def test_client_hello_fingerprint_extraction():
    pkt = {
        "tls_handshake_version": "0x0303",
        "tls_ciphersuite": "0xc02f,0xc030",
        "tls_extensions": "0,43",
        "tls_supported_groups": "29,23",
        "tls_ec_point_formats": "0",
        "tls_sni": "mail.secure.org"
    }
    fp = extract_client_hello_fingerprints(pkt)
    assert "ja3_hash" in fp
    assert "ja4" in fp
    assert len(fp["ja3_hash"]) == 32
    assert fp["ja4"].startswith("t12d020200_")


# -----------------------------------------------------------------------------
# 7. Anomaly Detector & Feature Vector Encoding Tests
# -----------------------------------------------------------------------------
def test_anomaly_feature_vector_encoding():
    session = {
        "handshake_duration_ms": 45.2,
        "offered_cipher_count": 18,
        "cipher_rarity_score": 0.15,
        "payload_bytes_avg": 240.0,
        "payload_bytes_var": 50.0,
        "packet_count": 22,
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ja3_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    }
    vec = encode_session_features(session)
    assert len(vec) == 9
    assert vec[0] == 45.2   # handshake_duration_ms
    assert vec[1] == 18.0   # offered_cipher_count
    assert vec[5] == 22.0   # packet_count
    assert vec[6] == 5.0    # TLS 1.3 encoded (ordinal 5.0)
    assert vec[7] == 5.0    # TLS_AES_256_GCM_SHA384 (AEAD 256 tier 5.0)
    assert vec[8] == round(float(int("a1b2", 16)) / 65535.0, 4)  # JA3 normalized prefix


def test_anomaly_detector_execution():
    detector = AnomalyDetector()
    dummy_sessions = [
        {"session_id": f"s_{i}", "handshake_duration_ms": 30.0 + i, "offered_cipher_count": 15, "cipher_rarity_score": 0.15, "payload_bytes_avg": 100.0, "payload_bytes_var": 10.0, "packet_count": 12, "tls_version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "ja3_hash": "abc"}
        for i in range(10)
    ]
    # Add one extreme outlier
    dummy_sessions.append({
        "session_id": "outlier",
        "handshake_duration_ms": 950.0,
        "offered_cipher_count": 1,
        "cipher_rarity_score": 0.95,
        "payload_bytes_avg": 9000.0,
        "payload_bytes_var": 99999.0,
        "packet_count": 500,
        "tls_version": "SSL 3.0",
        "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5",
        "ja3_hash": "xyz"
    })

    analyzed = detector.detect_anomalies(dummy_sessions)
    assert len(analyzed) == 11
    for s in analyzed:
        assert "is_anomaly" in s
        assert "anomaly_score" in s
        assert 0.0 <= s["anomaly_score"] <= 1.0


# -----------------------------------------------------------------------------
# 9. Certificate Extraction & Cryptography Analysis Unit Tests
# -----------------------------------------------------------------------------
def test_certificate_analysis_valid_and_expired():
    from app.pcap_generator import generate_expired_self_signed_cert
    expired_der = generate_expired_self_signed_cert()
    hex_der = expired_der.hex()

    extractor = TlsExtractor()
    res = extractor._analyze_certificate(
        raw_cert_hex=hex_der,
        tls_version="TLS 1.2",
        sni="mail.legacy-test.corp",
        cert_frame=42
    )
    assert res["cert_visibility"] == "visible"
    assert res["cert_self_signed"] is True
    assert res["cert_days_to_expiry"] < 0
    assert res["cert_hostname_match"] is True
    assert res["cert_public_key_algo"] == "RSA"
    assert res["cert_key_size"] == 2048


def test_certificate_san_mismatch():
    from app.pcap_generator import generate_expired_self_signed_cert
    cert_der = generate_expired_self_signed_cert()
    hex_der = cert_der.hex()

    extractor = TlsExtractor()
    # Provide an SNI that is completely different from SAN
    res = extractor._analyze_certificate(
        raw_cert_hex=hex_der,
        tls_version="TLS 1.2",
        sni="totally.different.domain.com",
        cert_frame=43
    )
    assert res["cert_hostname_match"] is False


def test_certificate_malformed_handling():
    extractor = TlsExtractor()
    # Invalid corrupt DER hex
    res = extractor._analyze_certificate(
        raw_cert_hex="deadbeef123456",
        tls_version="TLS 1.2",
        sni="mail.test.org",
        cert_frame=99
    )
    assert res["cert_visibility"] == "parse_error"
    assert res["cert_valid"] is False
    assert "error" in res["cert_explanation"].lower()


# -----------------------------------------------------------------------------
# 8. Environment Diagnostics Test
# -----------------------------------------------------------------------------
def test_environment_check():
    status = check_environment()
    assert status["all_valid"] is True
    assert status["tshark"]["available"] is True
    assert len(status["missing_packages"]) == 0
