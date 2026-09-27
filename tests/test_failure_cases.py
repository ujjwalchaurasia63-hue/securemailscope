"""
Failure Case and Edge Condition Tests for SecureMailScope.
Verifies graceful error handling on empty files, non-email captures, and missing files.
"""

import os
import tempfile
import pytest
from app.analyzer import MailSecurityAnalyzer
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap


def test_missing_pcap_raises_file_not_found():
    analyzer = MailSecurityAnalyzer()
    with pytest.raises((FileNotFoundError, ValueError)):
        analyzer.analyze_pcap("non_existent_file.pcap")


def test_invalid_extension_raises_error():
    analyzer = MailSecurityAnalyzer()
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"not a pcap")
        txt_path = f.name
    try:
        with pytest.raises(ValueError, match="extension"):
            analyzer.analyze_pcap(txt_path)
    finally:
        if os.path.exists(txt_path):
            os.remove(txt_path)


def test_empty_pcap_raises_value_error():
    analyzer = MailSecurityAnalyzer()
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        empty_path = f.name
    try:
        with pytest.raises(ValueError, match="empty"):
            analyzer.analyze_pcap(empty_path)
    finally:
        if os.path.exists(empty_path):
            os.remove(empty_path)


def test_no_email_traffic_pcap():
    analyzer = MailSecurityAnalyzer()
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        dns_pcap = f.name

    try:
        # Create non-email DNS packet
        pkt = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
        wrpcap(dns_pcap, [pkt])

        res = analyzer.analyze_pcap(dns_pcap)
        assert res["summary"]["total_sessions"] == 0
        assert res["summary"]["overall_severity"] == "CLEAN"
        assert len(res["findings"]) == 0
    finally:
        if os.path.exists(dns_pcap):
            os.remove(dns_pcap)
