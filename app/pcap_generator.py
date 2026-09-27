"""
Synthetic Demonstration PCAP Generator using Scapy and Cryptography.
Creates an actual binary PCAP file (data/demo_mail_traffic.pcap) containing real
Ethernet/IP/TCP conversations covering all required cybersecurity test scenarios.
"""

import os
import datetime
from typing import List, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from scapy.all import Ether, IP, TCP, Raw, wrpcap


def generate_expired_self_signed_cert() -> bytes:
    """Generates an actual DER-encoded expired self-signed X.509 certificate."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Insecure Internal Mail"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.legacy-test.corp"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    # Expired 60 days ago
    not_before = now - datetime.timedelta(days=425)
    not_after = now - datetime.timedelta(days=60)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_after
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("mail.legacy-test.corp")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    return cert.public_bytes(serialization.Encoding.DER)


def generate_mismatched_san_cert() -> bytes:
    """Generates a valid certificate with SAN 'attacker.phishing.org' to trigger SAN mismatch against mail.bank.corp."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Phishing Domains LLC"),
        x509.NameAttribute(NameOID.COMMON_NAME, "attacker.phishing.org"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(days=10)
    not_after = now + datetime.timedelta(days=365)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_before
    ).not_valid_after(
        not_after
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("attacker.phishing.org")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    return cert.public_bytes(serialization.Encoding.DER)


def build_tls_record(content_type: int, version: Tuple[int, int], payload: bytes) -> bytes:
    """Constructs a standard TLS record layer header."""
    rec = bytearray()
    rec.append(content_type)  # 22 = Handshake, 21 = Alert, 23 = Application Data
    rec.extend(version)       # e.g. (3, 3) for TLS 1.2
    rec.extend(len(payload).to_bytes(2, byteorder="big"))
    rec.extend(payload)
    return bytes(rec)


def build_tls_alert(level: int = 2, desc: int = 40) -> bytes:
    """Builds a TLS Alert record (content_type=21). Level 2=Fatal, Desc 40=handshake_failure."""
    alert_payload = bytes([level, desc])
    return build_tls_record(21, (3, 3), alert_payload)


def build_client_hello(tls_version_bytes: bytes, cipher_codes: List[int], sni: str = "") -> bytes:
    """Builds a real binary TLS ClientHello handshake packet."""
    hs = bytearray()
    hs.append(1)  # ClientHello

    body = bytearray()
    body.extend(tls_version_bytes)  # e.g. b'\x03\x03'
    body.extend(b"\x00" * 32)       # Random bytes
    body.append(0)                  # Session ID length = 0

    # Ciphersuites
    cs_bytes = bytearray()
    for c in cipher_codes:
        cs_bytes.extend(c.to_bytes(2, byteorder="big"))
    body.extend(len(cs_bytes).to_bytes(2, byteorder="big"))
    body.extend(cs_bytes)

    # Compression methods (1 method: null = 0)
    body.append(1)
    body.append(0)

    # Extensions
    exts = bytearray()
    if sni:
        sni_b = sni.encode("ascii")
        sni_entry = b"\x00" + len(sni_b).to_bytes(2, "big") + sni_b
        sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
        # Extension 0x0000 = server_name
        exts.extend(b"\x00\x00")
        exts.extend(len(sni_list).to_bytes(2, "big"))
        exts.extend(sni_list)

    # Supported versions extension for TLS 1.3
    if tls_version_bytes == b"\x03\x04":
        sup_vers = b"\x02\x03\x04"
        exts.extend(b"\x00\x2b")  # 43 = supported_versions
        exts.extend(len(sup_vers).to_bytes(2, "big"))
        exts.extend(sup_vers)

    if exts:
        body.extend(len(exts).to_bytes(2, byteorder="big"))
        body.extend(exts)

    hs.extend(len(body).to_bytes(3, byteorder="big"))
    hs.extend(body)

    rec_ver = (3, 1) if tls_version_bytes == b"\x03\x01" else (3, 3)
    return build_tls_record(22, rec_ver, bytes(hs))


def build_server_hello(tls_version_bytes: bytes, cipher_code: int) -> bytes:
    """Builds a real binary TLS ServerHello handshake packet."""
    hs = bytearray()
    hs.append(2)  # ServerHello

    body = bytearray()
    body.extend(tls_version_bytes)
    body.extend(b"\x11" * 32)  # Random bytes
    body.append(0)            # Session ID length

    # Selected cipher
    body.extend(cipher_code.to_bytes(2, byteorder="big"))
    body.append(0)            # Compression method = null

    # If TLS 1.3, supported_versions extension
    if tls_version_bytes == b"\x03\x04":
        sup_vers = b"\x03\x04"
        exts = bytearray()
        exts.extend(b"\x00\x2b")
        exts.extend(len(sup_vers).to_bytes(2, "big"))
        exts.extend(sup_vers)
        body.extend(len(exts).to_bytes(2, "big"))
        body.extend(exts)

    hs.extend(len(body).to_bytes(3, byteorder="big"))
    hs.extend(body)

    rec_ver = (3, 1) if tls_version_bytes == b"\x03\x01" else (3, 3)
    return build_tls_record(22, rec_ver, bytes(hs))


def build_cert_record(cert_der: bytes) -> bytes:
    """Builds a real binary TLS Certificate message record."""
    cert_entry = len(cert_der).to_bytes(3, "big") + cert_der
    certs_list = len(cert_entry).to_bytes(3, "big") + cert_entry

    hs = bytearray()
    hs.append(11)  # Certificate
    hs.extend(len(certs_list).to_bytes(3, "big"))
    hs.extend(certs_list)

    return build_tls_record(22, (3, 3), bytes(hs))


def create_demo_pcap(output_path: str = "data/demo_mail_traffic.pcap") -> str:
    """
    Generates a multi-session synthetic PCAP containing realistic scenarios:
    1. Compliant Modern SMTP (STARTTLS -> TLS 1.3 AES-GCM)
    2. Deprecated TLS 1.0 & Broken 3DES Cipher
    3. Plaintext Authentication Before TLS (SMTP AUTH LOGIN)
    4. IMAP with Expired / Self-Signed Certificate
    5. POP3 Plaintext Authentication (USER / PASS cleartext)
    6. STARTTLS Advertised but Ignored (Cleartext Mail relay)
    7. Statistical Anomaly Session (Abnormal Handshake Delay 580ms + Single Cipher)
    8. Hostname / SAN Mismatch (IMAP Client SNI mail.bank.corp vs Certificate attacker.phishing.org)
    9. TLS Handshake Failure / Alert (SMTP Fatal Handshake Alert 40)
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    packets: List[Any] = []

    def tcp_flow(sport, dport, s_ip, c_ip, turns, base_time=1710000000.0):
        """Helper to create TCP conversation with SYN, SYN-ACK, ACK and Data turns."""
        seq_c = 10000
        seq_s = 50000
        t = base_time

        # 1. 3-Way Handshake
        p1 = Ether()/IP(src=c_ip, dst=s_ip)/TCP(sport=sport, dport=dport, flags="S", seq=seq_c)
        p1.time = t
        packets.append(p1)
        t += 0.005

        p2 = Ether()/IP(src=s_ip, dst=c_ip)/TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1)
        p2.time = t
        packets.append(p2)
        t += 0.005

        p3 = Ether()/IP(src=c_ip, dst=s_ip)/TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1)
        p3.time = t
        packets.append(p3)
        t += 0.005

        seq_c += 1
        seq_s += 1

        # Application turns
        for sender, payload, delay in turns:
            t += delay
            if sender == "c":
                pkt = Ether()/IP(src=c_ip, dst=s_ip)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s)/Raw(payload)
                seq_c += len(payload)
            else:
                pkt = Ether()/IP(src=s_ip, dst=c_ip)/TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c)/Raw(payload)
                seq_s += len(payload)
            pkt.time = t
            packets.append(pkt)

        # Teardown
        t += 0.010
        fin = Ether()/IP(src=c_ip, dst=s_ip)/TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s)
        fin.time = t
        packets.append(fin)

    # -------------------------------------------------------------
    # Session 1: Compliant Modern SMTP (STARTTLS -> TLS 1.3 AES-GCM)
    # -------------------------------------------------------------
    c_hello_tls13 = build_client_hello(b"\x03\x04", [0x1302, 0x1301, 0xc02f], sni="smtp.secure.example.com")
    s_hello_tls13 = build_server_hello(b"\x03\x04", 0x1302)
    tcp_flow(
        sport=41001, dport=587, s_ip="10.0.1.25", c_ip="10.0.2.10",
        turns=[
            ("s", b"220 smtp.secure.example.com ESMTP Postfix\r\n", 0.005),
            ("c", b"EHLO client.secure.example.com\r\n", 0.010),
            ("s", b"250-smtp.secure.example.com\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 OK\r\n", 0.010),
            ("c", b"STARTTLS\r\n", 0.015),
            ("s", b"220 2.0.0 Ready to start TLS\r\n", 0.010),
            ("c", c_hello_tls13, 0.020),
            ("s", s_hello_tls13, 0.035),
            ("c", build_tls_record(23, (3, 3), b"\x00" * 80), 0.020),
            ("s", build_tls_record(23, (3, 3), b"\x00" * 120), 0.020),
        ],
        base_time=1710000000.0
    )

    # -------------------------------------------------------------
    # Session 2: Deprecated TLS 1.0 & Broken 3DES Cipher (SMTP)
    # -------------------------------------------------------------
    c_hello_tls10 = build_client_hello(b"\x03\x01", [0x000a, 0x0005], sni="mail.legacy.example.org")
    s_hello_tls10 = build_server_hello(b"\x03\x01", 0x000a)  # 3DES
    tcp_flow(
        sport=41002, dport=25, s_ip="10.0.1.26", c_ip="10.0.2.11",
        turns=[
            ("s", b"220 mail.legacy.example.org ESMTP Sendmail 8.14\r\n", 0.005),
            ("c", b"EHLO client.legacy.org\r\n", 0.010),
            ("s", b"250-mail.legacy.example.org\r\n250-STARTTLS\r\n250 OK\r\n", 0.010),
            ("c", b"STARTTLS\r\n", 0.012),
            ("s", b"220 2.0.0 Go ahead\r\n", 0.010),
            ("c", c_hello_tls10, 0.015),
            ("s", s_hello_tls10, 0.025),
        ],
        base_time=1710000010.0
    )

    # -------------------------------------------------------------
    # Session 3: Plaintext Credentials Transmitted Before TLS (SMTP)
    # -------------------------------------------------------------
    tcp_flow(
        sport=41003, dport=587, s_ip="10.0.1.27", c_ip="10.0.2.12",
        turns=[
            ("s", b"220 mail.insecure.corp ESMTP Exim 4.94\r\n", 0.005),
            ("c", b"EHLO client.corp\r\n", 0.010),
            ("s", b"250-mail.insecure.corp\r\n250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 OK\r\n", 0.010),
            ("c", b"AUTH LOGIN\r\n", 0.015),
            ("s", b"334 VXNlcm5hbWU6\r\n", 0.010),
            ("c", b"dGVzdHVzZXJAZXhhbXBsZS5jb20=\r\n", 0.012),
            ("s", b"334 UGFzc3dvcmQ6\r\n", 0.010),
            ("c", b"c3VwZXJzZWNyZXRwYXNzMTIz\r\n", 0.012),
            ("s", b"235 2.7.0 Authentication successful\r\n", 0.010),
        ],
        base_time=1710000020.0
    )

    # -------------------------------------------------------------
    # Session 4: IMAP with Visible Expired & Self-Signed Cert (TLS 1.2)
    # -------------------------------------------------------------
    expired_cert_der = generate_expired_self_signed_cert()
    c_hello_tls12 = build_client_hello(b"\x03\x03", [0xc02f, 0xc030], sni="mail.legacy-test.corp")
    s_hello_tls12 = build_server_hello(b"\x03\x03", 0xc02f)
    cert_pkt = build_cert_record(expired_cert_der)

    tcp_flow(
        sport=41004, dport=143, s_ip="10.0.1.28", c_ip="10.0.2.13",
        turns=[
            ("s", b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n", 0.005),
            ("c", b"A01 STARTTLS\r\n", 0.010),
            ("s", b"A01 OK Begin TLS negotiation now.\r\n", 0.010),
            ("c", c_hello_tls12, 0.015),
            ("s", s_hello_tls12, 0.020),
            ("s", cert_pkt, 0.010),
        ],
        base_time=1710000030.0
    )

    # -------------------------------------------------------------
    # Session 5: POP3 Plaintext Authentication (USER / PASS Cleartext)
    # -------------------------------------------------------------
    tcp_flow(
        sport=41005, dport=110, s_ip="10.0.1.29", c_ip="10.0.2.14",
        turns=[
            ("s", b"+OK POP3 server ready <1045.789@pop.victim.org>\r\n", 0.005),
            ("c", b"USER victim_employee\r\n", 0.010),
            ("s", b"+OK User name accepted\r\n", 0.008),
            ("c", b"PASS CorporateP@ssw0rd2026!\r\n", 0.012),
            ("s", b"+OK Mailbox open, 3 messages\r\n", 0.010),
            ("c", b"QUIT\r\n", 0.010),
            ("s", b"+OK Farewell.\r\n", 0.008),
        ],
        base_time=1710000040.0
    )

    # -------------------------------------------------------------
    # Session 6: STARTTLS Advertised but Not Enforced (SMTP cleartext relay)
    # -------------------------------------------------------------
    tcp_flow(
        sport=41006, dport=25, s_ip="10.0.1.30", c_ip="10.0.2.15",
        turns=[
            ("s", b"220 mail.open-relay.org ESMTP Postfix\r\n", 0.005),
            ("c", b"EHLO unencrypted.sender.org\r\n", 0.010),
            ("s", b"250-mail.open-relay.org\r\n250-STARTTLS\r\n250-SIZE 52428800\r\n250 OK\r\n", 0.010),
            ("c", b"MAIL FROM:<sender@unencrypted.sender.org>\r\n", 0.012),
            ("s", b"250 2.1.0 Ok\r\n", 0.010),
            ("c", b"RCPT TO:<dest@open-relay.org>\r\n", 0.010),
            ("s", b"250 2.1.5 Ok\r\n", 0.010),
        ],
        base_time=1710000050.0
    )

    # -------------------------------------------------------------
    # Session 7: Statistical Anomaly (Abnormal Handshake Latency 580ms + Single Cipher)
    # -------------------------------------------------------------
    c_hello_scanner = build_client_hello(b"\x03\x04", [0x1301], sni="target.mail.corp")
    s_hello_scanner = build_server_hello(b"\x03\x04", 0x1301)
    tcp_flow(
        sport=41007, dport=587, s_ip="10.0.1.31", c_ip="10.0.2.99",
        turns=[
            ("s", b"220 target.mail.corp ESMTP Postfix\r\n", 0.005),
            ("c", b"EHLO bot.scanner.ninja\r\n", 0.010),
            ("s", b"250-target.mail.corp\r\n250-STARTTLS\r\n250 OK\r\n", 0.010),
            ("c", b"STARTTLS\r\n", 0.012),
            ("s", b"220 2.0.0 Ready to start TLS\r\n", 0.010),
            ("c", c_hello_scanner, 0.010),
            # Injected latency: 0.580s delay simulating slow-read or tunnel delay
            ("s", s_hello_scanner, 0.580),
        ],
        base_time=1710000060.0
    )

    # -------------------------------------------------------------
    # Session 8: Hostname / SAN Mismatch (Scenario F)
    # IMAP with Client SNI 'mail.bank.corp' vs Certificate SAN 'attacker.phishing.org'
    # -------------------------------------------------------------
    c_hello_mismatch = build_client_hello(
        b"\x03\x03",
        [0xc02f, 0xc030, 0x009e],
        sni="mail.bank.corp"
    )
    s_hello_mismatch = build_server_hello(b"\x03\x03", 0xc02f)
    cert_mismatch = build_cert_record(generate_mismatched_san_cert())

    tcp_flow(
        sport=41008, dport=143, s_ip="10.0.1.40", c_ip="10.0.2.40",
        turns=[
            ("s", b"* OK IMAP4rev1 Service Ready at bank.corp\r\n", 0.005),
            ("c", b"a001 STARTTLS\r\n", 0.010),
            ("s", b"a001 OK Begin TLS negotiation now\r\n", 0.010),
            ("c", c_hello_mismatch, 0.010),
            ("s", s_hello_mismatch, 0.012),
            ("s", cert_mismatch, 0.010),
        ],
        base_time=1710000070.0
    )

    # -------------------------------------------------------------
    # Session 9: TLS Handshake Failure / Alert (Scenario G)
    # SMTP Client sends ClientHello, Server aborts with Fatal Alert 40 (handshake_failure)
    # -------------------------------------------------------------
    c_hello_fail = build_client_hello(
        b"\x03\x03",
        [0x0035],
        sni="mail.secure-alert.org"
    )
    alert_fatal = build_tls_alert(level=2, desc=40)

    tcp_flow(
        sport=41009, dport=587, s_ip="10.0.1.50", c_ip="10.0.2.50",
        turns=[
            ("s", b"220 mail.secure-alert.org ESMTP Postfix\r\n", 0.005),
            ("c", b"EHLO client.tester.org\r\n", 0.010),
            ("s", b"250-mail.secure-alert.org\r\n250-STARTTLS\r\n250 OK\r\n", 0.010),
            ("c", b"STARTTLS\r\n", 0.012),
            ("s", b"220 2.0.0 Ready to start TLS\r\n", 0.010),
            ("c", c_hello_fail, 0.010),
            ("s", alert_fatal, 0.015),
        ],
        base_time=1710000080.0
    )

    wrpcap(output_path, packets)
    return os.path.abspath(output_path)


if __name__ == "__main__":
    pcap_file = create_demo_pcap()
    print(f"Generated synthetic demonstration PCAP: {pcap_file}")

