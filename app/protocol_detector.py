"""
Protocol Detection Module for Email Protocols (SMTP, IMAP, POP3).
Detects protocol based on application payloads/grammar and TShark dissections.
Classifies unrelated traffic on mail ports as 'unrecognized mail-port traffic'.
"""

import re
from typing import List, Dict, Any, Optional

SMTP_PORTS = {25, 465, 587, 2525}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}
ALL_MAIL_PORTS = SMTP_PORTS | IMAP_PORTS | POP3_PORTS

# Regex signatures for mail protocols
SMTP_BANNER_RE = re.compile(rb"^220[ -].*(?:esmtp|smtp|mail|postfix|exim|sendmail)", re.IGNORECASE)
SMTP_CMD_RE = re.compile(rb"^(?:EHLO|HELO|MAIL FROM:|RCPT TO:|STARTTLS|AUTH\s+)\b", re.IGNORECASE)

IMAP_BANNER_RE = re.compile(rb"^\*\s+OK\b.*(?:IMAP|Dovecot|Courier|Cyrus)", re.IGNORECASE)
IMAP_CMD_RE = re.compile(rb"^[A-Za-z0-9]+\s+(?:CAPABILITY|STARTTLS|LOGIN|AUTHENTICATE|SELECT|FETCH|LOGOUT)\b", re.IGNORECASE)

POP3_BANNER_RE = re.compile(rb"^\+OK\b.*(?:POP|Dovecot|Courier)", re.IGNORECASE)
POP3_CMD_RE = re.compile(rb"^(?:CAPA|STLS|USER\s+|PASS\s+|STAT|LIST|RETR|DELE|QUIT)\b", re.IGNORECASE)


def detect_protocol_from_stream(
    packets: List[Dict[str, Any]],
    sport: int,
    dport: int
) -> str:
    """
    Detects whether a TCP stream represents SMTP, IMAP, or POP3.
    Requires actual grammar/payload match or TShark dissector evidence.
    Classifies traffic on mail ports without matching grammar as 'unrecognized mail-port traffic'.
    """
    smtp_grammar = 0
    imap_grammar = 0
    pop3_grammar = 0

    has_payload = False

    # 1. Inspect packet payloads for signatures
    for pkt in packets:
        payload = pkt.get("payload_bytes", b"")
        if not payload:
            continue
        has_payload = True

        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue

            # SMTP checks
            if SMTP_BANNER_RE.match(line) or SMTP_CMD_RE.match(line):
                smtp_grammar += 3
            if b"250-STARTTLS" in line or b"250 STARTTLS" in line or b"220 2.0.0 Ready to start TLS" in line:
                smtp_grammar += 4

            # IMAP checks
            if IMAP_BANNER_RE.match(line) or IMAP_CMD_RE.match(line):
                imap_grammar += 3
            if b"STARTTLS" in line and b"CAPABILITY" in line:
                imap_grammar += 3

            # POP3 checks
            if POP3_BANNER_RE.match(line) or POP3_CMD_RE.match(line):
                pop3_grammar += 3
            if b"STLS" in line:
                pop3_grammar += 3

        # TShark dissector column hints
        proto_col = (pkt.get("protocol_col") or "").upper()
        if "SMTP" in proto_col:
            smtp_grammar += 2
        elif "IMAP" in proto_col:
            imap_grammar += 2
        elif "POP" in proto_col:
            pop3_grammar += 2

    # 2. Evaluate grammar scores
    if smtp_grammar > 0 and smtp_grammar >= max(imap_grammar, pop3_grammar):
        return "SMTP"
    if imap_grammar > 0 and imap_grammar >= max(smtp_grammar, pop3_grammar):
        return "IMAP"
    if pop3_grammar > 0:
        return "POP3"

    # 3. Traffic occurs on a mail port but failed to match grammar
    ports = {sport, dport}
    if ports & ALL_MAIL_PORTS:
        # If payload was present and non-empty but didn't match, or if it was pure binary
        return "unrecognized mail-port traffic"

    return "UNKNOWN"
