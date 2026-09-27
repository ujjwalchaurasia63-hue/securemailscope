"""
STARTTLS / STLS State Machine and Plaintext Authentication Detection.
Tracks negotiation lifecycle across SMTP, IMAP, and POP3 streams.
"""

import re
from typing import List, Dict, Any, Tuple, Optional

# Authentication regex patterns (case-insensitive)
AUTH_PATTERNS = {
    "SMTP": [
        (re.compile(rb"^AUTH\s+(?:PLAIN|LOGIN|CRAM-MD5|EXTERNAL)", re.IGNORECASE), "AUTH command"),
    ],
    "IMAP": [
        (re.compile(rb"^[A-Za-z0-9]+\s+LOGIN\s+", re.IGNORECASE), "LOGIN command"),
        (re.compile(rb"^[A-Za-z0-9]+\s+AUTHENTICATE\s+", re.IGNORECASE), "AUTHENTICATE command"),
    ],
    "POP3": [
        (re.compile(rb"^USER\s+", re.IGNORECASE), "USER command"),
        (re.compile(rb"^PASS\s+", re.IGNORECASE), "PASS command"),
        (re.compile(rb"^AUTH\s+", re.IGNORECASE), "AUTH command"),
    ]
}

# STARTTLS advertisement indicators in server responses
STARTTLS_ADVERT_PATTERNS = {
    "SMTP": re.compile(rb"^250[ -].*STARTTLS", re.IGNORECASE | re.MULTILINE),
    "IMAP": re.compile(rb"\bSTARTTLS\b", re.IGNORECASE),
    "POP3": re.compile(rb"\bSTLS\b", re.IGNORECASE),
}

# STARTTLS upgrade request from client
STARTTLS_REQ_PATTERNS = {
    "SMTP": re.compile(rb"^STARTTLS\r?\n?", re.IGNORECASE),
    "IMAP": re.compile(rb"^[A-Za-z0-9]+\s+STARTTLS\r?\n?", re.IGNORECASE),
    "POP3": re.compile(rb"^STLS\r?\n?", re.IGNORECASE),
}

# STARTTLS server ready response
STARTTLS_OK_PATTERNS = {
    "SMTP": re.compile(rb"^220[ -].*(?:ready|tls|start|go ahead)", re.IGNORECASE),
    "IMAP": re.compile(rb"^[A-Za-z0-9]+\s+OK\b.*(?:begin|start|ready)", re.IGNORECASE),
    "POP3": re.compile(rb"^\+OK\b.*(?:begin|start|ready)", re.IGNORECASE),
}


class StarttlsTracker:
    """State machine tracking STARTTLS progress and plaintext auth violations."""

    def __init__(self, protocol: str):
        self.protocol = protocol
        self.state = "none"  # none, advertised, requested, completed, failed
        self.plaintext_auth_observed = False
        self.plaintext_auth_frames: List[int] = []
        self.plaintext_auth_evidence: List[str] = []

        self.advertised_frame: Optional[int] = None
        self.requested_frame: Optional[int] = None
        self.response_frame: Optional[int] = None
        self.tls_started_frame: Optional[int] = None

    def analyze_stream_packets(
        self,
        packets: List[Dict[str, Any]],
        client_ip: str,
        server_ip: str,
        server_port: int
    ) -> Dict[str, Any]:
        """
        Processes packets in chronological order to determine STARTTLS state
        and detect any plaintext credentials sent before TLS handshake completion.
        """
        # Implicit TLS ports (465 SMTPS, 993 IMAPS, 995 POP3S) start directly with TLS
        implicit_ports = {465, 993, 995}
        is_implicit = server_port in implicit_ports

        tls_completed = False
        tls_handshake_seen = False

        for pkt in packets:
            frame_num = pkt["frame_number"]
            src = pkt["src_ip"]
            dst = pkt["dst_ip"]
            payload = pkt.get("payload_bytes", b"")
            is_client = (src == client_ip)

            # Check if this frame has TLS handshake indicators
            handshake_type = pkt.get("tls_handshake_type", "")
            record_version = pkt.get("tls_record_version", "")
            if handshake_type or record_version:
                tls_handshake_seen = True
                if not self.tls_started_frame:
                    self.tls_started_frame = frame_num

                # If server hello or finished seen, handshake is well underway/completed
                if "2" in handshake_type.split(",") or "Server Hello" in handshake_type:
                    tls_completed = True
                    if self.state in ("requested", "advertised"):
                        self.state = "completed"

            if not payload:
                continue

            # If TLS is not completed, inspect application text
            if not tls_completed:
                # 1. Check for plaintext authentication from client
                if is_client:
                    patterns = AUTH_PATTERNS.get(self.protocol, [])
                    for pat, desc in patterns:
                        if pat.search(payload):
                            self.plaintext_auth_observed = True
                            self.plaintext_auth_frames.append(frame_num)
                            self.plaintext_auth_evidence.append(
                                f"Frame {frame_num}: Cleartext {desc} from {src}"
                            )

                    # 2. Check for client STARTTLS request
                    req_pat = STARTTLS_REQ_PATTERNS.get(self.protocol)
                    if req_pat and req_pat.search(payload):
                        self.state = "requested"
                        self.requested_frame = frame_num

                # 3. Check for server responses
                else:
                    # Check STARTTLS advertisement
                    advert_pat = STARTTLS_ADVERT_PATTERNS.get(self.protocol)
                    if advert_pat and advert_pat.search(payload):
                        if self.state == "none":
                            self.state = "advertised"
                            self.advertised_frame = frame_num

                    # Check STARTTLS OK response
                    ok_pat = STARTTLS_OK_PATTERNS.get(self.protocol)
                    if ok_pat and ok_pat.search(payload):
                        if self.state == "requested":
                            self.response_frame = frame_num

        # Post-scan state resolution
        if is_implicit:
            self.state = "completed" if tls_handshake_seen else "none"
        else:
            if self.state == "requested" and not tls_completed:
                self.state = "failed"
            elif self.state == "advertised" and not tls_completed:
                # Advertised but client never requested or upgraded
                pass
            elif tls_completed:
                self.state = "completed"

        return {
            "starttls_state": self.state,
            "plaintext_auth_observed": self.plaintext_auth_observed,
            "plaintext_auth_frames": self.plaintext_auth_frames,
            "plaintext_auth_evidence": self.plaintext_auth_evidence,
            "advertised_frame": self.advertised_frame,
            "requested_frame": self.requested_frame,
            "tls_started_frame": self.tls_started_frame
        }
