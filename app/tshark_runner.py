"""
TShark Execution and Packet Extraction Wrapper.
Provides two-pass packet parsing and TCP stream reassembly via TShark.
"""

import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple, Any


class TSharkError(Exception):
    """Raised when TShark encounters an error or cannot be found."""
    pass


class TSharkRunner:
    """Locates, validates, and runs TShark commands for PCAP analysis."""

    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = self._resolve_tshark_path(tshark_path)

    @staticmethod
    def _resolve_tshark_path(custom_path: Optional[str] = None) -> str:
        """Finds TShark executable in custom path, environment, PATH, or standard install dirs."""
        if custom_path and os.path.exists(custom_path):
            return custom_path

        env_path = os.environ.get("TSHARK_PATH")
        if env_path and os.path.exists(env_path):
            return env_path

        which_path = shutil.which("tshark")
        if which_path:
            return which_path

        # Standard Windows installation paths
        common_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        for p in common_paths:
            if os.path.exists(p):
                return p

        raise TSharkError(
            "TShark executable not found. TShark is a required system dependency for SecureMailScope. "
            "Please install Wireshark / TShark (e.g. 'winget install WiresharkFoundation.Wireshark') "
            "or set the TSHARK_PATH environment variable."
        )

    def get_version(self) -> str:
        """Returns the version line of TShark."""
        try:
            res = subprocess.run(
                [self.tshark_path, "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            return res.stdout.splitlines()[0] if res.stdout else "Unknown TShark version"
        except Exception as e:
            raise TSharkError(f"Failed to execute TShark at '{self.tshark_path}': {e}")

    def extract_packets(
        self,
        pcap_path: str,
        display_filter: Optional[str] = None,
        two_pass: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Runs TShark to extract packets matching the display filter with key fields.
        Returns a list of structured packet dictionaries.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        if os.path.getsize(pcap_path) == 0:
            raise ValueError(f"PCAP file is empty: {pcap_path}")

        fields = [
            "frame.number",
            "frame.time_epoch",
            "frame.len",
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.stream",
            "tcp.flags",
            "tcp.payload",
            "_ws.col.Protocol",
            "smtp.req.command",
            "smtp.req.parameter",
            "smtp.response.code",
            "imap.request",
            "pop.request",
            "tls.record.version",
            "tls.handshake.type",
            "tls.handshake.version",
            "tls.handshake.ciphersuite",
            "tls.handshake.ciphersuites",
            "tls.handshake.extensions_server_name",
            "tls.alert_message.level",
            "tls.alert_message.desc",
            "tls.handshake.certificate",
            "tls.handshake.extension.type",
            "tls.handshake.extensions_supported_group",
            "tls.handshake.extensions_ec_point_format",
            "x509af.utcTime",
            "x509ce.dNSName"
        ]

        cmd = [self.tshark_path, "-r", pcap_path]
        if two_pass:
            cmd.append("-2")

        # Mail & TLS protocol filter
        base_filter = "tcp"
        if display_filter:
            cmd.extend(["-R", f"({base_filter}) && ({display_filter})"])
        else:
            cmd.extend(["-R", base_filter])

        cmd.extend(["-T", "fields"])
        for f in fields:
            cmd.extend(["-e", f])

        cmd.extend([
            "-E", "header=y",
            "-E", "separator=\t",
            "-E", "occurrence=a"
        ])

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            if res.returncode != 0 and not res.stdout:
                raise TSharkError(f"TShark execution failed: {res.stderr.strip()}")

            lines = res.stdout.strip().splitlines()
            if not lines:
                return []

            header = [h.strip() for h in lines[0].split("\t")]
            packets = []

            for line in lines[1:]:
                parts = line.split("\t")
                row = {}
                for idx, col in enumerate(header):
                    val = parts[idx].strip() if idx < len(parts) else ""
                    row[col] = val
                
                # Normalize essentials
                frame_num = int(row.get("frame.number") or 0)
                if not frame_num:
                    continue

                stream_id = row.get("tcp.stream")
                stream_int = int(stream_id) if stream_id and stream_id.isdigit() else None

                src_ip = row.get("ip.src") or row.get("ipv6.src") or ""
                dst_ip = row.get("ip.dst") or row.get("ipv6.dst") or ""

                sport = int(row.get("tcp.srcport") or 0) if row.get("tcp.srcport", "").isdigit() else 0
                dport = int(row.get("tcp.dstport") or 0) if row.get("tcp.dstport", "").isdigit() else 0

                time_epoch = float(row.get("frame.time_epoch") or 0.0)
                frame_len = int(row.get("frame.len") or 0)

                payload_hex = row.get("tcp.payload", "")
                payload_bytes = bytes.fromhex(payload_hex.replace(":", "")) if payload_hex else b""

                packets.append({
                    "frame_number": frame_num,
                    "time_epoch": time_epoch,
                    "frame_len": frame_len,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": sport,
                    "dst_port": dport,
                    "tcp_stream": stream_int,
                    "protocol_col": row.get("_ws.col.Protocol", ""),
                    "payload_bytes": payload_bytes,
                    "smtp_command": row.get("smtp.req.command", ""),
                    "smtp_param": row.get("smtp.req.parameter", ""),
                    "smtp_code": row.get("smtp.response.code", ""),
                    "imap_request": row.get("imap.request", ""),
                    "pop_request": row.get("pop.request", ""),
                    "tls_record_version": row.get("tls.record.version", ""),
                    "tls_handshake_type": row.get("tls.handshake.type", ""),
                    "tls_handshake_version": row.get("tls.handshake.version", ""),
                    "tls_ciphersuite": row.get("tls.handshake.ciphersuite", ""),
                    "tls_ciphersuites": row.get("tls.handshake.ciphersuites", ""),
                    "tls_sni": row.get("tls.handshake.extensions_server_name", ""),
                    "tls_alert_level": row.get("tls.alert_message.level", ""),
                    "tls_alert_desc": row.get("tls.alert_message.desc", ""),
                    "tls_certificate": row.get("tls.handshake.certificate", ""),
                    "tls_extensions": row.get("tls.handshake.extension.type", ""),
                    "tls_supported_groups": row.get("tls.handshake.extensions_supported_group", ""),
                    "tls_ec_point_formats": row.get("tls.handshake.extensions_ec_point_format", ""),
                    "x509_utc_time": row.get("x509af.utcTime", ""),
                    "x509_dns_name": row.get("x509ce.dNSName", "")
                })

            return packets

        except subprocess.SubprocessError as e:
            raise TSharkError(f"Subprocess error running TShark: {e}")

    def follow_tcp_stream(self, pcap_path: str, stream_id: int) -> str:
        """Follows and reassembles ASCII text of a specific TCP stream."""
        cmd = [
            self.tshark_path,
            "-r", pcap_path,
            "-q",
            "-z", f"follow,tcp,ascii,{stream_id}"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.stdout
        except subprocess.SubprocessError as e:
            return ""
