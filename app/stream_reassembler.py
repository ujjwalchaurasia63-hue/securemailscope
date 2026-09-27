"""
TCP Stream Reassembly and Session Aggregation Module.
Groups packets by TCP stream and derives session-level flow attributes.
"""

import math
from typing import List, Dict, Any, Optional
from app.protocol_detector import detect_protocol_from_stream
from app.starttls_tracker import StarttlsTracker


class StreamReassembler:
    """Reassembles individual packets into cohesive TCP / Application sessions."""

    def __init__(self):
        pass

    def reassemble_streams(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Groups packets by tcp_stream and extracts session endpoints and timing.
        """
        streams_map: Dict[int, List[Dict[str, Any]]] = {}
        for pkt in packets:
            st_id = pkt.get("tcp_stream")
            if st_id is None:
                continue
            if st_id not in streams_map:
                streams_map[st_id] = []
            streams_map[st_id].append(pkt)

        sessions: List[Dict[str, Any]] = []

        for st_id, stream_pkts in sorted(streams_map.items()):
            if not stream_pkts:
                continue

            # Sort chronologically
            stream_pkts.sort(key=lambda p: (p["time_epoch"], p["frame_number"]))

            first_pkt = stream_pkts[0]
            last_pkt = stream_pkts[-1]

            # Determine client vs server
            # First packet source is usually the client (SYN or initial command)
            client_ip = first_pkt["src_ip"]
            client_port = first_pkt["src_port"]
            server_ip = first_pkt["dst_ip"]
            server_port = first_pkt["dst_port"]

            # Known mail server ports
            known_server_ports = {25, 110, 143, 465, 587, 993, 995, 2525}
            if client_port in known_server_ports and server_port not in known_server_ports:
                # Inverted capture; swap roles
                client_ip, server_ip = server_ip, client_ip
                client_port, server_port = server_port, client_port

            # Detect protocol
            protocol = detect_protocol_from_stream(stream_pkts, client_port, server_port)

            # Track STARTTLS lifecycle and plaintext authentication
            tracker = StarttlsTracker(protocol)
            starttls_results = tracker.analyze_stream_packets(
                stream_pkts, client_ip, server_ip, server_port
            )

            # Compute payload sizing variance
            payload_lens = [len(p.get("payload_bytes", b"")) for p in stream_pkts if p.get("payload_bytes")]
            if payload_lens:
                avg_payload = sum(payload_lens) / len(payload_lens)
                var_payload = sum((x - avg_payload) ** 2 for x in payload_lens) / len(payload_lens)
            else:
                avg_payload = 0.0
                var_payload = 0.0

            start_time = first_pkt["time_epoch"]
            end_time = last_pkt["time_epoch"]
            duration = max(0.0, end_time - start_time)

            session = {
                "session_id": f"tcp_stream_{st_id}",
                "stream_id": st_id,
                "first_frame": first_pkt["frame_number"],
                "last_frame": last_pkt["frame_number"],
                "start_time": start_time,
                "end_time": end_time,
                "duration_seconds": round(duration, 4),
                "client_ip": client_ip,
                "client_port": client_port,
                "server_ip": server_ip,
                "server_port": server_port,
                "protocol": protocol,
                "packet_count": len(stream_pkts),
                "payload_bytes_avg": round(avg_payload, 2),
                "payload_bytes_var": round(var_payload, 2),
                "starttls_state": starttls_results["starttls_state"],
                "plaintext_auth_observed": starttls_results["plaintext_auth_observed"],
                "plaintext_auth_frames": starttls_results["plaintext_auth_frames"],
                "plaintext_auth_evidence": starttls_results["plaintext_auth_evidence"],
                "advertised_frame": starttls_results["advertised_frame"],
                "requested_frame": starttls_results["requested_frame"],
                "tls_started_frame": starttls_results["tls_started_frame"],
                "packets": stream_pkts
            }
            sessions.append(session)

        return sessions
