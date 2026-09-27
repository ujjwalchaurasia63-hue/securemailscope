"""
SecureMailScope Core Analysis Engine.
Orchestrates TShark packet extraction, protocol detection, TCP stream reassembly,
STARTTLS state tracking, TLS metadata extraction, deterministic rule auditing,
and unsupervised anomaly detection into a single verified pipeline.
"""

import os
import uuid
import datetime
from typing import List, Dict, Any, Optional

from app.tshark_runner import TSharkRunner, TSharkError
from app.stream_reassembler import StreamReassembler
from app.tls_extractor import TlsExtractor
from app.rules import RuleEngine, get_max_severity
from app.anomaly import AnomalyDetector
from app.pcap_validator import validate_capture_file


class MailSecurityAnalyzer:
    """Core analysis orchestrator for passive mail cryptographic posture assessment."""

    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_runner = TSharkRunner(tshark_path=tshark_path)
        self.stream_reassembler = StreamReassembler()
        self.tls_extractor = TlsExtractor()
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector()

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        Executes complete passive analysis pipeline on a PCAP or PCAPNG file.
        Returns a structured dictionary of all verified findings and telemetry.
        """
        # Validate capture file integrity & format
        validate_capture_file(pcap_path, tshark_path=self.tshark_runner.tshark_path)

        file_size = os.path.getsize(pcap_path)
        analysis_id = f"ANALYSIS_{uuid.uuid4().hex[:10].upper()}"
        start_time = datetime.datetime.now(datetime.timezone.utc)

        # 1. TShark Packet Extraction (Two-Pass)
        display_filter = "smtp || imap || pop || tls || tcp.port in {25, 110, 143, 465, 587, 993, 995, 2525}"
        packets = self.tshark_runner.extract_packets(
            pcap_path=pcap_path,
            display_filter=display_filter,
            two_pass=True
        )

        if not packets:
            # Fallback scan on all TCP frames if port filter was too restrictive
            packets = self.tshark_runner.extract_packets(
                pcap_path=pcap_path,
                display_filter=None,
                two_pass=True
            )

        # 2. TCP Stream Reassembly & Protocol Detection
        sessions = self.stream_reassembler.reassemble_streams(packets)

        # 3. TLS Metadata & Certificate Extraction for each session
        for s in sessions:
            stream_pkts = s.pop("packets", [])
            tls_meta = self.tls_extractor.extract_tls_metadata(stream_pkts)
            s.update(tls_meta)

            # 4. Deterministic Rule Evaluation (Layer 1)
            findings = self.rule_engine.evaluate_session(s)
            s["findings"] = findings
            s["rule_violations_count"] = len(findings)

            # 5. Session Severity Calculation (MAX rule severity)
            fired_severities = [f["severity"] for f in findings]
            s["session_severity"] = get_max_severity(fired_severities)

        # 6. Unsupervised Anomaly Detection (Layer 2 - Independent Indicator)
        sessions = self.anomaly_detector.detect_anomalies(sessions)

        end_time = datetime.datetime.now(datetime.timezone.utc)
        duration_s = (end_time - start_time).total_seconds()

        # 7. Aggregate Metrics
        total_sessions = len(sessions)
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
        protocol_counts: Dict[str, int] = {}
        starttls_states: Dict[str, int] = {}
        total_anomalies = 0
        all_findings: List[Dict[str, Any]] = []

        for s in sessions:
            sev = s["session_severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            proto = s["protocol"]
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            st_state = s["starttls_state"]
            starttls_states[st_state] = starttls_states.get(st_state, 0) + 1

            if s.get("is_anomaly"):
                total_anomalies += 1

            all_findings.extend(s.get("findings", []))

        # Overall Posture Maximum Severity
        overall_severity = get_max_severity([s["session_severity"] for s in sessions])

        # STARTTLS upgrade success rate
        completed_upgrades = starttls_states.get("completed", 0)
        upgrade_rate = (completed_upgrades / total_sessions * 100.0) if total_sessions > 0 else 0.0

        return {
            "analysis_id": analysis_id,
            "timestamp": start_time.isoformat(),
            "duration_seconds": round(duration_s, 3),
            "capture_metadata": {
                "file_path": os.path.abspath(pcap_path),
                "filename": os.path.basename(pcap_path),
                "file_size_bytes": file_size,
                "total_packets_parsed": len(packets)
            },
            "summary": {
                "total_sessions": total_sessions,
                "overall_severity": overall_severity,
                "severity_counts": severity_counts,
                "protocol_counts": protocol_counts,
                "starttls_states": starttls_states,
                "starttls_upgrade_rate_pct": round(upgrade_rate, 1),
                "total_rule_findings": len(all_findings),
                "total_statistical_anomalies": total_anomalies
            },
            "sessions": sessions,
            "findings": all_findings
        }
