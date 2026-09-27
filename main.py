"""
SecureMailScope CLI Entrypoint.
Executes passive cryptographic security posture and protocol analysis on PCAP/PCAPNG captures.
"""

import sys
import json
import argparse
import os

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from app.analyzer import MailSecurityAnalyzer
from app.tshark_runner import TSharkError


def format_cli_report(result: dict) -> str:
    """Renders human-readable cybersecurity assessment report for terminal output."""
    summary = result["summary"]
    meta = result["capture_metadata"]

    lines = []
    lines.append("=" * 78)
    lines.append("🛡️  SECUREMAILSCOPE — PASSIVE MAIL CRYPTOGRAPHIC POSTURE REPORT")
    lines.append("=" * 78)
    lines.append(f"Analysis ID:    {result['analysis_id']}")
    lines.append(f"Target PCAP:    {meta['filename']} ({meta['file_size_bytes']} bytes, {meta['total_packets_parsed']} packets)")
    lines.append(f"Scan Duration:  {result['duration_seconds']}s")
    lines.append("-" * 78)
    lines.append("📊 EXECUTIVE SUMMARY")
    lines.append("-" * 78)
    lines.append(f"Total Reassembled Sessions:   {summary['total_sessions']}")
    lines.append(f"Protocols Observed:            {summary['protocol_counts']}")
    lines.append(f"STARTTLS Lifecycle States:     {summary['starttls_states']}")
    lines.append(f"STARTTLS Upgrade Rate:         {summary['starttls_upgrade_rate_pct']}%")
    lines.append(f"Overall Capture Severity:      {summary['overall_severity']}")
    lines.append(f"Total Rule Violations (L1):    {summary['total_rule_findings']}")
    lines.append(f"Statistical Anomalies (L2):    {summary['total_statistical_anomalies']}")

    lines.append("\n" + "-" * 78)
    lines.append("🔍 SESSION BREAKDOWN & EVIDENCE")
    lines.append("-" * 78)

    for s in result["sessions"]:
        sid = s["session_id"]
        proto = s["protocol"]
        client = f"{s['client_ip']}:{s['client_port']}"
        server = f"{s['server_ip']}:{s['server_port']}"
        st_state = s["starttls_state"]
        tls_ver = s.get("tls_version") or "None (Cleartext)"
        cipher = s.get("cipher_suite") or "None"
        sev = s["session_severity"]
        anom = "⚡ YES" if s.get("is_anomaly") else "NO"
        anom_score = s.get("anomaly_score", 0.0)

        lines.append(f"\n[Stream {s.get('stream_id', 'N/A')}: {sid}] Protocol: {proto}")
        lines.append(f"  • Endpoints:           Client {client} ➔ Server {server}")
        lines.append(f"  • Packet Range:        Frames {s.get('first_frame', '?')}..{s.get('last_frame', '?')} (Total: {s.get('packet_count', '?')} packets)")
        lines.append(f"  • STARTTLS State:      {st_state.upper()}")
        lines.append(f"  • TLS Version:         {tls_ver}")
        lines.append(f"  • Cipher Suite:        {cipher}")
        lines.append(f"  • Handshake Latency:   {s.get('handshake_duration_ms', 0)} ms")
        lines.append(f"  • Plaintext Auth Seen: {'CRITICAL (YES)' if s.get('plaintext_auth_observed') else 'No'}")
        lines.append(f"  • Certificate Status:  {s.get('cert_visibility')} ({s.get('cert_explanation', '')})")
        lines.append(f"  • Session Severity:    {sev} (Max Rule Severity)")
        lines.append(f"  • Statistical Anomaly: {anom} (Score: {anom_score})")

        findings = s.get("findings", [])
        if findings:
            lines.append("  • Rule Findings:")
            for f in findings:
                lines.append(f"     - [{f['severity']}] {f['title']} ({f['rule_id']})")
                lines.append(f"       Evidence: {f['evidence']}")
                lines.append(f"       Standard: {f['source']}")
                lines.append(f"       Fix:      {f['recommendation']}")
        else:
            lines.append("  • Rule Findings: None (Compliant)")

    lines.append("\n" + "=" * 78)
    return "\n".join(lines)


def main():
    # If launched via `python -m streamlit run main.py`, delegate immediately to the UI
    try:
        import streamlit as st
        if st.runtime.exists():
            import runpy
            app_entry = os.path.join(os.path.dirname(__file__), "app", "main.py")
            runpy.run_path(app_entry, run_name="__main__")
            return
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="SecureMailScope: Passive Mail Cryptographic Posture & Protocol Anomaly Analyzer"
    )
    parser.add_argument("pcap", nargs="?", help="Path to input .pcap or .pcapng capture file")
    parser.add_argument("--check-env", action="store_true", help="Run environment diagnostics and dependency check")
    parser.add_argument("--ui", action="store_true", help="Launch interactive Streamlit visualization dashboard")
    parser.add_argument("--json", dest="json_out", help="Optional path to write structured JSON output")
    parser.add_argument("--tshark-path", dest="tshark_path", help="Optional custom path to tshark executable")

    args = parser.parse_args()

    if args.check_env:
        from app.env_check import check_environment, format_env_report
        status = check_environment()
        print(format_env_report(status))
        sys.exit(0 if status["all_valid"] else 1)

    if args.ui:
        import subprocess
        app_entry = os.path.join(os.path.dirname(__file__), "app", "main.py")
        cmd = [sys.executable, "-m", "streamlit", "run", app_entry]
        print(f"[+] Launching Streamlit interface: {' '.join(cmd)}")
        subprocess.run(cmd)
        sys.exit(0)

    if not args.pcap:
        parser.print_help()
        sys.exit(1)

    try:
        analyzer = MailSecurityAnalyzer(tshark_path=args.tshark_path)
        result = analyzer.analyze_pcap(args.pcap)

        report = format_cli_report(result)
        print(report)

        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"\n[+] Successfully saved JSON report to: {args.json_out}")

    except TSharkError as e:
        print(f"\n[!] SYSTEM ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"\n[!] ERROR: Failed to analyze PCAP: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

