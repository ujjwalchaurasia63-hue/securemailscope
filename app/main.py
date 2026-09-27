"""
SecureMailScope — Streamlit Visualization Dashboard.
Consumes the real MailSecurityAnalyzer pipeline. No mock or fabricated findings.
"""

import os
import json
import tempfile
import pandas as pd
import streamlit as st

from app.analyzer import MailSecurityAnalyzer
from app.tshark_runner import TSharkError
from app.explainer import RemediationExplainer

st.set_page_config(
    page_title="SecureMailScope — Mail Cryptographic Posture & Anomaly Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling for Security Posture
st.markdown("""
<style>
    .metric-card {
        background-color: #1e2430;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        border-left: 4px solid #3b82f6;
    }
    .badge-critical { background-color: #dc2626; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #ea580c; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #eab308; color: black; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #3b82f6; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-clean { background-color: #10b981; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-anomaly { background-color: #8b5cf6; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)


def render_severity_badge(sev: str) -> str:
    s = (sev or "CLEAN").upper()
    if s == "CRITICAL":
        return '<span class="badge-critical">CRITICAL</span>'
    elif s == "HIGH":
        return '<span class="badge-high">HIGH</span>'
    elif s == "MEDIUM":
        return '<span class="badge-medium">MEDIUM</span>'
    elif s == "LOW":
        return '<span class="badge-low">LOW</span>'
    else:
        return '<span class="badge-clean">CLEAN</span>'


st.title("🛡️ SecureMailScope")
st.caption("Interactive visualization of offline PCAP analysis results (SMTP / IMAP / POP3)")

# Sidebar Controls
with st.sidebar:
    st.header("Capture Ingestion")
    st.markdown("Upload a network capture (.pcap / .pcapng) or analyze the bundled synthetic dataset:")

    uploaded_file = st.file_uploader(
        "Upload .pcap or .pcapng file",
        type=["pcap", "pcapng"],
        help="Upload raw mail traffic capture containing SMTP/IMAP/POP3 traffic."
    )

    use_demo_btn = st.button("📁 Load Bundled Demo PCAP", use_container_width=True)

    st.markdown("---")
    st.write("**Engine Pipeline:**")
    st.markdown("""
    1. **TShark Two-Pass (-2)**: TCP stream reassembly & packet dissections.
    2. **Protocol Engine**: SMTP / IMAP / POP3 signature extraction.
    3. **STARTTLS Tracker**: Negotiation state machine & cleartext auth audit.
    4. **TLS & Cert Extractor**: Ciphers, latency, passive X.509 analysis via `cryptography`.
    5. **Layer 1 Rule Engine**: Seven mandatory baseline rules plus additional checks.
    6. **Layer 2 Anomaly Detector**: Unsupervised Isolation Forest (behavioral outlier indicator).
    7. **Layer 3 Explainer**: Downstream advisory remediation (Administrator Action).
    """)

# Determine PCAP to analyze
target_pcap_path = None
if uploaded_file is not None:
    # Save uploaded file to temp file
    tfile = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}")
    tfile.write(uploaded_file.read())
    tfile.flush()
    target_pcap_path = tfile.name
elif use_demo_btn or "analysis_result" not in st.session_state:
    demo_path = os.path.abspath("data/demo_mail_traffic.pcap")
    if os.path.exists(demo_path):
        target_pcap_path = demo_path

# Run Analyzer if needed
if target_pcap_path and (st.session_state.get("current_pcap") != target_pcap_path or "analysis_result" not in st.session_state):
    try:
        with st.spinner("Executing Two-Pass TShark Analysis & Security Pipeline..."):
            analyzer = MailSecurityAnalyzer()
            res = analyzer.analyze_pcap(target_pcap_path)
            st.session_state["analysis_result"] = res
            st.session_state["current_pcap"] = target_pcap_path
    except TSharkError as e:
        st.error(f"TShark Error: {e}")
        st.stop()
    except Exception as e:
        st.error(f"Analysis failed: {e}")
        st.stop()

# Display Results
if "analysis_result" in st.session_state:
    result = st.session_state["analysis_result"]
    summary = result["summary"]
    meta = result["capture_metadata"]
    sessions = result["sessions"]
    findings = result["findings"]

    # Top KPI Metrics Row
    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.metric("Total Sessions", summary["total_sessions"])
    with kpi2:
        st.metric("STARTTLS Upgrade", f"{summary['starttls_upgrade_rate_pct']}%")
    with kpi3:
        st.metric("Overall Severity", summary["overall_severity"])
    with kpi4:
        st.metric("Rule Violations", summary["total_rule_findings"])
    with kpi5:
        st.metric("Statistical Anomalies", summary["total_statistical_anomalies"])

    st.markdown("---")

    # Main Tabs
    tab_overview, tab_sessions, tab_findings, tab_tls, tab_anomaly, tab_remediation, tab_export = st.tabs([
        "📊 Posture Overview",
        "🔍 Session Explorer",
        "⚖️ Rule Findings & Evidence",
        "🔐 TLS & Certificates",
        "⚡ Anomaly Detector",
        "🛠️ Hardening & Remediation",
        "📄 Export Report"
    ])

    # 1. Overview Tab
    with tab_overview:
        col_left, col_right = st.columns([1, 1])
        with col_left:
            st.subheader("Capture Metadata")
            st.write(f"**Filename:** `{meta['filename']}`")
            st.write(f"**File Size:** `{meta['file_size_bytes']} bytes`")
            st.write(f"**Total Packets Evaluated:** `{meta['total_packets_parsed']}`")
            st.write(f"**Analysis Latency:** `{result['duration_seconds']}s`")
            st.write(f"**Analysis ID:** `{result['analysis_id']}`")

            st.subheader("Protocol Distribution")
            df_proto = pd.DataFrame(list(summary["protocol_counts"].items()), columns=["Protocol", "Count"])
            st.dataframe(df_proto, use_container_width=True, hide_index=True)

        with col_right:
            st.subheader("Severity Breakdown (Max Rule)")
            df_sev = pd.DataFrame(list(summary["severity_counts"].items()), columns=["Severity", "Sessions"])
            st.dataframe(df_sev, use_container_width=True, hide_index=True)

            st.subheader("STARTTLS Lifecycle States")
            df_st = pd.DataFrame(list(summary["starttls_states"].items()), columns=["STARTTLS State", "Sessions"])
            st.dataframe(df_st, use_container_width=True, hide_index=True)

    # 2. Session Explorer Tab
    with tab_sessions:
        st.subheader("Reassembled TCP / Application Sessions")
        table_rows = []
        for s in sessions:
            table_rows.append({
                "Session ID": s["session_id"],
                "Protocol": s["protocol"],
                "Client": f"{s['client_ip']}:{s['client_port']}",
                "Server": f"{s['server_ip']}:{s['server_port']}",
                "STARTTLS State": s["starttls_state"].upper(),
                "TLS Version": s.get("tls_version") or "Cleartext",
                "Cipher Suite": s.get("cipher_suite") or "None",
                "Handshake (ms)": s.get("handshake_duration_ms", 0.0),
                "Severity": s["session_severity"],
                "Anomaly": "YES" if s.get("is_anomaly") else "No",
                "Violations": s.get("rule_violations_count", 0)
            })
        df_sessions = pd.DataFrame(table_rows)
        st.dataframe(df_sessions, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.subheader("Session Deep Dive")
        selected_sid = st.selectbox("Select Session to inspect:", [s["session_id"] for s in sessions])
        curr_session = next(s for s in sessions if s["session_id"] == selected_sid)

        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**Session:** `{curr_session['session_id']}`")
            st.markdown(f"**Flow:** `{curr_session['client_ip']}:{curr_session['client_port']}` ➔ `{curr_session['server_ip']}:{curr_session['server_port']}`")
            st.markdown(f"**Protocol:** `{curr_session['protocol']}`")
            st.markdown(f"**STARTTLS Negotiation State:** `{curr_session['starttls_state'].upper()}`")
            st.markdown(f"**Plaintext Credentials Observed:** `{curr_session.get('plaintext_auth_observed')}`")
        with c2:
            st.markdown(f"**TLS Version:** `{curr_session.get('tls_version') or 'Cleartext'}`")
            st.markdown(f"**Negotiated Cipher:** `{curr_session.get('cipher_suite') or 'None'}`")
            st.markdown(f"**Handshake Duration:** `{curr_session.get('handshake_duration_ms', 0)} ms`")
            st.markdown(f"**Session Severity (Max Rule):** `{curr_session['session_severity']}`")
            st.markdown(f"**Statistical Anomaly:** `{curr_session.get('is_anomaly')} (Score: {curr_session.get('anomaly_score', 0)})`")

    # 3. Rule Findings & Evidence Tab
    with tab_findings:
        st.subheader("Traceable Evidence-First Security Findings")
        if not findings:
            st.success("No security rule violations detected in this capture. Traffic complies with baseline standards.")
        else:
            for f in findings:
                sev_color = {
                    "CRITICAL": "red",
                    "HIGH": "orange",
                    "MEDIUM": "gold",
                    "LOW": "blue"
                }.get(f["severity"], "gray")

                with st.expander(f"[{f['severity']}] {f['title']} — Session: {f['session_id']}", expanded=True):
                    st.markdown(f"**Rule ID:** `{f['rule_id']}`")
                    st.markdown(f"**Severity:** `{f['severity']}`")
                    st.markdown(f"**Governing Standard:** `{f['source']}`")
                    st.markdown(f"**Forensic Evidence:** `{f['evidence']}`")
                    st.info(f"**Why It Matters:** {f['why_it_matters']}")
                    st.success(f"**Remediation:** {f['recommendation']}")

    # 4. TLS & Certificates Tab
    with tab_tls:
        st.subheader("Cryptographic Parameter Inspection")
        for s in sessions:
            if s.get("tls_version"):
                with st.expander(f"Session {s['session_id']} — {s['protocol']} ({s['tls_version']})", expanded=False):
                    st.write(f"**TLS Version:** {s['tls_version']}")
                    st.write(f"**Negotiated Cipher:** {s['cipher_suite']}")
                    st.write(f"**Client SNI:** {s.get('sni') or 'None'}")
                    st.write(f"**Offered Cipher Count:** {s.get('offered_cipher_count')}")
                    st.write(f"**Cipher Rarity Score:** {s.get('cipher_rarity_score')}")
                    st.write(f"**JA3 MD5 Fingerprint:** `{s.get('ja3_hash') or 'N/A'}`")
                    st.write(f"**JA4 Fingerprint:** `{s.get('ja4') or 'N/A'}`")
                    st.write(f"**OCSP Stapling Status:** `{s.get('ocsp_stapling', 'unknown')}`")

                    st.markdown("#### Certificate Inspection")
                    vis = s.get("cert_visibility")
                    if vis == "not_extractable_tls1.3":
                        st.info(f"ℹ️ {s.get('cert_explanation')}")
                    elif vis == "visible":
                        st.write(f"**Subject:** `{s.get('cert_subject')}`")
                        st.write(f"**Issuer:** `{s.get('cert_issuer')}`")
                        st.write(f"**Days to Expiry:** `{s.get('cert_days_to_expiry')} days`")
                        st.write(f"**Self-Signed:** `{s.get('cert_self_signed')}`")
                        st.write(f"**SAN Entries:** `{s.get('cert_sans')}`")
                        st.write(f"**Public Key Algorithm:** `{s.get('cert_public_key_algo') or 'N/A'}`")
                        st.write(f"**Public Key Size:** `{s.get('cert_key_size')} bits`")
                        st.write(f"**Signature Algorithm:** `{s.get('cert_sig_algo')}`")
                    else:
                        st.write(f"**Status:** {s.get('cert_explanation', 'No certificate exchange visible.')}")

    # 5. Anomaly Detector Tab
    with tab_anomaly:
        st.subheader("Layer 2: Unsupervised Anomaly Detector (Isolation Forest)")
        st.info("The anomaly score indicates how unusual a session is relative to the analyzed behavioral baseline. It is not a probability that the session is malicious.")
        st.markdown("""
        The Anomaly Detector evaluates statistical outliers across a 9-dimensional numeric telemetry vector:
        1. **Handshake Duration (ms)** — timing latency $\Delta t = (t_{ServerHello} - t_{ClientHello}) \times 1000$
        2. **Offered Cipher Suites Count** — distinguishes standard clients (15-30 ciphers) from scanner bots (1-2)
        3. **Cipher Rarity Index** — continuous heuristic proxy for cryptographic deprecation
        4. **Average Payload Bytes** — mean application-layer TCP payload per frame
        5. **Payload Size Variance** — variance of application-layer TCP payload across frames
        6. **Packet Count** — total frame count of the reassembled TCP stream
        7. **TLS Version Encoded** — monotonic ordinal ranking (Cleartext=0, SSL 3.0=1, TLS 1.0=2, TLS 1.1=3, TLS 1.2=4, TLS 1.3=5)
        8. **Cipher Suite Encoded** — cryptographic capability tiering (Cleartext=0, Broken=1, CBC=2, ChaCha20=3, AES-128=4, AES-256=5)
        9. **JA3 Fingerprint Partition** — normalized deterministic client fingerprint partition
        
        *Note: The anomaly flag is an independent behavioral outlier indicator and is never merged into the deterministic compliance severity.*
        """)

        anom_rows = []
        for s in sessions:
            anom_rows.append({
                "Session ID": s["session_id"],
                "Protocol": s["protocol"],
                "Handshake Latency (ms)": s.get("handshake_duration_ms", 0.0),
                "Offered Ciphers": s.get("offered_cipher_count", 0),
                "Cipher Rarity": s.get("cipher_rarity_score", 0.0),
                "Avg Payload": s.get("payload_bytes_avg", 0.0),
                "Payload Variance": s.get("payload_bytes_var", 0.0),
                "Anomaly Flag": "⚡ YES" if s.get("is_anomaly") else "No",
                "Anomaly Score": s.get("anomaly_score", 0.0),
                "Top Deviations": ", ".join(s.get("top_deviating_features", [])) or "None"
            })
        df_anom = pd.DataFrame(anom_rows)
        st.dataframe(df_anom, use_container_width=True, hide_index=True)

    # 6. Hardening & Remediation Tab
    with tab_remediation:
        st.subheader("Layer 3: Plain-Language Server Remediation Guide (Advisory Only)")
        st.caption("ℹ️ Suggested hardening configurations are advisory recommendations for system administrators. SecureMailScope is an offline, read-only analysis tool and never automatically modifies server configurations.")
        explainer = RemediationExplainer()
        unique_rules = list({f["rule_id"] for f in findings})

        if not unique_rules:
            st.success("No violations requiring remediation detected.")
        else:
            for rid in unique_rules:
                rec = explainer.explain_finding(rid)
                st.markdown(f"### {rec['title']}")
                st.write(rec["plain_explanation"])
                
                c_post, c_dov = st.columns(2)
                with c_post:
                    st.markdown("**Recommended Postfix Hardening (Administrator Action):**")
                    st.code(rec["postfix_snippet"], language="bash")
                with c_dov:
                    st.markdown("**Recommended Dovecot Hardening (Administrator Action):**")
                    st.code(rec["dovecot_snippet"], language="bash")
                st.markdown("---")

    # 7. Export Report Tab
    with tab_export:
        st.subheader("Export Verified Security Report")
        json_str = json.dumps(result, indent=2)
        st.download_button(
            label="⬇️ Download Machine-Readable JSON Report",
            data=json_str,
            file_name=f"securemailscope_{result['analysis_id']}.json",
            mime="application/json"
        )
