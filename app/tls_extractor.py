"""
TLS Handshake and Certificate Metadata Extraction Module.
Inspects ClientHello, ServerHello, TLS version, cipher suites, alerts,
and parses visible X.509 certificates using Python cryptography.
Handles TLS 1.3 encrypted certificate visibility explicitly.
"""

import datetime
from typing import List, Dict, Any, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.x509.oid import NameOID, ExtensionOID
from app.ja3_fingerprint import extract_client_hello_fingerprints

# IANA TLS Versions
TLS_VERSIONS_MAP = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
    "768": "SSL 3.0",
    "769": "TLS 1.0",
    "770": "TLS 1.1",
    "771": "TLS 1.2",
    "772": "TLS 1.3",
    "0x0200": "SSL 2.0"
}

# Known cipher suite hex to name mappings
KNOWN_CIPHERS = {
    # TLS 1.3
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "4865": "TLS_AES_128_GCM_SHA256",
    "4866": "TLS_AES_256_GCM_SHA384",
    "4867": "TLS_CHACHA20_POLY1305_SHA256",

    # Modern TLS 1.2 AEAD
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "49199": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "49200": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",

    # TLS 1.2 CBC (Non-AEAD)
    "0xc013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "0xc014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "49171": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "49172": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "47": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "53": "TLS_RSA_WITH_AES_256_CBC_SHA",

    # Broken / Legacy Ciphers
    "0x000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
    "0x0004": "TLS_RSA_WITH_RC4_128_MD5",
    "0x0000": "TLS_NULL_WITH_NULL_NULL",
    "10": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "5": "TLS_RSA_WITH_RC4_128_SHA",
    "4": "TLS_RSA_WITH_RC4_128_MD5",
    "0": "TLS_NULL_WITH_NULL_NULL",
}


def normalize_tls_version(raw_version: str) -> Optional[str]:
    """Converts raw version hex/integer or string into standard format."""
    if not raw_version:
        return None
    raw = raw_version.strip()
    if raw in TLS_VERSIONS_MAP:
        return TLS_VERSIONS_MAP[raw]
    for key, name in TLS_VERSIONS_MAP.items():
        if key in raw:
            return name
    if "1.3" in raw:
        return "TLS 1.3"
    if "1.2" in raw:
        return "TLS 1.2"
    if "1.1" in raw:
        return "TLS 1.1"
    if "1.0" in raw:
        return "TLS 1.0"
    if "3.0" in raw or "SSLv3" in raw:
        return "SSL 3.0"
    return raw


def normalize_cipher_suite(raw_cipher: str) -> Optional[str]:
    """Resolves raw cipher string or hex code into standard IANA name."""
    if not raw_cipher:
        return None
    raw = raw_cipher.strip()
    if raw in KNOWN_CIPHERS:
        return KNOWN_CIPHERS[raw]
    if raw.startswith("0x") and raw.lower() in KNOWN_CIPHERS:
        return KNOWN_CIPHERS[raw.lower()]
    # If already a descriptive string
    if "TLS_" in raw or "SSL_" in raw:
        return raw
    return raw


class TlsExtractor:
    """Extracts TLS session parameters, handshake timing, and certificate details."""

    def __init__(self):
        pass

    def extract_tls_metadata(self, stream_packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Scans all packets in a TCP stream to extract TLS negotiation parameters.
        """
        tls_version: Optional[str] = None
        cipher_suite: Optional[str] = None
        sni: Optional[str] = None
        client_hello_frame: Optional[int] = None
        server_hello_frame: Optional[int] = None
        client_hello_time: Optional[float] = None
        server_hello_time: Optional[float] = None
        handshake_duration_ms: float = 0.0

        offered_ciphers: List[str] = []
        offered_cipher_count: int = 0
        cipher_rarity_score: float = 0.1

        alert_observed: bool = False
        alert_level: Optional[str] = None
        alert_desc: Optional[str] = None
        alert_frame: Optional[int] = None

        raw_cert_hex: Optional[str] = None
        cert_frame: Optional[int] = None

        ja3_raw: Optional[str] = None
        ja3_hash: Optional[str] = None
        ja4: Optional[str] = None
        ocsp_requested: bool = False
        ocsp_stapled: bool = False

        for pkt in stream_packets:
            frame_num = pkt["frame_number"]
            epoch = pkt["time_epoch"]
            hs_type = pkt.get("tls_handshake_type", "")
            hs_version = pkt.get("tls_handshake_version", "")
            rec_version = pkt.get("tls_record_version", "")
            csuite = pkt.get("tls_ciphersuite", "")
            csuites = pkt.get("tls_ciphersuites", "")
            ext_sni = pkt.get("tls_sni", "")
            alt_level = pkt.get("tls_alert_level", "")
            alt_desc = pkt.get("tls_alert_desc", "")
            cert_hex = pkt.get("tls_certificate", "")
            cert_status = pkt.get("tls_certificate_status", "")

            if ext_sni and not sni:
                sni = ext_sni.split(",")[0].strip()

            # ClientHello (type 1)
            if "1" in hs_type.split(","):
                if not client_hello_frame:
                    client_hello_frame = frame_num
                    client_hello_time = epoch
                    # Extract JA3 and JA4 fingerprints
                    fp = extract_client_hello_fingerprints(pkt)
                    ja3_raw = fp["ja3_raw"]
                    ja3_hash = fp["ja3_hash"]
                    ja4 = fp["ja4"]
                    # Check OCSP status_request (extension type 5)
                    ext_types = [e.strip() for e in pkt.get("tls_extensions", "").split(",") if e.strip()]
                    if "5" in ext_types:
                        ocsp_requested = True

                if csuites:
                    raw_list = [c.strip() for c in csuites.split(",") if c.strip()]
                    offered_ciphers = [normalize_cipher_suite(c) or c for c in raw_list]
                    offered_cipher_count = len(offered_ciphers)
                if hs_version and not tls_version:
                    tls_version = normalize_tls_version(hs_version)

            # ServerHello (type 2)
            if "2" in hs_type.split(","):
                if not server_hello_frame:
                    server_hello_frame = frame_num
                    server_hello_time = epoch
                if hs_version:
                    tls_version = normalize_tls_version(hs_version)
                if csuite:
                    cipher_suite = normalize_cipher_suite(csuite.split(",")[0])

            # Check OCSP stapling response
            if cert_status or "22" in hs_type.split(","):
                ocsp_stapled = True

            # Fallback record version if handshake version wasn't populated
            if rec_version and not tls_version:
                tls_version = normalize_tls_version(rec_version.split(",")[0])

            # Alerts
            if alt_level or alt_desc:
                alert_observed = True
                alert_level = alt_level
                alert_desc = alt_desc
                alert_frame = frame_num

            # Certificate message (type 11)
            if cert_hex and not raw_cert_hex:
                raw_cert_hex = cert_hex
                cert_frame = frame_num

        # Calculate handshake duration
        if client_hello_time and server_hello_time:
            handshake_duration_ms = max(0.0, (server_hello_time - client_hello_time) * 1000.0)
        else:
            handshake_duration_ms = 0.0

        # Rarity calculation: check if negotiated or offered ciphers contain legacy or unusual suites
        if cipher_suite:
            if any(w in cipher_suite for w in ("RC4", "3DES", "DES", "NULL", "EXPORT")):
                cipher_rarity_score = 0.95
            elif "CBC" in cipher_suite:
                cipher_rarity_score = 0.60
            elif "CHACHA20" in cipher_suite:
                cipher_rarity_score = 0.35
            else:
                cipher_rarity_score = 0.15

        # OCSP Stapling Status
        if ocsp_stapled:
            ocsp_status = "present"
        elif ocsp_requested:
            ocsp_status = "absent"
        else:
            ocsp_status = "unknown"

        # Handle Certificate analysis
        cert_info = self._analyze_certificate(
            raw_cert_hex=raw_cert_hex,
            tls_version=tls_version,
            sni=sni,
            cert_frame=cert_frame
        )

        return {
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "sni": sni,
            "client_hello_frame": client_hello_frame,
            "server_hello_frame": server_hello_frame,
            "handshake_duration_ms": round(handshake_duration_ms, 2),
            "offered_cipher_count": offered_cipher_count,
            "offered_ciphers": offered_ciphers,
            "cipher_rarity_score": round(cipher_rarity_score, 2),
            "ja3_raw": ja3_raw,
            "ja3_hash": ja3_hash,
            "ja4": ja4,
            "ocsp_stapling": ocsp_status,
            "alert_observed": alert_observed,
            "alert_level": alert_level,
            "alert_desc": alert_desc,
            "alert_frame": alert_frame,
            "cert_visibility": cert_info["cert_visibility"],
            "cert_valid": cert_info["cert_valid"],
            "cert_days_to_expiry": cert_info["cert_days_to_expiry"],
            "cert_self_signed": cert_info["cert_self_signed"],
            "cert_hostname_match": cert_info["cert_hostname_match"],
            "cert_subject": cert_info["cert_subject"],
            "cert_issuer": cert_info["cert_issuer"],
            "cert_sans": cert_info["cert_sans"],
            "cert_not_before": cert_info["cert_not_before"],
            "cert_not_after": cert_info["cert_not_after"],
            "cert_sig_algo": cert_info["cert_sig_algo"],
            "cert_public_key_algo": cert_info.get("cert_public_key_algo"),
            "cert_key_size": cert_info["cert_key_size"],
            "cert_frame": cert_frame,
            "cert_explanation": cert_info["cert_explanation"]
        }

    def _analyze_certificate(
        self,
        raw_cert_hex: Optional[str],
        tls_version: Optional[str],
        sni: Optional[str],
        cert_frame: Optional[int]
    ) -> Dict[str, Any]:
        """
        Analyzes X.509 certificate metadata.
        For TLS 1.3, flags explicitly that certificate is encrypted in passive capture.
        """
        # TLS 1.3 certificate visibility handling (STRICT REQUIREMENT)
        if tls_version == "TLS 1.3":
            return {
                "cert_visibility": "not_extractable_tls1.3",
                "cert_valid": None,
                "cert_days_to_expiry": None,
                "cert_self_signed": None,
                "cert_hostname_match": None,
                "cert_subject": None,
                "cert_issuer": None,
                "cert_sans": [],
                "cert_not_before": None,
                "cert_not_after": None,
                "cert_sig_algo": None,
                "cert_key_size": None,
                "cert_explanation": (
                    "TLS 1.3 encrypts the relevant certificate handshake information in a passive capture, "
                    "so certificate details may not be available without appropriate decryption keys."
                )
            }

        if not raw_cert_hex:
            return {
                "cert_visibility": "not_captured",
                "cert_valid": None,
                "cert_days_to_expiry": None,
                "cert_self_signed": None,
                "cert_hostname_match": None,
                "cert_subject": None,
                "cert_issuer": None,
                "cert_sans": [],
                "cert_not_before": None,
                "cert_not_after": None,
                "cert_sig_algo": None,
                "cert_key_size": None,
                "cert_explanation": "No certificate exchange visible in this stream."
            }

        # Parse DER hex string via cryptography
        try:
            # TShark may emit multiple comma-separated certs or hex chunks
            first_cert_hex = raw_cert_hex.split(",")[0].replace(":", "").strip()
            cert_der = bytes.fromhex(first_cert_hex)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            # Subject & Issuer
            subject_str = cert.subject.rfc4514_string()
            issuer_str = cert.issuer.rfc4514_string()
            self_signed = (subject_str == issuer_str)

            # Validity Dates
            now = datetime.datetime.now(datetime.timezone.utc)
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            days_to_expiry = (not_after - now).days
            is_valid = (not_before <= now <= not_after)

            # SANs
            sans: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            # Hostname match check against SNI
            hostname_match: Optional[bool] = None
            if sni:
                clean_sni = sni.lower().strip()
                matches = False
                for san in sans:
                    san_clean = san.lower().strip()
                    if san_clean.startswith("*."):
                        # Wildcard match
                        domain_suffix = san_clean[2:]
                        if clean_sni.endswith(domain_suffix) and clean_sni.count(".") == domain_suffix.count(".") + 1:
                            matches = True
                            break
                    elif clean_sni == san_clean:
                        matches = True
                        break
                # Also check CN if no SAN matched
                if not matches and f"CN={clean_sni}" in subject_str.lower():
                    matches = True
                hostname_match = matches

            # Public key size & algorithm
            pub_key = cert.public_key()
            key_size = getattr(pub_key, "key_size", None)
            if isinstance(pub_key, rsa.RSAPublicKey):
                pubkey_algo = "RSA"
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pubkey_algo = f"EC ({pub_key.curve.name})"
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                pubkey_algo = "Ed25519"
            else:
                pubkey_algo = pub_key.__class__.__name__

            sig_algo = cert.signature_algorithm_oid._name

            return {
                "cert_visibility": "visible",
                "cert_valid": is_valid,
                "cert_days_to_expiry": days_to_expiry,
                "cert_self_signed": self_signed,
                "cert_hostname_match": hostname_match,
                "cert_subject": subject_str,
                "cert_issuer": issuer_str,
                "cert_sans": sans,
                "cert_not_before": not_before.isoformat(),
                "cert_not_after": not_after.isoformat(),
                "cert_sig_algo": sig_algo,
                "cert_public_key_algo": pubkey_algo,
                "cert_key_size": key_size,
                "cert_explanation": "X.509 Certificate successfully extracted and validated."
            }

        except Exception as e:
            return {
                "cert_visibility": "parse_error",
                "cert_valid": False,
                "cert_days_to_expiry": None,
                "cert_self_signed": None,
                "cert_hostname_match": None,
                "cert_subject": None,
                "cert_issuer": None,
                "cert_sans": [],
                "cert_not_before": None,
                "cert_not_after": None,
                "cert_sig_algo": None,
                "cert_public_key_algo": None,
                "cert_key_size": None,
                "cert_explanation": f"Certificate parsing error: {e}"
            }
