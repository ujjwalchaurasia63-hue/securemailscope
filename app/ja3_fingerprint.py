"""
JA3 and JA4 TLS ClientHello Fingerprinting Module.
Implements standard Salesforce JA3 and Cloudflare/Fox-IT JA4 algorithms
derived from actual passive ClientHello packets.
"""

import hashlib
from typing import List, Dict, Any, Optional, Tuple

# RFC 8701 GREASE values to exclude from fingerprints
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def _parse_int_list(raw_val: str) -> List[int]:
    """Parses comma or dash separated list of integer or hex strings into integers."""
    if not raw_val:
        return []
    items: List[int] = []
    for token in raw_val.replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if token.startswith("0x") or token.startswith("0X"):
                val = int(token, 16)
            else:
                val = int(token)
            if val not in GREASE_VALUES:
                items.append(val)
        except ValueError:
            continue
    return items


def compute_ja3(
    tls_version_code: int,
    ciphers: List[int],
    extensions: List[int],
    curves: List[int],
    point_formats: List[int]
) -> Tuple[str, str]:
    """
    Computes JA3 raw string and MD5 hash according to the JA3 standard:
    SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    """
    ciphers_str = "-".join(str(c) for c in ciphers)
    exts_str = "-".join(str(e) for e in extensions)
    curves_str = "-".join(str(c) for c in curves)
    formats_str = "-".join(str(f) for f in point_formats)

    ja3_raw = f"{tls_version_code},{ciphers_str},{exts_str},{curves_str},{formats_str}"
    ja3_hash = hashlib.md5(ja3_raw.encode("utf-8")).hexdigest()
    return ja3_raw, ja3_hash


def compute_ja4(
    tls_version_str: str,
    has_sni: bool,
    ciphers: List[int],
    extensions: List[int],
    alpn: str = ""
) -> str:
    """
    Computes modern JA4 fingerprint string:
    Format: [protocol][version][sni][cipher_count][ext_count][alpn]_[cipher_hash]_[ext_hash]
    Example: t13d030200_a309e36eb10f_e3b0c44298fc
    """
    proto = "t"  # TCP

    # Version mapping
    ver_clean = (tls_version_str or "").upper().replace(" ", "")
    if "1.3" in ver_clean or "0X0304" in ver_clean or "772" in ver_clean:
        ver = "13"
    elif "1.2" in ver_clean or "0X0303" in ver_clean or "771" in ver_clean:
        ver = "12"
    elif "1.1" in ver_clean or "0X0302" in ver_clean or "770" in ver_clean:
        ver = "11"
    elif "1.0" in ver_clean or "0X0301" in ver_clean or "769" in ver_clean:
        ver = "10"
    elif "3.0" in ver_clean or "SSL" in ver_clean or "768" in ver_clean:
        ver = "s3"
    else:
        ver = "00"

    sni_code = "d" if has_sni else "0"
    cipher_cnt = f"{min(len(ciphers), 99):02d}"
    ext_cnt = f"{min(len(extensions), 99):02d}"
    alpn_code = "00"
    if alpn:
        clean_alpn = alpn.strip()
        if len(clean_alpn) >= 2:
            alpn_code = f"{clean_alpn[0]}{clean_alpn[-1]}"
        elif len(clean_alpn) == 1:
            alpn_code = f"{clean_alpn[0]}0"

    # Truncated 12-char SHA-256 of sorted hex ciphers
    sorted_ciphers = [f"{c:04x}" for c in sorted(ciphers)]
    ciphers_blob = ",".join(sorted_ciphers).encode("utf-8")
    cipher_hash = hashlib.sha256(ciphers_blob).hexdigest()[:12] if sorted_ciphers else "000000000000"

    # Truncated 12-char SHA-256 of sorted hex extensions
    sorted_exts = [f"{e:04x}" for e in sorted(extensions)]
    exts_blob = ",".join(sorted_exts).encode("utf-8")
    ext_hash = hashlib.sha256(exts_blob).hexdigest()[:12] if sorted_exts else "000000000000"

    return f"{proto}{ver}{sni_code}{cipher_cnt}{ext_cnt}{alpn_code}_{cipher_hash}_{ext_hash}"


def extract_client_hello_fingerprints(
    client_hello_pkt: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Extracts JA3 and JA4 fingerprints from an individual ClientHello packet dictionary.
    """
    raw_ver = client_hello_pkt.get("tls_handshake_version") or client_hello_pkt.get("tls_record_version") or "0x0303"
    try:
        if raw_ver.startswith("0x") or raw_ver.startswith("0X"):
            version_int = int(raw_ver, 16)
        else:
            version_int = int(raw_ver)
    except ValueError:
        version_int = 771  # TLS 1.2 default

    ciphers = _parse_int_list(client_hello_pkt.get("tls_ciphersuite", ""))
    if not ciphers:
        ciphers = _parse_int_list(client_hello_pkt.get("tls_ciphersuites", ""))

    extensions = _parse_int_list(client_hello_pkt.get("tls_extensions", ""))
    curves = _parse_int_list(client_hello_pkt.get("tls_supported_groups", ""))
    point_formats = _parse_int_list(client_hello_pkt.get("tls_ec_point_formats", ""))

    has_sni = bool(client_hello_pkt.get("tls_sni"))

    ja3_raw, ja3_hash = compute_ja3(version_int, ciphers, extensions, curves, point_formats)
    ja4_str = compute_ja4(raw_ver, has_sni, ciphers, extensions)

    return {
        "ja3_raw": ja3_raw,
        "ja3_hash": ja3_hash,
        "ja4": ja4_str,
        "offered_ciphers_int": ciphers,
        "extensions_int": extensions
    }
