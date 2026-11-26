"""Pure-Python X.509/JKS certificate parser, policy inspector, and active/passive crypto risk evaluator."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

# Signature algorithm OIDs -> (hash_name, display_name)
SIG_OID_MAP: dict[str, tuple[str, str]] = {
    "1.2.840.113549.1.1.2": ("md2", "md2WithRSAEncryption"),
    "1.2.840.113549.1.1.3": ("md4", "md4WithRSAEncryption"),
    "1.2.840.113549.1.1.4": ("md5", "md5WithRSAEncryption"),
    "1.2.840.113549.1.1.5": ("sha1", "sha1WithRSAEncryption"),
    "1.2.840.113549.1.1.11": ("sha256", "sha256WithRSAEncryption"),
    "1.2.840.113549.1.1.12": ("sha384", "sha384WithRSAEncryption"),
    "1.2.840.113549.1.1.13": ("sha512", "sha512WithRSAEncryption"),
    "1.2.840.113549.1.1.14": ("sha224", "sha224WithRSAEncryption"),
    "1.2.840.113549.1.1.10": ("pss", "rsassaPss"),
    "1.2.840.10045.4.1": ("sha1", "ecdsa-with-SHA1"),
    "1.2.840.10045.4.3.1": ("sha224", "ecdsa-with-SHA224"),
    "1.2.840.10045.4.3.2": ("sha256", "ecdsa-with-SHA256"),
    "1.2.840.10045.4.3.3": ("sha384", "ecdsa-with-SHA384"),
    "1.2.840.10045.4.3.4": ("sha512", "ecdsa-with-SHA512"),
    "1.2.840.10040.4.3": ("sha1", "dsa-with-SHA1"),
    "2.16.840.1.101.3.4.3.2": ("sha256", "dsa-with-SHA256"),
    "1.3.14.3.2.29": ("sha1", "sha1WithRSA"),
    "1.3.101.112": ("ed25519", "Ed25519"),
    "1.3.101.113": ("ed448", "Ed448"),
    "2.16.840.1.101.3.4.3.17": ("ml-dsa-44", "ML-DSA-44"),
    "2.16.840.1.101.3.4.3.18": ("ml-dsa-65", "ML-DSA-65"),
    "2.16.840.1.101.3.4.3.19": ("ml-dsa-87", "ML-DSA-87"),
}

EC_CURVE_OID_MAP: dict[str, tuple[str, int]] = {
    "1.2.840.10045.3.1.7": ("secp256r1", 256),
    "1.3.132.0.34": ("secp384r1", 384),
    "1.3.132.0.35": ("secp521r1", 521),
    "1.3.132.0.10": ("secp256k1", 256),
    "1.3.132.0.33": ("secp224r1", 224),
    "1.2.840.10045.3.1.1": ("secp192r1", 192),
}

RDN_OID_LABELS: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}

HASH_OID_MAP: dict[str, str] = {
    "1.2.840.113549.2.5": "md5",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
}

PQC_PRIMITIVE_NAMES = frozenset(
    {
        "X25519MLKEM768",
        "ML-KEM-1024",
        "ML-KEM-768",
        "ML-KEM-512",
        "ML-DSA-87",
        "ML-DSA-65",
        "ML-DSA-44",
        "SLH-DSA",
    }
)

LEGACY_PRIMITIVE_NAMES = frozenset({"MD5", "SHA-1", "Legacy-Weak-Cipher"})

QUANTUM_VULNERABLE_NAMES = frozenset(
    {"RSA", "ECDSA", "ECDH-X25519", "Ed25519", "Diffie-Hellman"}
)

RISK_LEVEL_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Known PQC-capable libraries/packages across ecosystems
PQC_CAPABLE_APK_PREFIXES: dict[str, str] = {
    "openssl-4": "OpenSSL 4.x (ML-KEM / ML-DSA / SLH-DSA)",
    "openssl-3.5": "OpenSSL 3.5+ (ML-KEM / ML-DSA / SLH-DSA)",
    "openssl-3.6": "OpenSSL 3.6+ (ML-KEM / ML-DSA / SLH-DSA)",
    "openjdk-24": "OpenJDK 24+ (JEP 496 ML-KEM / JEP 497 ML-DSA)",
    "openjdk-25": "OpenJDK 25+ (ML-KEM / ML-DSA)",
    "openjdk-26": "OpenJDK 26+ (ML-KEM / ML-DSA)",
    "openjdk-27": "OpenJDK 27+ (ML-KEM / ML-DSA)",
    "liboqs": "liboqs post-quantum library",
    "oqs-provider": "OpenSSL OQS PQC provider",
}

PQC_CAPABLE_PKG_NAMES = frozenset(
    {
        "dilithium-py",
        "kyber-py",
        "liboqs-python",
        "pqcrypto",
        "bouncycastle",
        "bcprov-jdk18on",
        "bcprov-lts8on",
    }
)


def _read_tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    """Read a single ASN.1 DER TLV item starting at pos."""
    if pos >= len(buf):
        raise ValueError("Unexpected end of DER input")
    tag = buf[pos]
    pos += 1
    if pos >= len(buf):
        raise ValueError("Truncated DER length")
    first_len = buf[pos]
    pos += 1
    if first_len < 0x80:
        length = first_len
    else:
        num_octets = first_len & 0x7F
        if num_octets == 0 or pos + num_octets > len(buf):
            raise ValueError("Unsupported or truncated DER length")
        length = int.from_bytes(buf[pos : pos + num_octets], "big")
        pos += num_octets
    end = pos + length
    if end > len(buf):
        raise ValueError("Truncated DER value")
    return tag, buf[pos:end], end


def _iter_tlvs(buf: bytes) -> list[tuple[int, bytes]]:
    """Parse all consecutive DER TLV items within buf."""
    items: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(buf):
        tag, val, pos = _read_tlv(buf, pos)
        items.append((tag, val))
    return items


def _decode_oid(raw: bytes) -> str:
    """Decode DER OID bytes to dotted string."""
    if not raw:
        return ""
    arcs = [raw[0] // 40, raw[0] % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(val)
            val = 0
    return ".".join(str(a) for a in arcs)


def _decode_asn1_time(tag: int, raw: bytes) -> datetime.datetime:
    """Decode ASN.1 UTCTime (0x17) or GeneralizedTime (0x18) into UTC datetime."""
    text = raw.decode("ascii", errors="strict").rstrip("Z")
    # Strip optional fractional seconds or timezone offset if present
    text = re.split(r"[.\-+]", text, maxsplit=1)[0]
    if tag == 0x17:  # UTCTime: YYMMDDHHMM[SS]
        yy = int(text[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        rest = text[2:]
    elif tag == 0x18:  # GeneralizedTime: YYYYMMDDHHMM[SS]
        year = int(text[0:4])
        rest = text[4:]
    else:
        raise ValueError(f"Unexpected ASN.1 time tag: {hex(tag)}")
    month = int(rest[0:2])
    day = int(rest[2:4])
    hour = int(rest[4:6]) if len(rest) >= 6 else 0
    minute = int(rest[6:8]) if len(rest) >= 8 else 0
    second = int(rest[8:10]) if len(rest) >= 10 else 0
    return datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)


def _decode_dn(seq_bytes: bytes) -> str:
    """Decode an X.509 Name SEQUENCE into a compact RDN string."""
    parts: list[str] = []
    for tag, rdn_set in _iter_tlvs(seq_bytes):
        if tag != 0x31:
            continue
        for atag, attr_seq in _iter_tlvs(rdn_set):
            if atag != 0x30:
                continue
            kv = _iter_tlvs(attr_seq)
            if len(kv) < 2 or kv[0][0] != 0x06:
                continue
            oid = _decode_oid(kv[0][1])
            label = RDN_OID_LABELS.get(oid, oid)
            val = kv[1][1].decode("utf-8", errors="replace")
            parts.append(f"{label}={val}")
    return ", ".join(parts)


def _decode_sig_algorithm(alg_seq_bytes: bytes) -> tuple[str, str]:
    """Decode AlgorithmIdentifier into (hash_name, algorithm_name)."""
    items = _iter_tlvs(alg_seq_bytes)
    if not items or items[0][0] != 0x06:
        return "unknown", "unknown"
    oid = _decode_oid(items[0][1])
    if oid == "1.2.840.113549.1.1.10" and len(items) > 1 and items[1][0] == 0x30:
        # RSASSA-PSS parameters: [0] hashAlgorithm
        for ptag, pval in _iter_tlvs(items[1][1]):
            if ptag == 0xA0:
                htag, hseq, _ = _read_tlv(pval, 0)
                if htag == 0x30:
                    hitems = _iter_tlvs(hseq)
                    if hitems and hitems[0][0] == 0x06:
                        hname = HASH_OID_MAP.get(_decode_oid(hitems[0][1]), "sha256")
                        return hname, f"rsassaPss-{hname}"
        return "sha256", "rsassaPss"
    return SIG_OID_MAP.get(oid, (oid, oid))


def _decode_spki(spki_bytes: bytes) -> tuple[str, int]:
    """Decode SubjectPublicKeyInfo into (key_type_label, key_bits)."""
    items = _iter_tlvs(spki_bytes)
    if len(items) < 2 or items[0][0] != 0x30 or items[1][0] != 0x03:
        return "UNKNOWN", 0
    alg_items = _iter_tlvs(items[0][1])
    if not alg_items or alg_items[0][0] != 0x06:
        return "UNKNOWN", 0
    alg_oid = _decode_oid(alg_items[0][1])
    bit_payload = items[1][1][1:] if items[1][1] else b""

    if alg_oid in ("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10"):
        rtag, rseq, _ = _read_tlv(bit_payload, 0)
        if rtag == 0x30:
            ritems = _iter_tlvs(rseq)
            if ritems and ritems[0][0] == 0x02:
                mod_int = int.from_bytes(ritems[0][1], "big", signed=False)
                bits = mod_int.bit_length()
                return f"RSA-{bits}", bits
        return "RSA", 0

    if alg_oid == "1.2.840.10045.2.1":
        if len(alg_items) > 1 and alg_items[1][0] == 0x06:
            curve_oid = _decode_oid(alg_items[1][1])
            cname, cbits = EC_CURVE_OID_MAP.get(curve_oid, (curve_oid, 0))
            return f"EC-{cname}", cbits
        return "EC", 0

    if alg_oid == "1.2.840.10040.4.1":
        if len(alg_items) > 1 and alg_items[1][0] == 0x30:
            pitems = _iter_tlvs(alg_items[1][1])
            if pitems and pitems[0][0] == 0x02:
                p_int = int.from_bytes(pitems[0][1], "big", signed=False)
                bits = p_int.bit_length()
                return f"DSA-{bits}", bits
        return "DSA", 0

    if alg_oid == "1.3.101.112":
        return "Ed25519", 256
    if alg_oid == "1.3.101.113":
        return "Ed448", 448
    if alg_oid == "2.16.840.1.101.3.4.3.17":
        return "ML-DSA-44", 44
    if alg_oid == "2.16.840.1.101.3.4.3.18":
        return "ML-DSA-65", 65
    if alg_oid == "2.16.840.1.101.3.4.3.19":
        return "ML-DSA-87", 87

    return alg_oid, 0


def parse_x509_der(der_bytes: bytes, alias: str = "") -> dict[str, Any]:
    """Parse a single DER-encoded X.509 certificate into structured metadata."""
    top_tag, top_val, _ = _read_tlv(der_bytes, 0)
    if top_tag != 0x30:
        raise ValueError("Invalid X.509 DER certificate (expected SEQUENCE)")
    cert_parts = _iter_tlvs(top_val)
    if len(cert_parts) < 3 or cert_parts[0][0] != 0x30:
        raise ValueError("Invalid X.509 Certificate structure")

    tbs_items = _iter_tlvs(cert_parts[0][1])
    idx = 0
    if tbs_items and tbs_items[0][0] == 0xA0:
        idx += 1  # optional explicit [0] version
    if len(tbs_items) < idx + 6:
        raise ValueError("Truncated TBSCertificate")

    serial_tag, serial_raw = tbs_items[idx]
    if serial_tag != 0x02:
        raise ValueError("Expected serialNumber INTEGER")
    serial_number = int.from_bytes(serial_raw, "big", signed=True)

    sig_hash, sig_alg = _decode_sig_algorithm(tbs_items[idx + 1][1])
    issuer_raw = tbs_items[idx + 2][1]
    issuer = _decode_dn(issuer_raw)

    val_items = _iter_tlvs(tbs_items[idx + 3][1])
    if len(val_items) < 2:
        raise ValueError("Invalid X.509 Validity")
    not_before = _decode_asn1_time(val_items[0][0], val_items[0][1])
    not_after = _decode_asn1_time(val_items[1][0], val_items[1][1])

    subject_raw = tbs_items[idx + 4][1]
    subject = _decode_dn(subject_raw)
    key_type, key_bits = _decode_spki(tbs_items[idx + 5][1])

    is_ca: bool | None = None
    for tag, val in tbs_items[idx + 6 :]:
        if tag == 0xA3:
            ext_seq_tag, ext_seq_val, _ = _read_tlv(val, 0)
            if ext_seq_tag != 0x30:
                continue
            for etag, eval_bytes in _iter_tlvs(ext_seq_val):
                if etag != 0x30:
                    continue
                eitems = _iter_tlvs(eval_bytes)
                if not eitems or eitems[0][0] != 0x06:
                    continue
                ext_oid = _decode_oid(eitems[0][1])
                if ext_oid == "2.5.29.19":  # BasicConstraints
                    oct_val = eitems[-1][1] if eitems[-1][0] == 0x04 else b""
                    if oct_val:
                        btag, bseq, _ = _read_tlv(oct_val, 0)
                        if btag == 0x30:
                            bitems = _iter_tlvs(bseq)
                            if bitems and bitems[0][0] == 0x01:
                                is_ca = bitems[0][1] != b"\x00"
                            else:
                                is_ca = False

    return {
        "alias": alias,
        "fp": hashlib.sha256(der_bytes).hexdigest(),
        "subject": subject or "unknown",
        "issuer": issuer or "unknown",
        "self_signed": subject_raw == issuer_raw,
        "serial_number": serial_number,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "not_before_dt": not_before,
        "not_after_dt": not_after,
        "sig_hash": sig_hash,
        "sig_alg": sig_alg,
        "key_type": key_type,
        "key_bits": key_bits,
        "is_ca": is_ca,
    }


def parse_pem_certificates(data: bytes, source_name: str = "") -> list[dict[str, Any]]:
    """Extract and parse all PEM certificates in a buffer."""
    certs: list[dict[str, Any]] = []
    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        data,
        flags=re.DOTALL,
    )
    for idx, b64_body in enumerate(blocks):
        try:
            der = base64.b64decode(b"".join(b64_body.split()), validate=False)
            certs.append(parse_x509_der(der, alias=f"{source_name}#{idx}" if source_name else f"pem#{idx}"))
        except Exception:
            continue
    return certs


def parse_jks_certificates(data: bytes) -> list[dict[str, Any]]:
    """Parse trusted certificates from a Java KeyStore (JKS magic 0xFEEDFEED)."""
    if len(data) < 12:
        return []
    magic, version, count = struct.unpack_from(">III", data, 0)
    if magic != 0xFEEDFEED or version not in (1, 2):
        return []
    pos = 12
    certs: list[dict[str, Any]] = []
    for _ in range(count):
        if pos + 6 > len(data):
            break
        (tag,) = struct.unpack_from(">I", data, pos)
        pos += 4
        (alias_len,) = struct.unpack_from(">H", data, pos)
        pos += 2
        alias = data[pos : pos + alias_len].decode("utf-8", errors="replace")
        pos += alias_len + 8  # skip modified-UTF8 alias + 8-byte timestamp
        if tag == 1:  # PrivateKeyEntry
            (key_len,) = struct.unpack_from(">I", data, pos)
            pos += 4 + key_len
            (chain_len,) = struct.unpack_from(">I", data, pos)
            pos += 4
            for _ in range(chain_len):
                (ct_len,) = struct.unpack_from(">H", data, pos)
                pos += 2 + ct_len
                (cert_len,) = struct.unpack_from(">I", data, pos)
                pos += 4
                der = data[pos : pos + cert_len]
                pos += cert_len
                try:
                    certs.append(parse_x509_der(der, alias=alias))
                except Exception:
                    continue
        elif tag == 2:  # TrustedCertEntry
            if version == 2:
                (ct_len,) = struct.unpack_from(">H", data, pos)
                pos += 2 + ct_len
            (cert_len,) = struct.unpack_from(">I", data, pos)
            pos += 4
            der = data[pos : pos + cert_len]
            pos += cert_len
            try:
                certs.append(parse_x509_der(der, alias=alias))
            except Exception:
                continue
        else:
            break
    return certs


def parse_cert_store_bytes(data: bytes, location: str) -> tuple[str, list[dict[str, Any]]]:
    """Parse PEM, JKS, or DER certificate store bytes into (format_name, unique_certs)."""
    raw_certs: list[dict[str, Any]] = []
    fmt = "UNKNOWN"
    if b"-----BEGIN CERTIFICATE-----" in data:
        fmt = "PEM"
        raw_certs = parse_pem_certificates(data, source_name=Path(location).name)
    elif len(data) >= 12 and struct.unpack_from(">I", data, 0)[0] == 0xFEEDFEED:
        fmt = "JKS"
        raw_certs = parse_jks_certificates(data)
    elif location.lower().endswith((".der", ".cer", ".crt")):
        try:
            raw_certs = [parse_x509_der(data, alias=Path(location).name)]
            fmt = "DER"
        except Exception:
            raw_certs = []

    dedup: dict[str, dict[str, Any]] = {}
    for cert in raw_certs:
        cert["location"] = location
        dedup.setdefault(cert["fp"], cert)
    return fmt, list(dedup.values())


def evaluate_certificates(
    certs_by_fp: dict[str, dict[str, Any]],
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Evaluate deduplicated certificates for active and passive security risks."""
    ref_now = now or datetime.datetime.now(datetime.timezone.utc)
    day_90 = ref_now + datetime.timedelta(days=90)
    year_1 = ref_now + datetime.timedelta(days=365)

    expired: list[dict[str, Any]] = []
    not_yet_valid: list[dict[str, Any]] = []
    expiring_90d: list[dict[str, Any]] = []
    expiring_1y: list[dict[str, Any]] = []
    sha1_roots: list[dict[str, Any]] = []
    weak_sig_non_roots: list[dict[str, Any]] = []
    weak_keys: list[dict[str, Any]] = []
    non_ca_in_truststore: list[dict[str, Any]] = []
    non_positive_serials: list[dict[str, Any]] = []
    key_type_counts: dict[str, int] = {}
    sig_hash_counts: dict[str, int] = {}
    pqc_root_count = 0

    for cert in certs_by_fp.values():
        ktype = cert["key_type"]
        shash = cert["sig_hash"]
        key_type_counts[ktype] = key_type_counts.get(ktype, 0) + 1
        sig_hash_counts[shash] = sig_hash_counts.get(shash, 0) + 1

        if ktype.startswith("ML-DSA"):
            pqc_root_count += 1

        nvb = cert["not_before_dt"]
        nva = cert["not_after_dt"]
        compact = {
            "subject": cert["subject"],
            "issuer": cert["issuer"],
            "serial": str(cert["serial_number"]),
            "not_before": cert["not_before"],
            "not_after": cert["not_after"],
            "sig_hash": shash,
            "key_type": ktype,
            "is_ca": cert["is_ca"],
            "self_signed": cert["self_signed"],
            "location": cert.get("location", ""),
            "fp": cert["fp"][:16],
        }

        if nva < ref_now:
            expired.append(compact)
        elif nva <= day_90:
            expiring_90d.append(compact)
        elif nva <= year_1:
            expiring_1y.append(compact)

        if nvb > ref_now:
            not_yet_valid.append(compact)

        if shash in ("md2", "md4", "md5", "sha1"):
            if cert["self_signed"] and cert["is_ca"] is not False:
                sha1_roots.append(compact)
            else:
                weak_sig_non_roots.append(compact)

        if (ktype.startswith("RSA-") and cert["key_bits"] < 2048) or ktype.startswith("DSA"):
            weak_keys.append(compact)

        if cert["is_ca"] is False and any(
            tok in cert.get("location", "").lower()
            for tok in ("ca-certificates", "cacerts", "/etc/ssl/certs", "mozilla")
        ):
            non_ca_in_truststore.append(compact)

        if cert["serial_number"] <= 0:
            non_positive_serials.append(compact)

    return {
        "total_unique": len(certs_by_fp),
        "expired_count": len(expired),
        "not_yet_valid_count": len(not_yet_valid),
        "expiring_90d_count": len(expiring_90d),
        "expiring_1y_count": len(expiring_1y),
        "sha1_root_count": len(sha1_roots),
        "weak_sig_non_root_count": len(weak_sig_non_roots),
        "weak_key_count": len(weak_keys),
        "non_ca_truststore_count": len(non_ca_in_truststore),
        "non_positive_serial_count": len(non_positive_serials),
        "pqc_root_count": pqc_root_count,
        "key_type_counts": key_type_counts,
        "sig_hash_counts": sig_hash_counts,
        "expired": expired[:15],
        "not_yet_valid": not_yet_valid[:15],
        "expiring_90d": expiring_90d[:15],
        "sha1_roots": sha1_roots[:15],
        "weak_sig_non_roots": weak_sig_non_roots[:15],
        "weak_keys": weak_keys[:15],
        "non_ca_in_truststore": non_ca_in_truststore[:15],
        "non_positive_serials": non_positive_serials[:15],
    }


def inspect_openssl_cnf(text: str, location: str) -> dict[str, Any]:
    """Audit OpenSSL configuration for active legacy providers, TLS bounds, and PQC settings."""
    env_vars: dict[str, str] = {}
    sections: dict[str, dict[str, str]] = {}
    cur_sec = ""
    pending_key: str | None = None
    pending_buf: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if pending_key is not None:
            pending_buf.append(line.rstrip("\\").strip())
            if not line.endswith("\\"):
                sections.setdefault(cur_sec, {})[pending_key] = " ".join(pending_buf)
                pending_key = None
                pending_buf = []
            continue
        m_sec = re.match(r"^\[([^\]]+)\]$", line)
        if m_sec:
            cur_sec = m_sec.group(1).strip().lower()
            sections.setdefault(cur_sec, {})
            continue
        if "=" in line:
            k, v = [p.strip() for p in line.split("=", 1)]
            if v.endswith("\\"):
                pending_key = k.lower()
                pending_buf = [v.rstrip("\\").strip()]
                continue
            kl = k.lower()
            if cur_sec in ("", "default"):
                env_vars[k] = v
            sections.setdefault(cur_sec, {})[kl] = v

    def _resolve(val: str) -> str:
        m = re.match(r"^\$ENV::([A-Za-z0-9_]+)$", val.strip())
        if m:
            return env_vars.get(m.group(1), val)
        return val

    legacy_sec = sections.get("legacy_sect", {})
    providers_sec = sections.get("provider_sect", {})
    legacy_active = False
    if "legacy" in providers_sec:
        act = _resolve(legacy_sec.get("activate", "0")).strip().lower()
        legacy_active = act in ("1", "true", "yes", "on")

    des_enabled = _resolve(legacy_sec.get("enable-des", "0")).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    policy_sec = sections.get("crypto_policy", {}) or sections.get("system_default_sect", {})
    min_proto = policy_sec.get("tls.minprotocol", policy_sec.get("minprotocol", ""))
    cipher_str = policy_sec.get("cipherstring", "")
    groups = policy_sec.get("groups", "")
    sig_algs = policy_sec.get("signaturealgorithms", "")

    pqc_configured: list[str] = []
    combined_pqc = f"{groups} {sig_algs}"
    for token in ("X25519MLKEM768", "SecP256r1MLKEM768", "MLKEM1024", "MLKEM768", "mldsa65", "mldsa87", "mldsa44"):
        if re.search(rf"\b{re.escape(token)}\b", combined_pqc, re.IGNORECASE):
            pqc_configured.append(token)

    weak_tls = False
    if min_proto and min_proto.strip().lower() in ("sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"):
        weak_tls = True
    if "@seclevel=0" in cipher_str.lower() or "@seclevel=1" in cipher_str.lower():
        weak_tls = True

    return {
        "location": location,
        "legacy_provider_active": legacy_active,
        "legacy_des_enabled": des_enabled,
        "min_protocol": min_proto,
        "weak_tls_policy": weak_tls,
        "pqc_configured": pqc_configured,
    }


def inspect_java_security(text: str, location: str) -> dict[str, Any]:
    """Parse OpenJDK java.security to determine which legacy algorithms are disabled by policy."""
    props: dict[str, str] = {}
    cur_k: str | None = None
    buf: list[str] = []
    for raw_line in text.splitlines():
        s = raw_line.strip()
        if not s or s.startswith("#"):
            continue
        if cur_k is not None:
            buf.append(s.rstrip("\\").strip())
            if not s.endswith("\\"):
                props[cur_k] = " ".join(buf)
                cur_k = None
                buf = []
        elif "=" in s:
            k, v = s.split("=", 1)
            k = k.strip()
            v = v.strip()
            if v.endswith("\\"):
                cur_k = k
                buf = [v.rstrip("\\").strip()]
            else:
                props[k] = v

    tls_disabled = props.get("jdk.tls.disabledAlgorithms", "")
    cert_disabled = props.get("jdk.certpath.disabledAlgorithms", "")
    jar_disabled = props.get("jdk.jar.disabledAlgorithms", "")
    disabled_combined = f"{tls_disabled} {cert_disabled} {jar_disabled}".upper()

    policy_blocks: list[str] = []
    for tok in ("SSLV3", "TLSV1", "TLSV1.1", "RC4", "DES", "3DES", "MD5", "SHA1"):
        if tok in disabled_combined:
            policy_blocks.append(tok)

    allows_small_rsa = "RSA KEYSIZE < 1024" in cert_disabled.upper() and "RSA KEYSIZE < 2048" not in cert_disabled.upper()
    weak_tls_allowed = bool(tls_disabled) and ("TLSV1" not in tls_disabled.upper() or "SSLV3" not in tls_disabled.upper())

    return {
        "location": location,
        "policy_disabled_algorithms": policy_blocks,
        "allows_rsa_under_2048_in_certpath": allows_small_rsa,
        "weak_tls_allowed": weak_tls_allowed,
    }


def parse_apk_installed_packages(text: str) -> list[dict[str, str]]:
    """Parse Wolfi/Alpine /lib/apk/db/installed records."""
    pkgs: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if cur.get("P"):
                pkgs.append(
                    {
                        "name": cur["P"],
                        "version": cur.get("V", "unknown"),
                        "description": cur.get("T", ""),
                    }
                )
            cur = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            if k in ("P", "V", "T"):
                cur[k] = v.strip()
    if cur.get("P"):
        pkgs.append(
            {
                "name": cur["P"],
                "version": cur.get("V", "unknown"),
                "description": cur.get("T", ""),
            }
        )
    return pkgs


def parse_dpkg_status(text: str) -> list[dict[str, str]]:
    """Parse Debian/Ubuntu /var/lib/dpkg/status stanza format for installed packages."""
    pkgs: list[dict[str, str]] = []
    cur: dict[str, str] = {}

    def _flush() -> None:
        if not cur.get("Package"):
            return
        status = cur.get("Status", "install ok installed").lower()
        # status.d fragments may omit Status; main status marks removed pkgs as deinstall/config-files
        if "Status" in cur and "installed" not in status.split():
            return
        pkgs.append(
            {
                "name": cur["Package"],
                "version": cur.get("Version", "unknown"),
            }
        )

    for raw_line in text.splitlines():
        if not raw_line.strip():
            _flush()
            cur = {}
            continue
        if raw_line[0].isspace():
            continue
        if ":" in raw_line:
            k, v = raw_line.split(":", 1)
            if k in ("Package", "Version", "Status"):
                cur[k] = v.strip()
    _flush()
    return pkgs


def _max_risk_level(risks: list[dict[str, Any]]) -> str:
    best = "NONE"
    for item in risks:
        sev = str(item.get("severity", "NONE")).upper()
        if RISK_LEVEL_ORDER.get(sev, 0) > RISK_LEVEL_ORDER.get(best, 0):
            best = sev
    return best


def build_risk_assessment(
    *,
    primitives_by_origin: dict[str, set[str]],
    cert_summary: dict[str, Any],
    openssl_findings: list[dict[str, Any]],
    java_findings: list[dict[str, Any]],
    apk_packages: list[dict[str, str]],
    declared_deps: list[dict[str, str]],
    scan_scope: str,
    manifest_only_uninspected: bool = False,
) -> dict[str, Any]:
    """Classify Active vs. Passive cryptographic risks and PQC Compiled vs. Coding gaps."""
    if manifest_only_uninspected:
        return {
            "scan_scope": scan_scope,
            "crypto_risk_level": "UNKNOWN",
            "active_risk_count": 0,
            "passive_risk_count": 0,
            "active_risks": [],
            "passive_risks": [
                {
                    "id": "MANIFEST_ONLY_UNINSPECTED",
                    "category": "visibility",
                    "severity": "MEDIUM",
                    "title": "OCI manifest inspected without filesystem layers",
                    "detail": "Only the OCI manifest/index JSON was scanned; container layer binaries, configs, and truststores were not inspected.",
                    "location": "oci-manifest",
                    "remediation": "Enable OCI_BOM_DEEP_SCAN_ENABLED=true or re-pull the image through Gatekeeper so layer blobs are inspected.",
                }
            ],
            "pqc_compiled_ready": False,
            "pqc_code_used": False,
            "pqc_adoption_status": "UNINSPECTED_MANIFEST_ONLY",
            "compiled_risk": "UNKNOWN",
            "coding_risk": "UNKNOWN",
            "pqc_ready_unused_libraries": [],
            "cert_summary": cert_summary,
        }

    active_risks: list[dict[str, Any]] = []
    passive_risks: list[dict[str, Any]] = []

    app_prims = primitives_by_origin.get("application-code", set())
    runtime_prims = primitives_by_origin.get("compiled-runtime", set())
    cfg_prims = primitives_by_origin.get("configuration", set())
    all_prims = app_prims | runtime_prims | cfg_prims

    # 1. Certificate Hygiene (Active vs. Passive)
    if cert_summary.get("expired_count", 0) > 0:
        sample = cert_summary["expired"][0]
        active_risks.append(
            {
                "id": "EXPIRED_CERTIFICATE",
                "category": "certificate",
                "severity": "CRITICAL",
                "title": f"{cert_summary['expired_count']} expired X.509 certificate(s) present",
                "detail": f"Sample expired cert '{sample['subject']}' expired {sample['not_after']} in {sample['location']}.",
                "location": sample["location"],
                "remediation": "Remove expired certificates or update the CA trust bundle / keystore immediately.",
            }
        )

    if cert_summary.get("not_yet_valid_count", 0) > 0:
        sample = cert_summary["not_yet_valid"][0]
        active_risks.append(
            {
                "id": "NOT_YET_VALID_CERTIFICATE",
                "category": "certificate",
                "severity": "HIGH",
                "title": f"{cert_summary['not_yet_valid_count']} certificate(s) not yet valid",
                "detail": f"Sample '{sample['subject']}' is not valid until {sample['not_before']}.",
                "location": sample["location"],
                "remediation": "Verify truststore clock alignment or remove premature certificates.",
            }
        )

    if cert_summary.get("non_ca_truststore_count", 0) > 0:
        sample = cert_summary["non_ca_in_truststore"][0]
        active_risks.append(
            {
                "id": "UNTRUSTED_NON_CA_IN_TRUSTSTORE",
                "category": "certificate",
                "severity": "HIGH",
                "title": f"{cert_summary['non_ca_truststore_count']} non-CA leaf/end-entity certificate(s) in truststore",
                "detail": f"Sample '{sample['subject']}' has BasicConstraints CA:FALSE inside {sample['location']}.",
                "location": sample["location"],
                "remediation": "Remove end-entity leaf certificates from system or Java CA truststores.",
            }
        )

    if cert_summary.get("weak_key_count", 0) > 0:
        sample = cert_summary["weak_keys"][0]
        active_risks.append(
            {
                "id": "WEAK_CERTIFICATE_PUBLIC_KEY",
                "category": "certificate",
                "severity": "HIGH",
                "title": f"{cert_summary['weak_key_count']} certificate(s) with weak public keys (<2048-bit RSA or DSA)",
                "detail": f"Sample '{sample['subject']}' uses {sample['key_type']} in {sample['location']}.",
                "location": sample["location"],
                "remediation": "Replace sub-2048-bit RSA and DSA certificates with >=2048-bit RSA, ECDSA P-256+, or ML-DSA.",
            }
        )

    if cert_summary.get("weak_sig_non_root_count", 0) > 0:
        sample = cert_summary["weak_sig_non_roots"][0]
        active_risks.append(
            {
                "id": "WEAK_CERT_SIGNATURE_CHAIN",
                "category": "certificate",
                "severity": "HIGH",
                "title": f"{cert_summary['weak_sig_non_root_count']} non-root certificate(s) signed with SHA-1/MD5/MD2",
                "detail": f"Sample '{sample['subject']}' uses {sample['sig_hash']} in {sample['location']}.",
                "location": sample["location"],
                "remediation": "Re-issue intermediate/leaf certificates with SHA-256+ or ML-DSA.",
            }
        )

    if cert_summary.get("sha1_root_count", 0) > 0:
        names = ", ".join(c["subject"].split(",")[0] for c in cert_summary["sha1_roots"][:3])
        passive_risks.append(
            {
                "id": "SHA1_ROOT_CA_IN_TRUSTSTORE",
                "category": "certificate",
                "severity": "HIGH",
                "title": f"{cert_summary['sha1_root_count']} self-signed SHA-1/MD5 root CA(s) in truststore",
                "detail": f"Root anchors ({names}) carry sha1WithRSAEncryption. Self-signatures are ignored by modern anchor pinning but fail strict compliance checks and expose legacy verifiers if encountered.",
                "location": cert_summary["sha1_roots"][0]["location"],
                "remediation": "Distrust or remove legacy SHA-1 root CAs (update ca-certificates / java-cacerts or prune unused roots).",
            }
        )

    if cert_summary.get("expiring_90d_count", 0) > 0:
        sample = cert_summary["expiring_90d"][0]
        passive_risks.append(
            {
                "id": "CERT_EXPIRING_90D",
                "category": "certificate",
                "severity": "MEDIUM",
                "title": f"{cert_summary['expiring_90d_count']} certificate(s) expiring within 90 days",
                "detail": f"Earliest '{sample['subject']}' expires {sample['not_after']}.",
                "location": sample["location"],
                "remediation": "Schedule certificate or ca-certificates bundle rotation before expiration.",
            }
        )
    elif cert_summary.get("expiring_1y_count", 0) > 0:
        passive_risks.append(
            {
                "id": "CERT_EXPIRING_1Y",
                "category": "certificate",
                "severity": "LOW",
                "title": f"{cert_summary['expiring_1y_count']} certificate(s) expiring within 1 year",
                "detail": "Plan upcoming trust bundle refresh before certificate expiration.",
                "location": "truststore",
                "remediation": "Track CA bundle updates via scheduled rebuilds.",
            }
        )

    if cert_summary.get("non_positive_serial_count", 0) > 0:
        passive_risks.append(
            {
                "id": "RFC5280_NON_POSITIVE_SERIAL",
                "category": "certificate",
                "severity": "LOW",
                "title": f"{cert_summary['non_positive_serial_count']} legacy root CA(s) with RFC 5280 non-positive serial (<= 0)",
                "detail": "Strict X.509 parsers (including future python-cryptography releases) warn or reject certificates with serial <= 0.",
                "location": cert_summary["non_positive_serials"][0]["location"],
                "remediation": "Monitor upstream Mozilla CA removals for zero-serial legacy roots.",
            }
        )

    # 2. OpenSSL & Java Policy Findings (Active vs. Passive)
    policy_disabled_algos: set[str] = set()
    for ossl in openssl_findings:
        if ossl.get("legacy_provider_active"):
            sev = "HIGH" if ossl.get("legacy_des_enabled") else "MEDIUM"
            des_note = "DES enabled" if ossl.get("legacy_des_enabled") else "DES gated off (MD4/legacy EVP reachable)"
            active_risks.append(
                {
                    "id": "ACTIVE_LEGACY_PROVIDER",
                    "category": "configuration",
                    "severity": sev,
                    "title": "OpenSSL legacy provider activated by default",
                    "detail": f"{ossl['location']} activates legacy_sect ({des_note}).",
                    "location": ossl["location"],
                    "remediation": "Set CHAINGUARD_LEGACY_ALLOWED=0 or disable legacy_sect in openssl.cnf unless strictly required.",
                }
            )
        if ossl.get("weak_tls_policy"):
            active_risks.append(
                {
                    "id": "ACTIVE_WEAK_TLS_POLICY",
                    "category": "configuration",
                    "severity": "HIGH",
                    "title": "Weak TLS minimum protocol or SECLEVEL in openssl.cnf",
                    "detail": f"{ossl['location']} permits MinProtocol={ossl.get('min_protocol') or 'unspecified'} or SECLEVEL<2.",
                    "location": ossl["location"],
                    "remediation": "Enforce TLS.MinProtocol = TLSv1.2 (or TLSv1.3) and @SECLEVEL=2.",
                }
            )

    for jf in java_findings:
        policy_disabled_algos.update(jf.get("policy_disabled_algorithms", []))
        if jf.get("weak_tls_allowed"):
            active_risks.append(
                {
                    "id": "ACTIVE_WEAK_JAVA_TLS_POLICY",
                    "category": "configuration",
                    "severity": "HIGH",
                    "title": "Legacy TLSv1/SSLv3 not disabled in java.security",
                    "detail": f"{jf['location']} does not block SSLv3/TLSv1 in jdk.tls.disabledAlgorithms.",
                    "location": jf["location"],
                    "remediation": "Add SSLv3, TLSv1, TLSv1.1 to jdk.tls.disabledAlgorithms.",
                }
            )
        if jf.get("allows_rsa_under_2048_in_certpath"):
            passive_risks.append(
                {
                    "id": "JAVA_CERTPATH_ALLOWS_1024_RSA",
                    "category": "configuration",
                    "severity": "LOW",
                    "title": "java.security certpath floor permits RSA 1024-bit (<2048)",
                    "detail": f"{jf['location']} specifies 'RSA keySize < 1024' rather than '< 2048'.",
                    "location": jf["location"],
                    "remediation": "Raise jdk.certpath.disabledAlgorithms floor to RSA keySize < 2048.",
                }
            )

    # 3. Code vs. Runtime Legacy Algorithms
    code_legacy = sorted(app_prims & LEGACY_PRIMITIVE_NAMES)
    if code_legacy:
        active_risks.append(
            {
                "id": "ACTIVE_CODE_WEAK_CRYPTO",
                "category": "code",
                "severity": "HIGH",
                "title": f"Weak/broken algorithm(s) referenced in code: {', '.join(code_legacy)}",
                "detail": "Scanned source/bytecode references MD5, SHA-1, or weak legacy ciphers directly.",
                "location": "application-code",
                "remediation": "Replace MD5/SHA-1/RC4/3DES/ECB with SHA-256+, AES-256-GCM, or ChaCha20-Poly1305.",
            }
        )

    runtime_legacy = sorted((runtime_prims & LEGACY_PRIMITIVE_NAMES) - set(code_legacy))
    if runtime_legacy:
        blocked_note = (
            f" (blocked by runtime policy: {', '.join(sorted(policy_disabled_algos))})"
            if policy_disabled_algos
            else ""
        )
        passive_risks.append(
            {
                "id": "POLICY_DISABLED_LEGACY_ALGO",
                "category": "compiled-runtime",
                "severity": "LOW",
                "title": f"Legacy algorithms compiled into runtime binaries: {', '.join(runtime_legacy)}",
                "detail": f"Present in shared libraries/runtime modules{blocked_note}; not directly invoked by scanned application code.",
                "location": "compiled-runtime",
                "remediation": "Keep runtime disabledAlgorithms/SECLEVEL policies enforced and migrate any legacy callers.",
            }
        )

    # 4. Quantum-Vulnerable Classical Asymmetric Primitives & Trust Anchors
    qvuln_found = sorted(all_prims & QUANTUM_VULNERABLE_NAMES)
    if qvuln_found or cert_summary.get("total_unique", 0) > cert_summary.get("pqc_root_count", 0):
        detail_parts = []
        if qvuln_found:
            detail_parts.append(f"classical primitives ({', '.join(qvuln_found)})")
        if cert_summary.get("total_unique", 0) > cert_summary.get("pqc_root_count", 0):
            detail_parts.append(
                f"{cert_summary['total_unique'] - cert_summary.get('pqc_root_count', 0)} classical RSA/ECDSA trust anchors"
            )
        passive_risks.append(
            {
                "id": "QUANTUM_VULNERABLE_ASYMMETRIC",
                "category": "pqc-readiness",
                "severity": "MEDIUM",
                "title": "Quantum-vulnerable asymmetric cryptography present",
                "detail": "Contains " + " and ".join(detail_parts) + " susceptible to Shor's algorithm.",
                "location": "crypto-inventory",
                "remediation": "Adopt hybrid X25519MLKEM768 / ML-DSA-65 (FIPS 203/204) in application protocols and track CA PQC root transitions.",
            }
        )

    # 5. PQC Compiled Risk vs. Coding Risk (Unused PQC Libraries)
    pqc_unused_libs: list[str] = []
    for pkg in apk_packages:
        pname = pkg["name"].lower()
        for prefix, desc in PQC_CAPABLE_APK_PREFIXES.items():
            if pname.startswith(prefix):
                pqc_unused_libs.append(f"{pkg['name']}@{pkg['version']} ({desc})")
                break
    for dep in declared_deps:
        dname = dep.get("name", "").lower()
        if any(p in dname for p in PQC_CAPABLE_PKG_NAMES):
            ver = dep.get("version") or "declared"
            pqc_unused_libs.append(f"{dep['name']}@{ver}")
    for ossl in openssl_findings:
        if ossl.get("pqc_configured"):
            pqc_unused_libs.append(f"{ossl['location']} ({', '.join(ossl['pqc_configured'])})")

    pqc_in_runtime = bool(runtime_prims & PQC_PRIMITIVE_NAMES) or bool(cfg_prims & PQC_PRIMITIVE_NAMES)
    pqc_compiled_ready = pqc_in_runtime or bool(pqc_unused_libs)
    pqc_code_used = bool(app_prims & PQC_PRIMITIVE_NAMES)

    has_any_crypto = bool(all_prims) or cert_summary.get("total_unique", 0) > 0 or bool(openssl_findings)

    if not has_any_crypto and not active_risks and not passive_risks:
        pqc_adoption_status = "PQC_NOT_APPLICABLE_INERT"
        compiled_risk = "NONE"
        coding_risk = "NONE"
        pqc_unused_libs = []
    elif pqc_compiled_ready and pqc_code_used:
        pqc_adoption_status = "PQC_COMPILED_AND_USED"
        compiled_risk = "LOW"
        coding_risk = "LOW"
        pqc_unused_libs = []
    elif pqc_compiled_ready and not pqc_code_used:
        pqc_adoption_status = "PQC_COMPILED_BUT_UNUSED"
        compiled_risk = "LOW"
        coding_risk = "MEDIUM"
        passive_risks.append(
            {
                "id": "PQC_COMPILED_BUT_UNUSED",
                "category": "pqc-readiness",
                "severity": "MEDIUM",
                "title": "PQC-ready libraries compiled/configured but unused by application code",
                "detail": (
                    f"Runtime ships PQC-capable stacks ({', '.join(pqc_unused_libs[:4]) or 'ML-KEM/ML-DSA runtime'}) "
                    "with low compiled risk, but application/package code does not invoke FIPS 203/204 primitives."
                ),
                "location": "runtime-vs-code",
                "remediation": "Enable hybrid ML-KEM/ML-DSA TLS or signing APIs in application code to eliminate coding risk.",
            }
        )
    else:
        pqc_adoption_status = "PQC_NOT_COMPILED_CLASSICAL_ONLY"
        compiled_risk = "HIGH"
        coding_risk = "HIGH"

    overall_level = _max_risk_level(active_risks + passive_risks)

    return {
        "scan_scope": scan_scope,
        "crypto_risk_level": overall_level,
        "active_risk_count": len(active_risks),
        "passive_risk_count": len(passive_risks),
        "active_risks": active_risks,
        "passive_risks": passive_risks,
        "pqc_compiled_ready": pqc_compiled_ready,
        "pqc_code_used": pqc_code_used,
        "pqc_adoption_status": pqc_adoption_status,
        "compiled_risk": compiled_risk,
        "coding_risk": coding_risk,
        "pqc_ready_unused_libraries": sorted(set(pqc_unused_libs))[:12],
        "cert_summary": cert_summary,
    }


def extract_cbom_risk_summary(cbom_source: dict[str, Any] | Path) -> dict[str, Any]:
    """Extract normalized risk-posture summary from a CycloneDX 1.6 CBOM doc or file path."""
    default = {
        "present": False,
        "scan_status": "MISSING",
        "scan_scope": "unknown",
        "risk_level": "UNKNOWN",
        "active_risk_count": 0,
        "passive_risk_count": 0,
        "cert_total": 0,
        "cert_expired": 0,
        "cert_expiring_90d": 0,
        "cert_sha1_roots": 0,
        "cert_weak_keys": 0,
        "pqc_compiled_ready": False,
        "pqc_code_used": False,
        "pqc_adoption_status": "UNKNOWN",
        "compiled_risk": "UNKNOWN",
        "coding_risk": "UNKNOWN",
        "pqc_ready_unused_libraries": [],
        "active_risks": [],
        "passive_risks": [],
    }
    try:
        if isinstance(cbom_source, Path):
            if not cbom_source.is_file():
                return default
            doc = json.loads(cbom_source.read_text(encoding="utf-8"))
        else:
            doc = cbom_source
    except Exception:
        return default

    props = {
        str(p.get("name", "")): str(p.get("value", ""))
        for p in (doc.get("metadata") or {}).get("properties") or []
        if isinstance(p, dict)
    }

    def _as_int(key: str) -> int:
        try:
            return int(props.get(key, "0") or 0)
        except ValueError:
            return 0

    def _as_bool(key: str) -> bool:
        return props.get(key, "").strip().lower() == "true"

    detail_json = props.get("trusted-oss:risk-detail-json", "")
    parsed_detail: dict[str, Any] = {}
    if detail_json:
        try:
            parsed_detail = json.loads(detail_json)
        except Exception:
            parsed_detail = {}

    scan_status = props.get("trusted-oss:crypto-scan-status", "UNKNOWN")
    risk_level = props.get("trusted-oss:crypto-risk-level", "")
    if not risk_level:
        risk_level = "NONE" if scan_status == "VERIFIED_INERT" else "UNKNOWN"

    return {
        "present": True,
        "scan_status": scan_status,
        "scan_scope": props.get("trusted-oss:scan-scope", "legacy"),
        "risk_level": risk_level,
        "active_risk_count": _as_int("trusted-oss:active-risk-count"),
        "passive_risk_count": _as_int("trusted-oss:passive-risk-count"),
        "cert_total": _as_int("trusted-oss:cert-total"),
        "cert_expired": _as_int("trusted-oss:cert-expired"),
        "cert_expiring_90d": _as_int("trusted-oss:cert-expiring-90d"),
        "cert_sha1_roots": _as_int("trusted-oss:cert-sha1-roots"),
        "cert_weak_keys": _as_int("trusted-oss:cert-weak-keys"),
        "pqc_compiled_ready": _as_bool("trusted-oss:pqc-compiled-ready"),
        "pqc_code_used": _as_bool("trusted-oss:pqc-code-used"),
        "pqc_adoption_status": props.get("trusted-oss:pqc-adoption-status", "UNKNOWN"),
        "compiled_risk": props.get("trusted-oss:pqc-compiled-risk", "UNKNOWN"),
        "coding_risk": props.get("trusted-oss:pqc-coding-risk", "UNKNOWN"),
        "pqc_ready_unused_libraries": parsed_detail.get("pqc_ready_unused_libraries", []),
        "active_risks": parsed_detail.get("active_risks", []),
        "passive_risks": parsed_detail.get("passive_risks", []),
    }
