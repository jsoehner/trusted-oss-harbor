"""Pure-Python CycloneDX 1.6 SBOM & CBOM generator and PURL resolver for Trusted OSS Gatekeeper."""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import re
import tarfile
import uuid
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from defusedxml import ElementTree as ET

from app.crypto_risk import (
    build_risk_assessment,
    evaluate_certificates,
    inspect_java_security,
    inspect_openssl_cnf,
    parse_apk_installed_packages,
    parse_cert_store_bytes,
    parse_dpkg_status,
)
from app.storage import (
    ArtifactDigests,
    SAFE_SEGMENT_RE,
    is_safe_subpath,
    normalize_pypi_name,
    resolve_safe_relative_path,
)

BOM_SCANNER_NAME = "trusted-oss-gatekeeper-bom"
BOM_SCANNER_VERSION = "2.0.0"

# Limits to keep per-artifact inspection fast and memory-bounded
MAX_ARCHIVE_MEMBERS = 250
MAX_OCI_LAYER_FILES = 2500
MAX_MEMBER_BYTES = 512 * 1024  # 512 KiB per regular source/text member
MAX_BINARY_MEMBER_BYTES = 8 * 1024 * 1024  # 8 MiB per native shared library / cert store
MAX_JMOD_BYTES = 80 * 1024 * 1024  # 80 MiB streaming cap for OpenJDK lib/modules

# Scannable text/source/bytecode/binary extensions inside wheels, sdists, JARs, and OCI layers
TEXT_SCAN_EXTS = (
    ".py", ".pyi", ".java", ".kt", ".kts", ".scala", ".groovy",
    ".js", ".ts", ".mjs", ".cjs", ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".rb", ".php", ".cs", ".swift", ".pem", ".crt", ".cer", ".conf", ".cfg", ".cnf",
    ".ini", ".properties", ".security", ".xml", ".json", ".yaml", ".yml", ".toml",
)
APP_CODE_EXTS = (
    ".py", ".pyi", ".java", ".kt", ".kts", ".scala", ".groovy",
    ".js", ".ts", ".mjs", ".cjs", ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".rb", ".php", ".cs", ".swift", ".class",
)
BINARY_SCAN_EXTS = (".class", ".so", ".dylib", ".dll", ".pyd")
CERT_STORE_EXTS = (".pem", ".crt", ".cer", ".der", ".jks")
CERT_STORE_FILENAMES = ("cacerts", "ca-certificates.crt", "cert.pem", "cacert.pem")

_VERSIONED_SO_RE = re.compile(r"\.so(?:\.\d+)+$")

# Curated high-signal cryptographic patterns (aligned with jsi-bom-actions/scripts/scan_crypto_ast.py)
CRYPTO_RULES: list[dict[str, str]] = [
    # --- Post-Quantum Cryptography (NIST FIPS 203 / 204 / 205 & Hybrid) ---
    {
        "pattern": r"\b(?:X25519MLKEM768|SecP256r1MLKEM768|X25519Kyber768(?:Draft00)?|P256_MLKEM768)\b",
        "name": "X25519MLKEM768",
        "primitive": "kem",
        "asset_type": "algorithm",
        "param": "X25519+ML-KEM-768",
        "oid": "1.3.6.1.4.1.22554.5.6.1",
    },
    {
        "pattern": r"\b(?:ML[-_]?KEM[-_]?1024|KYBER[-_]?1024|MLKEM1024|ml_kem1024)\b",
        "name": "ML-KEM-1024",
        "primitive": "kem",
        "asset_type": "algorithm",
        "param": "1024",
        "oid": "2.16.840.1.101.3.4.4.3",
    },
    {
        "pattern": r"\b(?:ML[-_]?KEM[-_]?768|KYBER[-_]?768|MLKEM768|ml_kem768)\b",
        "name": "ML-KEM-768",
        "primitive": "kem",
        "asset_type": "algorithm",
        "param": "768",
        "oid": "2.16.840.1.101.3.4.4.2",
    },
    {
        "pattern": r"\b(?:ML[-_]?KEM[-_]?512|KYBER[-_]?512|MLKEM512|ml_kem512)\b",
        "name": "ML-KEM-512",
        "primitive": "kem",
        "asset_type": "algorithm",
        "param": "512",
        "oid": "2.16.840.1.101.3.4.4.1",
    },
    {
        "pattern": r"\b(?:ML[-_]?DSA[-_]?87|Dilithium5|MLDSA87|ml_dsa_87)\b",
        "name": "ML-DSA-87",
        "primitive": "signature",
        "asset_type": "algorithm",
        "param": "87",
        "oid": "2.16.840.1.101.3.4.3.19",
    },
    {
        "pattern": r"\b(?:ML[-_]?DSA[-_]?65|Dilithium3|MLDSA65|ml_dsa_65)\b",
        "name": "ML-DSA-65",
        "primitive": "signature",
        "asset_type": "algorithm",
        "param": "65",
        "oid": "2.16.840.1.101.3.4.3.18",
    },
    {
        "pattern": r"\b(?:ML[-_]?DSA[-_]?44|Dilithium2|MLDSA44|ml_dsa_44)\b",
        "name": "ML-DSA-44",
        "primitive": "signature",
        "asset_type": "algorithm",
        "param": "44",
        "oid": "2.16.840.1.101.3.4.3.17",
    },
    {
        "pattern": r"\b(?:SLH[-_]?DSA|SPHINCS\+?|sphincsplus)\b",
        "name": "SLH-DSA",
        "primitive": "signature",
        "asset_type": "algorithm",
        "param": "128s",
        "oid": "2.16.840.1.101.3.4.3.20",
    },
    # --- Quantum-Vulnerable Asymmetric & Legacy Primitives ---
    {
        "pattern": r"\b(?:RSA[-_]?PSS|RS256|RS384|RS512|RSAKey|RSAPublicKey|RSAPrivateKey|RSA/ECB|SHA256withRSA|rsa\.generate_private_key)\b",
        "name": "RSA",
        "primitive": "pke",
        "asset_type": "algorithm",
        "param": "2048",
        "oid": "1.2.840.113549.1.1.1",
    },
    {
        "pattern": r"\b(?:ECDSA|ES256|ES384|ES512|SHA256withECDSA|ECPublicKey|ECPrivateKey|ec\.ECDSA|SECP256R1|SECP384R1|prime256v1)\b",
        "name": "ECDSA",
        "primitive": "signature",
        "asset_type": "algorithm",
        "param": "P-256",
        "oid": "1.2.840.10045.2.1",
    },
    {
        "pattern": r"\b(?:ECDH|ec\.ECDH|X25519PrivateKey|X25519PublicKey|X25519)\b",
        "name": "ECDH-X25519",
        "primitive": "key-agree",
        "asset_type": "algorithm",
        "param": "25519",
        "oid": "1.3.101.110",
    },
    {
        "pattern": r"\b(?:Ed25519PrivateKey|Ed25519PublicKey|Ed25519|EdDSA)\b",
        "name": "Ed25519",
        "primitive": "signature",
        "asset_type": "algorithm",
        "param": "25519",
        "oid": "1.3.101.112",
    },
    {
        "pattern": r"\b(?:DiffieHellman|DHParameterSpec|dh\.generate_parameters)\b",
        "name": "Diffie-Hellman",
        "primitive": "key-agree",
        "asset_type": "algorithm",
        "param": "2048",
        "oid": "1.2.840.113549.1.3.1",
    },
    {
        "pattern": r"\b(?:hashlib\.md5|MD5\.new|MessageDigest\.getInstance\(['\"]MD5['\"]\)|EVP_md5)\b",
        "name": "MD5",
        "primitive": "hash",
        "asset_type": "algorithm",
        "param": "128",
        "oid": "1.2.840.113549.2.5",
    },
    {
        "pattern": r"\b(?:hashlib\.sha1|SHA1\.new|MessageDigest\.getInstance\(['\"]SHA-?1['\"]\)|EVP_sha1|HMACSHA1)\b",
        "name": "SHA-1",
        "primitive": "hash",
        "asset_type": "algorithm",
        "param": "160",
        "oid": "1.3.14.3.2.26",
    },
    {
        "pattern": r"\b(?:DESede|TripleDES|3DES|RC4|ARC4|AES/ECB)\b",
        "name": "Legacy-Weak-Cipher",
        "primitive": "block-cipher",
        "asset_type": "algorithm",
        "param": "128",
        "oid": "",
    },
    # --- Classical Symmetric, Digests, KDFs, Protocols ---
    {
        "pattern": r"\b(?:AES[-_]?256[-_]?GCM|AESGCM|AES/GCM/NoPadding|EVP_aes_256_gcm)\b",
        "name": "AES-256-GCM",
        "primitive": "ae",
        "asset_type": "algorithm",
        "param": "256",
        "oid": "2.16.840.1.101.3.4.1.46",
    },
    {
        "pattern": r"\b(?:ChaCha20Poly1305|ChaCha20-Poly1305|EVP_chacha20_poly1305)\b",
        "name": "ChaCha20-Poly1305",
        "primitive": "ae",
        "asset_type": "algorithm",
        "param": "256",
        "oid": "1.2.840.113549.1.9.16.3.18",
    },
    {
        "pattern": r"\b(?:hashlib\.sha256|SHA256|SHA-256|HmacSHA256|EVP_sha256)\b",
        "name": "SHA-256",
        "primitive": "hash",
        "asset_type": "algorithm",
        "param": "256",
        "oid": "2.16.840.1.101.3.4.2.1",
    },
    {
        "pattern": r"\b(?:hashlib\.sha384|SHA384|SHA-384|HmacSHA384|EVP_sha384)\b",
        "name": "SHA-384",
        "primitive": "hash",
        "asset_type": "algorithm",
        "param": "384",
        "oid": "2.16.840.1.101.3.4.2.2",
    },
    {
        "pattern": r"\b(?:hashlib\.sha512|SHA512|SHA-512|HmacSHA512|EVP_sha512)\b",
        "name": "SHA-512",
        "primitive": "hash",
        "asset_type": "algorithm",
        "param": "512",
        "oid": "2.16.840.1.101.3.4.2.3",
    },
    {
        "pattern": r"\b(?:Argon2id|PBKDF2HMAC|PBKDF2WithHmacSHA256|scrypt|bcrypt|HKDF)\b",
        "name": "KDF-Password-Hash",
        "primitive": "kdf",
        "asset_type": "algorithm",
        "param": "256",
        "oid": "",
    },
    {
        "pattern": r"\b(?:SSLContext|TLSVersion\.TLSv1_3|TLSv1\.3|TLSv1\.2|SSLSocketFactory|ssl\.create_default_context)\b",
        "name": "TLS",
        "primitive": "protocol",
        "asset_type": "protocol",
        "param": "1.3",
        "oid": "",
    },
    {
        "pattern": r"-----BEGIN CERTIFICATE-----",
        "name": "X.509-Certificate",
        "primitive": "certificate",
        "asset_type": "certificate",
        "param": "X.509",
        "oid": "",
    },
]

_COMPILED_RULES = [
    (re.compile(rule["pattern"]), rule) for rule in CRYPTO_RULES
]

# Fast byte-token rules for streaming large runtime archives (e.g., OpenJDK lib/modules)
_JMOD_TOKEN_RULES: tuple[tuple[bytes, str], ...] = (
    (b"ML-KEM-768", "ML-KEM-768"),
    (b"ML-KEM-1024", "ML-KEM-1024"),
    (b"ML-KEM-512", "ML-KEM-512"),
    (b"ML-KEM", "ML-KEM-768"),
    (b"ML-DSA-65", "ML-DSA-65"),
    (b"ML-DSA-87", "ML-DSA-87"),
    (b"ML-DSA-44", "ML-DSA-44"),
    (b"ML-DSA", "ML-DSA-65"),
    (b"X25519", "ECDH-X25519"),
    (b"Ed25519", "Ed25519"),
    (b"ECDSA", "ECDSA"),
    (b"SHA256withRSA", "RSA"),
    (b"AES/GCM", "AES-256-GCM"),
    (b"ChaCha20-Poly1305", "ChaCha20-Poly1305"),
    (b"SHA-256", "SHA-256"),
    (b"SHA-384", "SHA-384"),
    (b"SHA-512", "SHA-512"),
    (b"SHA-1", "SHA-1"),
    (b"MD5", "MD5"),
    (b"DESede", "Legacy-Weak-Cipher"),
    (b"RC4", "Legacy-Weak-Cipher"),
    (b"TLSv1.3", "TLS"),
)

_RULE_BY_NAME: dict[str, dict[str, str]] = {r["name"]: r for r in CRYPTO_RULES}


def build_canonical_purl(
    ecosystem: str,
    pkg_name: str,
    pkg_version: str,
    artifact_rel_path: str = "",
) -> str:
    """Build a canonical Package URL (purl) for Maven, PyPI, OCI, or APK artifacts."""
    eco = ecosystem.lower()
    ver_suffix = f"@{pkg_version}" if pkg_version and pkg_version != "unknown" else ""
    if eco == "pypi":
        norm = normalize_pypi_name(pkg_name) if pkg_name else ""
        return f"pkg:pypi/{norm}{ver_suffix}" if norm else f"pkg:pypi/{artifact_rel_path}"
    if eco == "maven":
        if ":" in pkg_name:
            group_id, artifact_id = pkg_name.split(":", 1)
            return f"pkg:maven/{group_id}/{artifact_id}{ver_suffix}"
        return f"pkg:maven/{pkg_name}{ver_suffix}"
    if eco == "apk":
        return f"pkg:apk/wolfi/{pkg_name}{ver_suffix}"
    if eco == "deb":
        return f"pkg:deb/{pkg_name}{ver_suffix}"
    if eco.startswith("oci"):
        clean = artifact_rel_path.strip("/")
        return f"pkg:oci/{clean}{ver_suffix}"
    return f"pkg:generic/{pkg_name or artifact_rel_path}{ver_suffix}"


def parse_purl(purl: str) -> dict[str, str]:
    """Parse a PURL string into ecosystem, namespace, name, and version."""
    raw = unquote(purl.strip())
    if not raw.startswith("pkg:"):
        return {}
    body = raw[4:]
    # Strip qualifiers (?...) and subpath (#...)
    body = body.split("#", 1)[0].split("?", 1)[0]
    version = ""
    if "@" in body:
        body, version = body.rsplit("@", 1)
    parts = [p for p in body.split("/") if p]
    if len(parts) < 2:
        return {}
    eco = parts[0].lower()
    if len(parts) == 2:
        return {"ecosystem": eco, "namespace": "", "name": parts[1], "version": version}
    return {
        "ecosystem": eco,
        "namespace": "/".join(parts[1:-1]),
        "name": parts[-1],
        "version": version,
    }


def _classify_member_origin(member_path: str, is_binary: bool) -> str:
    """Classify scanned file as application-code, configuration, or compiled-runtime."""
    lower = member_path.lower()
    base = Path(lower).name
    if base in ("openssl.cnf", "java.security") or lower.endswith((".cnf", ".security")):
        return "configuration"
    if (
        is_binary
        and not lower.endswith(".class")
        and (".so" in base or base.endswith((".dylib", ".dll", ".pyd")) or lower.endswith("/modules"))
    ):
        return "compiled-runtime"
    if "site-packages/" in lower or lower.endswith(APP_CODE_EXTS):
        return "application-code"
    if lower.endswith((".pem", ".crt", ".cer", ".der", ".jks")) or base in CERT_STORE_FILENAMES:
        return "configuration"
    return "compiled-runtime" if is_binary else "application-code"


def _is_scannable_binary(member_lower: str) -> bool:
    return member_lower.endswith(BINARY_SCAN_EXTS) or bool(_VERSIONED_SO_RE.search(member_lower))


def _is_cert_store_member(member_lower: str) -> bool:
    base = Path(member_lower).name
    return member_lower.endswith(CERT_STORE_EXTS) or base in CERT_STORE_FILENAMES


def _record_rule_finding(
    found: dict[str, dict[str, Any]],
    rule: dict[str, str],
    location: str,
    origin: str,
    primitives_by_origin: dict[str, set[str]],
) -> None:
    key = rule["name"]
    primitives_by_origin.setdefault(origin, set()).add(key)
    if key not in found:
        found[key] = {
            "rule": rule,
            "locations": [location],
            "origins": {origin},
        }
    else:
        found[key]["origins"].add(origin)
        if len(found[key]["locations"]) < 5 and location not in found[key]["locations"]:
            found[key]["locations"].append(location)


def _scan_text_for_crypto(
    text: str,
    location: str,
    found: dict[str, dict[str, Any]],
    origin: str = "application-code",
    primitives_by_origin: dict[str, set[str]] | None = None,
) -> None:
    """Run compiled cryptographic regex rules over text and accumulate unique findings."""
    prim_map = primitives_by_origin if primitives_by_origin is not None else {}
    for regex, rule in _COMPILED_RULES:
        if regex.search(text):
            _record_rule_finding(found, rule, location, origin, prim_map)


def _extract_printable_ascii(data: bytes) -> str:
    """Extract printable ASCII runs (length >= 4) from binary/bytecode payloads."""
    return "\n".join(
        m.group(0).decode("ascii", errors="ignore")
        for m in re.finditer(rb"[\x20-\x7e]{4,}", data)
    )


def _extract_sbom_dependencies_from_archive(file_path: Path) -> list[dict[str, str]]:
    """Extract declared dependency names from wheel METADATA or Maven pom.xml if present."""
    deps: list[dict[str, str]] = []
    name_lower = file_path.name.lower()
    try:
        if name_lower.endswith((".whl", ".jar", ".zip")) and zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as zf:
                for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
                    fname = info.filename
                    if fname.endswith("/METADATA") or fname == "METADATA":
                        with zf.open(info, "r") as stream:
                            raw = stream.read(MAX_MEMBER_BYTES).decode("utf-8", errors="replace")
                        for line in raw.splitlines():
                            if line.startswith("Requires-Dist:") and "; extra ==" not in line:
                                spec = line.split(":", 1)[1].strip().split(";")[0].strip()
                                m = re.match(r"^([A-Za-z0-9._-]+)", spec)
                                if m:
                                    deps.append({"ecosystem": "pypi", "name": m.group(1)})
                    elif fname.endswith("pom.xml"):
                        with zf.open(info, "r") as stream:
                            raw = stream.read(MAX_MEMBER_BYTES).decode("utf-8", errors="replace")
                        try:
                            root = ET.fromstring(raw)
                            for dep_el in root.iter():
                                if dep_el.tag.endswith("dependency"):
                                    gid = aid = ver = ""
                                    for child in dep_el:
                                        if child.tag.endswith("groupId") and child.text:
                                            gid = child.text.strip()
                                        elif child.tag.endswith("artifactId") and child.text:
                                            aid = child.text.strip()
                                        elif child.tag.endswith("version") and child.text:
                                            ver = child.text.strip()
                                    if gid and aid:
                                        deps.append({
                                            "ecosystem": "maven",
                                            "name": f"{gid}:{aid}",
                                            "version": ver,
                                        })
                        except ET.ParseError:
                            pass
    except Exception:
        pass
    return deps


def _build_crypto_components(
    found: dict[str, dict[str, Any]],
    cert_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build CycloneDX 1.6 cryptographic-asset component entries for primitives and flagged certs."""
    components: list[dict[str, Any]] = []
    for key, entry in sorted(found.items()):
        rule = entry["rule"]
        asset_type = rule["asset_type"]
        crypto_props: dict[str, Any] = {"assetType": asset_type}
        if asset_type == "algorithm":
            crypto_props["algorithmProperties"] = {
                "name": rule["name"],
                "primitive": rule["primitive"],
                "parameterSetIdentifier": rule["param"],
            }
            if rule.get("oid"):
                crypto_props["oid"] = rule["oid"]
        elif asset_type == "protocol":
            crypto_props["protocolProperties"] = {
                "type": "tls",
                "version": rule["param"],
            }
        elif asset_type == "certificate":
            crypto_props["certificateProperties"] = {
                "certificateFormat": "X.509",
            }

        origins = sorted(entry.get("origins", ()))
        comp_props = [{"name": "trusted-oss:origin", "value": ",".join(origins)}] if origins else []
        if asset_type == "certificate" and cert_summary.get("total_unique", 0) > 0:
            comp_props.extend(
                [
                    {"name": "trusted-oss:cert-total", "value": str(cert_summary["total_unique"])},
                    {"name": "trusted-oss:cert-expired", "value": str(cert_summary["expired_count"])},
                    {"name": "trusted-oss:cert-sha1-roots", "value": str(cert_summary["sha1_root_count"])},
                ]
            )

        comp: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto:{key.lower()}",
            "name": rule["name"],
            "cryptoProperties": crypto_props,
            "evidence": {
                "occurrences": [{"location": loc} for loc in entry["locations"]]
            },
        }
        if comp_props:
            comp["properties"] = comp_props
        components.append(comp)

    # Emit concrete certificate findings so downstream auditors see exact expired/SHA-1 subjects
    flagged_groups = (
        ("expired", "ACTIVE_EXPIRED"),
        ("not_yet_valid", "ACTIVE_NOT_YET_VALID"),
        ("weak_sig_non_roots", "ACTIVE_WEAK_SIG_CHAIN"),
        ("weak_keys", "ACTIVE_WEAK_KEY"),
        ("non_ca_in_truststore", "ACTIVE_NON_CA_TRUSTSTORE"),
        ("sha1_roots", "PASSIVE_SHA1_ROOT_CA"),
    )
    seen_cert_refs: set[str] = set()
    for group_key, risk_tag in flagged_groups:
        for cert in cert_summary.get(group_key, [])[:10]:
            bom_ref = f"crypto:cert:{cert['fp']}:{risk_tag.lower()}"
            if bom_ref in seen_cert_refs:
                continue
            seen_cert_refs.add(bom_ref)
            components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": bom_ref,
                    "name": f"X.509:{cert['subject'][:80]}",
                    "cryptoProperties": {
                        "assetType": "certificate",
                        "certificateProperties": {
                            "subjectName": cert["subject"],
                            "issuerName": cert["issuer"],
                            "notValidBefore": cert["not_before"],
                            "notValidAfter": cert["not_after"],
                            "certificateFormat": "X.509",
                        },
                    },
                    "evidence": {"occurrences": [{"location": cert["location"]}]},
                    "properties": [
                        {"name": "trusted-oss:cert-risk", "value": risk_tag},
                        {"name": "trusted-oss:cert-sig-hash", "value": cert["sig_hash"]},
                        {"name": "trusted-oss:cert-key-type", "value": cert["key_type"]},
                        {"name": "trusted-oss:cert-not-after", "value": cert["not_after"]},
                    ],
                }
            )
    return components


def _inspect_archive_details(
    file_path: Path,
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Inspect a non-OCI artifact (wheel, sdist, JAR, or file) for crypto primitives and certs."""
    found: dict[str, dict[str, Any]] = {}
    primitives_by_origin: dict[str, set[str]] = {}
    certs_by_fp: dict[str, dict[str, Any]] = {}
    openssl_findings: list[dict[str, Any]] = []
    java_findings: list[dict[str, Any]] = []
    name_lower = file_path.name.lower()
    scan_scope = "file-direct"

    def _process_member(member_name: str, data: bytes) -> None:
        member_lower = member_name.lower()
        base = Path(member_lower).name
        if _is_cert_store_member(member_lower):
            fmt, parsed_certs = parse_cert_store_bytes(data, member_name)
            for cert in parsed_certs:
                certs_by_fp.setdefault(cert["fp"], cert)
            if parsed_certs and "X.509-Certificate" in _RULE_BY_NAME:
                _record_rule_finding(
                    found,
                    _RULE_BY_NAME["X.509-Certificate"],
                    member_name,
                    "configuration",
                    primitives_by_origin,
                )
            if fmt != "UNKNOWN":
                return

        if base == "openssl.cnf":
            text = data.decode("utf-8", errors="ignore")
            openssl_findings.append(inspect_openssl_cnf(text, member_name))
            _scan_text_for_crypto(text, member_name, found, "configuration", primitives_by_origin)
        elif base == "java.security":
            text = data.decode("utf-8", errors="ignore")
            java_findings.append(inspect_java_security(text, member_name))
            _scan_text_for_crypto(text, member_name, found, "configuration", primitives_by_origin)
        elif member_lower.endswith(TEXT_SCAN_EXTS):
            origin = _classify_member_origin(member_name, is_binary=False)
            _scan_text_for_crypto(
                data.decode("utf-8", errors="ignore"),
                member_name,
                found,
                origin,
                primitives_by_origin,
            )
        elif _is_scannable_binary(member_lower):
            origin = _classify_member_origin(member_name, is_binary=True)
            _scan_text_for_crypto(
                _extract_printable_ascii(data),
                member_name,
                found,
                origin,
                primitives_by_origin,
            )

    if name_lower.endswith((".whl", ".jar", ".zip")) and zipfile.is_zipfile(file_path):
        scan_scope = "archive-deep"
        with zipfile.ZipFile(file_path, "r") as zf:
            for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
                if info.is_dir():
                    continue
                member_lower = info.filename.lower()
                if member_lower.endswith(TEXT_SCAN_EXTS) or _is_scannable_binary(member_lower) or _is_cert_store_member(member_lower):
                    cap = MAX_BINARY_MEMBER_BYTES if (_is_scannable_binary(member_lower) or _is_cert_store_member(member_lower)) else MAX_MEMBER_BYTES
                    with zf.open(info, "r") as stream:
                        data = stream.read(cap)
                    _process_member(info.filename, data)
    elif name_lower.endswith((".tar.gz", ".tgz")):
        scan_scope = "archive-deep"
        try:
            with tarfile.open(file_path, "r:gz") as tf:
                count = 0
                for member in tf.getmembers():
                    if count >= MAX_ARCHIVE_MEMBERS:
                        break
                    if not member.isfile():
                        continue
                    count += 1
                    member_lower = member.name.lower()
                    if member_lower.endswith(TEXT_SCAN_EXTS) or _is_scannable_binary(member_lower) or _is_cert_store_member(member_lower):
                        extracted = tf.extractfile(member)
                        if extracted is None:
                            continue
                        cap = MAX_BINARY_MEMBER_BYTES if (_is_scannable_binary(member_lower) or _is_cert_store_member(member_lower)) else MAX_MEMBER_BYTES
                        _process_member(member.name, extracted.read(cap))
        except tarfile.TarError:
            pass
    else:
        data = file_path.read_bytes()[:MAX_MEMBER_BYTES]
        if _is_cert_store_member(name_lower):
            _process_member(file_path.name, data)
        else:
            origin = "application-code" if name_lower.endswith(APP_CODE_EXTS) else "configuration"
            _scan_text_for_crypto(
                data.decode("utf-8", errors="ignore"),
                file_path.name,
                found,
                origin,
                primitives_by_origin,
            )

    cert_summary = evaluate_certificates(certs_by_fp, now=now)
    components = _build_crypto_components(found, cert_summary)
    return {
        "scan_scope": scan_scope,
        "components": components,
        "primitives_by_origin": primitives_by_origin,
        "cert_summary": cert_summary,
        "openssl_findings": openssl_findings,
        "java_findings": java_findings,
    }


def inspect_artifact_crypto(file_path: Path) -> list[dict[str, Any]]:
    """Inspect an artifact (wheel, sdist, JAR, or generic file) for cryptographic assets."""
    return _inspect_archive_details(file_path)["components"]


def _scan_streaming_jmod(
    stream: io.BufferedReader | Any,
    location: str,
    found: dict[str, dict[str, Any]],
    primitives_by_origin: dict[str, set[str]],
) -> None:
    """Scan large Java runtime module image (lib/modules) in bounded streaming chunks."""
    chunk_size = 2 * 1024 * 1024
    read_total = 0
    tail = b""
    matched_rules: set[str] = set()
    while read_total < MAX_JMOD_BYTES:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        read_total += len(chunk)
        buf = tail + chunk
        for token, rule_name in _JMOD_TOKEN_RULES:
            if rule_name in matched_rules:
                continue
            if token in buf and rule_name in _RULE_BY_NAME:
                matched_rules.add(rule_name)
                _record_rule_finding(
                    found,
                    _RULE_BY_NAME[rule_name],
                    location,
                    "compiled-runtime",
                    primitives_by_origin,
                )
        tail = buf[-64:]


def inspect_oci_layers(
    layer_paths: list[Path],
    now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Inspect downloaded OCI container layer tarballs in memory without unsafe disk extraction."""
    found: dict[str, dict[str, Any]] = {}
    primitives_by_origin: dict[str, set[str]] = {}
    cert_blobs: dict[str, bytes] = {}
    openssl_configs: dict[str, str] = {}
    java_sec_configs: dict[str, str] = {}
    apk_db_chunks: list[str] = []
    dpkg_chunks: list[str] = []

    scanned_files = 0
    for layer_path in layer_paths:
        if not layer_path.is_file():
            continue
        try:
            with tarfile.open(layer_path, "r:*") as tf:
                for member in tf:
                    if scanned_files >= MAX_OCI_LAYER_FILES:
                        break
                    rel = member.name.lstrip("./")
                    if not rel or ".." in Path(rel).parts:
                        continue
                    base = Path(rel).name
                    if base == ".wh..wh..opq":
                        parent_prefix = rel[: -len(base)]
                        for store_map in (cert_blobs, openssl_configs, java_sec_configs):
                            for k in [p for p in store_map if p.startswith(parent_prefix)]:
                                store_map.pop(k, None)
                        continue
                    if base.startswith(".wh."):
                        target_rel = str(Path(rel).with_name(base[4:]))
                        for store_map in (cert_blobs, openssl_configs, java_sec_configs):
                            store_map.pop(target_rel, None)
                            for k in [p for p in store_map if p.startswith(f"{target_rel}/")]:
                                store_map.pop(k, None)
                        continue

                    if not member.isfile():
                        continue

                    rel_lower = rel.lower()
                    base_lower = base.lower()
                    is_apk_db = rel_lower in ("lib/apk/db/installed", "usr/lib/apk/db/installed")
                    is_dpkg_db = rel_lower == "var/lib/dpkg/status" or rel_lower.startswith("var/lib/dpkg/status.d/")
                    is_jmod = base_lower == "modules" and "/jvm/" in f"/{rel_lower}"
                    is_cert = _is_cert_store_member(rel_lower)
                    is_text = rel_lower.endswith(TEXT_SCAN_EXTS)
                    is_bin = _is_scannable_binary(rel_lower)
                    is_jar = rel_lower.endswith(".jar")

                    if not (is_apk_db or is_dpkg_db or is_jmod or is_cert or is_text or is_bin or is_jar):
                        continue

                    extracted = tf.extractfile(member)
                    if extracted is None:
                        continue
                    scanned_files += 1

                    if is_jmod:
                        _scan_streaming_jmod(extracted, rel, found, primitives_by_origin)
                        continue

                    cap = (
                        MAX_BINARY_MEMBER_BYTES
                        if (is_bin or is_cert or is_apk_db or is_dpkg_db or is_jar)
                        else MAX_MEMBER_BYTES
                    )
                    data = extracted.read(cap)

                    if is_apk_db:
                        apk_db_chunks.append(data.decode("utf-8", errors="replace"))
                        continue

                    if is_dpkg_db:
                        dpkg_chunks.append(data.decode("utf-8", errors="replace"))
                        continue

                    if is_cert:
                        cert_blobs[rel] = data
                        continue

                    if base_lower == "openssl.cnf":
                        txt = data.decode("utf-8", errors="ignore")
                        openssl_configs[rel] = txt
                        _scan_text_for_crypto(txt, rel, found, "configuration", primitives_by_origin)
                        continue

                    if base_lower == "java.security":
                        txt = data.decode("utf-8", errors="ignore")
                        java_sec_configs[rel] = txt
                        _scan_text_for_crypto(txt, rel, found, "configuration", primitives_by_origin)
                        continue

                    if is_jar:
                        try:
                            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                                for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
                                    if info.is_dir():
                                        continue
                                    il = info.filename.lower()
                                    if il.endswith(TEXT_SCAN_EXTS):
                                        jtxt = zf.read(info).decode("utf-8", errors="ignore")
                                        _scan_text_for_crypto(
                                            jtxt,
                                            f"{rel}!/{info.filename}",
                                            found,
                                            "application-code",
                                            primitives_by_origin,
                                        )
                                    elif _is_scannable_binary(il):
                                        jbin = _extract_printable_ascii(zf.read(info)[:MAX_MEMBER_BYTES])
                                        _scan_text_for_crypto(
                                            jbin,
                                            f"{rel}!/{info.filename}",
                                            found,
                                            "application-code",
                                            primitives_by_origin,
                                        )
                        except Exception:
                            pass
                        continue

                    if is_text:
                        origin = _classify_member_origin(rel, is_binary=False)
                        _scan_text_for_crypto(
                            data.decode("utf-8", errors="ignore"),
                            rel,
                            found,
                            origin,
                            primitives_by_origin,
                        )
                    elif is_bin:
                        origin = _classify_member_origin(rel, is_binary=True)
                        _scan_text_for_crypto(
                            _extract_printable_ascii(data),
                            rel,
                            found,
                            origin,
                            primitives_by_origin,
                        )
        except (tarfile.TarError, OSError):
            continue

    certs_by_fp: dict[str, dict[str, Any]] = {}
    for rel, raw in sorted(cert_blobs.items()):
        fmt, parsed = parse_cert_store_bytes(raw, rel)
        for cert in parsed:
            certs_by_fp.setdefault(cert["fp"], cert)
        if parsed and "X.509-Certificate" in _RULE_BY_NAME:
            _record_rule_finding(
                found,
                _RULE_BY_NAME["X.509-Certificate"],
                rel,
                "configuration",
                primitives_by_origin,
            )

    cert_summary = evaluate_certificates(certs_by_fp, now=now)
    openssl_findings = [inspect_openssl_cnf(txt, loc) for loc, txt in sorted(openssl_configs.items())]
    java_findings = [inspect_java_security(txt, loc) for loc, txt in sorted(java_sec_configs.items())]
    raw_apk_packages = parse_apk_installed_packages("\n\n".join(apk_db_chunks)) if apk_db_chunks else []
    seen_apk: set[tuple[str, str]] = set()
    apk_packages: list[dict[str, str]] = []
    for pkg in raw_apk_packages:
        key = (pkg.get("name", ""), pkg.get("version", ""))
        if key not in seen_apk:
            seen_apk.add(key)
            apk_packages.append(pkg)
    deb_packages = parse_dpkg_status("\n\n".join(dpkg_chunks)) if dpkg_chunks else []
    components = _build_crypto_components(found, cert_summary)

    return {
        "scan_scope": "oci-layers",
        "components": components,
        "primitives_by_origin": primitives_by_origin,
        "cert_summary": cert_summary,
        "openssl_findings": openssl_findings,
        "java_findings": java_findings,
        "apk_packages": apk_packages,
        "deb_packages": deb_packages,
    }


def generate_artifact_boms(
    staged_file: Path,
    ecosystem: str,
    pkg_name: str,
    pkg_version: str,
    artifact_rel_path: str,
    digests: ArtifactDigests,
    oci_layer_paths: list[Path] | None = None,
    now: datetime.datetime | None = None,
) -> tuple[Path, Path, int, str]:
    """Generate CycloneDX 1.6 SBOM and CBOM sidecars next to staged_file.

    Returns (sbom_path, cbom_path, crypto_asset_count, scan_status).
    """
    now_dt = now or datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_dt.isoformat()
    purl = build_canonical_purl(ecosystem, pkg_name, pkg_version, artifact_rel_path)

    hashes = [{"alg": "SHA-256", "content": digests.sha256}]
    if digests.sha384:
        hashes.append({"alg": "SHA-384", "content": digests.sha384})
    if digests.sha512:
        hashes.append({"alg": "SHA-512", "content": digests.sha512})

    base_component = {
        "type": "library" if ecosystem in ("pypi", "maven") else "container",
        "bom-ref": purl,
        "name": pkg_name or staged_file.name,
        "version": pkg_version or "unknown",
        "purl": purl,
        "hashes": hashes,
    }

    tools_block = {
        "components": [
            {
                "type": "application",
                "name": BOM_SCANNER_NAME,
                "version": BOM_SCANNER_VERSION,
            }
        ]
    }

    extracted_deps = _extract_sbom_dependencies_from_archive(staged_file)

    is_oci = ecosystem.lower().startswith("oci")
    valid_layers = [p for p in (oci_layer_paths or []) if p.is_file()]
    manifest_only_uninspected = False

    if is_oci and valid_layers:
        scan_res = inspect_oci_layers(valid_layers, now=now_dt)
        apk_packages = scan_res["apk_packages"]
        for pkg in apk_packages:
            extracted_deps.append(
                {
                    "ecosystem": "apk",
                    "name": pkg["name"],
                    "version": pkg["version"],
                }
            )
        for pkg in scan_res.get("deb_packages", []):
            extracted_deps.append(
                {
                    "ecosystem": "deb",
                    "name": pkg["name"],
                    "version": pkg["version"],
                }
            )
    elif is_oci:
        manifest_only_uninspected = True
        scan_res = {
            "scan_scope": "oci-manifest-only",
            "components": [],
            "primitives_by_origin": {},
            "cert_summary": evaluate_certificates({}, now=now_dt),
            "openssl_findings": [],
            "java_findings": [],
            "apk_packages": [],
            "deb_packages": [],
        }
    else:
        scan_res = _inspect_archive_details(staged_file, now=now_dt)
        scan_res["apk_packages"] = []
        scan_res["deb_packages"] = []

    # 1. CycloneDX 1.6 SBOM
    sbom_components: list[dict[str, Any]] = []
    seen_dep_purls: set[str] = set()
    for dep in extracted_deps:
        dep_purl = build_canonical_purl(
            dep["ecosystem"], dep["name"], dep.get("version", "")
        )
        if dep_purl not in seen_dep_purls:
            seen_dep_purls.add(dep_purl)
            sbom_components.append(
                {
                    "type": "library",
                    "bom-ref": dep_purl,
                    "name": dep["name"],
                    "version": dep.get("version", "N/A") or "N/A",
                    "purl": dep_purl,
                }
            )

    sbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": tools_block,
            "component": base_component,
            "properties": [
                {"name": "trusted-oss:ecosystem", "value": ecosystem},
                {"name": "trusted-oss:artifact-path", "value": artifact_rel_path},
                {"name": "trusted-oss:scan-scope", "value": scan_res["scan_scope"]},
            ],
        },
        "components": sbom_components,
    }

    # 2. CycloneDX 1.6 CBOM + Risk Assessment
    crypto_components = scan_res["components"]
    risk = build_risk_assessment(
        primitives_by_origin=scan_res["primitives_by_origin"],
        cert_summary=scan_res["cert_summary"],
        openssl_findings=scan_res["openssl_findings"],
        java_findings=scan_res["java_findings"],
        apk_packages=scan_res["apk_packages"],
        declared_deps=extracted_deps,
        scan_scope=scan_res["scan_scope"],
        manifest_only_uninspected=manifest_only_uninspected,
    )

    if manifest_only_uninspected:
        scan_status = "MANIFEST_ONLY_UNINSPECTED"
    elif crypto_components or risk["active_risk_count"] > 0 or risk["passive_risk_count"] > 0:
        scan_status = "CRYPTO_ASSETS_DETECTED"
    else:
        scan_status = "VERIFIED_INERT"

    cert_summary = risk["cert_summary"]
    risk_detail_compact = {
        "active_risks": risk["active_risks"][:10],
        "passive_risks": risk["passive_risks"][:10],
        "pqc_ready_unused_libraries": risk["pqc_ready_unused_libraries"],
        "cert_key_types": cert_summary.get("key_type_counts", {}),
        "cert_sig_hashes": cert_summary.get("sig_hash_counts", {}),
    }

    cbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": tools_block,
            "component": base_component,
            "properties": [
                {"name": "trusted-oss:ecosystem", "value": ecosystem},
                {"name": "trusted-oss:artifact-path", "value": artifact_rel_path},
                {"name": "trusted-oss:crypto-scan-status", "value": scan_status},
                {"name": "trusted-oss:scan-scope", "value": risk["scan_scope"]},
                {"name": "trusted-oss:crypto-asset-count", "value": str(len(crypto_components))},
                {"name": "trusted-oss:crypto-risk-level", "value": risk["crypto_risk_level"]},
                {"name": "trusted-oss:active-risk-count", "value": str(risk["active_risk_count"])},
                {"name": "trusted-oss:passive-risk-count", "value": str(risk["passive_risk_count"])},
                {"name": "trusted-oss:cert-total", "value": str(cert_summary.get("total_unique", 0))},
                {"name": "trusted-oss:cert-expired", "value": str(cert_summary.get("expired_count", 0))},
                {"name": "trusted-oss:cert-expiring-90d", "value": str(cert_summary.get("expiring_90d_count", 0))},
                {"name": "trusted-oss:cert-sha1-roots", "value": str(cert_summary.get("sha1_root_count", 0))},
                {"name": "trusted-oss:cert-weak-keys", "value": str(cert_summary.get("weak_key_count", 0))},
                {"name": "trusted-oss:pqc-compiled-ready", "value": str(risk["pqc_compiled_ready"]).lower()},
                {"name": "trusted-oss:pqc-code-used", "value": str(risk["pqc_code_used"]).lower()},
                {"name": "trusted-oss:pqc-adoption-status", "value": risk["pqc_adoption_status"]},
                {"name": "trusted-oss:pqc-compiled-risk", "value": risk["compiled_risk"]},
                {"name": "trusted-oss:pqc-coding-risk", "value": risk["coding_risk"]},
                {"name": "trusted-oss:risk-detail-json", "value": json.dumps(risk_detail_compact, separators=(",", ":"))},
            ],
        },
        "components": crypto_components,
    }

    sbom_path = staged_file.with_name(f"{staged_file.name}.sbom.cdx.json")
    cbom_path = staged_file.with_name(f"{staged_file.name}.cbom.cdx.json")
    sbom_path.write_text(json.dumps(sbom_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    cbom_path.write_text(json.dumps(cbom_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return sbom_path, cbom_path, len(crypto_components), scan_status


def compute_file_sha256(file_path: Path) -> str:
    """Compute hex SHA-256 of a file."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def resolve_purl_to_bom_file(
    trusted_pypi_dir: Path,
    trusted_maven_dir: Path,
    harbor_oci_cache_dir: Path,
    purl: str,
    bom_type: str = "cbom",
) -> tuple[Path, Path] | None:
    """Resolve a canonical PURL to (base_artifact_path, bom_file_path) in trusted storage.

    Returns None if no matching promoted artifact with the requested BOM sidecar exists.
    """
    parsed = parse_purl(purl)
    if not parsed:
        return None

    eco = parsed["ecosystem"]
    namespace = parsed["namespace"]
    name = parsed["name"]
    version = parsed["version"]
    suffix = ".cbom.cdx.json" if bom_type == "cbom" else ".sbom.cdx.json"

    if eco == "pypi":
        try:
            norm_pkg = normalize_pypi_name(name)
        except ValueError:
            return None
        pkg_dir = trusted_pypi_dir / norm_pkg
        if not pkg_dir.is_dir() or not is_safe_subpath(trusted_pypi_dir, pkg_dir):
            return None
        candidates: list[tuple[Path, Path]] = []
        for bom_file in sorted(pkg_dir.iterdir(), key=lambda p: p.name):
            if bom_file.is_symlink() or not bom_file.is_file():
                continue
            if not bom_file.name.endswith(suffix):
                continue
            base_name = bom_file.name[: -len(suffix)]
            base_file = pkg_dir / base_name
            if not base_file.is_file():
                continue
            if version:
                if f"-{version}-" in base_name or f"-{version}." in base_name:
                    return base_file, bom_file
            else:
                candidates.append((base_file, bom_file))
        return candidates[-1] if candidates else None

    if eco == "maven":
        if not namespace:
            return None
        group_path = namespace.replace(".", "/")
        try:
            art_dir = resolve_safe_relative_path(trusted_maven_dir, f"{group_path}/{name}")
        except ValueError:
            return None
        if not art_dir.is_dir():
            return None
        search_dirs: list[Path] = []
        if version:
            try:
                vdir = resolve_safe_relative_path(art_dir, version)
            except ValueError:
                return None
            if vdir.is_dir():
                search_dirs.append(vdir)
        else:
            search_dirs = [p for p in sorted(art_dir.iterdir()) if p.is_dir() and not p.is_symlink()]

        for vdir in reversed(search_dirs):
            # Prefer .jar BOM over .pom BOM
            jar_matches: list[tuple[Path, Path]] = []
            other_matches: list[tuple[Path, Path]] = []
            for bom_file in sorted(vdir.iterdir(), key=lambda p: p.name):
                if bom_file.is_symlink() or not bom_file.is_file():
                    continue
                if not bom_file.name.endswith(suffix):
                    continue
                base_name = bom_file.name[: -len(suffix)]
                base_file = vdir / base_name
                if base_file.is_symlink() or not base_file.is_file():
                    continue
                if base_name.endswith(".jar"):
                    jar_matches.append((base_file, bom_file))
                else:
                    other_matches.append((base_file, bom_file))
            if jar_matches:
                return jar_matches[0]
            if other_matches:
                return other_matches[0]
        return None

    if eco in ("oci", "docker"):
        # Search harbor_oci_cache_dir for matching repo/manifests/<ref>
        repo_sub = f"{namespace}/{name}" if namespace else name
        ref = version or "latest"
        if not SAFE_SEGMENT_RE.match(ref):
            return None
        try:
            manifests_dir = resolve_safe_relative_path(harbor_oci_cache_dir, f"{repo_sub}/manifests")
            base_file = resolve_safe_relative_path(manifests_dir, ref)
            bom_file = resolve_safe_relative_path(manifests_dir, f"{ref}{suffix}")
        except ValueError:
            return None
        if (
            manifests_dir.is_dir()
            and base_file.is_file()
            and not base_file.is_symlink()
            and bom_file.is_file()
            and not bom_file.is_symlink()
        ):
            return base_file, bom_file
        return None

    return None
