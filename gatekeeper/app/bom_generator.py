"""Pure-Python CycloneDX 1.6 SBOM & CBOM generator and PURL resolver for Trusted OSS Gatekeeper."""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import tarfile
import uuid
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from app.storage import ArtifactDigests, is_safe_subpath, normalize_pypi_name

BOM_SCANNER_NAME = "trusted-oss-gatekeeper-bom"
BOM_SCANNER_VERSION = "1.0.0"

# Limits to keep per-artifact inspection fast and memory-bounded
MAX_ARCHIVE_MEMBERS = 250
MAX_MEMBER_BYTES = 512 * 1024  # 512 KiB per member

# Scannable text/source/bytecode/binary extensions inside wheels, sdists, and JARs
TEXT_SCAN_EXTS = (
    ".py", ".pyi", ".java", ".kt", ".kts", ".scala", ".groovy",
    ".js", ".ts", ".mjs", ".cjs", ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".rb", ".php", ".cs", ".swift", ".pem", ".crt", ".cer", ".conf", ".cfg",
    ".ini", ".properties", ".xml", ".json", ".yaml", ".yml", ".toml",
)
BINARY_SCAN_EXTS = (".class", ".so", ".dylib", ".dll", ".pyd")

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


def build_canonical_purl(
    ecosystem: str,
    pkg_name: str,
    pkg_version: str,
    artifact_rel_path: str = "",
) -> str:
    """Build a canonical Package URL (purl) for Maven, PyPI, or OCI artifacts."""
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


def _scan_text_for_crypto(text: str, location: str, found: dict[str, dict[str, Any]]) -> None:
    """Run compiled cryptographic regex rules over text and accumulate unique findings."""
    for regex, rule in _COMPILED_RULES:
        if regex.search(text):
            key = rule["name"]
            if key not in found:
                found[key] = {
                    "rule": rule,
                    "locations": [location],
                }
            elif len(found[key]["locations"]) < 5 and location not in found[key]["locations"]:
                found[key]["locations"].append(location)


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
                        raw = zf.read(info)[:MAX_MEMBER_BYTES].decode("utf-8", errors="replace")
                        for line in raw.splitlines():
                            if line.startswith("Requires-Dist:") and "; extra ==" not in line:
                                spec = line.split(":", 1)[1].strip().split(";")[0].strip()
                                m = re.match(r"^([A-Za-z0-9._-]+)", spec)
                                if m:
                                    deps.append({"ecosystem": "pypi", "name": m.group(1)})
                    elif fname.endswith("pom.xml"):
                        raw = zf.read(info)[:MAX_MEMBER_BYTES].decode("utf-8", errors="replace")
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


def inspect_artifact_crypto(file_path: Path) -> list[dict[str, Any]]:
    """Inspect an artifact (wheel, sdist, JAR, OCI manifest, or generic file) for cryptographic assets."""
    found: dict[str, dict[str, Any]] = {}
    name_lower = file_path.name.lower()

    if name_lower.endswith((".whl", ".jar", ".zip")) and zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path, "r") as zf:
            for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
                if info.is_dir():
                    continue
                member_lower = info.filename.lower()
                if member_lower.endswith(TEXT_SCAN_EXTS):
                    data = zf.read(info)[:MAX_MEMBER_BYTES]
                    _scan_text_for_crypto(
                        data.decode("utf-8", errors="ignore"), info.filename, found
                    )
                elif member_lower.endswith(BINARY_SCAN_EXTS):
                    data = zf.read(info)[:MAX_MEMBER_BYTES]
                    _scan_text_for_crypto(
                        _extract_printable_ascii(data), info.filename, found
                    )
    elif name_lower.endswith((".tar.gz", ".tgz")):
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
                    if member_lower.endswith(TEXT_SCAN_EXTS) or member_lower.endswith(BINARY_SCAN_EXTS):
                        extracted = tf.extractfile(member)
                        if extracted is None:
                            continue
                        data = extracted.read(MAX_MEMBER_BYTES)
                        text = (
                            data.decode("utf-8", errors="ignore")
                            if member_lower.endswith(TEXT_SCAN_EXTS)
                            else _extract_printable_ascii(data)
                        )
                        _scan_text_for_crypto(text, member.name, found)
        except tarfile.TarError:
            pass
    else:
        data = file_path.read_bytes()[:MAX_MEMBER_BYTES]
        _scan_text_for_crypto(data.decode("utf-8", errors="ignore"), file_path.name, found)

    components: list[dict[str, Any]] = []
    for key, entry in sorted(found.items()):
        rule = entry["rule"]
        asset_type = rule["asset_type"]
        crypto_props: dict[str, Any] = {"assetType": asset_type}
        if asset_type == "algorithm":
            algo_props: dict[str, Any] = {
                "name": rule["name"],
                "primitive": rule["primitive"],
                "parameterSetIdentifier": rule["param"],
            }
            crypto_props["algorithmProperties"] = algo_props
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

        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto:{key.lower()}",
                "name": rule["name"],
                "cryptoProperties": crypto_props,
                "evidence": {
                    "occurrences": [
                        {"location": loc} for loc in entry["locations"]
                    ]
                },
            }
        )
    return components


def generate_artifact_boms(
    staged_file: Path,
    ecosystem: str,
    pkg_name: str,
    pkg_version: str,
    artifact_rel_path: str,
    digests: ArtifactDigests,
) -> tuple[Path, Path, int, str]:
    """Generate CycloneDX 1.6 SBOM and CBOM sidecars next to staged_file.

    Returns (sbom_path, cbom_path, crypto_asset_count, scan_status).
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
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

    # 1. CycloneDX 1.6 SBOM
    extracted_deps = _extract_sbom_dependencies_from_archive(staged_file)
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
            ],
        },
        "components": sbom_components,
    }

    # 2. CycloneDX 1.6 CBOM
    crypto_components = inspect_artifact_crypto(staged_file)
    scan_status = "CRYPTO_ASSETS_DETECTED" if crypto_components else "VERIFIED_INERT"

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
                {"name": "trusted-oss:crypto-asset-count", "value": str(len(crypto_components))},
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
        art_dir = trusted_maven_dir / group_path / name
        if not art_dir.is_dir() or not is_safe_subpath(trusted_maven_dir, art_dir):
            return None
        search_dirs: list[Path] = []
        if version:
            vdir = art_dir / version
            if vdir.is_dir() and is_safe_subpath(trusted_maven_dir, vdir):
                search_dirs.append(vdir)
        else:
            search_dirs = [p for p in sorted(art_dir.iterdir()) if p.is_dir()]

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
                if not base_file.is_file():
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
        manifests_dir = harbor_oci_cache_dir / repo_sub / "manifests"
        if not manifests_dir.is_dir() or not is_safe_subpath(harbor_oci_cache_dir, manifests_dir):
            return None
        ref = version or "latest"
        base_file = manifests_dir / ref
        bom_file = manifests_dir / f"{ref}{suffix}"
        if base_file.is_file() and bom_file.is_file():
            return base_file, bom_file
        return None

    return None
