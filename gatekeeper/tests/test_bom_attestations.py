"""Tests for CycloneDX 1.6 SBOM/CBOM generation, dual-signing, PURL lookup, batch API, and OCI 1.1 Referrers."""

from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from app.bom_generator import build_canonical_purl, generate_artifact_boms, parse_purl
from app.config import Settings
from app.main import app, initialize_storage_and_keys
from app.signer import verify_artifact_mldsa65, verify_artifact_signature
from app.storage import compute_digests


def _make_wheel(path: Path, pkg_name: str, py_code: str, requires: str = "") -> Path:
    """Create a minimal valid Python .whl archive for testing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{pkg_name}/__init__.py", py_code)
        meta = f"Metadata-Version: 2.1\nName: {pkg_name}\nVersion: 1.2.3\n"
        if requires:
            meta += f"Requires-Dist: {requires}\n"
        zf.writestr(f"{pkg_name}-1.2.3.dist-info/METADATA", meta)
    return path


def test_parse_and_build_purl():
    assert build_canonical_purl("pypi", "My_Pkg", "2.0.1") == "pkg:pypi/my-pkg@2.0.1"
    assert build_canonical_purl("maven", "org.example:demo-lib", "3.1.0") == "pkg:maven/org.example/demo-lib@3.1.0"
    parsed = parse_purl("pkg:maven/org.example/demo-lib@3.1.0")
    assert parsed == {
        "ecosystem": "maven",
        "namespace": "org.example",
        "name": "demo-lib",
        "version": "3.1.0",
    }


def test_generate_boms_crypto_and_inert(tmp_path: Path):
    crypto_whl = _make_wheel(
        tmp_path / "cryptodemo-1.2.3-py3-none-any.whl",
        "cryptodemo",
        "import hashlib\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def f():\n    return hashlib.sha256(b'x'), rsa.generate_private_key(65537, 2048)\n",
        requires="cryptography>=42.0",
    )
    digests = compute_digests(crypto_whl)
    sbom_p, cbom_p, count, status = generate_artifact_boms(
        staged_file=crypto_whl,
        ecosystem="pypi",
        pkg_name="cryptodemo",
        pkg_version="1.2.3",
        artifact_rel_path="cryptodemo/cryptodemo-1.2.3-py3-none-any.whl",
        digests=digests,
    )
    assert sbom_p.is_file() and cbom_p.is_file()
    assert count >= 2
    assert status == "CRYPTO_ASSETS_DETECTED"
    cbom = json.loads(cbom_p.read_text(encoding="utf-8"))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["metadata"]["component"]["purl"] == "pkg:pypi/cryptodemo@1.2.3"
    algo_names = {c["name"] for c in cbom["components"]}
    assert "RSA" in algo_names and "SHA-256" in algo_names

    inert_whl = _make_wheel(
        tmp_path / "inertdemo-1.2.3-py3-none-any.whl",
        "inertdemo",
        "def add(a, b):\n    return a + b\n",
    )
    _, inert_cbom_p, inert_count, inert_status = generate_artifact_boms(
        staged_file=inert_whl,
        ecosystem="pypi",
        pkg_name="inertdemo",
        pkg_version="1.2.3",
        artifact_rel_path="inertdemo/inertdemo-1.2.3-py3-none-any.whl",
        digests=compute_digests(inert_whl),
    )
    assert inert_count == 0
    assert inert_status == "VERIFIED_INERT"
    inert_cbom = json.loads(inert_cbom_p.read_text(encoding="utf-8"))
    props = {p["name"]: p["value"] for p in inert_cbom["metadata"]["properties"]}
    assert props["trusted-oss:crypto-scan-status"] == "VERIFIED_INERT"


def test_ingest_generates_dual_signed_boms_and_serves_batch_lookup(tmp_path: Path):
    settings = Settings(
        OSS_DATA_ROOT=tmp_path,
        CLAMAV_REQUIRED=False,
        CVE_SCANNER_MODE="none",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token-1234",
        PQC_SIGNING_ENABLED=True,
        BOM_GENERATION_ENABLED=True,
        CVE_RESCAN_INTERVAL_SECONDS=0,
    )
    initialize_storage_and_keys(settings)
    app.state.settings = settings
    client = TestClient(app)

    crypto_whl = _make_wheel(
        tmp_path / "stage" / "pqcdemo-1.2.3-py3-none-any.whl",
        "pqcdemo",
        "ALG = 'ML-KEM-768'\n",
    )
    inert_whl = _make_wheel(
        tmp_path / "stage" / "plaindemo-1.2.3-py3-none-any.whl",
        "plaindemo",
        "X = 42\n",
    )

    for pkg, whl in (("pqcdemo", crypto_whl), ("plaindemo", inert_whl)):
        resp = client.post(
            f"/ingest/pypi/{pkg}/{whl.name}",
            headers={"X-Gatekeeper-Token": "test-secret-token-1234"},
            files={"file": (whl.name, whl.read_bytes(), "application/octet-stream")},
        )
        assert resp.status_code == 201, resp.text
        rec = resp.json()
        assert rec["cbom_file"].endswith(".cbom.cdx.json")
        assert rec["sbom_file"].endswith(".sbom.cdx.json")

        promoted_cbom = settings.trusted_pypi_dir / pkg / f"{whl.name}.cbom.cdx.json"
        assert promoted_cbom.is_file()
        assert verify_artifact_signature(
            promoted_cbom,
            promoted_cbom.with_name(f"{promoted_cbom.name}.asc"),
            settings.gnupghome,
        )
        assert verify_artifact_mldsa65(
            promoted_cbom,
            promoted_cbom.with_name(f"{promoted_cbom.name}.mldsa65"),
            settings.mldsa_public_key_path,
        )

    # PEP 503 index must NOT expose .cbom.cdx.json or .sbom.cdx.json
    idx_resp = client.get("/pypi/trusted/simple/pqcdemo/")
    assert idx_resp.status_code == 200
    assert ".cbom.cdx.json" not in idx_resp.text
    assert ".sbom.cdx.json" not in idx_resp.text

    # Single lookup
    lookup_resp = client.get("/bom/lookup", params={"purl": "pkg:pypi/pqcdemo@1.2.3"})
    assert lookup_resp.status_code == 200
    lookup_data = lookup_resp.json()
    assert lookup_data["cbom"]["metadata"]["component"]["purl"] == "pkg:pypi/pqcdemo@1.2.3"
    assert "BEGIN PGP SIGNATURE" in lookup_data["signature_gpg"]
    assert "BEGIN ML-DSA-65 SIGNATURE" in lookup_data["signature_mldsa65"]
    assert base64.b64decode(lookup_data["cbom_raw_b64"])

    # Batch lookup with hit + inert hit + miss
    batch_resp = client.post(
        "/bom/batch",
        json={
            "purls": [
                "pkg:pypi/pqcdemo@1.2.3",
                "pkg:pypi/plaindemo@1.2.3",
                "pkg:pypi/not-cached@9.9.9",
            ],
            "bom_type": "cbom",
            "include_signatures": True,
        },
    )
    assert batch_resp.status_code == 200
    bdata = batch_resp.json()
    assert bdata["found_count"] == 2
    assert bdata["missing_count"] == 1
    assert "pkg:pypi/pqcdemo@1.2.3" in bdata["found"]
    assert "pkg:pypi/plaindemo@1.2.3" in bdata["found"]
    assert bdata["missing"] == ["pkg:pypi/not-cached@9.9.9"]


def test_oci_v2_head_support_and_referrers_blobs(tmp_path: Path):
    """Verify OCI Distribution Spec v1.1 HEAD/GET routes required by ORAS CLI."""
    import hashlib

    settings = Settings(
        OSS_DATA_ROOT=tmp_path,
        CLAMAV_REQUIRED=False,
        CVE_SCANNER_MODE="none",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token-1234",
        PQC_SIGNING_ENABLED=False,
        BOM_GENERATION_ENABLED=True,
        CVE_RESCAN_INTERVAL_SECONDS=0,
    )
    manifests_dir = settings.harbor_oci_cache_dir / "chainguard" / "jre" / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    manifest_bytes = b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}'
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    (manifests_dir / "latest").write_bytes(manifest_bytes)
    (manifests_dir / "latest.sha256").write_text(manifest_sha, encoding="utf-8")

    cbom_bytes = b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}'
    sbom_bytes = b'{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{}}'
    cbom_sha = hashlib.sha256(cbom_bytes).hexdigest()
    (manifests_dir / "latest.cbom.cdx.json").write_bytes(cbom_bytes)
    (manifests_dir / "latest.sbom.cdx.json").write_bytes(sbom_bytes)

    app.state.settings = settings
    client = TestClient(app)

    # 1. OCI /v2/ ping supports both GET and HEAD
    assert client.get("/v2/").status_code == 200
    head_v2 = client.head("/v2/")
    assert head_v2.status_code == 200
    assert head_v2.headers.get("docker-distribution-api-version") == "registry/2.0"

    # 2. OCI 1.1 Referrers exposes CBOM & SBOM descriptors
    ref_resp = client.get(f"/v2/chainguard-cache/chainguard/jre/referrers/sha256:{manifest_sha}")
    assert ref_resp.status_code == 200
    ref_data = ref_resp.json()
    assert len(ref_data["manifests"]) == 2
    assert {m["annotations"]["io.cyclonedx.type"] for m in ref_data["manifests"]} == {"cbom", "sbom"}

    # 3. OCI /blobs/{digest} supports both HEAD (used by `oras blob fetch`) and GET
    blob_url = f"/v2/chainguard-cache/chainguard/jre/blobs/sha256:{cbom_sha}"
    head_blob = client.head(blob_url)
    assert head_blob.status_code == 200
    assert head_blob.headers.get("docker-content-digest") == f"sha256:{cbom_sha}"
    assert head_blob.content == b""

    get_blob = client.get(blob_url)
    assert get_blob.status_code == 200
    assert get_blob.content == cbom_bytes


def test_oci_digest_path_segment_and_bearer_challenge_parser(tmp_path: Path):
    """Verify OCI sha256 digest segments are allowed safely while unsafe colons remain blocked."""
    import pytest
    from app.main import _parse_www_authenticate_bearer
    from app.storage import resolve_safe_relative_path

    valid_digest = "sha256:" + ("a" * 64)
    p = resolve_safe_relative_path(tmp_path, f"apache/airflow/manifests/{valid_digest}")
    assert p == tmp_path / "apache" / "airflow" / "manifests" / valid_digest

    p_sig = resolve_safe_relative_path(tmp_path, f"apache/airflow/manifests/{valid_digest}.mldsa65")
    assert p_sig.name == f"{valid_digest}.mldsa65"

    for bad in ("C:/Windows/System32", "foo:bar", "sha256:nothex", "sha256:../escape"):
        with pytest.raises(ValueError):
            resolve_safe_relative_path(tmp_path, bad)

    challenge = _parse_www_authenticate_bearer(
        'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:apache/airflow:pull"'
    )
    assert challenge == {
        "realm": "https://auth.docker.io/token",
        "service": "registry.docker.io",
        "scope": "repository:apache/airflow:pull",
    }
    assert _parse_www_authenticate_bearer("Basic realm=\"other\"") == {}


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(val)) + val


def _der_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        enc = []
        while p > 0:
            enc.append(p & 0x7F)
            p >>= 7
        for i in range(len(enc) - 1, -1, -1):
            out.append(enc[i] | (0x80 if i > 0 else 0))
    return _der_tlv(0x06, bytes(out))


def _der_int(val: int) -> bytes:
    if val == 0:
        return _der_tlv(0x02, b"\x00")
    raw = val.to_bytes((val.bit_length() + 8) // 8, "big", signed=True)
    return _der_tlv(0x02, raw)


def _der_dn(cn: str) -> bytes:
    attr = _der_tlv(0x30, _der_oid("2.5.4.3") + _der_tlv(0x0C, cn.encode("utf-8")))
    return _der_tlv(0x30, _der_tlv(0x31, attr))


def _build_der_test_cert(
    cn: str,
    *,
    issuer_cn: str | None = None,
    bits: int = 2048,
    sig_oid: str = "1.2.840.113549.1.1.11",
    not_before: str = "200101000000Z",
    not_after: str = "350101000000Z",
    is_ca: bool = True,
    serial: int = 12345,
) -> bytes:
    """Build a valid ASN.1 DER X.509 v3 certificate without relying on host OpenSSL crypto-policy."""
    sig_alg = _der_tlv(0x30, _der_oid(sig_oid) + b"\x05\x00")
    modulus = (1 << (bits - 1)) | 1
    rsa_pub = _der_tlv(0x30, _der_int(modulus) + _der_int(65537))
    spki = _der_tlv(
        0x30,
        _der_tlv(0x30, _der_oid("1.2.840.113549.1.1.1") + b"\x05\x00")
        + _der_tlv(0x03, b"\x00" + rsa_pub),
    )
    validity = _der_tlv(
        0x30,
        _der_tlv(0x17, not_before.encode("ascii")) + _der_tlv(0x17, not_after.encode("ascii")),
    )
    bc_seq = _der_tlv(0x30, _der_tlv(0x01, b"\xff" if is_ca else b"\x00"))
    bc_ext = _der_tlv(0x30, _der_oid("2.5.29.19") + _der_tlv(0x01, b"\xff") + _der_tlv(0x04, bc_seq))
    exts = _der_tlv(0xA3, _der_tlv(0x30, bc_ext))

    tbs = _der_tlv(
        0x30,
        _der_tlv(0xA0, _der_int(2))
        + _der_int(serial)
        + sig_alg
        + _der_dn(issuer_cn or cn)
        + validity
        + _der_dn(cn)
        + spki
        + exts,
    )
    return _der_tlv(0x30, tbs + sig_alg + _der_tlv(0x03, b"\x00" + b"\xab" * 32))


def _wrap_pem(der_bytes: bytes) -> bytes:
    b64 = base64.b64encode(der_bytes).decode("ascii")
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n".encode("ascii")


def _build_jks_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a minimal valid Java JKS (magic 0xFEEDFEED, version 2) binary truststore."""
    import struct

    buf = bytearray(struct.pack(">III", 0xFEEDFEED, 2, len(entries)))
    for alias, der in entries:
        ab = alias.encode("utf-8")
        ct = b"X.509"
        buf.extend(struct.pack(">IH", 2, len(ab)))
        buf.extend(ab)
        buf.extend(struct.pack(">Q", 1700000000000))
        buf.extend(struct.pack(">H", len(ct)))
        buf.extend(ct)
        buf.extend(struct.pack(">I", len(der)))
        buf.extend(der)
    return bytes(buf)


def test_x509_and_jks_certificate_risk_audit(tmp_path: Path):
    """Verify pure-Python PEM/JKS X.509 parsing detects expired, SHA-1 root, chain SHA-1, and weak RSA-1024 certs."""
    import datetime
    import subprocess
    from app.crypto_risk import evaluate_certificates, parse_cert_store_bytes

    # Cross-check against a real OpenSSL-generated SHA-256 RSA-2048 certificate
    ossl_key = tmp_path / "ossl.key"
    ossl_crt = tmp_path / "ossl.crt"
    subprocess.run(["openssl", "genrsa", "-out", str(ossl_key), "2048"], check=True, capture_output=True)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-new", "-key", str(ossl_key),
            "-subj", "/CN=healthy-openssl-root/O=TrustedOSS-Test",
            "-days", "3650", "-sha256", "-out", str(ossl_crt),
        ],
        check=True,
        capture_output=True,
    )
    ossl_der = base64.b64decode("".join(l.strip() for l in ossl_crt.read_text().splitlines() if not l.startswith("-----")))

    sha1_root_der = _build_der_test_cert("legacy-sha1-root", bits=2048, sig_oid="1.2.840.113549.1.1.5", is_ca=True, serial=10)
    weak_key_der = _build_der_test_cert("weak-rsa1024-root", bits=1024, sig_oid="1.2.840.113549.1.1.11", is_ca=True, serial=11)
    expired_der = _build_der_test_cert("expired-root", bits=2048, sig_oid="1.2.840.113549.1.1.11", not_before="200101000000Z", not_after="240101000000Z", is_ca=True, serial=0)
    leaf_sha1_der = _build_der_test_cert("leaf-sha1-chain", issuer_cn="healthy-openssl-root", bits=2048, sig_oid="1.2.840.113549.1.1.5", is_ca=False, serial=12)

    pem_bundle = ossl_crt.read_bytes() + b"".join(
        _wrap_pem(d) for d in (sha1_root_der, weak_key_der, expired_der, leaf_sha1_der)
    )
    fmt_pem, pem_certs = parse_cert_store_bytes(pem_bundle, "etc/ssl/certs/ca-certificates.crt")
    assert fmt_pem == "PEM"
    assert len(pem_certs) == 5

    jks_bytes = _build_jks_bytes(
        [
            ("healthy", ossl_der),
            ("sha1root", sha1_root_der),
            ("weak1024", weak_key_der),
            ("expired", expired_der),
            ("leafsha1", leaf_sha1_der),
        ]
    )
    fmt_jks, jks_certs = parse_cert_store_bytes(jks_bytes, "etc/ssl/certs/java/cacerts")
    assert fmt_jks == "JKS"
    assert len(jks_certs) == 5

    ref_now = datetime.datetime(2026, 11, 26, 0, 0, 0, tzinfo=datetime.timezone.utc)
    summary = evaluate_certificates({c["fp"]: c for c in jks_certs}, now=ref_now)
    assert summary["total_unique"] == 5
    assert summary["expired_count"] == 1
    assert summary["sha1_root_count"] == 1
    assert summary["weak_sig_non_root_count"] == 1
    assert summary["weak_key_count"] == 1
    assert summary["non_ca_truststore_count"] == 1
    assert summary["non_positive_serial_count"] == 1


def test_oci_layer_deep_cbom_active_passive_and_pqc_gap(tmp_path: Path):
    """Verify OCI layer scanning detects active/passive risks, certs, and PQC compiled-vs-coding gap."""
    import datetime
    import io
    import tarfile

    sha1_root_pem = _wrap_pem(_build_der_test_cert("sha1-anchor", bits=2048, sig_oid="1.2.840.113549.1.1.5", is_ca=True))
    expired_pem = _wrap_pem(_build_der_test_cert("expired-anchor", bits=2048, sig_oid="1.2.840.113549.1.1.11", not_before="200101000000Z", not_after="240101000000Z", is_ca=True))

    layer_tar = tmp_path / "layer_00.tar.gz"
    with tarfile.open(layer_tar, "w:gz") as tf:
        files: dict[str, bytes] = {
            "lib/apk/db/installed": (
                b"P:openssl-4.0-libcrypto\nV:4.0.3-r8\nT:OpenSSL libcrypto\n\n"
                b"P:openjdk-27-jre\nV:27.0.1.0.3-r1\nT:OpenJDK 27 JRE\n\n"
                b"P:openssl-provider-legacy-allowed\nV:4.1.0-r0\nT:OpenSSL legacy provider\n\n"
            ),
            "etc/ssl/openssl.cnf": (
                b"[default]\nCHAINGUARD_LEGACY_ALLOWED = 1\nCHAINGUARD_LEGACY_ENABLE_DES = 0\n"
                b"[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n"
                b"[legacy_sect]\nactivate = $ENV::CHAINGUARD_LEGACY_ALLOWED\nenable-des = $ENV::CHAINGUARD_LEGACY_ENABLE_DES\n"
                b"[crypto_policy]\nTLS.MinProtocol = TLSv1.2\nGroups = X25519MLKEM768:x25519\n"
                b"SignatureAlgorithms = mldsa65:ecdsa_secp256r1_sha256\n"
            ),
            "usr/lib/jvm/java-27-openjdk/conf/security/java.security": (
                b"jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, 3DES_EDE_CBC, MD5withRSA\n"
                b"jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024\n"
            ),
            "usr/lib/libcrypto.so.4": b"OpenSSL 4.0.3 ML-KEM-768 ML-DSA-65 EVP_md5 EVP_sha1\n",
            "etc/ssl/certs/ca-certificates.crt": sha1_root_pem + expired_pem,
        }
        for rel, content in files.items():
            info = tarfile.TarInfo(name=rel)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))

    manifest_file = tmp_path / "latest"
    manifest_file.write_text('{"schemaVersion":2,"manifests":[]}', encoding="utf-8")

    # 1. Manifest-only OCI call (no layers) must report MANIFEST_ONLY_UNINSPECTED, never VERIFIED_INERT
    _, uninsp_cbom_p, _, uninsp_status = generate_artifact_boms(
        staged_file=manifest_file,
        ecosystem="oci-harbor",
        pkg_name="chainguard/jre",
        pkg_version="latest",
        artifact_rel_path="chainguard-cache/chainguard/jre/manifests/latest",
        digests=compute_digests(manifest_file),
    )
    assert uninsp_status == "MANIFEST_ONLY_UNINSPECTED"
    uninsp_props = {p["name"]: p["value"] for p in json.loads(uninsp_cbom_p.read_text())["metadata"]["properties"]}
    assert uninsp_props["trusted-oss:scan-scope"] == "oci-manifest-only"

    # 2. Full OCI layer scan must detect active/passive risks, cert issues, and PQC compiled-but-unused gap
    ref_now = datetime.datetime(2026, 11, 26, 0, 0, 0, tzinfo=datetime.timezone.utc)
    sbom_p, cbom_p, count, status = generate_artifact_boms(
        staged_file=manifest_file,
        ecosystem="oci-harbor",
        pkg_name="chainguard/jre",
        pkg_version="latest",
        artifact_rel_path="chainguard-cache/chainguard/jre/manifests/latest",
        digests=compute_digests(manifest_file),
        oci_layer_paths=[layer_tar],
        now=ref_now,
    )
    assert status == "CRYPTO_ASSETS_DETECTED"
    assert count >= 4

    sbom_doc = json.loads(sbom_p.read_text(encoding="utf-8"))
    sbom_names = {c["name"] for c in sbom_doc["components"]}
    assert "openssl-4.0-libcrypto" in sbom_names
    assert "openjdk-27-jre" in sbom_names

    cbom_doc = json.loads(cbom_p.read_text(encoding="utf-8"))
    props = {p["name"]: p["value"] for p in cbom_doc["metadata"]["properties"]}
    assert props["trusted-oss:scan-scope"] == "oci-layers"
    assert props["trusted-oss:crypto-risk-level"] == "CRITICAL"
    assert int(props["trusted-oss:active-risk-count"]) >= 2
    assert int(props["trusted-oss:passive-risk-count"]) >= 3
    assert props["trusted-oss:cert-expired"] == "1"
    assert props["trusted-oss:cert-sha1-roots"] == "1"
    assert props["trusted-oss:pqc-compiled-ready"] == "true"
    assert props["trusted-oss:pqc-code-used"] == "false"
    assert props["trusted-oss:pqc-adoption-status"] == "PQC_COMPILED_BUT_UNUSED"
    assert props["trusted-oss:pqc-compiled-risk"] == "LOW"
    assert props["trusted-oss:pqc-coding-risk"] == "MEDIUM"

    detail = json.loads(props["trusted-oss:risk-detail-json"])
    active_ids = {r["id"] for r in detail["active_risks"]}
    passive_ids = {r["id"] for r in detail["passive_risks"]}
    assert "EXPIRED_CERTIFICATE" in active_ids
    assert "ACTIVE_LEGACY_PROVIDER" in active_ids
    assert "SHA1_ROOT_CA_IN_TRUSTSTORE" in passive_ids
    assert "POLICY_DISABLED_LEGACY_ALGO" in passive_ids
    assert "PQC_COMPILED_BUT_UNUSED" in passive_ids
    assert any("openssl-4.0-libcrypto@4.0.3-r8" in lib for lib in detail["pqc_ready_unused_libraries"])


def test_pqc_compiled_and_used_vs_classical_only(tmp_path: Path):
    """Verify PQC coding-vs-compiled risk classification for Python wheels."""
    pqc_used_whl = _make_wheel(
        tmp_path / "pqcused-1.0.0-py3-none-any.whl",
        "pqcused",
        "ALG = 'ML-DSA-65'\nKEM = 'ML-KEM-768'\n",
        requires="dilithium-py>=1.5.1",
    )
    _, cbom_pqc_p, _, status1 = generate_artifact_boms(
        staged_file=pqc_used_whl,
        ecosystem="pypi",
        pkg_name="pqcused",
        pkg_version="1.0.0",
        artifact_rel_path="pqcused/pqcused-1.0.0-py3-none-any.whl",
        digests=compute_digests(pqc_used_whl),
    )
    assert status1 == "CRYPTO_ASSETS_DETECTED"
    p1 = {p["name"]: p["value"] for p in json.loads(cbom_pqc_p.read_text())["metadata"]["properties"]}
    assert p1["trusted-oss:pqc-adoption-status"] == "PQC_COMPILED_AND_USED"
    assert p1["trusted-oss:pqc-coding-risk"] == "LOW"

    classical_whl = _make_wheel(
        tmp_path / "legacyapp-1.0.0-py3-none-any.whl",
        "legacyapp",
        "import hashlib\ndef h(x): return hashlib.md5(x).hexdigest()\n",
    )
    _, cbom_cls_p, _, status2 = generate_artifact_boms(
        staged_file=classical_whl,
        ecosystem="pypi",
        pkg_name="legacyapp",
        pkg_version="1.0.0",
        artifact_rel_path="legacyapp/legacyapp-1.0.0-py3-none-any.whl",
        digests=compute_digests(classical_whl),
    )
    assert status2 == "CRYPTO_ASSETS_DETECTED"
    p2 = {p["name"]: p["value"] for p in json.loads(cbom_cls_p.read_text())["metadata"]["properties"]}
    assert p2["trusted-oss:pqc-adoption-status"] == "PQC_NOT_COMPILED_CLASSICAL_ONLY"
    assert p2["trusted-oss:pqc-compiled-risk"] == "HIGH"
    assert p2["trusted-oss:pqc-coding-risk"] == "HIGH"
    detail2 = json.loads(p2["trusted-oss:risk-detail-json"])
    assert any(r["id"] == "ACTIVE_CODE_WEAK_CRYPTO" for r in detail2["active_risks"])


def test_oras_referrers_and_catalog_crypto_risk_endpoints(tmp_path: Path):
    """Verify core ORAS Referrers annotations and /catalog/crypto-risk + /catalog/vulnerabilities reporting."""
    import hashlib
    import io
    import tarfile

    settings = Settings(
        OSS_DATA_ROOT=tmp_path,
        CLAMAV_REQUIRED=False,
        CVE_SCANNER_MODE="none",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token-1234",
        PQC_SIGNING_ENABLED=False,
        BOM_GENERATION_ENABLED=True,
        CVE_RESCAN_INTERVAL_SECONDS=0,
    )
    initialize_storage_and_keys(settings)
    app.state.settings = settings

    # Build a cached OCI manifest with deep layer CBOM
    sha1_root_pem = _wrap_pem(_build_der_test_cert("oras-sha1-root", bits=2048, sig_oid="1.2.840.113549.1.1.5", is_ca=True))
    layer_tar = tmp_path / "oci_layer.tar.gz"
    with tarfile.open(layer_tar, "w:gz") as tf:
        for rel, raw in (
            ("lib/apk/db/installed", b"P:openssl-4.0-libcrypto\nV:4.0.3-r8\nT:libcrypto\n\n"),
            ("etc/ssl/openssl.cnf", b"[default]\nCHAINGUARD_LEGACY_ALLOWED = 1\n[provider_sect]\nlegacy = legacy_sect\n[legacy_sect]\nactivate = $ENV::CHAINGUARD_LEGACY_ALLOWED\n"),
            ("etc/ssl/certs/ca-certificates.crt", sha1_root_pem),
        ):
            ti = tarfile.TarInfo(name=rel)
            ti.size = len(raw)
            tf.addfile(ti, io.BytesIO(raw))

    manifests_dir = settings.harbor_oci_cache_dir / "chainguard" / "jre" / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    manifest_file = manifests_dir / "latest"
    manifest_bytes = b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}'
    manifest_file.write_bytes(manifest_bytes)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    (manifests_dir / "latest.sha256").write_text(manifest_sha, encoding="utf-8")
    (manifests_dir / "latest.asc").write_text("dummy-sig", encoding="utf-8")

    generate_artifact_boms(
        staged_file=manifest_file,
        ecosystem="oci-harbor",
        pkg_name="chainguard/jre",
        pkg_version="latest",
        artifact_rel_path="chainguard-cache/chainguard/jre/manifests/latest",
        digests=compute_digests(manifest_file),
        oci_layer_paths=[layer_tar],
    )

    client = TestClient(app)

    # 1. Core ORAS Referrers endpoint exposes risk annotations
    ref_resp = client.get(f"/v2/chainguard-cache/chainguard/jre/referrers/sha256:{manifest_sha}")
    assert ref_resp.status_code == 200
    cbom_desc = next(m for m in ref_resp.json()["manifests"] if m["annotations"]["io.cyclonedx.type"] == "cbom")
    ann = cbom_desc["annotations"]
    assert ann["trusted-oss.crypto.scan-status"] == "CRYPTO_ASSETS_DETECTED"
    assert ann["trusted-oss.crypto.scan-scope"] == "oci-layers"
    assert ann["trusted-oss.crypto.cert-sha1-roots"] == "1"
    assert ann["trusted-oss.crypto.pqc-adoption"] == "PQC_COMPILED_BUT_UNUSED"

    # 2. Core /catalog/vulnerabilities embeds crypto_posture & summary counters
    vuln_resp = client.get("/catalog/vulnerabilities?ecosystem=oci&components=chainguard/jre")
    assert vuln_resp.status_code == 200
    vdata = vuln_resp.json()
    assert vdata["summary"]["crypto_active_risk_components"] == 1
    assert vdata["summary"]["cert_sha1_root_components"] == 1
    assert vdata["summary"]["pqc_compiled_unused_components"] == 1
    assert vdata["components"][0]["crypto_posture"]["pqc_adoption_status"] == "PQC_COMPILED_BUT_UNUSED"

    # 3. Dedicated /catalog/crypto-risk filter query
    cr_resp = client.get("/catalog/crypto-risk?only_active_risks=true&only_pqc_unused=true")
    assert cr_resp.status_code == 200
    cr_data = cr_resp.json()
    assert cr_data["count"] == 1
    assert cr_data["components"][0]["component"] == "chainguard/jre"
    assert cr_data["components"][0]["crypto_posture"]["coding_risk"] == "MEDIUM"


def test_parse_dpkg_status_and_oci_deb_sbom(tmp_path: Path):
    """Verify Debian dpkg status parsing populates pkg:deb SBOM components in OCI layer inspection."""
    import io
    import tarfile
    from app.bom_generator import inspect_oci_layers
    from app.crypto_risk import parse_dpkg_status

    status_text = (
        "Package: openssl\n"
        "Status: install ok installed\n"
        "Version: 3.5.0-1deb13u1\n\n"
        "Package: removed-legacy-pkg\n"
        "Status: deinstall ok config-files\n"
        "Version: 1.0.0\n"
    )
    fragment_text = "Package: libssl3t64\nVersion: 3.5.0-1deb13u1\n"

    parsed = parse_dpkg_status(status_text)
    assert parsed == [{"name": "openssl", "version": "3.5.0-1deb13u1"}]

    layer_tar = tmp_path / "debian_layer.tar.gz"
    with tarfile.open(layer_tar, "w:gz") as tf:
        for rel, raw in (
            ("var/lib/dpkg/status", status_text.encode("utf-8")),
            ("var/lib/dpkg/status.d/libssl3t64", fragment_text.encode("utf-8")),
        ):
            ti = tarfile.TarInfo(name=rel)
            ti.size = len(raw)
            tf.addfile(ti, io.BytesIO(raw))

    layer_res = inspect_oci_layers([layer_tar])
    deb_pkgs = {(p["name"], p["version"]) for p in layer_res["deb_packages"]}
    assert ("openssl", "3.5.0-1deb13u1") in deb_pkgs
    assert ("libssl3t64", "3.5.0-1deb13u1") in deb_pkgs
    assert ("removed-legacy-pkg", "1.0.0") not in deb_pkgs

    manifest_file = tmp_path / "slim-latest"
    manifest_file.write_text('{"schemaVersion":2,"manifests":[]}', encoding="utf-8")
    sbom_p, _, _, _ = generate_artifact_boms(
        staged_file=manifest_file,
        ecosystem="oci-harbor",
        pkg_name="apache/airflow",
        pkg_version="slim-latest",
        artifact_rel_path="docker-cache/apache/airflow/manifests/slim-latest",
        digests=compute_digests(manifest_file),
        oci_layer_paths=[layer_tar],
    )
    sbom_doc = json.loads(sbom_p.read_text(encoding="utf-8"))
    purls = {c["purl"] for c in sbom_doc["components"]}
    assert "pkg:deb/openssl@3.5.0-1deb13u1" in purls
    assert "pkg:deb/libssl3t64@3.5.0-1deb13u1" in purls
    assert all("removed-legacy-pkg" not in p for p in purls)


def test_backfill_cached_boms_deep_oci_all_namespaces_and_dedup(tmp_path: Path, monkeypatch):
    """Verify async backfill_cached_boms scans all OCI namespaces, deduplicates layers, and upgrades legacy BOMs."""
    import asyncio
    import hashlib
    import io
    import tarfile
    import app.main as main_mod

    settings = Settings(
        OSS_DATA_ROOT=tmp_path,
        CLAMAV_REQUIRED=False,
        CVE_SCANNER_MODE="none",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token-1234",
        PQC_SIGNING_ENABLED=True,
        BOM_GENERATION_ENABLED=True,
        OCI_BOM_DEEP_SCAN_ENABLED=True,
        CVE_RESCAN_INTERVAL_SECONDS=0,
    )
    initialize_storage_and_keys(settings)

    sha1_root_pem = _wrap_pem(_build_der_test_cert("backfill-sha1-root", bits=2048, sig_oid="1.2.840.113549.1.1.5", is_ca=True))

    def _write_manifest_with_legacy_boms(manifests_dir: Path, ref: str, payload: bytes) -> Path:
        manifests_dir.mkdir(parents=True, exist_ok=True)
        mfile = manifests_dir / ref
        mfile.write_bytes(payload)
        msha = hashlib.sha256(payload).hexdigest()
        (manifests_dir / f"{ref}.sha256").write_text(msha, encoding="utf-8")
        (manifests_dir / f"{ref}.asc").write_text("dummy-manifest-sig", encoding="utf-8")
        legacy_cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [],
            "metadata": {"properties": [{"name": "trusted-oss:crypto-scan-status", "value": "VERIFIED_INERT"}]},
        }
        (manifests_dir / f"{ref}.cbom.cdx.json").write_text(json.dumps(legacy_cbom), encoding="utf-8")
        (manifests_dir / f"{ref}.sbom.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}), encoding="utf-8")
        return mfile

    cg_dir = settings.harbor_oci_cache_dir / "chainguard" / "jre" / "manifests"
    cg_payload = b'{"schemaVersion":2,"tag":"latest"}'
    cg_digest_ref = f"sha256:{hashlib.sha256(cg_payload).hexdigest()}"
    cg_latest = _write_manifest_with_legacy_boms(cg_dir, "latest", cg_payload)
    cg_dig_file = _write_manifest_with_legacy_boms(cg_dir, cg_digest_ref, cg_payload)

    docker_dir = settings.oss_data_root / "harbor" / "registry" / "docker-cache" / "apache" / "airflow" / "manifests"
    docker_payload = b'{"schemaVersion":2,"tag":"slim-latest"}'
    docker_manifest = _write_manifest_with_legacy_boms(docker_dir, "slim-latest", docker_payload)

    fetch_calls: list[tuple[str, str]] = []

    async def _fake_fetch_layers(*, upstream_base_url, repo_path, manifest_bytes, staging_dir, settings):
        fetch_calls.append((upstream_base_url, repo_path))
        staging_dir.mkdir(parents=True, exist_ok=True)
        out = staging_dir / "layer_00.tar.gz"
        with tarfile.open(out, "w:gz") as tf:
            entries = (
                [
                    ("lib/apk/db/installed", b"P:openssl-4.0-libcrypto\nV:4.0.3-r8\nT:libcrypto\n\n"),
                    ("etc/ssl/certs/ca-certificates.crt", sha1_root_pem),
                    ("etc/ssl/openssl.cnf", b"[default]\nCHAINGUARD_LEGACY_ALLOWED = 1\n[provider_sect]\nlegacy = legacy_sect\n[legacy_sect]\nactivate = $ENV::CHAINGUARD_LEGACY_ALLOWED\n"),
                ]
                if "chainguard" in repo_path
                else [
                    ("var/lib/dpkg/status", b"Package: openssl\nStatus: install ok installed\nVersion: 3.5.0-1\n\n"),
                    ("etc/ssl/certs/ca-certificates.crt", sha1_root_pem),
                    ("usr/lib/libcrypto.so.3", b"OpenSSL 3.5.0 ML-KEM-768\n"),
                ]
            )
            for rel, raw in entries:
                ti = tarfile.TarInfo(name=rel)
                ti.size = len(raw)
                tf.addfile(ti, io.BytesIO(raw))
        return [out]

    monkeypatch.setattr(main_mod, "fetch_upstream_oci_layers_for_bom", _fake_fetch_layers)

    summary = asyncio.run(main_mod.backfill_cached_boms(settings=settings, force=True, deep_oci=True))
    assert summary["errors"] == []
    assert summary["scanned"] == 3
    assert summary["generated"] == 3
    assert summary["oci_deep_scanned"] == 3
    # Same (chainguard-cache, chainguard/jre, sha256) should fetch upstream layers once, plus once for docker-cache
    assert len(fetch_calls) == 2
    assert any("registry-1.docker.io" in u and r == "apache/airflow" for u, r in fetch_calls)

    for mf in (cg_latest, cg_dig_file, docker_manifest):
        sbom_p = mf.with_name(f"{mf.name}.sbom.cdx.json")
        cbom_p = mf.with_name(f"{mf.name}.cbom.cdx.json")
        sbom_doc = json.loads(sbom_p.read_text(encoding="utf-8"))
        cbom_doc = json.loads(cbom_p.read_text(encoding="utf-8"))
        props = {p["name"]: p["value"] for p in cbom_doc["metadata"]["properties"]}
        assert len(sbom_doc["components"]) >= 1
        assert props["trusted-oss:scan-scope"] == "oci-layers"
        assert props["trusted-oss:crypto-scan-status"] == "CRYPTO_ASSETS_DETECTED"
        assert props["trusted-oss:cert-sha1-roots"] == "1"
        assert props["trusted-oss:pqc-adoption-status"] == "PQC_COMPILED_BUT_UNUSED"
        for bom_p in (sbom_p, cbom_p):
            assert verify_artifact_signature(bom_p, bom_p.with_name(f"{bom_p.name}.asc"), settings.gnupghome)
            assert verify_artifact_mldsa65(bom_p, bom_p.with_name(f"{bom_p.name}.mldsa65"), settings.mldsa_public_key_path)


def test_backfill_cached_boms_ecosystem_filter(tmp_path: Path, monkeypatch):
    """Verify ecosystem filter on backfill_cached_boms and POST /catalog/backfill-boms."""
    import asyncio
    import app.main as main_mod

    settings = Settings(
        OSS_DATA_ROOT=tmp_path,
        CLAMAV_REQUIRED=False,
        CVE_SCANNER_MODE="none",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token-1234",
        PQC_SIGNING_ENABLED=False,
        BOM_GENERATION_ENABLED=True,
        OCI_BOM_DEEP_SCAN_ENABLED=False,
        CVE_RESCAN_INTERVAL_SECONDS=0,
    )

    # Seed one promoted artifact in each ecosystem (pypi, maven, oci)
    pypi_file = settings.trusted_pypi_dir / "demo" / "demo-1.0.0-py3-none-any.whl"
    pypi_file.parent.mkdir(parents=True, exist_ok=True)
    pypi_file.write_bytes(b"pypi-bytes")
    pypi_file.with_name(f"{pypi_file.name}.asc").write_text("sig", encoding="utf-8")

    maven_file = settings.trusted_maven_dir / "org" / "demo" / "lib" / "1.0" / "lib-1.0.jar"
    maven_file.parent.mkdir(parents=True, exist_ok=True)
    maven_file.write_bytes(b"maven-bytes")
    maven_file.with_name(f"{maven_file.name}.asc").write_text("sig", encoding="utf-8")

    oci_file = settings.harbor_oci_cache_dir / "chainguard" / "jre" / "manifests" / "latest"
    oci_file.parent.mkdir(parents=True, exist_ok=True)
    oci_file.write_bytes(b'{"schemaVersion":2,"manifests":[]}')
    oci_file.with_name(f"{oci_file.name}.asc").write_text("sig", encoding="utf-8")

    monkeypatch.setattr(main_mod, "sign_artifact_detached_gpg", lambda **kw: kw["artifact_path"].with_name(f"{kw['artifact_path'].name}.asc").write_text("sig", encoding="utf-8"))

    # 1. OCI-only filter skips PyPI and Maven
    oci_summary = asyncio.run(
        main_mod.backfill_cached_boms(settings=settings, force=True, deep_oci=False, ecosystems={"oci"})
    )
    assert oci_summary["ecosystem_filter"] == ["oci"]
    assert oci_summary["scanned"] == 1
    assert oci_summary["generated"] == 1
    assert oci_file.with_name("latest.sbom.cdx.json").is_file()
    assert not pypi_file.with_name(f"{pypi_file.name}.sbom.cdx.json").is_file()
    assert not maven_file.with_name(f"{maven_file.name}.sbom.cdx.json").is_file()

    # 2. HTTP endpoint rejects invalid ecosystem filter with 400
    app.state.settings = settings
    client = TestClient(app)
    bad_resp = client.post(
        "/catalog/backfill-boms?ecosystem=invalid&force=true&wait=true",
        headers={"X-Gatekeeper-Token": "test-secret-token-1234"},
    )
    assert bad_resp.status_code == 400

    # 3. HTTP endpoint with ecosystem=pypi only processes PyPI
    pypi_resp = client.post(
        "/catalog/backfill-boms?ecosystem=pypi&force=true&wait=true",
        headers={"X-Gatekeeper-Token": "test-secret-token-1234"},
    )
    assert pypi_resp.status_code == 200
    pdata = pypi_resp.json()
    assert pdata["ecosystem_filter"] == ["pypi"]
    assert pdata["scanned"] == 1
    assert pdata["generated"] == 1
    assert pypi_file.with_name(f"{pypi_file.name}.sbom.cdx.json").is_file()
    assert not maven_file.with_name(f"{maven_file.name}.sbom.cdx.json").is_file()


def test_inspect_oci_layers_wolfi_usrmerge_apk_db(tmp_path: Path):
    """Verify Wolfi/Chainguard usrmerge usr/lib/apk/db/installed across multiple layers populates SBOM components."""
    import io
    import tarfile
    from app.bom_generator import inspect_oci_layers

    layer0 = tmp_path / "layer0.tar.gz"
    layer1 = tmp_path / "layer1.tar.gz"
    with tarfile.open(layer0, "w:gz") as tf:
        raw = b"P:openjdk-27-jre\nV:27.0.1.1-r2\nT:OpenJDK 27 JRE\n\nP:glibc-2.44\nV:2.44-r28\n\n"
        ti = tarfile.TarInfo(name="usr/lib/apk/db/installed")
        ti.size = len(raw)
        tf.addfile(ti, io.BytesIO(raw))
    with tarfile.open(layer1, "w:gz") as tf:
        raw = b"P:openssl-4.0-libcrypto\nV:4.0.3-r8\n\nP:glibc-2.44\nV:2.44-r28\n\n"
        ti = tarfile.TarInfo(name="usr/lib/apk/db/installed")
        ti.size = len(raw)
        tf.addfile(ti, io.BytesIO(raw))

    res = inspect_oci_layers([layer0, layer1])
    pkgs = {(p["name"], p["version"]) for p in res["apk_packages"]}
    assert pkgs == {
        ("openjdk-27-jre", "27.0.1.1-r2"),
        ("glibc-2.44", "2.44-r28"),
        ("openssl-4.0-libcrypto", "4.0.3-r8"),
    }
    assert len(res["apk_packages"]) == 3
