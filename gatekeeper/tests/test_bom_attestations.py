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
