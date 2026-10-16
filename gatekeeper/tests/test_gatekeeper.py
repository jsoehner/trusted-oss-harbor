"""Unit and integration tests for the Trusted OSS Quarantine-Scan-Sign Gatekeeper."""

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app, initialize_storage_and_keys
from app.scanner import EICAR_SIGNATURE, inspect_archive_safety
from app.storage import is_safe_subpath, resolve_safe_relative_path


def build_sample_jar(entries: dict[str, bytes]) -> bytes:
    """Create an in-memory JAR/Wheel archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture()
def test_settings(tmp_path: Path) -> Settings:
    """Configure isolated temporary storage and GPG keyring for testing."""
    data_root = tmp_path / "trusted-oss"
    return Settings(
        OSS_DATA_ROOT=data_root,
        CLAMAV_HOST="127.0.0.1",
        CLAMAV_PORT=65530,
        CLAMAV_REQUIRED=False,
        CVSS_FAIL_THRESHOLD=7.0,
        AUTO_PROMOTE_CLEAN_ARTIFACTS=False,
        GNUPGHOME=data_root / "keys" / "gnupg",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token",
    )


@pytest.fixture()
def client(test_settings: Settings) -> TestClient:
    """Create a FastAPI TestClient initialized with isolated test settings."""
    app.state.settings = test_settings
    initialize_storage_and_keys(test_settings)
    with TestClient(app) as c:
        yield c


def test_path_containment_blocks_traversal(tmp_path: Path) -> None:
    """Verify path containment rejects '..' and symlink traversal."""
    base = tmp_path / "repo"
    base.mkdir()
    with pytest.raises(ValueError, match="Invalid relative artifact path"):
        resolve_safe_relative_path(base, "../../etc/passwd")

    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    symlink_file = base / "escape.jar"
    symlink_file.symlink_to(outside)
    assert is_safe_subpath(base, symlink_file) is False


def test_archive_inspector_detects_eicar_and_zip_slip(tmp_path: Path) -> None:
    """Verify archive scanner blocks embedded EICAR malware and Zip-Slip entries."""
    infected_jar = tmp_path / "infected.jar"
    infected_jar.write_bytes(
        build_sample_jar({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "payload.bin": EICAR_SIGNATURE})
    )
    ok, reason = inspect_archive_safety(infected_jar)
    assert ok is False
    assert "EICAR" in reason

    zipslip_jar = tmp_path / "zipslip.jar"
    zipslip_jar.write_bytes(build_sample_jar({"../../evil.sh": b"#!/bin/sh\n"}))
    ok2, reason2 = inspect_archive_safety(zipslip_jar)
    assert ok2 is False
    assert "traversal" in reason2


def test_e2e_maven_ingest_scan_sign_and_serve(client: TestClient) -> None:
    """Verify a clean JAR is scanned, GPG-signed (.asc), recorded in provenance, and served."""
    clean_jar_bytes = build_sample_jar(
        {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "com/example/App.class": b"\xca\xfe\xba\xbe"}
    )
    rel_path = "com/example/demo-lib/1.0.0/demo-lib-1.0.0.jar"

    resp = client.post(
        f"/ingest/maven/{rel_path}",
        headers={"X-Gatekeeper-Token": "test-secret-token"},
        files={"file": ("demo-lib-1.0.0.jar", clean_jar_bytes, "application/java-archive")},
    )
    assert resp.status_code == 201, resp.text
    record = resp.json()
    assert record["ecosystem"] == "maven"
    assert record["artifact"] == rel_path
    assert record["signature_file"] == f"{rel_path}.asc"

    # Fetch the signed JAR and its detached GPG signature (.asc)
    jar_resp = client.get(f"/maven/trusted/{rel_path}")
    assert jar_resp.status_code == 200
    assert jar_resp.content == clean_jar_bytes

    asc_resp = client.get(f"/maven/trusted/{rel_path}.asc")
    assert asc_resp.status_code == 200
    assert "BEGIN PGP SIGNATURE" in asc_resp.text

    # Fetch the public key and provenance log
    key_resp = client.get("/keys/trusted-oss-pubkey.asc")
    assert key_resp.status_code == 200
    assert "BEGIN PGP PUBLIC KEY BLOCK" in key_resp.text

    audit_resp = client.get("/audit/provenance")
    assert audit_resp.status_code == 200
    assert audit_resp.json()["count"] == 1


def test_malware_and_high_cvss_rejected_from_promotion(client: TestClient) -> None:
    """Verify infected or high-CVSS packages are rejected with HTTP 451 and never promoted."""
    infected_whl = build_sample_jar({"pkg/__init__.py": EICAR_SIGNATURE})
    rel_path = "bad-pkg/bad_pkg-0.1.0-py3-none-any.whl"

    av_resp = client.post(
        f"/ingest/pypi/{rel_path}",
        headers={"X-Gatekeeper-Token": "test-secret-token"},
        files={"file": ("bad_pkg-0.1.0-py3-none-any.whl", infected_whl, "application/octet-stream")},
    )
    assert av_resp.status_code == 451
    assert "EICAR" in av_resp.json()["detail"]

    clean_whl = build_sample_jar({"pkg/__init__.py": b"__version__ = '0.1.0'\n"})
    cve_resp = client.post(
        f"/ingest/pypi/{rel_path}",
        headers={
            "X-Gatekeeper-Token": "test-secret-token",
            "X-Simulated-Cvss": "8.5",
        },
        files={"file": ("bad_pkg-0.1.0-py3-none-any.whl", clean_whl, "application/octet-stream")},
    )
    assert cve_resp.status_code == 451
    assert "CVSS 8.5 >= 7.0" in cve_resp.json()["detail"]

    # Confirm the rejected package is not served
    get_resp = client.get(f"/pypi/trusted/packages/{rel_path}")
    assert get_resp.status_code == 404


def test_pypi_pep503_simple_index_serves_signed_wheels(client: TestClient) -> None:
    """Verify PyPI Simple index exposes SHA-256 fragment and data-gpg-sig for signed wheels."""
    wheel_bytes = build_sample_jar({"requests/__init__.py": b"__version__ = '2.32.3'\n"})
    fname = "requests-2.32.3-py3-none-any.whl"
    resp = client.post(
        f"/ingest/pypi/requests/{fname}",
        headers={"X-Gatekeeper-Token": "test-secret-token"},
        files={"file": (fname, wheel_bytes, "application/octet-stream")},
    )
    assert resp.status_code == 201
    sha256_digest = resp.json()["sha256"]

    idx_resp = client.get("/pypi/trusted/simple/requests/")
    assert idx_resp.status_code == 200
    assert f"#sha256={sha256_digest}" in idx_resp.text
    assert 'data-gpg-sig="true"' in idx_resp.text

    whl_resp = client.get(f"/pypi/trusted/packages/requests/{fname}")
    assert whl_resp.status_code == 200
    assert whl_resp.content == wheel_bytes
