"""Comprehensive unit, protocol, security, and end-to-end tests for the Trusted OSS Gatekeeper."""

from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import socketserver
import struct
import tarfile
import threading
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app, initialize_storage_and_keys
from app.scanner import EICAR_SIGNATURE, inspect_archive_safety, scan_with_clamd_instream
from app.signer import (
    ensure_gpg_signing_key,
    ensure_mldsa_signing_key,
    sign_artifact_detached_gpg,
    sign_artifact_mldsa65,
    verify_artifact_mldsa65,
)
from app.storage import (
    is_safe_subpath,
    normalize_pypi_name,
    resolve_safe_relative_path,
)


CLAMD_CUSTOM_MALWARE_MARKER = b"MALICIOUS-BYTECODE-SIGNATURE-2026"


def build_sample_jar(entries: dict[str, bytes], symlink_entry: str | None = None) -> bytes:
    """Create an in-memory JAR/Wheel/ZIP archive with optional symlink entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink_entry:
            info = zipfile.ZipInfo(symlink_entry)
            info.create_system = 3  # Unix
            info.external_attr = (0o120777 << 16)  # S_IFLNK
            zf.writestr(info, b"/etc/shadow")
    return buf.getvalue()


def build_sample_tar_gz(
    entries: dict[str, bytes],
    symlink_name: str | None = None,
    hardlink_name: str | None = None,
) -> bytes:
    """Create an in-memory .tar.gz sdist archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        if symlink_name:
            sym = tarfile.TarInfo(name=symlink_name)
            sym.type = tarfile.SYMTYPE
            sym.linkname = "/etc/passwd"
            tf.addfile(sym)
        if hardlink_name:
            lnk = tarfile.TarInfo(name=hardlink_name)
            lnk.type = tarfile.LNKTYPE
            lnk.linkname = "PKG-INFO"
            tf.addfile(lnk)
    return buf.getvalue()


class MockClamdTCPHandler(socketserver.BaseRequestHandler):
    """Real TCP socket handler implementing ClamAV's binary zINSTREAM\\0 protocol."""

    def handle(self) -> None:
        header = self.request.recv(10)
        if header != b"zINSTREAM\x00":
            self.request.sendall(b"stream: COMMAND READ TIMED OUT\x00")
            return

        stream_buf = bytearray()
        while True:
            raw_len = self._recv_exact(4)
            if not raw_len:
                break
            (chunk_len,) = struct.unpack("!I", raw_len)
            if chunk_len == 0:
                break
            chunk = self._recv_exact(chunk_len)
            stream_buf.extend(chunk)

        if self._contains_signature(bytes(stream_buf), EICAR_SIGNATURE):
            self.request.sendall(b"stream: Win.Test.EICAR_HDB-1 FOUND\x00")
        elif self._contains_signature(bytes(stream_buf), CLAMD_CUSTOM_MALWARE_MARKER):
            self.request.sendall(b"stream: Java.Trojan.SupplyChain-99 FOUND\x00")
        else:
            self.request.sendall(b"stream: OK\x00")

    @staticmethod
    def _contains_signature(payload: bytes, marker: bytes) -> bool:
        if marker in payload:
            return True
        if zipfile.is_zipfile(io.BytesIO(payload)):
            with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
                for info in zf.infolist():
                    if marker in zf.read(info.filename):
                        return True
        return False

    def _recv_exact(self, n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            packet = self.request.recv(n - len(data))
            if not packet:
                break
            data.extend(packet)
        return bytes(data)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


@pytest.fixture()
def mock_clamd_server():
    """Start a real background TCP server speaking ClamAV's zINSTREAM protocol."""
    server = ThreadedTCPServer(("127.0.0.1", 0), MockClamdTCPHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield host, port
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def mock_upstream_registry():
    """Start a local HTTP server simulating Chainguard (cgr.dev), Maven Central, and PyPI."""
    catalog_path = (
        Path(__file__).resolve().parents[2]
        / "config"
        / "catalog"
        / "trusted-seed-catalog.json"
    )
    import json as _json

    catalog_data = _json.loads(catalog_path.read_text(encoding="utf-8"))

    artifacts: dict[str, bytes] = {
        "/maven2/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar": build_sample_jar(
            {
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
                "org/slf4j/Logger.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x3d",
            }
        ),
        "/maven2/org/evil/backdoor/1.0.0/backdoor-1.0.0.jar": build_sample_jar(
            {
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
                "org/evil/Exploit.class": CLAMD_CUSTOM_MALWARE_MARKER,
            }
        ),
        "/pypi/urllib3/urllib3-2.2.3-py3-none-any.whl": build_sample_jar(
            {"urllib3/__init__.py": b"__version__ = '2.2.3'\n"}
        ),
        "/v2/chainguard/jre/manifests/latest": _json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "subject": "cgr.dev/chainguard/jre:latest",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:665d04353c8404fcb6649b39636f2b3b7b9870d29163654718d7059563feef7c",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    }
                ],
            }
        ).encode("utf-8"),
        "/v2/chainguard/python/manifests/latest": _json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "subject": "cgr.dev/chainguard/python:latest",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:991b04353c8404fcb6649b39636f2b3b7b9870d29163654718d7059563feef88",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    }
                ],
            }
        ).encode("utf-8"),
    }

    for comp in catalog_data.get("spring_boot_maven_components", []):
        for rel in comp.get("artifacts", []):
            key = f"/maven2/{rel}"
            if key not in artifacts:
                if rel.endswith(".pom"):
                    artifacts[key] = (
                        f"<project><groupId>{comp['groupId']}</groupId>"
                        f"<artifactId>{comp['artifactId']}</artifactId>"
                        f"<version>{comp['version']}</version></project>\n"
                    ).encode("utf-8")
                else:
                    artifacts[key] = build_sample_jar(
                        {
                            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
                            f"META-INF/spring/{comp['artifactId']}.imports": b"AutoConfiguration\n",
                        }
                    )

    class UpstreamHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path_only = self.path.split("?", 1)[0]
            if path_only == "/token":
                body = b'{"token":"chainguard-mock-bearer-token"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path_only.startswith("/v2/chainguard/"):
                auth = self.headers.get("Authorization", "")
                if auth != "Bearer chainguard-mock-bearer-token":
                    self.send_response(401)
                    self.send_header(
                        "WWW-Authenticate",
                        'Bearer realm="/token",service="cgr.dev"',
                    )
                    self.end_headers()
                    return

            payload = artifacts.get(path_only)
            if payload is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

    server = HTTPServer(("127.0.0.1", 0), UpstreamHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def test_settings(tmp_path: Path, mock_clamd_server: tuple[str, int]) -> Settings:
    """Configure isolated temporary storage, GPG keyring, and live mock clamd server."""
    clamd_host, clamd_port = mock_clamd_server
    data_root = tmp_path / "trusted-oss"
    return Settings(
        OSS_DATA_ROOT=data_root,
        CLAMAV_HOST=clamd_host,
        CLAMAV_PORT=clamd_port,
        CLAMAV_REQUIRED=True,
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


# ==============================================================================
# Suite A: Path Containment, Traversal, Symlink & PEP 503 Normalization Tests
# ==============================================================================


@pytest.mark.parametrize(
    "malicious_path",
    [
        "../../etc/passwd",
        "com/example/../../../etc/shadow",
        "",
        "/",
        "com/example/bad;rm -rf/1.0/a.jar",
        "com/example/$HOME/1.0/a.jar",
    ],
)
def test_path_containment_blocks_traversal_and_unsafe_chars(
    tmp_path: Path, malicious_path: str
) -> None:
    """Verify path containment rejects '..' and shell metacharacters."""
    base = tmp_path / "repo"
    base.mkdir()
    with pytest.raises(ValueError):
        resolve_safe_relative_path(base, malicious_path)


def test_path_containment_blocks_direct_and_parent_symlinks(tmp_path: Path) -> None:
    """Verify symlink escape attempts (both leaf and intermediate directory) are rejected."""
    base = tmp_path / "repo"
    base.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("top-secret", encoding="utf-8")

    leaf_symlink = base / "escape.jar"
    leaf_symlink.symlink_to(outside_file)
    assert is_safe_subpath(base, leaf_symlink) is False

    dir_symlink = base / "linked_dir"
    dir_symlink.symlink_to(outside_dir)
    assert is_safe_subpath(base, dir_symlink / "secret.txt") is False


def test_pypi_package_name_normalization_and_validation() -> None:
    """Verify PEP 503 normalization collapses runs of '-', '_', and '.' into a single '-'."""
    assert normalize_pypi_name("FastAPI_Cloud.Utils--Extra") == "fastapi-cloud-utils-extra"
    with pytest.raises(ValueError, match="Invalid PyPI package name"):
        normalize_pypi_name("---...___")


# ==============================================================================
# Suite B: Archive Security Inspector (.jar, .whl, .zip, .tar.gz)
# ==============================================================================


def test_archive_inspector_detects_eicar_and_zip_slip(tmp_path: Path) -> None:
    """Verify archive scanner blocks embedded EICAR malware and Zip-Slip entries."""
    infected_jar = tmp_path / "infected.jar"
    infected_jar.write_bytes(
        build_sample_jar(
            {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "payload.bin": EICAR_SIGNATURE}
        )
    )
    ok, reason = inspect_archive_safety(infected_jar)
    assert ok is False
    assert "EICAR" in reason

    zipslip_jar = tmp_path / "zipslip.jar"
    zipslip_jar.write_bytes(build_sample_jar({"../../evil.sh": b"#!/bin/sh\n"}))
    ok2, reason2 = inspect_archive_safety(zipslip_jar)
    assert ok2 is False
    assert "traversal" in reason2


def test_archive_inspector_detects_zip_symlinks_and_corrupt_archives(tmp_path: Path) -> None:
    """Verify ZIP/JAR/Wheel archives with Unix symlink modes or corrupt headers are rejected."""
    symlink_jar = tmp_path / "symlink.jar"
    symlink_jar.write_bytes(
        build_sample_jar({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"}, symlink_entry="evil_link")
    )
    ok, reason = inspect_archive_safety(symlink_jar)
    assert ok is False
    assert "Symlink entry prohibited" in reason

    corrupt_jar = tmp_path / "corrupt.jar"
    corrupt_jar.write_bytes(b"not-a-valid-zip-header")
    ok_corrupt, reason_corrupt = inspect_archive_safety(corrupt_jar)
    assert ok_corrupt is False
    assert "Corrupt or invalid" in reason_corrupt


def test_archive_inspector_tar_gz_sdist_security(tmp_path: Path) -> None:
    """Verify .tar.gz Python sdists are checked for tar-slip, symlinks, hardlinks, and EICAR."""
    clean_tgz = tmp_path / "clean-1.0.0.tar.gz"
    clean_tgz.write_bytes(build_sample_tar_gz({"clean-1.0.0/PKG-INFO": b"Name: clean\n"}))
    assert inspect_archive_safety(clean_tgz) == (True, "CLEAN")

    tarslip_tgz = tmp_path / "tarslip-1.0.0.tar.gz"
    tarslip_tgz.write_bytes(build_sample_tar_gz({"../escape.py": b"import os\n"}))
    ok_slip, msg_slip = inspect_archive_safety(tarslip_tgz)
    assert ok_slip is False
    assert "Tar path traversal" in msg_slip

    sym_tgz = tmp_path / "symlink-1.0.0.tar.gz"
    sym_tgz.write_bytes(
        build_sample_tar_gz({"PKG-INFO": b"Name: sym\n"}, symlink_name="sym/passwd")
    )
    ok_sym, msg_sym = inspect_archive_safety(sym_tgz)
    assert ok_sym is False
    assert "Symlink/hardlink" in msg_sym

    lnk_tgz = tmp_path / "hardlink-1.0.0.tar.gz"
    lnk_tgz.write_bytes(
        build_sample_tar_gz({"PKG-INFO": b"Name: lnk\n"}, hardlink_name="lnk/hard")
    )
    ok_lnk, msg_lnk = inspect_archive_safety(lnk_tgz)
    assert ok_lnk is False
    assert "Symlink/hardlink" in msg_lnk


# ==============================================================================
# Suite C: Live TCP clamd (zINSTREAM\0) Binary Protocol Tests
# ==============================================================================


@pytest.mark.anyio
async def test_clamd_instream_tcp_protocol_clean_infected_and_fail_closed(
    tmp_path: Path, mock_clamd_server: tuple[str, int]
) -> None:
    """Verify binary zINSTREAM protocol against a real TCP server and fail-closed behavior."""
    host, port = mock_clamd_server

    clean_file = tmp_path / "clean.jar"
    clean_file.write_bytes(build_sample_jar({"App.class": b"\xca\xfe\xba\xbe"}))
    ok_clean, status_clean = await scan_with_clamd_instream(clean_file, host, port, required=True)
    assert ok_clean is True
    assert status_clean == "CLAMD_OK"

    trojan_file = tmp_path / "trojan.jar"
    trojan_file.write_bytes(build_sample_jar({"Exploit.class": CLAMD_CUSTOM_MALWARE_MARKER}))
    ok_trojan, status_trojan = await scan_with_clamd_instream(trojan_file, host, port, required=True)
    assert ok_trojan is False
    assert "Java.Trojan.SupplyChain-99 FOUND" in status_trojan

    # Unreachable clamd port must fail closed when required=True
    ok_down, status_down = await scan_with_clamd_instream(
        clean_file, "127.0.0.1", 65531, required=True
    )
    assert ok_down is False
    assert "ClamAV daemon unreachable" in status_down


# ==============================================================================
# Suite D: Cryptographic Signing, Read-Time Tamper Detection & Rogue Key Rejection
# ==============================================================================


def test_e2e_maven_ingest_scan_sign_and_serve(client: TestClient) -> None:
    """Verify a clean JAR is scanned via clamd, GPG-signed (.asc), recorded in provenance, and served."""
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
    assert record["clamav_status"] == "CLAMD_OK"
    assert record["artifact"] == rel_path
    assert record["signature_file"] == f"{rel_path}.asc"

    # Fetch the signed JAR, detached GPG signature (.asc), and SHA-256 digest
    jar_resp = client.get(f"/maven/trusted/{rel_path}")
    assert jar_resp.status_code == 200
    assert jar_resp.content == clean_jar_bytes

    asc_resp = client.get(f"/maven/trusted/{rel_path}.asc")
    assert asc_resp.status_code == 200
    assert "BEGIN PGP SIGNATURE" in asc_resp.text

    sha_resp = client.get(f"/maven/trusted/{rel_path}.sha256")
    assert sha_resp.status_code == 200
    assert sha_resp.text.strip() == record["sha256"]

    # Fetch the public key and provenance log
    key_resp = client.get("/keys/trusted-oss-pubkey.asc")
    assert key_resp.status_code == 200
    assert "BEGIN PGP PUBLIC KEY BLOCK" in key_resp.text

    audit_resp = client.get("/audit/provenance")
    assert audit_resp.status_code == 200
    assert audit_resp.json()["count"] == 1


def test_tampered_artifact_or_rogue_signature_blocked_on_read(
    client: TestClient, test_settings: Settings, tmp_path: Path
) -> None:
    """Verify that post-promotion tampering or signing with an untrusted key triggers HTTP 403."""
    jar_bytes = build_sample_jar({"com/example/Safe.class": b"\xca\xfe\xba\xbe"})
    rel_path = "com/example/safe/1.0.0/safe-1.0.0.jar"
    resp = client.post(
        f"/ingest/maven/{rel_path}",
        headers={"X-Gatekeeper-Token": "test-secret-token"},
        files={"file": ("safe-1.0.0.jar", jar_bytes, "application/java-archive")},
    )
    assert resp.status_code == 201

    # 1. Flip a single byte in the promoted JAR on disk (simulating storage tampering)
    promoted_jar = test_settings.trusted_maven_dir / rel_path
    tampered_bytes = bytearray(promoted_jar.read_bytes())
    tampered_bytes[-1] ^= 0xFF
    promoted_jar.write_bytes(bytes(tampered_bytes))

    tampered_resp = client.get(f"/maven/trusted/{rel_path}")
    assert tampered_resp.status_code == 403
    assert "Integrity violation" in tampered_resp.json()["detail"]

    # Restore original bytes and verify serving works again
    promoted_jar.write_bytes(jar_bytes)
    assert client.get(f"/maven/trusted/{rel_path}").status_code == 200

    # 2. Re-sign the artifact with an attacker's rogue GPG keypair
    rogue_gnupg = tmp_path / "rogue-gnupg"
    rogue_pub = tmp_path / "rogue-pub"
    ensure_gpg_signing_key(
        gnupghome=rogue_gnupg,
        public_keys_dir=rogue_pub,
        key_name="Rogue Attacker Key",
        key_email="attacker@evil.example.com",
    )
    rogue_stage = tmp_path / "rogue.jar"
    rogue_stage.write_bytes(jar_bytes)
    rogue_sig = sign_artifact_detached_gpg(rogue_stage, rogue_gnupg)
    promoted_jar.with_name(f"{promoted_jar.name}.asc").write_bytes(rogue_sig.read_bytes())

    rogue_resp = client.get(f"/maven/trusted/{rel_path}")
    assert rogue_resp.status_code == 403
    assert "Integrity violation" in rogue_resp.json()["detail"]


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


def test_pypi_pep503_simple_index_serves_only_signed_wheels(
    client: TestClient, test_settings: Settings
) -> None:
    """Verify PyPI Simple index exposes SHA-256 fragment and data-gpg-sig only for signed wheels."""
    wheel_bytes = build_sample_jar({"requests/__init__.py": b"__version__ = '2.32.3'\n"})
    fname = "requests-2.32.3-py3-none-any.whl"
    resp = client.post(
        f"/ingest/pypi/requests/{fname}",
        headers={"X-Gatekeeper-Token": "test-secret-token"},
        files={"file": (fname, wheel_bytes, "application/octet-stream")},
    )
    assert resp.status_code == 201
    sha256_digest = resp.json()["sha256"]

    # Drop an unsigned rogue wheel into the same directory and verify PEP 503 index omits it
    unsigned_wheel = test_settings.trusted_pypi_dir / "requests" / "requests-9.9.9-py3-none-any.whl"
    unsigned_wheel.write_bytes(wheel_bytes)

    idx_resp = client.get("/pypi/trusted/simple/requests/")
    assert idx_resp.status_code == 200
    assert f"#sha256={sha256_digest}" in idx_resp.text
    assert 'data-gpg-sig="true"' in idx_resp.text
    assert "requests-9.9.9" not in idx_resp.text

    whl_resp = client.get(f"/pypi/trusted/packages/requests/{fname}")
    assert whl_resp.status_code == 200
    assert whl_resp.content == wheel_bytes


# ==============================================================================
# Suite E: Dynamic Upstream Pull-Through on Cache Miss (Auto-Approval Pipeline)
# ==============================================================================


def test_dynamic_upstream_pull_through_maven_and_pypi(
    client: TestClient, test_settings: Settings, mock_upstream_registry: str
) -> None:
    """Verify cache misses dynamically pull from upstream, scan with clamd, GPG-sign, and serve."""
    test_settings.auto_promote_clean_artifacts = True
    test_settings.upstream_maven_url = f"{mock_upstream_registry}/maven2"
    test_settings.upstream_pypi_simple_url = f"{mock_upstream_registry}/pypi"

    # 1. Clean Maven artifact dynamically fetched, scanned, signed, and served on first GET
    slf4j_path = "org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar"
    maven_resp = client.get(f"/maven/trusted/{slf4j_path}")
    assert maven_resp.status_code == 200
    asc_resp = client.get(f"/maven/trusted/{slf4j_path}.asc")
    assert asc_resp.status_code == 200
    assert "BEGIN PGP SIGNATURE" in asc_resp.text

    # 2. Infected upstream Maven artifact dynamically fetched -> blocked by clamd with HTTP 451
    evil_path = "org/evil/backdoor/1.0.0/backdoor-1.0.0.jar"
    evil_resp = client.get(f"/maven/trusted/{evil_path}")
    assert evil_resp.status_code == 451
    assert "Java.Trojan.SupplyChain-99 FOUND" in evil_resp.json()["detail"]
    assert not (test_settings.trusted_maven_dir / evil_path).exists()

    # 3. Clean PyPI wheel dynamically fetched, scanned, signed, and served on first GET
    pypi_resp = client.get("/pypi/trusted/packages/urllib3/urllib3-2.2.3-py3-none-any.whl")
    assert pypi_resp.status_code == 200
    pypi_asc = client.get("/pypi/trusted/packages/urllib3/urllib3-2.2.3-py3-none-any.whl.asc")
    assert pypi_asc.status_code == 200
    assert "BEGIN PGP SIGNATURE" in pypi_asc.text


# ==============================================================================
# Suite F: Auth, Error Handling & Concurrent Promotion Stress Test
# ==============================================================================


def test_auth_and_unsupported_ecosystem_rejection(client: TestClient) -> None:
    """Verify missing/invalid admin tokens return 403 and invalid ecosystems return 400."""
    jar_bytes = build_sample_jar({"A.class": b"\xca\xfe\xba\xbe"})
    no_token = client.post(
        "/ingest/maven/com/a/1.0/a-1.0.jar",
        files={"file": ("a-1.0.jar", jar_bytes, "application/java-archive")},
    )
    assert no_token.status_code == 403

    bad_eco = client.post(
        "/ingest/rubygems/rails-7.0.gem",
        headers={"X-Gatekeeper-Token": "test-secret-token"},
        files={"file": ("rails-7.0.gem", jar_bytes, "application/octet-stream")},
    )
    assert bad_eco.status_code == 400


def test_concurrent_parallel_artifact_promotions(client: TestClient) -> None:
    """Verify parallel artifact ingestions and GPG signings complete atomically without race conditions."""

    def ingest_one(idx: int) -> int:
        payload = build_sample_jar({f"com/concurrent/Mod{idx}.class": f"class-{idx}".encode("utf-8")})
        rel = f"com/concurrent/mod-{idx}/1.0.0/mod-{idx}-1.0.0.jar"
        r = client.post(
            f"/ingest/maven/{rel}",
            headers={"X-Gatekeeper-Token": "test-secret-token"},
            files={"file": (f"mod-{idx}-1.0.0.jar", payload, "application/java-archive")},
        )
        assert r.status_code == 201
        get_r = client.get(f"/maven/trusted/{rel}")
        assert get_r.status_code == 200
        return get_r.status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(ingest_one, range(6)))

    assert results == [200] * 6
    audit = client.get("/audit/provenance").json()
    assert audit["count"] == 6


# ==============================================================================
# Suite G: Operational Harbor Chainguard (JRE & Python) + Spring Boot Catalog Cache
# ==============================================================================


def test_harbor_chainguard_jre_and_python_oci_proxy_cache_with_token_auth(
    client: TestClient, test_settings: Settings, mock_upstream_registry: str
) -> None:
    """Verify Harbor OCI v2 Proxy Cache pulls, scans, signs, and caches chainguard/jre and chainguard/python."""
    test_settings.auto_promote_clean_artifacts = True
    test_settings.upstream_chainguard_url = mock_upstream_registry

    v2_resp = client.get("/v2/")
    assert v2_resp.status_code == 200
    assert v2_resp.headers["Docker-Distribution-API-Version"] == "registry/2.0"

    for repo in ("chainguard/jre", "chainguard/python"):
        # First pull: MISS -> dynamically fetched via OCI Bearer token, scanned by clamd, GPG-signed
        miss_resp = client.get(f"/v2/chainguard-cache/{repo}/manifests/latest")
        assert miss_resp.status_code == 200
        assert miss_resp.headers["X-Cache-Status"] == "MISS"
        assert miss_resp.headers["Docker-Content-Digest"].startswith("sha256:")
        assert f"cgr.dev/{repo}:latest" in miss_resp.text

        # Second pull: HIT -> served directly from local Harbor persistent store
        hit_resp = client.get(f"/v2/chainguard-cache/{repo}/manifests/latest")
        assert hit_resp.status_code == 200
        assert hit_resp.headers["X-Cache-Status"] == "HIT"

        # Verify detached GPG signature (.asc) for the cached OCI manifest
        asc_resp = client.get(f"/v2/chainguard-cache/{repo}/manifests/latest.asc")
        assert asc_resp.status_code == 200
        assert "BEGIN PGP SIGNATURE" in asc_resp.text


def test_operational_harbor_warms_spring_boot_collection_and_chainguard_before_teardown(
    client: TestClient, test_settings: Settings, mock_upstream_registry: str
) -> None:
    """Verify warming the full Chainguard (JRE+Python) and shared Spring Boot component catalog."""
    test_settings.auto_promote_clean_artifacts = True
    test_settings.upstream_chainguard_url = mock_upstream_registry
    test_settings.upstream_maven_url = f"{mock_upstream_registry}/maven2"

    # 1. Initial catalog status shows 0 cached items
    initial_status = client.get("/catalog/status").json()
    assert all(not c["cached"] for c in initial_status["chainguard_containers"])
    assert all(not s["cached"] for s in initial_status["spring_boot_components"])

    # 2. Warm the operational test Harbor cache (Chainguard JRE & Python + 8 Spring Boot components = 16 Maven files)
    warm_miss = client.post(
        "/catalog/warm",
        headers={"X-Gatekeeper-Token": "test-secret-token"},
    )
    assert warm_miss.status_code == 200
    warm_data = warm_miss.json()
    assert warm_data["chainguard_containers_cached"] == 2
    assert warm_data["spring_boot_artifacts_cached"] == 16
    assert all(c["cache_status"] == "MISS" and c["signed"] for c in warm_data["chainguard_containers"])
    assert all(s["cache_status"] == "MISS" and s["signed"] for s in warm_data["spring_boot_artifacts"])

    # 3. Re-warm / verify all 18 remote components are now served as CACHE HITs with valid GPG signatures
    warm_hit = client.post(
        "/catalog/warm",
        headers={"X-Gatekeeper-Token": "test-secret-token"},
    ).json()
    assert all(c["cache_status"] == "HIT" for c in warm_hit["chainguard_containers"])
    assert all(s["cache_status"] == "HIT" for s in warm_hit["spring_boot_artifacts"])

    final_status = client.get("/catalog/status").json()
    assert all(
        c["cached"] and c["signature_valid"] for c in final_status["chainguard_containers"]
    )
    assert all(
        s["cached"] and s["signature_valid"] for s in final_status["spring_boot_components"]
    )


def test_live_remote_chainguard_cgr_and_maven_central_spring_boot_caching(
    client: TestClient, test_settings: Settings
) -> None:
    """Pull real Chainguard (cgr.dev/chainguard/jre & python) and Spring Boot starters from Maven Central before teardown."""
    test_settings.auto_promote_clean_artifacts = True
    test_settings.upstream_chainguard_url = "https://cgr.dev"
    test_settings.upstream_maven_url = "https://repo.maven.apache.org/maven2"

    # 1. Live remote pull of Chainguard JRE & Python OCI manifests from https://cgr.dev
    for repo in ("chainguard/jre", "chainguard/python"):
        r_miss = client.get(f"/v2/chainguard-cache/{repo}/manifests/latest")
        assert r_miss.status_code == 200
        assert r_miss.headers["X-Cache-Status"] == "MISS"
        assert "application/vnd.oci.image" in r_miss.text

        r_hit = client.get(f"/v2/chainguard-cache/{repo}/manifests/latest")
        assert r_hit.status_code == 200
        assert r_hit.headers["X-Cache-Status"] == "HIT"

    # 2. Live remote pull of shared Spring Boot starter JARs from Maven Central
    spring_starters = [
        "org/springframework/boot/spring-boot-starter-web/3.4.4/spring-boot-starter-web-3.4.4.jar",
        "org/springframework/boot/spring-boot-starter-actuator/3.4.4/spring-boot-starter-actuator-3.4.4.jar",
        "org/springframework/boot/spring-boot-starter-security/3.4.4/spring-boot-starter-security-3.4.4.jar",
        "org/springframework/boot/spring-boot-starter-validation/3.4.4/spring-boot-starter-validation-3.4.4.jar",
    ]
    for rel_path in spring_starters:
        sb_miss = client.get(f"/maven/trusted/{rel_path}")
        assert sb_miss.status_code == 200
        assert sb_miss.headers["X-Cache-Status"] == "MISS"

        sb_hit = client.get(f"/maven/trusted/{rel_path}")
        assert sb_hit.status_code == 200
        assert sb_hit.headers["X-Cache-Status"] == "HIT"

        sb_asc = client.get(f"/maven/trusted/{rel_path}.asc")
        assert sb_asc.status_code == 200
        assert "BEGIN PGP SIGNATURE" in sb_asc.text


def test_mldsa65_post_quantum_key_generation_and_verification(test_settings: Settings) -> None:
    """Validate NIST FIPS 204 ML-DSA-65 keypair generation, signing, and detached signature verification."""
    pubkey_path = ensure_mldsa_signing_key(
        mldsa_keys_dir=test_settings.mldsa_keys_dir,
        public_keys_dir=test_settings.public_keys_dir,
    )
    assert pubkey_path.exists()
    assert "-----BEGIN ML-DSA-65 PUBLIC KEY-----" in pubkey_path.read_text(encoding="utf-8")

    fingerprint_path = test_settings.public_keys_dir / "trusted-oss-mldsa65.fingerprint"
    assert fingerprint_path.exists()
    assert "SHA256:" in fingerprint_path.read_text(encoding="utf-8")
    assert "SHA384:" in fingerprint_path.read_text(encoding="utf-8")

    test_settings.quarantine_dir.mkdir(parents=True, exist_ok=True)
    dummy_artifact = test_settings.quarantine_dir / "test-component-1.0.jar"
    dummy_artifact.write_bytes(b"PK\x03\x04test-post-quantum-artifact-payload")

    sig_path = sign_artifact_mldsa65(dummy_artifact, test_settings.mldsa_private_key_path)
    assert sig_path.exists()
    assert "-----BEGIN ML-DSA-65 SIGNATURE-----" in sig_path.read_text(encoding="utf-8")

    # Positive verification
    assert verify_artifact_mldsa65(dummy_artifact, sig_path, pubkey_path) is True

    # Tamper test
    tampered_artifact = test_settings.quarantine_dir / "tampered.jar"
    tampered_artifact.write_bytes(b"PK\x03\x04tampered-content")
    assert verify_artifact_mldsa65(tampered_artifact, sig_path, pubkey_path) is False


def test_mldsa65_dual_signing_and_http_endpoints(
    client: TestClient, test_settings: Settings
) -> None:
    """Verify that artifact promotion generates dual signatures (.asc and .mldsa65) and serves /keys endpoints."""
    # 1. Verify /keys/trusted-oss-mldsa65.pub
    r_pub = client.get("/keys/trusted-oss-mldsa65.pub")
    assert r_pub.status_code == 200
    assert "-----BEGIN ML-DSA-65 PUBLIC KEY-----" in r_pub.text

    # 2. Verify /keys/trusted-oss-mldsa65.fingerprint
    r_fp = client.get("/keys/trusted-oss-mldsa65.fingerprint")
    assert r_fp.status_code == 200
    assert "SHA256:" in r_fp.text

    # 3. Ingest artifact and verify dual-signing promotion
    jar_data = build_sample_jar({"com/example/MyClass.class": b"\xca\xfe\xba\xbe\x00\x00"})
    ingest_path = "/ingest/maven/com/example/pqc-demo/1.0.0/pqc-demo-1.0.0.jar"
    resp = client.post(
        ingest_path,
        files={"file": ("pqc-demo-1.0.0.jar", jar_data, "application/java-archive")},
        headers={"x-gatekeeper-token": test_settings.gatekeeper_admin_token},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["signature_file"].endswith(".asc")
    assert data["signature_file_mldsa"].endswith(".mldsa65")
    assert data["pqc_status"] == "POST-QUANTUM READY"
    assert "sha384" in data

    # 4. Fetch artifact, GPG signature, and ML-DSA-65 signature
    r_jar = client.get("/maven/trusted/com/example/pqc-demo/1.0.0/pqc-demo-1.0.0.jar")
    assert r_jar.status_code == 200

    r_asc = client.get("/maven/trusted/com/example/pqc-demo/1.0.0/pqc-demo-1.0.0.jar.asc")
    assert r_asc.status_code == 200
    assert "BEGIN PGP SIGNATURE" in r_asc.text

    r_pqc = client.get("/maven/trusted/com/example/pqc-demo/1.0.0/pqc-demo-1.0.0.jar.mldsa65")
    assert r_pqc.status_code == 200
    assert "BEGIN ML-DSA-65 SIGNATURE" in r_pqc.text

    # 5. Fetch sha384 Grover-resistant companion
    r_sha384 = client.get("/maven/trusted/com/example/pqc-demo/1.0.0/pqc-demo-1.0.0.jar.sha384")
    assert r_sha384.status_code == 200
    assert len(r_sha384.text.strip()) == 96

