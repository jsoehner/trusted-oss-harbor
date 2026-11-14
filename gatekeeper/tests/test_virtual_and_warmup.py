"""Tests for dynamic project discovery, catalog warmup, and virtual repo pull-through."""

from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import io
import json
import socketserver
import struct
import threading
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.discovery import discover_local_projects
from app.main import app, initialize_storage_and_keys
from app.scanner import evaluate_artifact_security


CLAMD_CUSTOM_MALWARE_MARKER = b"MALICIOUS-BYTECODE-SIGNATURE-2026"


def _build_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


class _MockClamdHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        header = self.request.recv(10)
        if header != b"zINSTREAM\x00":
            self.request.sendall(b"stream: ERROR\x00")
            return
        buf = bytearray()
        while True:
            raw_len = self.request.recv(4)
            if not raw_len:
                break
            (chunk_len,) = struct.unpack("!I", raw_len)
            if chunk_len == 0:
                break
            while len(buf) < len(buf) + chunk_len:
                chunk = self.request.recv(chunk_len)
                buf.extend(chunk)
                chunk_len -= len(chunk)
                if chunk_len <= 0:
                    break
        if CLAMD_CUSTOM_MALWARE_MARKER in bytes(buf):
            self.request.sendall(b"stream: Trojan.Test FOUND\x00")
        else:
            self.request.sendall(b"stream: OK\x00")


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def _start_mock_clamd():
    server = _ThreadedTCPServer(("127.0.0.1", 0), _MockClamdHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def test_discovery_parses_pom_gradle_requirements_pyproject_and_dockerfile(tmp_path: Path) -> None:
    proj_java = tmp_path / "demo-spring-app"
    proj_java.mkdir()
    (proj_java / "pom.xml").write_text(
        """<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.5.16</version>
  </parent>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.postgresql</groupId>
      <artifactId>postgresql</artifactId>
      <version>42.7.14</version>
    </dependency>
  </dependencies>
</project>""",
        encoding="utf-8",
    )
    (proj_java / "Dockerfile").write_text(
        "FROM cgr.dev/chainguard/jre:latest\nCOPY app.jar /app.jar\n",
        encoding="utf-8",
    )

    proj_py = tmp_path / "demo-py-agent"
    proj_py.mkdir()
    (proj_py / "requirements.txt").write_text(
        "# comment\nrequests==2.32.3\nFlask>=3.1.0\n",
        encoding="utf-8",
    )
    (proj_py / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["pydantic>=2.9.0", "httpx==0.28.1"]\n',
        encoding="utf-8",
    )

    discovered = discover_local_projects([tmp_path], max_projects=10)
    assert set(discovered["source_projects"]) == {"demo-spring-app", "demo-py-agent"}
    maven_coords = {
        (c["groupId"], c["artifactId"], c["version"])
        for c in discovered["spring_boot_maven_components"]
    }
    assert ("org.springframework.boot", "spring-boot-starter-web", "3.5.16") in maven_coords
    assert ("org.postgresql", "postgresql", "42.7.14") in maven_coords

    pypi_names = {c["name"] for c in discovered["pypi_components"]}
    assert {"requests", "flask", "pydantic", "httpx"}.issubset(pypi_names)
    assert any(c["repository"] == "chainguard/jre" for c in discovered["chainguard_containers"])


def test_virtual_repo_pypi_maven_and_dynamic_warmup_e2e(tmp_path: Path) -> None:
    clamd = _start_mock_clamd()
    clamd_host, clamd_port = clamd.server_address

    clean_wheel = _build_zip({"requests/__init__.py": b"__version__ = '2.32.3'\n"})
    clean_jar = _build_zip({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})
    evil_jar = _build_zip({"org/evil/Exploit.class": CLAMD_CUSTOM_MALWARE_MARKER})
    clean_pom = b"<project><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><version>42.7.14</version></project>\n"
    cg_manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json"}).encode("utf-8")

    base_url_holder: dict[str, str] = {}

    class MockUpstream(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            base = base_url_holder["url"]
            if path == "/simple/requests/":
                html_body = (
                    f'<html><body><a href="{base}/files/requests-2.32.3-py3-none-any.whl">'
                    "requests-2.32.3-py3-none-any.whl</a></body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html_body)))
                self.end_headers()
                self.wfile.write(html_body)
                return

            payloads = {
                "/files/requests-2.32.3-py3-none-any.whl": clean_wheel,
                "/maven2/org/postgresql/postgresql/42.7.14/postgresql-42.7.14.pom": clean_pom,
                "/maven2/org/postgresql/postgresql/42.7.14/postgresql-42.7.14.jar": clean_jar,
                "/maven2/org/evil/malware/1.0.0/malware-1.0.0.jar": evil_jar,
                "/v2/chainguard/jre/manifests/latest": cg_manifest,
            }
            data = payloads.get(path)
            if data is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

    http_srv = HTTPServer(("127.0.0.1", 0), MockUpstream)
    http_port = http_srv.server_address[1]
    base_url_holder["url"] = f"http://127.0.0.1:{http_port}"
    t = threading.Thread(target=http_srv.serve_forever, daemon=True)
    t.start()

    try:
        workspace = tmp_path / "projects"
        proj = workspace / "sample-app"
        proj.mkdir(parents=True)
        (proj / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
        (proj / "pom.xml").write_text(
            "<project><dependencies><dependency><groupId>org.postgresql</groupId>"
            "<artifactId>postgresql</artifactId><version>42.7.14</version>"
            "</dependency></dependencies></project>",
            encoding="utf-8",
        )
        (proj / "Dockerfile").write_text("FROM cgr.dev/chainguard/jre:latest\n", encoding="utf-8")

        data_root = tmp_path / "oss-data"
        seed_cat = tmp_path / "seed.json"
        seed_cat.write_text(
            json.dumps({"chainguard_containers": [], "spring_boot_maven_components": []}),
            encoding="utf-8",
        )

        settings = Settings(
            OSS_DATA_ROOT=data_root,
            CLAMAV_HOST=clamd_host,
            CLAMAV_PORT=clamd_port,
            CLAMAV_REQUIRED=True,
            CVE_SCANNER_MODE="none",
            UPSTREAM_MAVEN_URL=f"{base_url_holder['url']}/maven2",
            UPSTREAM_PYPI_SIMPLE_URL=f"{base_url_holder['url']}/simple",
            UPSTREAM_CHAINGUARD_URL=base_url_holder["url"],
            SEED_CATALOG_PATH=seed_cat,
            GATEKEEPER_ADMIN_TOKEN="test-admin-token",
        )
        initialize_storage_and_keys(settings)
        app.state.settings = settings
        app.state.pypi_upstream_map = {}

        with TestClient(app) as client:
            # 1. Virtual PyPI Simple index rewrites upstream links to /pypi/virtual/packages/...
            idx_resp = client.get("/pypi/virtual/simple/requests/")
            assert idx_resp.status_code == 200
            assert "/pypi/virtual/packages/requests/requests-2.32.3-py3-none-any.whl" in idx_resp.text

            # 2. Virtual PyPI package pull-through: MISS -> scan -> sign -> serve -> HIT
            pkg_miss = client.get("/pypi/virtual/packages/requests/requests-2.32.3-py3-none-any.whl")
            assert pkg_miss.status_code == 200
            assert pkg_miss.headers["X-Cache-Status"] == "MISS"
            assert pkg_miss.content == clean_wheel
            assert (data_root / "packages" / "trusted-pypi" / "requests" / "requests-2.32.3-py3-none-any.whl.asc").exists()
            assert (data_root / "packages" / "trusted-pypi" / "requests" / "requests-2.32.3-py3-none-any.whl.mldsa65").exists()

            pkg_hit = client.get("/pypi/virtual/packages/requests/requests-2.32.3-py3-none-any.whl")
            assert pkg_hit.status_code == 200
            assert pkg_hit.headers["X-Cache-Status"] == "HIT"

            # 3. Virtual Maven rejects malware with 451 and never promotes it
            evil_resp = client.get("/maven/virtual/org/evil/malware/1.0.0/malware-1.0.0.jar")
            assert evil_resp.status_code == 451
            assert not (data_root / "packages" / "trusted-maven" / "org/evil/malware/1.0.0/malware-1.0.0.jar").exists()

            # 4. Dynamic discovery + warmup from local workspace
            disc_resp = client.post(
                "/catalog/discover",
                headers={"X-Gatekeeper-Token": "test-admin-token"},
                json={"scan_roots": [str(workspace)], "save_to_catalog": True, "warm": True},
            )
            assert disc_resp.status_code == 200
            body = disc_resp.json()
            assert body["source_projects"] == ["sample-app"]
            assert body["saved_catalog_path"].endswith("dynamic-catalog.json")
            assert Path(body["saved_catalog_path"]).is_file()
            assert body["warmup"]["chainguard_containers_cached"] == 1
            assert body["warmup"]["spring_boot_artifacts_cached"] == 2
            assert body["warmup"]["pypi_artifacts_cached"] == 1
            assert body["warmup"]["failures_count"] == 0

            status_resp = client.get("/catalog/status")
            assert status_resp.status_code == 200
            st = status_resp.json()
            assert len(st["pypi_components"]) == 1
            assert st["pypi_components"][0]["cached"] is True
            assert st["pypi_components"][0]["signature_valid"] is True

            vuln_resp = client.get("/catalog/vulnerabilities")
            assert vuln_resp.status_code == 200
            vbody = vuln_resp.json()
            assert vbody["summary"]["total"] >= 4
            assert vbody["summary"]["vulnerable"] == 0
            ecos = {item["ecosystem"] for item in vbody["components"]}
            assert {"oci", "maven", "pypi"} <= ecos
            assert all(item["signature_valid"] for item in vbody["components"])
    finally:
        http_srv.shutdown()
        http_srv.server_close()
        clamd.shutdown()
        clamd.server_close()


@pytest.mark.asyncio
async def test_cve_gate_rejects_high_and_critical_defects(tmp_path: Path, monkeypatch) -> None:
    artifact = tmp_path / "vuln.jar"
    artifact.write_bytes(_build_zip({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"}))

    async def fake_osv(eco: str, pkg: str, ver: str):
        return True, 9.8, ["CVE-2026-99999"], "OSV_OK"

    monkeypatch.setattr("app.scanner.query_osv_vulnerabilities", fake_osv)

    verdict = await evaluate_artifact_security(
        file_path=artifact,
        clamav_host="127.0.0.1",
        clamav_port=1,
        clamav_required=False,
        cvss_threshold=7.0,
        cve_scanner_mode="osv",
        package_ecosystem="maven",
        package_name="org.example:vuln",
        package_version="1.0.0",
    )
    assert verdict.passed is False
    assert verdict.max_cvss == 9.8
    assert "CVE-2026-99999" in verdict.cve_ids


def test_remediation_quarantines_vulnerable_version_and_tags_latest(tmp_path: Path, monkeypatch) -> None:
    """When a cached version fails a new CVE >= 7.0, fetch clean newer version, tag 'latest', and quarantine old."""
    old_whl = _build_zip({"requests/__init__.py": b"__version__ = '2.32.3'\n"})
    new_whl = _build_zip({"requests/__init__.py": b"__version__ = '2.32.4'\n"})

    class _RemediationHTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/simple/requests/":
                html = (
                    "<html><body>"
                    "<a href='/files/requests-2.32.3-py3-none-any.whl'>requests-2.32.3-py3-none-any.whl</a>"
                    "<a href='/files/requests-2.32.4-py3-none-any.whl'>requests-2.32.4-py3-none-any.whl</a>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html)
                return
            if self.path == "/files/requests-2.32.3-py3-none-any.whl":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(old_whl)
                return
            if self.path == "/files/requests-2.32.4-py3-none-any.whl":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(new_whl)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RemediationHTTPHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"

    data_root = tmp_path / "oss-data"
    settings = Settings(
        OSS_DATA_ROOT=data_root,
        CLAMAV_REQUIRED=False,
        CVSS_FAIL_THRESHOLD=7.0,
        AUTO_PROMOTE_CLEAN_ARTIFACTS=True,
        PQC_SIGNING_ENABLED=True,
        CVE_SCANNER_MODE="osv",
        CVE_RESCAN_INTERVAL_SECONDS=0,
        UPSTREAM_PYPI_SIMPLE_URL=f"{base}/simple/",
        GATEKEEPER_ADMIN_TOKEN="test-admin-token",
    )
    app.state.settings = settings
    app.state.pypi_upstream_map = {}

    async def fake_osv_initial(eco: str, pkg: str, ver: str):
        return False, 0.0, [], "OSV_OK"

    monkeypatch.setattr("app.scanner.query_osv_vulnerabilities", fake_osv_initial)

    try:
        with TestClient(app) as client:
            # 1. Cache 2.32.3 while it is clean
            r1 = client.get("/pypi/virtual/packages/requests/requests-2.32.3-py3-none-any.whl")
            assert r1.status_code == 200

            # 2. Simulate new CVE published for 2.32.3 (CVSS 8.5 >= 7.0), while 2.32.4 is clean
            async def fake_osv_after_cve(eco: str, pkg: str, ver: str):
                if "2.32.3" in ver:
                    return True, 8.5, ["CVE-2026-88888"], "OSV_OK"
                return False, 0.0, [], "OSV_OK"

            monkeypatch.setattr("app.scanner.query_osv_vulnerabilities", fake_osv_after_cve)

            # 3. Trigger scoped remediation by ecosystem
            rem = client.post("/catalog/remediate?ecosystem=pypi", headers={"X-Gatekeeper-Token": "test-admin-token"})
            assert rem.status_code == 200
            rem_body = rem.json()
            assert rem_body["quarantined_count"] == 1
            assert rem_body["upgraded_count"] == 1
            assert rem_body["upgraded"][0]["latest_version"] == "2.32.4"

            # 4. Verify /catalog/vulnerabilities shows 2.32.4 as 'latest', 2.32.3 as quarantined, and history
            vulns = client.get("/catalog/vulnerabilities?ecosystem=pypi&components=requests").json()
            assert vulns["summary"]["quarantined"] == 1
            assert len(vulns["components"]) == 1
            assert vulns["components"][0]["version"] == "2.32.4"
            assert "latest" in vulns["components"][0]["tags"]
            assert vulns["components"][0]["vulnerability_status"] == "CLEAN"

            q_item = vulns["quarantined"][0]
            assert q_item["status"] == "QUARANTINED"
            assert q_item["version"] == "2.32.3"
            assert q_item["max_cvss"] == 8.5
            assert "CVE-2026-88888" in q_item["cve_ids"]
            assert q_item["superseded_by"] == "2.32.4"

            hist = vulns["history"][0]
            assert hist["serving_latest_version"] == "2.32.4"
            states = {v["version"]: v["state"] for v in hist["versions"]}
            assert states == {"2.32.4": "SERVING_LATEST", "2.32.3": "QUARANTINED"}
    finally:
        srv.shutdown()
        srv.server_close()
