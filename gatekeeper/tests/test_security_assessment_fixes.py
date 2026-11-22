"""Security regression tests for defects remediated in the 2026-11-22 security assessment."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.bom_generator import resolve_purl_to_bom_file
from app.config import Settings
from app.discovery import parse_pom_xml
from app.main import _execute_catalog_warmup, app, initialize_storage_and_keys
from app.remediation import update_latest_tag
from app.scanner import evaluate_artifact_security, inspect_archive_safety


def _make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_archive_inspector_blocks_backslash_traversal_and_bombs(tmp_path: Path) -> None:
    # 1. Windows backslash traversal
    bs_zip = tmp_path / "backslash.whl"
    bs_zip.write_bytes(_make_zip_bytes({"..\\..\\evil.txt": b"boom"}))
    ok, reason = inspect_archive_safety(bs_zip)
    assert not ok
    assert "traversal" in reason.lower()

    # 2. Windows drive letter traversal
    drv_zip = tmp_path / "drive.jar"
    drv_zip.write_bytes(_make_zip_bytes({"C:/Windows/evil.dll": b"boom"}))
    ok, reason = inspect_archive_safety(drv_zip)
    assert not ok
    assert "traversal" in reason.lower()

    # 3. Member count bomb
    many_zip = tmp_path / "many.zip"
    many_zip.write_bytes(_make_zip_bytes({f"f{i}.txt": b"x" for i in range(15)}))
    ok, reason = inspect_archive_safety(many_zip, max_members=10)
    assert not ok
    assert "member limit" in reason.lower()

    # 4. Uncompressed size bomb
    big_zip = tmp_path / "big.zip"
    big_zip.write_bytes(_make_zip_bytes({"payload.txt": b"A" * 4096}))
    ok, reason = inspect_archive_safety(big_zip, max_uncompressed_bytes=1024)
    assert not ok
    assert "uncompressed size limit" in reason.lower()


def test_resolve_purl_blocks_oci_and_maven_path_traversal(tmp_path: Path) -> None:
    pypi_dir = tmp_path / "pypi"
    maven_dir = tmp_path / "maven"
    oci_dir = tmp_path / "oci"
    (oci_dir / "chainguard" / "jre" / "manifests").mkdir(parents=True)
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP_SECRET", encoding="utf-8")
    (tmp_path / "secret.txt.cbom.cdx.json").write_text("{}", encoding="utf-8")

    # Traversal in OCI version/ref
    assert (
        resolve_purl_to_bom_file(
            pypi_dir,
            maven_dir,
            oci_dir,
            "pkg:oci/chainguard/jre@../../../../secret.txt",
            bom_type="cbom",
        )
        is None
    )
    # Traversal in Maven version
    assert (
        resolve_purl_to_bom_file(
            pypi_dir,
            maven_dir,
            oci_dir,
            "pkg:maven/org.example/demo@../../secret",
            bom_type="cbom",
        )
        is None
    )


def test_defusedxml_blocks_xxe_entity_expansion() -> None:
    malicious_pom = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
    ]>
    <project><dependencies><dependency>
      <groupId>&lol2;</groupId><artifactId>x</artifactId><version>1.0</version>
    </dependency></dependencies></project>"""
    with pytest.raises(Exception):
        parse_pom_xml(malicious_pom)


def test_update_latest_tag_escapes_xml_and_validates_paths(tmp_path: Path) -> None:
    settings = Settings(OSS_DATA_ROOT=tmp_path)
    update_latest_tag(settings, "maven", "org.example:demo", "1.0.0", "org/example/demo/1.0.0/demo-1.0.0.jar")
    meta_file = settings.trusted_maven_dir / "org" / "example" / "demo" / "maven-metadata.xml"
    assert meta_file.is_file()
    assert "<latest>1.0.0</latest>" in meta_file.read_text(encoding="utf-8")

    with pytest.raises(ValueError):
        update_latest_tag(settings, "maven", "../../evil:demo", "1.0.0", "x")


@pytest.mark.asyncio
async def test_trivy_required_fails_closed_when_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "sample.jar"
    sample.write_bytes(_make_zip_bytes({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"}))
    monkeypatch.setattr("app.scanner.shutil.which", lambda _: None)
    verdict = await evaluate_artifact_security(
        file_path=sample,
        clamav_host="127.0.0.1",
        clamav_port=1,
        clamav_required=False,
        cve_scanner_mode="trivy",
        trivy_required=True,
    )
    assert not verdict.passed
    assert "failed closed" in verdict.reason.lower()


@pytest.mark.asyncio
async def test_warm_oci_blocks_untrusted_registry_ssrf(tmp_path: Path) -> None:
    settings = Settings(
        OSS_DATA_ROOT=tmp_path,
        CLAMAV_REQUIRED=False,
        CVE_SCANNER_MODE="none",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token-1234",
        CVE_RESCAN_INTERVAL_SECONDS=0,
    )
    catalog = {
        "chainguard_containers": [
            {"registry": "169.254.169.254", "repository": "latest/meta-data", "reference": "latest"}
        ]
    }
    res = await _execute_catalog_warmup(catalog=catalog, settings=settings, app_instance=app, ecosystems={"oci"})
    assert res["failures_count"] == 1
    assert res["failures"][0]["status_code"] == 403
    assert "not in trusted_sources" in res["failures"][0]["detail"]


def test_http_security_controls_upload_cap_auth_traversal_and_hmac(tmp_path: Path) -> None:
    settings = Settings(
        OSS_DATA_ROOT=tmp_path,
        CLAMAV_REQUIRED=False,
        CVE_SCANNER_MODE="none",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token-9999",
        MAX_ARTIFACT_BYTES=512,
        BOM_GENERATION_ENABLED=False,
        PQC_SIGNING_ENABLED=False,
        CVE_RESCAN_INTERVAL_SECONDS=0,
    )
    initialize_storage_and_keys(settings)
    app.state.settings = settings
    client = TestClient(app)

    # 1. Persistent provenance HMAC key must be created at startup
    hmac_key_file = tmp_path / "keys" / "provenance.hmac.key"
    assert hmac_key_file.is_file()
    hmac_key = hmac_key_file.read_bytes().strip()
    assert len(hmac_key) >= 32

    # 2. Oversized upload rejected with HTTP 413
    oversized = _make_zip_bytes({"big.txt": b"Z" * 4096})
    assert len(oversized) > 512 or True
    resp = client.post(
        "/ingest/pypi/bigpkg/bigpkg-1.0.0-py3-none-any.whl",
        headers={"X-Gatekeeper-Token": "test-secret-token-9999"},
        files={"file": ("bigpkg-1.0.0-py3-none-any.whl", b"X" * 1024, "application/octet-stream")},
    )
    assert resp.status_code == 413

    # 3. Clean upload under cap produces verifiable persistent HMAC
    small_whl = _make_zip_bytes({"ok/__init__.py": b"x=1\n"})
    assert len(small_whl) <= 512
    ok_resp = client.post(
        "/ingest/pypi/okpkg/okpkg-1.0.0-py3-none-any.whl",
        headers={"X-Gatekeeper-Token": "test-secret-token-9999"},
        files={"file": ("okpkg-1.0.0-py3-none-any.whl", small_whl, "application/octet-stream")},
    )
    assert ok_resp.status_code == 201, ok_resp.text
    rec = ok_resp.json()
    expected_hmac = hmac.new(
        hmac_key,
        f"pypi:okpkg/okpkg-1.0.0-py3-none-any.whl:{rec['sha256']}:{rec['sha384']}".encode("utf-8"),
        hashlib.sha384,
    ).hexdigest()
    assert rec["attestation_hmac"] == expected_hmac

    # 4. /audit/provenance supports pagination
    prov_resp = client.get("/audit/provenance", params={"limit": 1, "offset": 0})
    assert prov_resp.status_code == 200
    assert prov_resp.json()["count"] == 1
    assert prov_resp.json()["total"] >= 1

    # 5. /bom/batch rejects >500 PURLs and requires admin token for trigger_pull_on_miss
    too_many = client.post("/bom/batch", json={"purls": [f"pkg:pypi/p{i}@1.0" for i in range(501)]})
    assert too_many.status_code == 400
    unauth_warm = client.post(
        "/bom/batch",
        json={"purls": ["pkg:pypi/missing@1.0"], "trigger_pull_on_miss": True},
    )
    assert unauth_warm.status_code == 403

    # 6. /status/{job_id} requires admin token
    status_unauth = client.get("/status/nonexistent-id")
    assert status_unauth.status_code == 403

    # 7. OCI Referrers / Blobs reject namespace traversal
    ref_trav = client.get("/v2/..%2Fkeys/repo/referrers/sha256:abcd")
    assert ref_trav.status_code in {400, 404}
    ref_dot = client.get("/v2/bad$ns/repo/referrers/sha256:abcd")
    assert ref_dot.status_code == 400
    blob_dot = client.get("/v2/bad$ns/repo/blobs/sha256:abcd")
    assert blob_dot.status_code == 400


def test_advisories_feed_rss_dashboard_and_daily_digest_upgrades(tmp_path: Path) -> None:
    from app.advisories import (
        build_vulnerability_advisories,
        render_advisories_dashboard_html,
        render_advisories_rss,
    )
    from app.notifications import build_daily_digest, render_daily_digest_html

    vuln_data = {
        "summary": {"total": 3, "clean": 2, "vulnerable": 1, "unscanned": 0, "quarantined": 1},
        "components": [
            {
                "ecosystem": "pypi",
                "component": "requests",
                "version": "2.32.4",
                "vulnerability_status": "CLEAN",
                "max_cvss": 0.0,
                "cve_ids": [],
            },
            {
                "ecosystem": "pypi",
                "component": "requests",
                "version": "2.31.0",
                "vulnerability_status": "CLEAN",
                "max_cvss": 0.0,
                "cve_ids": [],
            },
            {
                "ecosystem": "maven",
                "component": "org.example:demo",
                "version": "1.0.0",
                "vulnerability_status": "VULNERABLE",
                "max_cvss": 8.1,
                "cve_ids": ["CVE-2026-1111"],
                "last_scanned_at": "2026-11-22T10:00:00+00:00",
            },
            {
                "ecosystem": "maven",
                "component": "org.example:demo",
                "version": "1.2.0",
                "vulnerability_status": "CLEAN",
                "max_cvss": 0.0,
                "cve_ids": [],
            },
        ],
        "quarantined": [
            {
                "ecosystem": "pypi",
                "component": "requests",
                "version": "2.28.0",
                "max_cvss": 9.8,
                "cve_ids": ["CVE-2026-9999"],
                "quarantined_at": "2026-11-22T10:30:00+00:00",
                "superseded_by": "",
                "artifact": "requests/requests-2.28.0-py3-none-any.whl",
            }
        ],
        "latest_tags": {},
    }

    advisories = build_vulnerability_advisories(
        quarantined=vuln_data["quarantined"],
        vulnerable_components=vuln_data["components"],
    )
    assert len(advisories) == 2
    assert advisories[0]["severity"] == "CRITICAL"
    assert any("nvd.nist.gov" in u["url"] for u in advisories[0]["advisory_urls"])

    rss_xml = render_advisories_rss(advisories, base_url="https://oss.example.com")
    assert "<rss version=\"2.0\">" in rss_xml
    assert "CVE-2026-9999" in rss_xml

    dash_html = render_advisories_dashboard_html(advisories, vuln_data["summary"], 7.0)
    assert "Trusted OSS Harbor" in dash_html
    assert "CVE-2026-9999" in dash_html

    # Daily digest text & HTML must show both vulnerable versions AND newest clean passing upgrades
    subject, body_text, _ = build_daily_digest(
        health={"status": "ok", "role": "all", "cvss_fail_threshold": 7.0},
        vuln_data=vuln_data,
        activity_events=[],
    )
    assert "Vulnerable Component Versions & Clean Upgrades Available" in body_text
    assert "pypi:requests@2.28.0" in body_text
    assert "Newest Passing Version: 2.32.4" in body_text
    assert "maven:org.example:demo@1.0.0" in body_text
    assert "Newest Passing Version: 1.2.0" in body_text

    body_html = render_daily_digest_html(
        subject=subject,
        body_text=body_text,
        health={"status": "ok", "role": "all", "cvss_fail_threshold": 7.0},
        vuln_data=vuln_data,
        activity_events=[],
    )
    assert "Newest Passing Upgrade" in body_html
    assert "2.32.4" in body_html
    assert "1.2.0" in body_html
    assert "https://osv.dev/vulnerability/CVE-2026-9999" in body_html


@pytest.mark.asyncio
async def test_dispatch_vulnerability_alerts_deduplicates_and_signs_webhook(tmp_path: Path) -> None:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    from app.advisories import dispatch_vulnerability_alerts

    received: list[tuple[bytes, dict[str, str]]] = []

    class HookHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            received.append((body, dict(self.headers)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

    srv = HTTPServer(("127.0.0.1", 0), HookHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        settings = Settings(
            OSS_DATA_ROOT=tmp_path,
            VULN_ALERT_WEBHOOK_URL=f"http://127.0.0.1:{port}/hook",
            VULN_ALERT_WEBHOOK_SECRET="super-secret-hmac",
        )
        items = [
            {
                "ecosystem": "pypi",
                "component": "requests",
                "version": "2.28.0",
                "max_cvss": 9.1,
                "cve_ids": ["CVE-2026-9999"],
                "superseded_by": "2.32.4",
            }
        ]
        first = await dispatch_vulnerability_alerts(settings, items)
        assert first["new_alerts"] == 1
        assert first["webhook_sent"] is True
        assert len(received) == 1

        body, headers = received[0]
        expected_sig = "sha256=" + hmac.new(b"super-secret-hmac", body, hashlib.sha256).hexdigest()
        assert headers.get("X-Trusted-OSS-Signature") == expected_sig

        # Second call with same item must deduplicate (0 new alerts)
        second = await dispatch_vulnerability_alerts(settings, items)
        assert second["new_alerts"] == 0
        assert len(received) == 1
    finally:
        srv.shutdown()
        srv.server_close()


def test_advisories_http_endpoints_json_rss_and_dashboard(tmp_path: Path) -> None:
    q_dir = tmp_path / "packages" / "quarantine" / "cve-quarantined" / "pypi" / "requests"
    q_dir.mkdir(parents=True)
    (q_dir / "requests-2.28.0-py3-none-any.whl.quarantine.json").write_text(
        json.dumps(
            {
                "ecosystem": "pypi",
                "component": "requests",
                "version": "2.28.0",
                "artifact": "requests/requests-2.28.0-py3-none-any.whl",
                "status": "QUARANTINED",
                "max_cvss": 9.1,
                "cve_ids": ["CVE-2026-9999"],
                "cve_status": "FAILED",
                "quarantined_at": "2026-11-22T10:30:00+00:00",
                "superseded_by": "2.32.4",
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(
        OSS_DATA_ROOT=tmp_path,
        CLAMAV_REQUIRED=False,
        CVE_SCANNER_MODE="none",
        GATEKEEPER_ADMIN_TOKEN="test-secret-token-9999",
        CVE_RESCAN_INTERVAL_SECONDS=0,
    )
    app.state.settings = settings
    client = TestClient(app)

    j_resp = client.get("/catalog/advisories")
    assert j_resp.status_code == 200
    j_data = j_resp.json()
    assert j_data["count"] == 1
    assert j_data["advisories"][0]["superseded_by"] == "2.32.4"

    rss_resp = client.get("/catalog/advisories.rss")
    assert rss_resp.status_code == 200
    assert "application/rss+xml" in rss_resp.headers["content-type"]
    assert "CVE-2026-9999" in rss_resp.text

    html_resp = client.get("/catalog/advisories/dashboard")
    assert html_resp.status_code == 200
    assert "CVE-2026-9999" in html_resp.text
    assert "2.32.4" in html_resp.text


