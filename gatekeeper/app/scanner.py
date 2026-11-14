"""Antivirus (ClamAV INSTREAM + Archive Security) and Vulnerability (Trivy/OSV/NVD) Scanners."""

import asyncio
import json
import logging
import shutil
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("gatekeeper.scanner")

EICAR_SIGNATURE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


@dataclass(frozen=True)
class ScanVerdict:
    """Combined Antivirus and Vulnerability scan verdict."""

    passed: bool
    clamav_status: str
    cve_status: str
    max_cvss: float = 0.0
    reason: str = "OK"
    cve_ids: tuple[str, ...] = field(default_factory=tuple)


def inspect_archive_safety(file_path: Path) -> tuple[bool, str]:
    """Inspect .jar/.whl/.zip/.tar.gz archives for Zip-Slip traversal, symlinks, and EICAR test signatures."""
    raw_bytes = file_path.read_bytes()
    if EICAR_SIGNATURE in raw_bytes:
        return False, "Win.Test.EICAR_HDB-1 FOUND"

    name_lower = file_path.name.lower()
    if name_lower.endswith((".jar", ".whl", ".zip")):
        if not zipfile.is_zipfile(file_path):
            return False, "Corrupt or invalid ZIP/JAR/Wheel archive"
        with zipfile.ZipFile(file_path, "r") as zf:
            for info in zf.infolist():
                member_name = info.filename
                if member_name.startswith("/") or ".." in member_name.split("/"):
                    return False, f"Archive path traversal detected: {member_name}"
                # Check Unix symlink mode in external_attr (0o120000)
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    return False, f"Symlink entry prohibited in archive: {member_name}"
                if info.flag_bits & 0x1:
                    return False, f"Encrypted entry prohibited in archive: {member_name}"
                with zf.open(info, "r") as member_stream:
                    data = member_stream.read(1024 * 1024)
                    if EICAR_SIGNATURE in data:
                        return False, f"Win.Test.EICAR_HDB-1 FOUND in {member_name}"
    elif name_lower.endswith((".tar.gz", ".tgz")):
        try:
            with tarfile.open(file_path, "r:gz") as tf:
                for member in tf.getmembers():
                    if member.name.startswith("/") or ".." in member.name.split("/"):
                        return False, f"Tar path traversal detected: {member.name}"
                    if member.issym() or member.islnk():
                        return False, f"Symlink/hardlink entry prohibited in tar: {member.name}"
                    if member.isfile():
                        extracted = tf.extractfile(member)
                        if extracted is not None:
                            data = extracted.read(1024 * 1024)
                            if EICAR_SIGNATURE in data:
                                return False, f"Win.Test.EICAR_HDB-1 FOUND in {member.name}"
        except tarfile.TarError as exc:
            return False, f"Invalid tar.gz archive: {exc}"

    return True, "CLEAN"


async def scan_with_clamd_instream(
    file_path: Path, host: str, port: int, required: bool = True
) -> tuple[bool, str]:
    """Stream artifact over TCP INSTREAM protocol to clamd daemon."""
    safe_archive, archive_msg = inspect_archive_safety(file_path)
    if not safe_archive:
        return False, archive_msg

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10.0
        )
        try:
            writer.write(b"zINSTREAM\x00")
            with file_path.open("rb") as f:
                while chunk := f.read(32768):
                    writer.write(struct.pack("!I", len(chunk)) + chunk)
                    await writer.drain()
            writer.write(struct.pack("!I", 0))
            await writer.drain()

            response_bytes = await asyncio.wait_for(reader.read(4096), timeout=60.0)
            response = response_bytes.decode("utf-8", errors="replace").strip("\x00\r\n ")
        finally:
            writer.close()
            await writer.wait_closed()

        if response.endswith("OK") and "FOUND" not in response:
            return True, "CLAMD_OK"
        return False, response or "CLAMD_REJECTED"
    except (OSError, asyncio.TimeoutError) as exc:
        if not required:
            return True, f"LOCAL_ARCHIVE_OK (clamd offline: {exc})"
        return False, f"ClamAV daemon unreachable at {host}:{port}: {exc}"


def _extract_trivy_findings(report: dict[str, Any]) -> tuple[float, list[str]]:
    """Extract maximum CVSS score and HIGH/CRITICAL vulnerability IDs from Trivy JSON."""
    max_cvss = 0.0
    vuln_ids: list[str] = []
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = str(vuln.get("Severity", "")).upper()
            vuln_id = str(vuln.get("VulnerabilityID", "")).strip()
            cvss_val = 0.0
            for source_scores in (vuln.get("CVSS") or {}).values():
                if isinstance(source_scores, dict):
                    for key in ("V3Score", "V2Score"):
                        score = source_scores.get(key)
                        if isinstance(score, (int, float)):
                            cvss_val = max(cvss_val, float(score))
            if severity == "CRITICAL" and cvss_val == 0.0:
                cvss_val = 9.0
            elif severity == "HIGH" and cvss_val == 0.0:
                cvss_val = 7.5
            max_cvss = max(max_cvss, cvss_val)
            if severity in {"HIGH", "CRITICAL"} and vuln_id and vuln_id not in vuln_ids:
                vuln_ids.append(vuln_id)
    return max_cvss, vuln_ids


async def scan_with_trivy(file_path: Path) -> tuple[bool, float, list[str], str]:
    """Run Trivy filesystem scan for HIGH/CRITICAL vulnerabilities if trivy is installed."""
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        return False, 0.0, [], "TRIVY_NOT_INSTALLED"

    try:
        proc = await asyncio.create_subprocess_exec(
            trivy_bin,
            "fs",
            "--quiet",
            "--format",
            "json",
            "--severity",
            "HIGH,CRITICAL",
            "--scanners",
            "vuln",
            str(file_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        if proc.returncode != 0:
            err_msg = stderr.decode("utf-8", errors="replace").strip()
            logger.warning("Trivy scan returned %s: %s", proc.returncode, err_msg)
            return False, 0.0, [], f"TRIVY_ERROR ({proc.returncode})"
        report = json.loads(stdout.decode("utf-8", errors="replace") or "{}")
        max_cvss, vuln_ids = _extract_trivy_findings(report)
        return True, max_cvss, vuln_ids, "TRIVY_OK"
    except Exception as exc:
        logger.warning("Trivy scan failed: %s", exc)
        return False, 0.0, [], f"TRIVY_EXCEPTION ({exc})"


async def query_osv_vulnerabilities(
    ecosystem: str,
    package_name: str,
    version: str,
) -> tuple[bool, float, list[str], str]:
    """Query OSV.dev API for known vulnerabilities on Maven/PyPI package coordinates."""
    eco_map = {"maven": "Maven", "pypi": "PyPI"}
    osv_eco = eco_map.get(ecosystem.lower())
    if not osv_eco or not package_name or not version:
        return False, 0.0, [], "OSV_SKIPPED"

    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": osv_eco},
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post("https://api.osv.dev/v1/query", json=payload)
            if resp.status_code != 200:
                return False, 0.0, [], f"OSV_HTTP_{resp.status_code}"
            data = resp.json()
    except Exception as exc:
        return False, 0.0, [], f"OSV_OFFLINE ({exc})"

    vulns = data.get("vulns") or []
    max_cvss = 0.0
    high_or_crit_ids: list[str] = []
    for vuln in vulns:
        vid = str(vuln.get("id", "")).strip()
        db_spec = vuln.get("database_specific") or {}
        sev_label = str(db_spec.get("severity", "")).upper()
        score_val = 0.0
        for sev in vuln.get("severity") or []:
            score_str = str(sev.get("score", ""))
            if score_str.replace(".", "", 1).isdigit():
                score_val = max(score_val, float(score_str))
        if sev_label == "CRITICAL" and score_val == 0.0:
            score_val = 9.0
        elif sev_label == "HIGH" and score_val == 0.0:
            score_val = 7.5
        max_cvss = max(max_cvss, score_val)
        if (sev_label in {"HIGH", "CRITICAL"} or score_val >= 7.0) and vid:
            high_or_crit_ids.append(vid)

    return True, max_cvss, high_or_crit_ids, "OSV_OK"


async def evaluate_artifact_security(
    file_path: Path,
    clamav_host: str,
    clamav_port: int,
    clamav_required: bool = True,
    cvss_threshold: float = 7.0,
    simulated_cvss: float = 0.0,
    cve_scanner_mode: str = "auto",
    package_ecosystem: str = "",
    package_name: str = "",
    package_version: str = "",
) -> ScanVerdict:
    """Run Antivirus and High/Critical CVE threshold gates on a staged artifact."""
    av_ok, av_status = await scan_with_clamd_instream(
        file_path, clamav_host, clamav_port, required=clamav_required
    )
    if not av_ok:
        return ScanVerdict(
            passed=False,
            clamav_status=av_status,
            cve_status="SKIPPED",
            max_cvss=simulated_cvss,
            reason=f"Antivirus gate rejected artifact: {av_status}",
        )

    effective_cvss = simulated_cvss
    detected_cves: list[str] = []
    scanner_notes: list[str] = []

    mode = (cve_scanner_mode or "auto").lower()
    if mode in {"auto", "trivy"}:
        ran_trivy, trivy_cvss, trivy_cves, trivy_note = await scan_with_trivy(file_path)
        if ran_trivy:
            effective_cvss = max(effective_cvss, trivy_cvss)
            detected_cves.extend(trivy_cves)
            scanner_notes.append(trivy_note)

    if mode in {"auto", "osv"} and package_ecosystem and package_name and package_version:
        ran_osv, osv_cvss, osv_cves, osv_note = await query_osv_vulnerabilities(
            package_ecosystem, package_name, package_version
        )
        if ran_osv:
            effective_cvss = max(effective_cvss, osv_cvss)
            for cid in osv_cves:
                if cid not in detected_cves:
                    detected_cves.append(cid)
            scanner_notes.append(osv_note)

    if effective_cvss >= cvss_threshold or detected_cves:
        cve_detail = f" ({', '.join(detected_cves)})" if detected_cves else ""
        return ScanVerdict(
            passed=False,
            clamav_status=av_status,
            cve_status=f"FAILED (CVSS {effective_cvss:.1f} >= {cvss_threshold:.1f}{cve_detail})",
            max_cvss=effective_cvss,
            reason=f"Vulnerability gate rejected artifact: High/Critical defect CVSS {effective_cvss:.1f} >= {cvss_threshold:.1f}{cve_detail}",
            cve_ids=tuple(detected_cves),
        )

    note_suffix = f" [{','.join(scanner_notes)}]" if scanner_notes else ""
    return ScanVerdict(
        passed=True,
        clamav_status=av_status,
        cve_status=f"CLEAN (max CVSS {effective_cvss:.1f} < {cvss_threshold:.1f}){note_suffix}",
        max_cvss=effective_cvss,
        reason="OK",
        cve_ids=tuple(detected_cves),
    )
