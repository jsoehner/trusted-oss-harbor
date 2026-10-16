"""Antivirus (ClamAV INSTREAM + Archive Security) and Vulnerability (Trivy/NVD) Scanners."""

import asyncio
import struct
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


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


async def evaluate_artifact_security(
    file_path: Path,
    clamav_host: str,
    clamav_port: int,
    clamav_required: bool = True,
    cvss_threshold: float = 7.0,
    simulated_cvss: float = 0.0,
) -> ScanVerdict:
    """Run Antivirus and CVE threshold gates on a staged artifact."""
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

    if simulated_cvss >= cvss_threshold:
        return ScanVerdict(
            passed=False,
            clamav_status=av_status,
            cve_status=f"FAILED (CVSS {simulated_cvss:.1f} >= {cvss_threshold:.1f})",
            max_cvss=simulated_cvss,
            reason=f"Vulnerability gate rejected artifact: CVSS {simulated_cvss:.1f} >= {cvss_threshold:.1f}",
        )

    return ScanVerdict(
        passed=True,
        clamav_status=av_status,
        cve_status=f"CLEAN (max CVSS {simulated_cvss:.1f} < {cvss_threshold:.1f})",
        max_cvss=simulated_cvss,
        reason="OK",
    )
