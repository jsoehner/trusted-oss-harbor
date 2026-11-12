"""Safe persistent storage, path containment, and PEP 503 index generation."""

import hashlib
import html
import os
import re
import shutil
from pathlib import Path
from typing import NamedTuple


SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._+-]+$")


class ArtifactDigests(NamedTuple):
    """Cryptographic digests for a verified artifact."""

    sha256: str
    sha512: str
    sha384: str = ""


def is_safe_subpath(base_dir: Path, target_path: Path) -> bool:
    """Verify target_path resolves strictly inside base_dir without symlinks."""
    try:
        resolved_base = base_dir.resolve(strict=False)
        if target_path.is_symlink():
            return False
        for parent in target_path.parents:
            if parent == resolved_base:
                break
            if parent.exists() and parent.is_symlink():
                return False
        resolved_target = target_path.resolve(strict=False)
        resolved_target.relative_to(resolved_base)
        return True
    except (ValueError, OSError):
        return False


def resolve_safe_relative_path(base_dir: Path, rel_path: str) -> Path:
    """Validate and resolve a relative artifact path inside base_dir."""
    cleaned = rel_path.strip("/")
    if not cleaned or ".." in cleaned.split("/"):
        raise ValueError(f"Invalid relative artifact path: {rel_path!r}")
    parts = [p for p in cleaned.split("/") if p]
    if not parts:
        raise ValueError(f"Empty relative artifact path: {rel_path!r}")
    for part in parts:
        if part in {".", ".."} or not SAFE_SEGMENT_RE.match(part):
            raise ValueError(f"Unsafe path segment: {part!r}")
    candidate = base_dir.joinpath(*parts)
    if not is_safe_subpath(base_dir, candidate):
        raise ValueError(f"Path escapes base directory: {rel_path!r}")
    return candidate


def compute_digests(file_path: Path) -> ArtifactDigests:
    """Compute SHA-256, SHA-384, and SHA-512 hex digests for a file."""
    h256 = hashlib.sha256()
    h384 = hashlib.sha384()
    h512 = hashlib.sha512()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            h256.update(chunk)
            h384.update(chunk)
            h512.update(chunk)
    return ArtifactDigests(
        sha256=h256.hexdigest(),
        sha512=h512.hexdigest(),
        sha384=h384.hexdigest(),
    )


def atomic_promote_artifact(
    staged_file: Path,
    sig_file: Path,
    dest_file: Path,
    digests: ArtifactDigests,
    pqc_sig_file: Path | None = None,
) -> None:
    """Atomically promote a scanned & signed artifact and its .asc/.mldsa65/.sha256/.sha384/.sha512 files."""
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    pid = os.getpid()
    tmp_dest = dest_file.with_name(f".{dest_file.name}.tmp.{pid}")
    tmp_sig = dest_file.with_name(f".{dest_file.name}.asc.tmp.{pid}")
    tmp_pqc = dest_file.with_name(f".{dest_file.name}.mldsa65.tmp.{pid}") if pqc_sig_file and pqc_sig_file.exists() else None

    shutil.copy2(staged_file, tmp_dest)
    shutil.copy2(sig_file, tmp_sig)
    if tmp_pqc and pqc_sig_file:
        shutil.copy2(pqc_sig_file, tmp_pqc)

    os.replace(tmp_dest, dest_file)
    os.replace(tmp_sig, dest_file.with_name(f"{dest_file.name}.asc"))
    if tmp_pqc:
        os.replace(tmp_pqc, dest_file.with_name(f"{dest_file.name}.mldsa65"))

    dest_file.with_name(f"{dest_file.name}.sha256").write_text(
        f"{digests.sha256}\n", encoding="utf-8"
    )
    if digests.sha384:
        dest_file.with_name(f"{dest_file.name}.sha384").write_text(
            f"{digests.sha384}\n", encoding="utf-8"
        )
    dest_file.with_name(f"{dest_file.name}.sha512").write_text(
        f"{digests.sha512}\n", encoding="utf-8"
    )


def normalize_pypi_name(name: str) -> str:
    """PEP 503 package name normalization."""
    normalized = re.sub(r"[-_.]+", "-", name).lower().strip("-")
    if not normalized or not SAFE_SEGMENT_RE.match(normalized):
        raise ValueError(f"Invalid PyPI package name: {name!r}")
    return normalized


def render_pep503_simple_index(package_name: str, pkg_dir: Path) -> str:
    """Generate a PEP 503 Simple Repository HTML page with SHA-256 hashes, GPG, and PQC metadata."""
    safe_pkg = html.escape(package_name)
    links: list[str] = []
    if pkg_dir.exists() and pkg_dir.is_dir():
        for entry in sorted(pkg_dir.iterdir(), key=lambda p: p.name):
            if entry.is_symlink() or not entry.is_file():
                continue
            if entry.name.endswith((".asc", ".mldsa65", ".sha256", ".sha384", ".sha512", ".html")):
                continue
            asc_path = entry.with_name(f"{entry.name}.asc")
            sha256_path = entry.with_name(f"{entry.name}.sha256")
            if not asc_path.exists() or not sha256_path.exists():
                # Never expose unsigned artifacts in the trusted PEP 503 index
                continue
            mldsa_path = entry.with_name(f"{entry.name}.mldsa65")
            pqc_attr = ' data-pqc-sig="true"' if mldsa_path.exists() else ""
            sha256_val = html.escape(sha256_path.read_text(encoding="utf-8").strip(), quote=True)
            safe_fname = html.escape(entry.name, quote=True)
            href = f"/pypi/trusted/packages/{safe_pkg}/{safe_fname}#sha256={sha256_val}"
            links.append(
                f'    <a href="{href}" data-gpg-sig="true"{pqc_attr}>{safe_fname}</a><br/>'
            )

    body = "\n".join(links)
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        f"  <head><title>Links for {safe_pkg}</title></head>\n"
        "  <body>\n"
        f"    <h1>Links for {safe_pkg}</h1>\n"
        f"{body}\n"
        "  </body>\n"
        "</html>\n"
    )
