"""FastAPI application for the Trusted OSS Quarantine, Scan, and Sign Gatekeeper."""

from contextlib import asynccontextmanager
import json
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, UploadFile, File
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse

from app.config import Settings
from app.scanner import evaluate_artifact_security
from app.signer import (
    SigningError,
    append_provenance_record,
    ensure_gpg_signing_key,
    sign_artifact_detached_gpg,
    verify_artifact_signature,
)
from app.storage import (
    atomic_promote_artifact,
    compute_digests,
    normalize_pypi_name,
    render_pep503_simple_index,
    resolve_safe_relative_path,
)


def get_settings(request: Request) -> Settings:
    """Retrieve application settings from app.state or instantiate default Settings."""
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        settings = Settings()
        request.app.state.settings = settings
    return settings


def initialize_storage_and_keys(settings: Settings) -> Path:
    """Create persistent directory structure and ensure Trusted OSS GPG key exists."""
    for directory in (
        settings.quarantine_dir,
        settings.trusted_maven_dir,
        settings.trusted_pypi_dir,
        settings.public_keys_dir,
        settings.provenance_log_path.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    return ensure_gpg_signing_key(
        gnupghome=settings.gnupghome,
        public_keys_dir=settings.public_keys_dir,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize storage directories and GPG signing authority on startup."""
    settings = getattr(app.state, "settings", None) or Settings()
    app.state.settings = settings
    initialize_storage_and_keys(settings)
    yield


app = FastAPI(
    title="Trusted OSS Supply Chain Gatekeeper",
    description=(
        "Dynamic pull-through quarantine, ClamAV antivirus inspection, "
        "Trivy/NVD vulnerability gating, and GPG/Cosign cryptographic signing."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


async def quarantine_scan_sign_and_promote(
    staged_file: Path,
    dest_file: Path,
    ecosystem: str,
    artifact_rel_path: str,
    settings: Settings,
    simulated_cvss: float = 0.0,
) -> dict[str, Any]:
    """Execute the Quarantine -> ClamAV -> CVE -> GPG Sign -> Trusted Promotion pipeline."""
    verdict = await evaluate_artifact_security(
        file_path=staged_file,
        clamav_host=settings.clamav_host,
        clamav_port=settings.clamav_port,
        clamav_required=settings.clamav_required,
        cvss_threshold=settings.cvss_fail_threshold,
        simulated_cvss=simulated_cvss,
    )
    if not verdict.passed:
        staged_file.unlink(missing_ok=True)
        raise HTTPException(status_code=451, detail=verdict.reason)

    try:
        sig_file = sign_artifact_detached_gpg(
            artifact_path=staged_file,
            gnupghome=settings.gnupghome,
            passphrase=settings.gpg_passphrase,
        )
    except SigningError as exc:
        staged_file.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    digests = compute_digests(staged_file)
    atomic_promote_artifact(
        staged_file=staged_file,
        sig_file=sig_file,
        dest_file=dest_file,
        digests=digests,
    )
    staged_file.unlink(missing_ok=True)
    sig_file.unlink(missing_ok=True)

    return append_provenance_record(
        provenance_log_path=settings.provenance_log_path,
        ecosystem=ecosystem,
        artifact_rel_path=artifact_rel_path,
        sha256=digests.sha256,
        sha512=digests.sha512,
        clamav_status=verdict.clamav_status,
        cve_status=verdict.cve_status,
        signature_file=f"{artifact_rel_path}.asc",
    )


@app.get("/healthz")
async def healthz(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Liveness and readiness probe."""
    pubkey = settings.public_keys_dir / "trusted-oss-pubkey.asc"
    return {
        "status": "ok",
        "signing_authority_ready": pubkey.exists(),
        "cvss_fail_threshold": settings.cvss_fail_threshold,
    }


@app.get("/keys/trusted-oss-pubkey.asc", response_class=PlainTextResponse)
async def get_public_gpg_key(
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Return the ASCII-armored Trusted OSS GPG Public Key for client signature verification."""
    pubkey = initialize_storage_and_keys(settings)
    return pubkey.read_text(encoding="utf-8")


@app.get("/audit/provenance")
async def get_provenance_log(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return all recorded cryptographic provenance attestations."""
    records: list[dict[str, Any]] = []
    if settings.provenance_log_path.exists():
        for line in settings.provenance_log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    return {"count": len(records), "records": records}


@app.post("/ingest/{ecosystem}/{artifact_path:path}")
async def ingest_artifact(
    ecosystem: str,
    artifact_path: str,
    file: Annotated[UploadFile, File(...)],
    settings: Annotated[Settings, Depends(get_settings)],
    x_gatekeeper_token: Annotated[str | None, Header()] = None,
    x_simulated_cvss: Annotated[float, Header()] = 0.0,
) -> JSONResponse:
    """Ingest, ClamAV-scan, CVE-verify, GPG-sign, and promote a Maven or PyPI artifact."""
    if x_gatekeeper_token != settings.gatekeeper_admin_token:
        raise HTTPException(status_code=403, detail="Invalid gatekeeper admin token")

    if ecosystem == "maven":
        target_root = settings.trusted_maven_dir
    elif ecosystem == "pypi":
        target_root = settings.trusted_pypi_dir
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported ecosystem: {ecosystem}")

    try:
        dest_file = resolve_safe_relative_path(target_root, artifact_path)
        staged_file = resolve_safe_relative_path(
            settings.quarantine_dir, f"{ecosystem}/{artifact_path}"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    staged_file.parent.mkdir(parents=True, exist_ok=True)
    content = await file.read()
    staged_file.write_bytes(content)

    record = await quarantine_scan_sign_and_promote(
        staged_file=staged_file,
        dest_file=dest_file,
        ecosystem=ecosystem,
        artifact_rel_path=artifact_path,
        settings=settings,
        simulated_cvss=x_simulated_cvss,
    )
    return JSONResponse(status_code=201, content=record)


@app.get("/maven/trusted/{artifact_path:path}")
async def get_maven_trusted_artifact(
    artifact_path: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Serve only GPG-signed Maven artifacts, dynamically pulling & scanning on cache miss."""
    try:
        requested_file = resolve_safe_relative_path(
            settings.trusted_maven_dir, artifact_path
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Determine base artifact path if client requested .asc / .sha256 / .sha512
    base_rel_path = artifact_path
    for suffix in (".asc", ".sha256", ".sha512"):
        if artifact_path.endswith(suffix):
            base_rel_path = artifact_path[: -len(suffix)]
            break

    base_file = resolve_safe_relative_path(settings.trusted_maven_dir, base_rel_path)

    if not base_file.exists() and settings.auto_promote_clean_artifacts:
        upstream_url = f"{settings.upstream_maven_url.rstrip('/')}/{base_rel_path}"
        staged_file = resolve_safe_relative_path(
            settings.quarantine_dir, f"maven/{base_rel_path}"
        )
        staged_file.parent.mkdir(parents=True, exist_ok=True)
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            resp = await client.get(upstream_url)
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=404,
                    detail=f"Artifact not found in trusted store or upstream: {base_rel_path}",
                )
            staged_file.write_bytes(resp.content)

        await quarantine_scan_sign_and_promote(
            staged_file=staged_file,
            dest_file=base_file,
            ecosystem="maven",
            artifact_rel_path=base_rel_path,
            settings=settings,
        )

    if not requested_file.exists():
        raise HTTPException(status_code=404, detail="Trusted artifact not found")

    # Enforce mandatory signature verification before serving any primary artifact
    base_sig = base_file.with_name(f"{base_file.name}.asc")
    if not verify_artifact_signature(base_file, base_sig, settings.gnupghome):
        raise HTTPException(
            status_code=403,
            detail="Integrity violation: artifact lacks a valid Trusted OSS GPG signature",
        )

    return FileResponse(requested_file)


@app.get("/pypi/trusted/simple/{package}/", response_class=HTMLResponse)
async def get_pypi_simple_package_index(
    package: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Return PEP 503 Simple Repository index containing only GPG-signed wheels/sdists."""
    try:
        norm_pkg = normalize_pypi_name(package)
        pkg_dir = resolve_safe_relative_path(settings.trusted_pypi_dir, norm_pkg)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return render_pep503_simple_index(norm_pkg, pkg_dir)


@app.get("/pypi/trusted/packages/{package}/{filename}")
async def get_pypi_trusted_package_file(
    package: str,
    filename: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Serve only GPG-signed Python wheels/sdists and their .asc signatures."""
    try:
        norm_pkg = normalize_pypi_name(package)
        rel_path = f"{norm_pkg}/{filename}"
        requested_file = resolve_safe_relative_path(settings.trusted_pypi_dir, rel_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not requested_file.exists():
        raise HTTPException(status_code=404, detail="Trusted PyPI artifact not found")

    base_file = (
        requested_file.with_name(requested_file.name[:-4])
        if requested_file.name.endswith(".asc")
        else requested_file
    )
    base_sig = base_file.with_name(f"{base_file.name}.asc")
    if not verify_artifact_signature(base_file, base_sig, settings.gnupghome):
        raise HTTPException(
            status_code=403,
            detail="Integrity violation: Python package lacks a valid Trusted OSS GPG signature",
        )

    return FileResponse(requested_file)
