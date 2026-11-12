"""FastAPI application for the Trusted OSS Quarantine, Scan, and Sign Gatekeeper."""

from contextlib import asynccontextmanager
import json
import logging
from pathlib import Path
import secrets
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
    ensure_mldsa_signing_key,
    ensure_provenance_hmac_key,
    sign_artifact_detached_gpg,
    sign_artifact_mldsa65,
    verify_artifact_signature,
    verify_artifact_mldsa65,
)
from app.storage import (
    atomic_promote_artifact,
    compute_digests,
    normalize_pypi_name,
    render_pep503_simple_index,
    resolve_safe_relative_path,
)

logger = logging.getLogger(__name__)
INSECURE_DEFAULT_TOKENS = {"", "ChangeMe_GatekeeperToken_2026!"}


OCI_ACCEPT_HEADER = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json"
)


def get_settings(request: Request) -> Settings:
    """Retrieve application settings from app.state or instantiate default Settings."""
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        settings = Settings()
        request.app.state.settings = settings
    return settings


def initialize_storage_and_keys(settings: Settings) -> Path:
    """Create persistent directory structure and ensure Trusted OSS GPG and PQC keys exist."""
    for directory in (
        settings.quarantine_dir,
        settings.trusted_maven_dir,
        settings.trusted_pypi_dir,
        settings.harbor_oci_cache_dir,
        settings.public_keys_dir,
        settings.mldsa_keys_dir,
        settings.provenance_log_path.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    if settings.pqc_signing_enabled:
        ensure_mldsa_signing_key(
            mldsa_keys_dir=settings.mldsa_keys_dir,
            public_keys_dir=settings.public_keys_dir,
        )

    ensure_provenance_hmac_key(
        key_path=settings.provenance_hmac_key_path,
        configured_key=settings.provenance_hmac_key,
    )

    return ensure_gpg_signing_key(
        gnupghome=settings.gnupghome,
        public_keys_dir=settings.public_keys_dir,
    )


def require_admin_token(x_gatekeeper_token: str | None, settings: Settings) -> None:
    """Enforce non-default, constant-time admin token authentication."""
    configured = settings.gatekeeper_admin_token
    if configured in INSECURE_DEFAULT_TOKENS:
        raise HTTPException(
            status_code=503,
            detail="Gatekeeper admin token is unset or uses an insecure default",
        )
    if not x_gatekeeper_token or not secrets.compare_digest(x_gatekeeper_token, configured):
        raise HTTPException(status_code=403, detail="Invalid gatekeeper admin token")


async def stream_http_to_file(
    client: httpx.AsyncClient, url: str, dest_path: Path, max_bytes: int
) -> bool:
    """Stream an upstream HTTP GET response to disk, enforcing a maximum byte limit."""
    async with client.stream("GET", url) as resp:
        if resp.status_code != 200:
            return False
        total = 0
        with dest_path.open("wb") as f:
            async for chunk in resp.aiter_bytes(chunk_size=65536):
                total += len(chunk)
                if total > max_bytes:
                    dest_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upstream artifact exceeds maximum allowed size ({max_bytes} bytes)",
                    )
                f.write(chunk)
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize storage directories and GPG/PQC signing authorities on startup."""
    settings = getattr(app.state, "settings", None) or Settings()
    app.state.settings = settings
    initialize_storage_and_keys(settings)
    yield


app = FastAPI(
    title="Trusted OSS Supply Chain Gatekeeper",
    description=(
        "Dynamic pull-through quarantine, Harbor Chainguard OCI proxy cache, "
        "ClamAV antivirus inspection, Trivy/NVD vulnerability gating, GPG/Cosign signing, "
        "and NIST FIPS 204 ML-DSA-65 Post-Quantum Cryptography dual-signing."
    ),
    version="0.2.0",
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
    """Execute the Quarantine -> ClamAV -> CVE -> GPG + ML-DSA-65 Dual Sign -> Trusted Promotion pipeline."""
    verdict = await evaluate_artifact_security(
        file_path=staged_file,
        clamav_host=settings.clamav_host,
        clamav_port=settings.clamav_port,
        clamav_required=settings.clamav_required,
        cvss_threshold=settings.cvss_fail_threshold,
        simulated_cvss=simulated_cvss,
        trivy_required=settings.trivy_required,
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

    pqc_sig_file: Path | None = None
    if settings.pqc_signing_enabled:
        try:
            pqc_sig_file = sign_artifact_mldsa65(
                artifact_path=staged_file,
                privkey_path=settings.mldsa_private_key_path,
            )
        except SigningError as exc:
            staged_file.unlink(missing_ok=True)
            sig_file.unlink(missing_ok=True)
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    digests = compute_digests(staged_file)
    atomic_promote_artifact(
        staged_file=staged_file,
        sig_file=sig_file,
        dest_file=dest_file,
        digests=digests,
        pqc_sig_file=pqc_sig_file,
    )
    staged_file.unlink(missing_ok=True)
    sig_file.unlink(missing_ok=True)
    if pqc_sig_file:
        pqc_sig_file.unlink(missing_ok=True)

    hmac_key = ensure_provenance_hmac_key(
        key_path=settings.provenance_hmac_key_path,
        configured_key=settings.provenance_hmac_key,
    )
    return append_provenance_record(
        provenance_log_path=settings.provenance_log_path,
        ecosystem=ecosystem,
        artifact_rel_path=artifact_rel_path,
        sha256=digests.sha256,
        sha384=digests.sha384,
        sha512=digests.sha512,
        clamav_status=verdict.clamav_status,
        cve_status=verdict.cve_status,
        signature_file=f"{artifact_rel_path}.asc",
        signature_file_mldsa=f"{artifact_rel_path}.mldsa65" if settings.pqc_signing_enabled else "",
        hmac_key=hmac_key,
    )


async def fetch_upstream_oci_manifest(
    upstream_base_url: str, repo_path: str, reference: str
) -> bytes:
    """Fetch an OCI manifest/index from upstream (e.g., Chainguard cgr.dev) with OCI Bearer token support."""
    base = upstream_base_url.rstrip("/")
    manifest_url = f"{base}/v2/{repo_path}/manifests/{reference}"
    headers = {"Accept": OCI_ACCEPT_HEADER}

    async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
        resp = await client.get(manifest_url, headers=headers)
        if resp.status_code == 401:
            token_resp = await client.get(
                f"{base}/token", params={"scope": f"repository:{repo_path}:pull"}
            )
            if token_resp.status_code == 200:
                token = token_resp.json().get("token", "")
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    resp = await client.get(manifest_url, headers=headers)

        if resp.status_code != 200:
            raise HTTPException(
                status_code=404,
                detail=f"OCI manifest not found upstream: {repo_path}:{reference} (HTTP {resp.status_code})",
            )
        return resp.content


async def ensure_maven_artifact_cached(
    base_rel_path: str, settings: Settings
) -> tuple[Path, str]:
    """Ensure a Maven artifact is cached and GPG-signed, pulling from upstream on cache miss."""
    base_file = resolve_safe_relative_path(settings.trusted_maven_dir, base_rel_path)
    if base_file.exists():
        return base_file, "HIT"

    if not settings.auto_promote_clean_artifacts:
        raise HTTPException(status_code=404, detail="Trusted Maven artifact not found")

    upstream_urls = [
        u.strip() for u in settings.upstream_maven_url.split(",") if u.strip()
    ]
    staged_file = resolve_safe_relative_path(
        settings.quarantine_dir, f"maven/{base_rel_path}"
    )
    staged_file.parent.mkdir(parents=True, exist_ok=True)
    downloaded = False
    async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
        for base_url in upstream_urls:
            candidate_url = f"{base_url.rstrip('/')}/{base_rel_path}"
            try:
                if await stream_http_to_file(client, candidate_url, staged_file, settings.max_artifact_bytes):
                    downloaded = True
                    break
            except HTTPException:
                raise
            except Exception as e:
                logger.warning(
                    "Failed to fetch maven artifact from %s: %s", candidate_url, e
                )

    if not downloaded:
        raise HTTPException(
            status_code=404,
            detail=f"Artifact not found in trusted store or upstream: {base_rel_path}",
        )

    await quarantine_scan_sign_and_promote(
        staged_file=staged_file,
        dest_file=base_file,
        ecosystem="maven",
        artifact_rel_path=base_rel_path,
        settings=settings,
    )
    return base_file, "MISS"


async def ensure_oci_manifest_cached(
    repo_path: str, base_ref: str, settings: Settings
) -> tuple[Path, str]:
    """Ensure a Chainguard/OCI manifest is cached, scanned, and GPG-signed in Harbor storage."""
    rel_manifest_path = f"{repo_path}/manifests/{base_ref}"
    base_file = resolve_safe_relative_path(
        settings.harbor_oci_cache_dir, rel_manifest_path
    )
    if base_file.exists():
        return base_file, "HIT"

    if not settings.auto_promote_clean_artifacts:
        raise HTTPException(status_code=404, detail="Cached OCI manifest not found")

    manifest_bytes = await fetch_upstream_oci_manifest(
        settings.upstream_chainguard_url, repo_path, base_ref
    )
    staged_file = resolve_safe_relative_path(
        settings.quarantine_dir, f"oci/{rel_manifest_path}"
    )
    staged_file.parent.mkdir(parents=True, exist_ok=True)
    staged_file.write_bytes(manifest_bytes)

    await quarantine_scan_sign_and_promote(
        staged_file=staged_file,
        dest_file=base_file,
        ecosystem="oci-harbor",
        artifact_rel_path=rel_manifest_path,
        settings=settings,
    )
    return base_file, "MISS"


@app.api_route("/healthz", methods=["GET", "HEAD"])
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


@app.get("/v2/")
async def oci_v2_root() -> JSONResponse:
    """OCI Distribution Spec v2 conformance endpoint for Harbor Proxy Cache clients."""
    return JSONResponse(
        status_code=200,
        content={"harbor_proxy_cache": "chainguard-cache", "status": "ready"},
        headers={"Docker-Distribution-API-Version": "registry/2.0"},
    )


@app.get("/v2/chainguard-cache/{repo_path:path}/manifests/{reference}")
async def get_chainguard_cached_manifest(
    repo_path: str,
    reference: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Serve and cache Chainguard OCI manifests (e.g., chainguard/jre, chainguard/python) with GPG signing."""
    rel_requested = f"{repo_path}/manifests/{reference}"
    try:
        requested_file = resolve_safe_relative_path(
            settings.harbor_oci_cache_dir, rel_requested
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    base_ref = reference
    for suffix in (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512"):
        if reference.endswith(suffix):
            base_ref = reference[: -len(suffix)]
            break

    base_file, cache_status = await ensure_oci_manifest_cached(
        repo_path=repo_path, base_ref=base_ref, settings=settings
    )

    if not requested_file.exists():
        raise HTTPException(status_code=404, detail="Cached OCI manifest companion not found")

    base_sig = base_file.with_name(f"{base_file.name}.asc")
    if requested_file.name.endswith(".mldsa65") and settings.pqc_signing_enabled:
        if not verify_artifact_mldsa65(base_file, requested_file, settings.mldsa_public_key_path):
            raise HTTPException(
                status_code=403,
                detail="Integrity violation: OCI manifest lacks a valid Trusted OSS ML-DSA-65 PQC signature",
            )
    elif not verify_artifact_signature(base_file, base_sig, settings.gnupghome):
        raise HTTPException(
            status_code=403,
            detail="Integrity violation: OCI manifest lacks a valid Trusted OSS GPG signature",
        )

    sha256_file = base_file.with_name(f"{base_file.name}.sha256")
    digest_val = (
        sha256_file.read_text(encoding="utf-8").strip() if sha256_file.exists() else ""
    )
    media_type = "application/vnd.oci.image.index.v1+json"
    if reference.endswith((".asc", ".mldsa65", ".sha256", ".sha384", ".sha512")):
        media_type = "text/plain; charset=utf-8"

    return FileResponse(
        requested_file,
        media_type=media_type,
        headers={
            "X-Cache-Status": cache_status,
            "Docker-Content-Digest": f"sha256:{digest_val}",
            "Docker-Distribution-API-Version": "registry/2.0",
        },
    )


@app.post("/catalog/warm")
async def warm_seed_catalog(
    settings: Annotated[Settings, Depends(get_settings)],
    x_gatekeeper_token: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Warm the Harbor Chainguard (JRE & Python) and shared Spring Boot component caches."""
    require_admin_token(x_gatekeeper_token, settings)

    if not settings.seed_catalog_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Seed catalog file not found: {settings.seed_catalog_path}",
        )

    catalog = json.loads(settings.seed_catalog_path.read_text(encoding="utf-8"))
    chainguard_results: list[dict[str, Any]] = []
    spring_boot_results: list[dict[str, Any]] = []

    for img in catalog.get("chainguard_containers", []):
        repo = img["repository"]
        ref = img.get("reference", "latest")
        manifest_file, status = await ensure_oci_manifest_cached(repo, ref, settings)
        sha256 = (
            manifest_file.with_name(f"{manifest_file.name}.sha256")
            .read_text(encoding="utf-8")
            .strip()
        )
        chainguard_results.append(
            {
                "image": f"{repo}:{ref}",
                "cache_status": status,
                "sha256": sha256,
                "signed": manifest_file.with_name(f"{manifest_file.name}.asc").exists(),
            }
        )

    for comp in catalog.get("spring_boot_maven_components", []):
        coord = f"{comp['groupId']}:{comp['artifactId']}:{comp['version']}"
        for rel_path in comp.get("artifacts", []):
            artifact_file, status = await ensure_maven_artifact_cached(
                rel_path, settings
            )
            sha256 = (
                artifact_file.with_name(f"{artifact_file.name}.sha256")
                .read_text(encoding="utf-8")
                .strip()
            )
            spring_boot_results.append(
                {
                    "coordinate": coord,
                    "artifact": rel_path,
                    "cache_status": status,
                    "sha256": sha256,
                    "signed": artifact_file.with_name(
                        f"{artifact_file.name}.asc"
                    ).exists(),
                }
            )

    return {
        "status": "warmed",
        "chainguard_containers_cached": len(chainguard_results),
        "spring_boot_artifacts_cached": len(spring_boot_results),
        "chainguard_containers": chainguard_results,
        "spring_boot_artifacts": spring_boot_results,
    }


@app.get("/catalog/status")
async def get_catalog_cache_status(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return current cache status for Chainguard containers and Spring Boot components."""
    if not settings.seed_catalog_path.exists():
        return {"chainguard_containers": [], "spring_boot_components": []}

    catalog = json.loads(settings.seed_catalog_path.read_text(encoding="utf-8"))
    cg_status: list[dict[str, Any]] = []
    for img in catalog.get("chainguard_containers", []):
        repo = img["repository"]
        ref = img.get("reference", "latest")
        m_file = resolve_safe_relative_path(
            settings.harbor_oci_cache_dir, f"{repo}/manifests/{ref}"
        )
        sig_file = m_file.with_name(f"{m_file.name}.asc")
        cg_status.append(
            {
                "image": f"{repo}:{ref}",
                "cached": m_file.exists(),
                "signature_valid": verify_artifact_signature(
                    m_file, sig_file, settings.gnupghome
                )
                if m_file.exists()
                else False,
            }
        )

    sb_status: list[dict[str, Any]] = []
    for comp in catalog.get("spring_boot_maven_components", []):
        coord = f"{comp['groupId']}:{comp['artifactId']}:{comp['version']}"
        for rel_path in comp.get("artifacts", []):
            a_file = resolve_safe_relative_path(settings.trusted_maven_dir, rel_path)
            sig_file = a_file.with_name(f"{a_file.name}.asc")
            sb_status.append(
                {
                    "coordinate": coord,
                    "artifact": rel_path,
                    "cached": a_file.exists(),
                    "signature_valid": verify_artifact_signature(
                        a_file, sig_file, settings.gnupghome
                    )
                    if a_file.exists()
                    else False,
                }
            )

    return {
        "chainguard_containers": cg_status,
        "spring_boot_components": sb_status,
    }


@app.api_route("/keys/trusted-oss-pubkey.asc", methods=["GET", "HEAD"], response_class=PlainTextResponse)
async def get_public_gpg_key(
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Return the ASCII-armored Trusted OSS GPG Public Key for client signature verification."""
    pubkey = settings.public_keys_dir / "trusted-oss-pubkey.asc"
    if not pubkey.exists():
        pubkey = initialize_storage_and_keys(settings)
    return pubkey.read_text(encoding="utf-8")


@app.api_route("/keys/trusted-oss-mldsa65.pub", methods=["GET", "HEAD"], response_class=PlainTextResponse)
async def get_public_mldsa65_key(
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Return the ASCII-armored Trusted OSS NIST FIPS 204 ML-DSA-65 Public Key."""
    if not settings.mldsa_public_key_path.exists():
        initialize_storage_and_keys(settings)
    if not settings.mldsa_public_key_path.exists():
        raise HTTPException(status_code=404, detail="ML-DSA-65 public key not initialized")
    return settings.mldsa_public_key_path.read_text(encoding="utf-8")


@app.api_route("/keys/trusted-oss-mldsa65.fingerprint", methods=["GET", "HEAD"], response_class=PlainTextResponse)
async def get_mldsa65_fingerprint(
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Return SHA-256 and SHA-384 fingerprints for the ML-DSA-65 Public Key."""
    fp_file = settings.public_keys_dir / "trusted-oss-mldsa65.fingerprint"
    if not fp_file.exists():
        initialize_storage_and_keys(settings)
    if not fp_file.exists():
        raise HTTPException(status_code=404, detail="ML-DSA-65 fingerprint not initialized")
    return fp_file.read_text(encoding="utf-8")


@app.get("/audit/provenance")
async def get_provenance_log(
    settings: Annotated[Settings, Depends(get_settings)],
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """Return recorded cryptographic provenance attestations with pagination."""
    safe_limit = max(1, min(limit, 1000))
    safe_offset = max(0, offset)
    records: list[dict[str, Any]] = []
    total = 0
    if settings.provenance_log_path.exists():
        with settings.provenance_log_path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                if safe_offset <= total < safe_offset + safe_limit:
                    records.append(json.loads(stripped))
                total += 1
    return {"count": total, "limit": safe_limit, "offset": safe_offset, "records": records}


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
    require_admin_token(x_gatekeeper_token, settings)

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
    total_written = 0
    with staged_file.open("wb") as out_f:
        while chunk := await file.read(65536):
            total_written += len(chunk)
            if total_written > settings.max_artifact_bytes:
                out_f.close()
                staged_file.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"Uploaded artifact exceeds maximum allowed size ({settings.max_artifact_bytes} bytes)",
                )
            out_f.write(chunk)

    effective_sim_cvss = x_simulated_cvss if settings.allow_simulated_cvss else 0.0
    record = await quarantine_scan_sign_and_promote(
        staged_file=staged_file,
        dest_file=dest_file,
        ecosystem=ecosystem,
        artifact_rel_path=artifact_path,
        settings=settings,
        simulated_cvss=effective_sim_cvss,
    )
    return JSONResponse(status_code=201, content=record)


@app.api_route("/maven/trusted/{artifact_path:path}", methods=["GET", "HEAD"])
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

    # Determine base artifact path if client requested .asc / .mldsa65 / .sha256 / .sha384 / .sha512
    base_rel_path = artifact_path
    for suffix in (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512"):
        if artifact_path.endswith(suffix):
            base_rel_path = artifact_path[: -len(suffix)]
            break

    base_file, cache_status = await ensure_maven_artifact_cached(base_rel_path, settings)

    if not requested_file.exists():
        raise HTTPException(status_code=404, detail="Trusted artifact not found")

    # Enforce mandatory signature verification before serving any primary artifact or companion
    base_sig = base_file.with_name(f"{base_file.name}.asc")
    if requested_file.name.endswith(".mldsa65") and settings.pqc_signing_enabled:
        if not verify_artifact_mldsa65(base_file, requested_file, settings.mldsa_public_key_path):
            raise HTTPException(
                status_code=403,
                detail="Integrity violation: artifact lacks a valid Trusted OSS ML-DSA-65 PQC signature",
            )
    elif not verify_artifact_signature(base_file, base_sig, settings.gnupghome):
        raise HTTPException(
            status_code=403,
            detail="Integrity violation: artifact lacks a valid Trusted OSS GPG signature",
        )

    return FileResponse(requested_file, headers={"X-Cache-Status": cache_status})


@app.api_route("/pypi/trusted/simple/{package}/", methods=["GET", "HEAD"], response_class=HTMLResponse)
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


@app.api_route("/pypi/trusted/packages/{package}/{filename}", methods=["GET", "HEAD"])
async def get_pypi_trusted_package_file(
    package: str,
    filename: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Serve only GPG-signed Python wheels/sdists and their .asc/.sha256/.sha512 files."""
    try:
        norm_pkg = normalize_pypi_name(package)
        rel_path = f"{norm_pkg}/{filename}"
        requested_file = resolve_safe_relative_path(settings.trusted_pypi_dir, rel_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    base_filename = filename
    for suffix in (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512"):
        if filename.endswith(suffix):
            base_filename = filename[: -len(suffix)]
            break

    base_rel_path = f"{norm_pkg}/{base_filename}"
    base_file = resolve_safe_relative_path(settings.trusted_pypi_dir, base_rel_path)
    cache_status = "HIT"

    if not base_file.exists() and settings.auto_promote_clean_artifacts:
        upstream_urls = [
            u.strip() for u in settings.upstream_pypi_simple_url.split(",") if u.strip()
        ]
        staged_file = resolve_safe_relative_path(
            settings.quarantine_dir, f"pypi/{base_rel_path}"
        )
        staged_file.parent.mkdir(parents=True, exist_ok=True)
        downloaded = False
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            for base_url in upstream_urls:
                candidate_url = f"{base_url.rstrip('/')}/{base_rel_path}"
                try:
                    if await stream_http_to_file(client, candidate_url, staged_file, settings.max_artifact_bytes):
                        downloaded = True
                        break
                except HTTPException:
                    raise
                except Exception as e:
                    logger.warning(
                        "Failed to fetch PyPI artifact from %s: %s", candidate_url, e
                    )

        if not downloaded:
            raise HTTPException(
                status_code=404,
                detail=f"PyPI artifact not found in trusted store or upstream: {base_rel_path}",
            )

        await quarantine_scan_sign_and_promote(
            staged_file=staged_file,
            dest_file=base_file,
            ecosystem="pypi",
            artifact_rel_path=base_rel_path,
            settings=settings,
        )
        cache_status = "MISS"

    if not requested_file.exists():
        raise HTTPException(status_code=404, detail="Trusted PyPI artifact not found")

    base_sig = base_file.with_name(f"{base_file.name}.asc")
    if requested_file.name.endswith(".mldsa65") and settings.pqc_signing_enabled:
        if not verify_artifact_mldsa65(base_file, requested_file, settings.mldsa_public_key_path):
            raise HTTPException(
                status_code=403,
                detail="Integrity violation: Python package lacks a valid Trusted OSS ML-DSA-65 PQC signature",
            )
    elif not verify_artifact_signature(base_file, base_sig, settings.gnupghome):
        raise HTTPException(
            status_code=403,
            detail="Integrity violation: Python package lacks a valid Trusted OSS GPG signature",
        )

    return FileResponse(requested_file, headers={"X-Cache-Status": cache_status})
