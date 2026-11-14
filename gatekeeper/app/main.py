"""FastAPI application for the Trusted OSS Quarantine, Scan, and Sign Gatekeeper."""

import asyncio
from contextlib import asynccontextmanager
import json
import logging
from pathlib import Path
import secrets
import sys
from typing import Annotated, Any
import uuid

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, UploadFile, File
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from app.config import Settings
from app.discovery import (
    discover_github_projects,
    discover_local_projects,
    merge_catalogs,
)
from app.scanner import evaluate_artifact_security
from app.signer import (
    SigningError,
    append_provenance_record,
    ensure_gpg_signing_key,
    ensure_mldsa_signing_key,
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
from app.virtual_repo import (
    OCI_REGISTRY_ALIASES,
    extract_package_coordinates,
    fetch_upstream_pypi_distributions,
    render_virtual_pep503_index,
    select_preferred_distribution,
)
from app.remediation import (
    fetch_upstream_maven_versions,
    load_latest_tags,
    load_quarantined_components,
    quarantine_artifact_with_sidecars,
    update_latest_tag,
    version_sort_key,
)

logger = logging.getLogger("gatekeeper")
if not logger.handlers:
    _stdout_handler = logging.StreamHandler(sys.stdout)
    _stdout_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] [gatekeeper] %(message)s")
    )
    logger.addHandler(_stdout_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


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

    return ensure_gpg_signing_key(
        gnupghome=settings.gnupghome,
        public_keys_dir=settings.public_keys_dir,
    )


async def _hourly_cve_rescan_loop(app: FastAPI) -> None:
    """Periodically rescan cached components for newly published CVEs and auto-remediate."""
    settings = get_settings_from_app(app)
    interval = max(60, settings.cve_rescan_interval_seconds)
    while True:
        await asyncio.sleep(interval)
        try:
            summary = await remediate_vulnerable_components(settings=settings, app_instance=app)
            logger.info(
                "[CACHE] HOURLY_CVE_RESCAN scanned=%d quarantined=%d upgraded=%d",
                summary["scanned"],
                summary["quarantined_count"],
                summary["upgraded_count"],
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("[CACHE] HOURLY_CVE_RESCAN failed: %s", exc)


def get_settings_from_app(app: FastAPI) -> Settings:
    settings = getattr(app.state, "settings", None)
    if settings is None:
        settings = Settings()
        app.state.settings = settings
    return settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize storage directories and GPG/PQC signing authorities on startup."""
    settings = get_settings_from_app(app)
    initialize_storage_and_keys(settings)
    rescan_task: asyncio.Task[Any] | None = None
    if settings.cve_rescan_interval_seconds > 0:
        rescan_task = asyncio.create_task(_hourly_cve_rescan_loop(app))
    try:
        yield
    finally:
        if rescan_task is not None:
            rescan_task.cancel()
            try:
                await rescan_task
            except asyncio.CancelledError:
                pass


app = FastAPI(
    title="Trusted OSS Supply Chain Gatekeeper",
    description=(
        "Dynamic pull-through quarantine, Harbor Chainguard OCI proxy cache, "
        "ClamAV antivirus inspection, Trivy/NVD vulnerability gating, GPG/Cosign signing, "
        "and NIST FIPS 204 ML-DSA-65 Post-Quantum Cryptography dual-signing."
    ),
    version="0.3.0",
    lifespan=lifespan,
)


class DiscoverRequest(BaseModel):
    """Optional parameters for dynamic project component discovery."""

    scan_roots: list[str] | None = None
    include_github: bool = False
    github_username: str | None = None
    max_projects: int = 30
    save_to_catalog: bool = True
    warm: bool = False
    ecosystems: list[str] | None = None
    concurrency: int | None = None


class WarmRequest(BaseModel):
    """Optional parameters for dynamic catalog warming."""

    discover: bool = False
    scan_roots: list[str] | None = None
    include_github: bool = False
    github_username: str | None = None
    max_projects: int = 30
    ecosystems: list[str] | None = None
    concurrency: int | None = None


def _get_artifact_lock(app_instance: FastAPI, key: str) -> asyncio.Lock:
    """Return a per-artifact asyncio.Lock for single-flight pull-through."""
    locks: dict[str, asyncio.Lock] | None = getattr(app_instance.state, "artifact_locks", None)
    if locks is None:
        locks = {}
        app_instance.state.artifact_locks = locks
    lock = locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        locks[key] = lock
    return lock


def _get_pypi_upstream_map(app_instance: FastAPI) -> dict[str, dict[str, str]]:
    """Return cached mapping of {norm_pkg: {filename: upstream_download_url}}."""
    mapping: dict[str, dict[str, str]] | None = getattr(app_instance.state, "pypi_upstream_map", None)
    if mapping is None:
        mapping = {}
        app_instance.state.pypi_upstream_map = mapping
    return mapping


def require_admin_token(x_gatekeeper_token: str | None, settings: Settings) -> None:
    """Fail closed (503) if admin token is unset/default, and 403 on mismatch."""
    configured = settings.gatekeeper_admin_token
    if not configured or configured in {"ChangeMe_GatekeeperToken_2026!", "changeme"}:
        raise HTTPException(
            status_code=503,
            detail="Gatekeeper admin token is not securely configured",
        )
    if not x_gatekeeper_token or not secrets.compare_digest(x_gatekeeper_token, configured):
        raise HTTPException(status_code=403, detail="Invalid gatekeeper admin token")


def _active_catalog_path(settings: Settings) -> Path:
    """Return dynamic catalog path if it exists, otherwise the configured seed catalog."""
    for candidate in (
        settings.oss_data_root / "catalog" / "dynamic-catalog.json",
        settings.oss_data_root / "audit" / "dynamic-catalog.json",
    ):
        if candidate.is_file():
            return candidate
    return settings.seed_catalog_path


def _save_dynamic_catalog(settings: Settings, catalog: dict[str, Any]) -> str:
    """Persist dynamic catalog to OSS_DATA_ROOT/catalog or fall back to OSS_DATA_ROOT/audit."""
    payload = json.dumps(catalog, indent=2)
    for candidate in (
        settings.oss_data_root / "catalog" / "dynamic-catalog.json",
        settings.oss_data_root / "audit" / "dynamic-catalog.json",
    ):
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text(payload, encoding="utf-8")
            return str(candidate)
        except OSError as exc:
            logger.warning("Unable to persist dynamic catalog to %s: %s", candidate, exc)
    return ""


async def quarantine_scan_sign_and_promote(
    staged_file: Path,
    dest_file: Path,
    ecosystem: str,
    artifact_rel_path: str,
    settings: Settings,
    simulated_cvss: float = 0.0,
) -> dict[str, Any]:
    """Execute the Quarantine -> ClamAV -> CVE -> GPG + ML-DSA-65 Dual Sign -> Trusted Promotion pipeline."""
    pkg_name, pkg_version = extract_package_coordinates(ecosystem, artifact_rel_path)
    verdict = await evaluate_artifact_security(
        file_path=staged_file,
        clamav_host=settings.clamav_host,
        clamav_port=settings.clamav_port,
        clamav_required=settings.clamav_required,
        cvss_threshold=settings.cvss_fail_threshold,
        simulated_cvss=simulated_cvss,
        cve_scanner_mode=settings.cve_scanner_mode,
        package_ecosystem=ecosystem,
        package_name=pkg_name,
        package_version=pkg_version,
    )
    if not verdict.passed:
        staged_file.unlink(missing_ok=True)
        logger.warning(
            "[CACHE] BLOCKED ecosystem=%s artifact=%s version=%s clamav=%s cve_status=%s max_cvss=%.1f cves=%s reason=%s",
            ecosystem,
            artifact_rel_path,
            pkg_version or "unknown",
            verdict.clamav_status,
            verdict.cve_status,
            verdict.max_cvss,
            ",".join(verdict.cve_ids) if verdict.cve_ids else "none",
            verdict.reason,
        )
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

    record = append_provenance_record(
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
        max_cvss=verdict.max_cvss,
        cve_ids=verdict.cve_ids,
    )
    logger.info(
        "[CACHE] PROMOTED ecosystem=%s artifact=%s version=%s clamav=%s cve_status=%s max_cvss=%.1f cves=%s sha256=%s pqc=%s",
        ecosystem,
        artifact_rel_path,
        pkg_version or "unknown",
        verdict.clamav_status,
        verdict.cve_status,
        verdict.max_cvss,
        ",".join(verdict.cve_ids) if verdict.cve_ids else "none",
        digests.sha256[:12],
        "enabled" if settings.pqc_signing_enabled else "disabled",
    )
    return record


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
    base_rel_path: str, settings: Settings, app_instance: FastAPI | None = None
) -> tuple[Path, str]:
    """Ensure a Maven artifact is cached and GPG-signed, pulling from upstream on cache miss."""
    base_file = resolve_safe_relative_path(settings.trusted_maven_dir, base_rel_path)
    if base_file.exists():
        logger.info("[CACHE] HIT ecosystem=maven artifact=%s", base_rel_path)
        return base_file, "HIT"

    if not settings.auto_promote_clean_artifacts:
        raise HTTPException(status_code=404, detail="Trusted Maven artifact not found")

    lock = _get_artifact_lock(app_instance or app, f"maven:{base_rel_path}")
    async with lock:
        if base_file.exists():
            return base_file, "HIT"

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
                    resp = await client.get(candidate_url)
                    if resp.status_code == 200:
                        staged_file.write_bytes(resp.content)
                        downloaded = True
                        break
                except Exception as e:
                    logger.warning(
                        f"Failed to fetch maven artifact from {candidate_url}: {e}"
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


async def ensure_pypi_artifact_cached(
    norm_pkg: str,
    base_filename: str,
    settings: Settings,
    app_instance: FastAPI | None = None,
) -> tuple[Path, str]:
    """Ensure a PyPI wheel/sdist is cached, scanned, and signed, pulling via PEP 503/691 on miss."""
    base_rel_path = f"{norm_pkg}/{base_filename}"
    base_file = resolve_safe_relative_path(settings.trusted_pypi_dir, base_rel_path)
    if base_file.exists():
        logger.info("[CACHE] HIT ecosystem=pypi artifact=%s", base_rel_path)
        return base_file, "HIT"

    if not settings.auto_promote_clean_artifacts:
        raise HTTPException(status_code=404, detail="Trusted PyPI artifact not found")

    target_app = app_instance or app
    lock = _get_artifact_lock(target_app, f"pypi:{base_rel_path}")
    async with lock:
        if base_file.exists():
            return base_file, "HIT"

        upstream_urls = [
            u.strip() for u in settings.upstream_pypi_simple_url.split(",") if u.strip()
        ]
        url_map = _get_pypi_upstream_map(target_app)
        candidate_urls: list[str] = []

        pkg_map = url_map.get(norm_pkg, {})
        if base_filename in pkg_map:
            candidate_urls.append(pkg_map[base_filename])
        else:
            dists = await fetch_upstream_pypi_distributions(upstream_urls, norm_pkg)
            if dists:
                pkg_map = {d["filename"]: d["url"] for d in dists}
                url_map[norm_pkg] = pkg_map
                if base_filename in pkg_map:
                    candidate_urls.append(pkg_map[base_filename])

        # Fallback for direct-path mock upstreams (e.g. /pypi/<pkg>/<filename>)
        for base_url in upstream_urls:
            candidate_urls.append(f"{base_url.rstrip('/')}/{base_rel_path}")

        staged_file = resolve_safe_relative_path(
            settings.quarantine_dir, f"pypi/{base_rel_path}"
        )
        staged_file.parent.mkdir(parents=True, exist_ok=True)
        downloaded = False
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            for candidate_url in candidate_urls:
                try:
                    resp = await client.get(candidate_url)
                    if resp.status_code == 200:
                        staged_file.write_bytes(resp.content)
                        downloaded = True
                        break
                except Exception as e:
                    logger.warning(
                        f"Failed to fetch PyPI artifact from {candidate_url}: {e}"
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
        return base_file, "MISS"


async def ensure_oci_manifest_cached(
    repo_path: str,
    base_ref: str,
    settings: Settings,
    upstream_base_url: str | None = None,
    cache_namespace: str = "chainguard-cache",
    app_instance: FastAPI | None = None,
) -> tuple[Path, str]:
    """Ensure a Chainguard/OCI manifest is cached, scanned, and GPG-signed in Harbor storage."""
    rel_manifest_path = f"{repo_path}/manifests/{base_ref}"
    cache_root = (
        settings.harbor_oci_cache_dir
        if cache_namespace == "chainguard-cache"
        else settings.oss_data_root / "harbor" / "registry" / cache_namespace
    )
    base_file = resolve_safe_relative_path(cache_root, rel_manifest_path)
    if base_file.exists():
        logger.info("[CACHE] HIT ecosystem=oci namespace=%s artifact=%s", cache_namespace, rel_manifest_path)
        return base_file, "HIT"

    if not settings.auto_promote_clean_artifacts:
        raise HTTPException(status_code=404, detail="Cached OCI manifest not found")

    lock = _get_artifact_lock(app_instance or app, f"oci:{cache_namespace}:{rel_manifest_path}")
    async with lock:
        if base_file.exists():
            return base_file, "HIT"

        manifest_bytes = await fetch_upstream_oci_manifest(
            upstream_base_url or settings.upstream_chainguard_url, repo_path, base_ref
        )
        staged_file = resolve_safe_relative_path(
            settings.quarantine_dir, f"oci/{cache_namespace}/{rel_manifest_path}"
        )
        staged_file.parent.mkdir(parents=True, exist_ok=True)
        staged_file.write_bytes(manifest_bytes)

        await quarantine_scan_sign_and_promote(
            staged_file=staged_file,
            dest_file=base_file,
            ecosystem="oci-harbor",
            artifact_rel_path=f"{cache_namespace}/{rel_manifest_path}",
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


@app.get("/v2/virtual/{registry_alias}/{repo_path:path}/manifests/{reference}")
async def get_virtual_oci_manifest(
    registry_alias: str,
    repo_path: str,
    reference: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Virtual OCI Repository: fetch on miss, scan for malware/CVEs, sign, and serve."""
    upstream_base = OCI_REGISTRY_ALIASES.get(registry_alias)
    if not upstream_base:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown virtual OCI registry alias: {registry_alias}",
        )

    cache_root = (
        settings.harbor_oci_cache_dir
        if registry_alias == "chainguard-cache"
        else settings.oss_data_root / "harbor" / "registry" / registry_alias
    )
    rel_requested = f"{repo_path}/manifests/{reference}"
    try:
        requested_file = resolve_safe_relative_path(cache_root, rel_requested)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    base_ref = reference
    for suffix in (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512"):
        if reference.endswith(suffix):
            base_ref = reference[: -len(suffix)]
            break

    base_file, cache_status = await ensure_oci_manifest_cached(
        repo_path=repo_path,
        base_ref=base_ref,
        settings=settings,
        upstream_base_url=settings.upstream_chainguard_url if registry_alias == "chainguard-cache" else upstream_base,
        cache_namespace=registry_alias,
        app_instance=request.app,
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


async def _build_dynamic_catalog(
    settings: Settings,
    scan_roots: list[str] | None = None,
    include_github: bool = False,
    github_username: str | None = None,
    max_projects: int = 30,
) -> dict[str, Any]:
    """Discover components from local projects and/or GitHub, merged with seed catalog."""
    base_catalog: dict[str, Any] = {}
    if settings.seed_catalog_path.exists():
        base_catalog = json.loads(settings.seed_catalog_path.read_text(encoding="utf-8"))

    roots: list[Path] = []
    if scan_roots:
        roots = [Path(r) for r in scan_roots if r]
    elif settings.workspace_scan_roots:
        roots = [Path(r.strip()) for r in settings.workspace_scan_roots.split(",") if r.strip()]

    discovered: dict[str, Any] = {}
    if roots:
        discovered = discover_local_projects(roots, max_projects=max_projects)

    if include_github:
        gh_user = github_username or settings.github_username
        gh_discovered = await discover_github_projects(
            username=gh_user,
            token=settings.github_token,
            max_repos=max_projects,
        )
        discovered = merge_catalogs(discovered, gh_discovered) if discovered else gh_discovered

    return merge_catalogs(base_catalog, discovered) if discovered else base_catalog


async def _execute_catalog_warmup(
    catalog: dict[str, Any],
    settings: Settings,
    app_instance: FastAPI,
    ecosystems: set[str] | None = None,
    concurrency: int = 4,
) -> dict[str, Any]:
    """Warm OCI, Maven, and PyPI caches concurrently with per-component fault isolation."""
    sem = asyncio.Semaphore(max(1, concurrency))
    active_ecosystems = ecosystems or {"oci", "maven", "pypi"}

    chainguard_results: list[dict[str, Any]] = []
    spring_boot_results: list[dict[str, Any]] = []
    pypi_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    async def warm_oci(img: dict[str, Any]) -> None:
        repo = img["repository"]
        ref = img.get("reference", "latest")
        registry = img.get("registry", "cgr.dev")
        upstream_url = f"https://{registry}" if "." in registry else settings.upstream_chainguard_url
        ns = "chainguard-cache" if registry in {"cgr.dev", ""} else registry.replace(".", "-")
        async with sem:
            try:
                manifest_file, status = await ensure_oci_manifest_cached(
                    repo_path=repo,
                    base_ref=ref,
                    settings=settings,
                    upstream_base_url=settings.upstream_chainguard_url if registry == "cgr.dev" else upstream_url,
                    cache_namespace=ns,
                    app_instance=app_instance,
                )
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
            except HTTPException as exc:
                failures.append({"ecosystem": "oci", "target": f"{repo}:{ref}", "status_code": exc.status_code, "detail": exc.detail})
            except Exception as exc:
                failures.append({"ecosystem": "oci", "target": f"{repo}:{ref}", "status_code": 500, "detail": str(exc)})

    async def warm_maven_artifact(coord: str, rel_path: str) -> None:
        async with sem:
            try:
                artifact_file, status = await ensure_maven_artifact_cached(
                    rel_path, settings, app_instance=app_instance
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
                        "signed": artifact_file.with_name(f"{artifact_file.name}.asc").exists(),
                    }
                )
            except HTTPException as exc:
                failures.append({"ecosystem": "maven", "target": rel_path, "status_code": exc.status_code, "detail": exc.detail})
            except Exception as exc:
                failures.append({"ecosystem": "maven", "target": rel_path, "status_code": 500, "detail": str(exc)})

    async def warm_pypi_package(comp: dict[str, Any]) -> None:
        raw_name = comp["name"]
        pinned = comp.get("pinned_version", "")
        async with sem:
            try:
                norm_pkg = normalize_pypi_name(raw_name)
                upstream_urls = [
                    u.strip() for u in settings.upstream_pypi_simple_url.split(",") if u.strip()
                ]
                dists = await fetch_upstream_pypi_distributions(upstream_urls, norm_pkg)
                chosen = select_preferred_distribution(dists, pinned_version=pinned)
                if not chosen:
                    failures.append({"ecosystem": "pypi", "target": raw_name, "status_code": 404, "detail": "No upstream distribution found"})
                    return
                _get_pypi_upstream_map(app_instance).setdefault(norm_pkg, {})[chosen["filename"]] = chosen["url"]
                artifact_file, status = await ensure_pypi_artifact_cached(
                    norm_pkg, chosen["filename"], settings, app_instance=app_instance
                )
                sha256 = (
                    artifact_file.with_name(f"{artifact_file.name}.sha256")
                    .read_text(encoding="utf-8")
                    .strip()
                )
                pypi_results.append(
                    {
                        "package": norm_pkg,
                        "filename": chosen["filename"],
                        "cache_status": status,
                        "sha256": sha256,
                        "signed": artifact_file.with_name(f"{artifact_file.name}.asc").exists(),
                    }
                )
            except HTTPException as exc:
                failures.append({"ecosystem": "pypi", "target": raw_name, "status_code": exc.status_code, "detail": exc.detail})
            except Exception as exc:
                failures.append({"ecosystem": "pypi", "target": raw_name, "status_code": 500, "detail": str(exc)})

    tasks: list[Any] = []
    if "oci" in active_ecosystems:
        for img in catalog.get("chainguard_containers", []):
            tasks.append(warm_oci(img))
    if "maven" in active_ecosystems:
        for comp in catalog.get("spring_boot_maven_components", []):
            coord = f"{comp['groupId']}:{comp['artifactId']}:{comp['version']}"
            for rel_path in comp.get("artifacts", []):
                tasks.append(warm_maven_artifact(coord, rel_path))
    if "pypi" in active_ecosystems:
        for comp in catalog.get("pypi_components", []):
            tasks.append(warm_pypi_package(comp))

    if tasks:
        await asyncio.gather(*tasks)

    logger.info(
        "[CACHE] WARMUP_SUMMARY oci=%d maven=%d pypi=%d failures=%d",
        len(chainguard_results),
        len(spring_boot_results),
        len(pypi_results),
        len(failures),
    )

    return {
        "status": "warmed",
        "source_projects": catalog.get("source_projects", []),
        "chainguard_containers_cached": len(chainguard_results),
        "spring_boot_artifacts_cached": len(spring_boot_results),
        "pypi_artifacts_cached": len(pypi_results),
        "failures_count": len(failures),
        "chainguard_containers": chainguard_results,
        "spring_boot_artifacts": spring_boot_results,
        "pypi_artifacts": pypi_results,
        "failures": failures,
    }


@app.post("/catalog/discover")
async def discover_project_catalog(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    body: Annotated[DiscoverRequest | None, Body()] = None,
    x_gatekeeper_token: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Dynamically discover Maven, PyPI, and OCI dependencies from recent local/GitHub projects."""
    require_admin_token(x_gatekeeper_token, settings)

    params = body or DiscoverRequest()
    catalog = await _build_dynamic_catalog(
        settings=settings,
        scan_roots=params.scan_roots,
        include_github=params.include_github,
        github_username=params.github_username,
        max_projects=params.max_projects,
    )

    saved_path = ""
    if params.save_to_catalog:
        saved_path = _save_dynamic_catalog(settings, catalog)

    warmup_summary: dict[str, Any] | None = None
    if params.warm:
        ecosystems = {e.lower() for e in params.ecosystems} if params.ecosystems else None
        warmup_summary = await _execute_catalog_warmup(
            catalog=catalog,
            settings=settings,
            app_instance=request.app,
            ecosystems=ecosystems,
            concurrency=params.concurrency or settings.warmup_concurrency,
        )

    return {
        "status": "discovered",
        "saved_catalog_path": saved_path,
        "source_projects": catalog.get("source_projects", []),
        "counts": {
            "chainguard_containers": len(catalog.get("chainguard_containers", [])),
            "oci_containers": len(catalog.get("oci_containers", [])),
            "maven_components": len(catalog.get("spring_boot_maven_components", [])),
            "pypi_components": len(catalog.get("pypi_components", [])),
        },
        "catalog": catalog,
        "warmup": warmup_summary,
    }


@app.post("/catalog/warm")
async def warm_seed_catalog(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    body: Annotated[WarmRequest | None, Body()] = None,
    x_gatekeeper_token: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Warm the Harbor Chainguard, Maven, and PyPI component caches (with optional dynamic discovery)."""
    require_admin_token(x_gatekeeper_token, settings)

    params = body or WarmRequest()
    if params.discover:
        catalog = await _build_dynamic_catalog(
            settings=settings,
            scan_roots=params.scan_roots,
            include_github=params.include_github,
            github_username=params.github_username,
            max_projects=params.max_projects,
        )
        _save_dynamic_catalog(settings, catalog)
    else:
        cat_path = _active_catalog_path(settings)
        if not cat_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Seed catalog file not found: {cat_path}",
            )
        catalog = json.loads(cat_path.read_text(encoding="utf-8"))

    ecosystems = {e.lower() for e in params.ecosystems} if params.ecosystems else None
    return await _execute_catalog_warmup(
        catalog=catalog,
        settings=settings,
        app_instance=request.app,
        ecosystems=ecosystems,
        concurrency=params.concurrency or settings.warmup_concurrency,
    )


@app.get("/catalog/status")
async def get_catalog_cache_status(
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Return current cache status for Chainguard containers, Maven, and PyPI components."""
    cat_path = _active_catalog_path(settings)
    if not cat_path.exists():
        return {"chainguard_containers": [], "spring_boot_components": [], "pypi_components": []}

    catalog = json.loads(cat_path.read_text(encoding="utf-8"))
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

    pypi_status: list[dict[str, Any]] = []
    for comp in catalog.get("pypi_components", []):
        norm_pkg = normalize_pypi_name(comp["name"])
        pkg_dir = resolve_safe_relative_path(settings.trusted_pypi_dir, norm_pkg)
        cached_files = (
            [
                p
                for p in pkg_dir.iterdir()
                if p.is_file()
                and not p.is_symlink()
                and not p.name.endswith((".asc", ".mldsa65", ".sha256", ".sha384", ".sha512", ".html"))
            ]
            if pkg_dir.exists()
            else []
        )
        sig_valid = any(
            verify_artifact_signature(f, f.with_name(f"{f.name}.asc"), settings.gnupghome)
            for f in cached_files
        )
        pypi_status.append(
            {
                "package": norm_pkg,
                "cached": len(cached_files) > 0,
                "files": [f.name for f in sorted(cached_files)],
                "signature_valid": sig_valid,
            }
        )

    return {
        "chainguard_containers": cg_status,
        "spring_boot_components": sb_status,
        "pypi_components": pypi_status,
    }


_SIDECAR_SUFFIXES = (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512", ".html", ".json", ".xml")


def _classify_vulnerability_status(
    cve_status: str, max_cvss: float, threshold: float
) -> str:
    """Classify per-version vulnerability posture from provenance scan metadata."""
    upper = (cve_status or "").upper()
    if max_cvss >= threshold or "FAIL" in upper or "BLOCKED" in upper or "VULN" in upper:
        return "VULNERABLE"
    if any(tok in upper for tok in ("OK", "CLEAN", "PASS")):
        return "CLEAN"
    return "UNSCANNED"


def _load_latest_provenance_map(provenance_log_path: Path) -> dict[str, dict[str, Any]]:
    """Return latest provenance record keyed by relative artifact path."""
    latest: dict[str, dict[str, Any]] = {}
    if not provenance_log_path.is_file():
        return latest
    for line in provenance_log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        art = str(rec.get("artifact", ""))
        if art:
            latest[art] = rec
    return latest


def _parse_ecosystem_filter(ecosystem: str | None) -> set[str] | None:
    """Parse a comma-separated ecosystem parameter ('oci,maven,pypi' or 'all')."""
    if not ecosystem:
        return None
    tokens = [t.strip().lower() for t in ecosystem.split(",") if t.strip()]
    if not tokens or "all" in tokens:
        return None
    invalid = [t for t in tokens if t not in {"oci", "maven", "pypi"}]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported ecosystem filter: {','.join(invalid)}",
        )
    return set(tokens)


def _parse_component_filter(components: str | None) -> list[str]:
    """Parse a comma-separated component name filter."""
    if not components:
        return []
    return [c.strip().lower() for c in components.split(",") if c.strip()]


def _matches_component_filter(component_name: str, filters: list[str]) -> bool:
    if not filters:
        return True
    low = component_name.lower()
    return any(f in low for f in filters)


def _build_component_history(
    components: list[dict[str, Any]],
    quarantined: list[dict[str, Any]],
    provenance_log_path: Path,
    latest_tags: dict[str, dict[str, Any]],
    eco_filters: set[str] | None = None,
    comp_filters: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Build per-component caching history showing active 'latest', older cached, quarantined, and historical versions."""
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    c_filters = comp_filters or []

    def _bucket(eco: str, comp: str) -> dict[str, Any]:
        key = (eco, comp)
        if key not in grouped:
            tag_entry = latest_tags.get(f"{eco}:{comp}", {})
            grouped[key] = {
                "ecosystem": eco,
                "component": comp,
                "serving_latest_version": tag_entry.get("latest_version", ""),
                "versions": [],
            }
        return grouped[key]

    seen_keys: set[tuple[str, str, str, str]] = set()
    for item in components:
        eco = str(item.get("ecosystem", ""))
        comp = str(item.get("component", ""))
        if (eco_filters and eco not in eco_filters) or not _matches_component_filter(comp, c_filters):
            continue
        ver = str(item.get("version", ""))
        tags = list(item.get("tags") or [])
        state = "SERVING_LATEST" if "latest" in tags else "CACHED"
        bucket = _bucket(eco, comp)
        if state == "SERVING_LATEST" and not bucket["serving_latest_version"]:
            bucket["serving_latest_version"] = ver
        bucket["versions"].append(
            {
                "version": ver,
                "state": state,
                "tags": tags,
                "vulnerability_status": item.get("vulnerability_status", "UNSCANNED"),
                "max_cvss": item.get("max_cvss", 0.0),
                "cve_ids": item.get("cve_ids", []),
                "timestamp": item.get("last_scanned_at", ""),
                "artifact": item.get("artifact", ""),
            }
        )
        seen_keys.add((eco, comp, ver, state))

    for q in quarantined:
        eco = str(q.get("ecosystem", ""))
        comp = str(q.get("component", ""))
        if (eco_filters and eco not in eco_filters) or not _matches_component_filter(comp, c_filters):
            continue
        ver = str(q.get("version", ""))
        bucket = _bucket(eco, comp)
        bucket["versions"].append(
            {
                "version": ver,
                "state": "QUARANTINED",
                "tags": [],
                "vulnerability_status": "VULNERABLE",
                "max_cvss": q.get("max_cvss", 0.0),
                "cve_ids": q.get("cve_ids", []),
                "superseded_by": q.get("superseded_by", ""),
                "timestamp": q.get("quarantined_at", ""),
                "artifact": q.get("artifact", ""),
            }
        )
        seen_keys.add((eco, comp, ver, "QUARANTINED"))

    if provenance_log_path.is_file():
        for line in provenance_log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw_eco = str(rec.get("ecosystem", ""))
            eco = "oci" if raw_eco == "oci-harbor" else raw_eco
            art = str(rec.get("artifact", ""))
            if eco == "oci" and "/manifests/" in art:
                comp_part, _, ver = art.partition("/manifests/")
                comp = comp_part.split("/", 1)[-1] if "/" in comp_part else comp_part
            else:
                comp, ver = extract_package_coordinates(eco, art)
            comp = comp or art
            ver = ver or "unknown"
            if (eco_filters and eco not in eco_filters) or not _matches_component_filter(comp, c_filters):
                continue
            if any(
                (eco, comp, ver, st) in seen_keys
                for st in ("SERVING_LATEST", "CACHED", "QUARANTINED", "HISTORICAL")
            ):
                continue
            bucket = _bucket(eco, comp)
            bucket["versions"].append(
                {
                    "version": ver,
                    "state": "HISTORICAL",
                    "tags": [],
                    "vulnerability_status": "CLEAN",
                    "max_cvss": rec.get("max_cvss", 0.0),
                    "cve_ids": rec.get("cve_ids", []),
                    "timestamp": rec.get("timestamp", ""),
                    "artifact": art,
                }
            )
            seen_keys.add((eco, comp, ver, "HISTORICAL"))

    for bucket in grouped.values():
        bucket["versions"].sort(
            key=lambda v: (
                1 if v["state"] == "SERVING_LATEST" else 0,
                version_sort_key(str(v["version"])),
            ),
            reverse=True,
        )
        if not bucket["serving_latest_version"]:
            clean_vers = [v for v in bucket["versions"] if v["state"] in ("SERVING_LATEST", "CACHED")]
            if clean_vers:
                bucket["serving_latest_version"] = clean_vers[0]["version"]

    return sorted(grouped.values(), key=lambda b: (b["ecosystem"], b["component"]))


@app.get("/catalog/vulnerabilities")
async def get_catalog_vulnerabilities(
    settings: Annotated[Settings, Depends(get_settings)],
    ecosystem: str | None = None,
    components: str | None = None,
    verify_signatures: bool = False,
) -> dict[str, Any]:
    """Return all cached components on disk with per-version signature, CVE status, and caching history."""
    eco_filters = _parse_ecosystem_filter(ecosystem)
    comp_filters = _parse_component_filter(components)
    provenance_map = _load_latest_provenance_map(settings.provenance_log_path)
    latest_tags = load_latest_tags(settings)
    quarantined = load_quarantined_components(settings.quarantine_dir)
    if eco_filters:
        quarantined = [q for q in quarantined if q.get("ecosystem") in eco_filters]
    if comp_filters:
        quarantined = [
            q for q in quarantined if _matches_component_filter(str(q.get("component", "")), comp_filters)
        ]
    cached_components: list[dict[str, Any]] = []

    # 1. OCI / Harbor proxy cache (all namespaces under harbor/registry)
    registry_root = settings.oss_data_root / "harbor" / "registry"
    if registry_root.is_dir():
        for ns_dir in sorted(registry_root.iterdir()):
            if not ns_dir.is_dir() or ns_dir.is_symlink():
                continue
            ns = ns_dir.name
            for path in sorted(ns_dir.rglob("*")):
                if (
                    not path.is_file()
                    or path.is_symlink()
                    or path.name.endswith(_SIDECAR_SUFFIXES)
                    or "/manifests/" not in path.as_posix()
                ):
                    continue
                rel = path.relative_to(ns_dir).as_posix()
                repo_part, _, tag_part = rel.partition("/manifests/")
                prov = provenance_map.get(f"{ns}/{rel}") or provenance_map.get(rel) or {}
                cve_status = str(prov.get("cve_status", "UNKNOWN"))
                max_cvss = float(prov.get("max_cvss", 0.0) or 0.0)
                cve_ids = list(prov.get("cve_ids") or [])
                tag_entry = latest_tags.get(f"oci:{repo_part}", {})
                comp_tags = ["latest"] if (tag_part == "latest" or tag_entry.get("latest_version") == (tag_part or "latest")) else []
                cached_components.append(
                    {
                        "ecosystem": "oci",
                        "namespace": ns,
                        "component": repo_part,
                        "version": tag_part or "latest",
                        "artifact": rel,
                        "tags": comp_tags,
                        "signature_valid": (
                            verify_artifact_signature(
                                path, path.with_name(f"{path.name}.asc"), settings.gnupghome
                            )
                            if verify_signatures
                            else path.with_name(f"{path.name}.asc").is_file()
                        ),
                        "pqc_signed": path.with_name(f"{path.name}.mldsa65").is_file(),
                        "clamav_status": str(prov.get("clamav_status", "UNKNOWN")),
                        "cve_status": cve_status,
                        "max_cvss": max_cvss,
                        "cve_ids": cve_ids,
                        "vulnerability_status": _classify_vulnerability_status(
                            cve_status, max_cvss, settings.cvss_fail_threshold
                        ),
                        "last_scanned_at": str(prov.get("timestamp", "")),
                    }
                )

    # 2. Trusted Maven & PyPI caches
    for eco, root_dir in (("maven", settings.trusted_maven_dir), ("pypi", settings.trusted_pypi_dir)):
        if not root_dir.is_dir():
            continue
        for path in sorted(root_dir.rglob("*")):
            if (
                not path.is_file()
                or path.is_symlink()
                or path.name.endswith(_SIDECAR_SUFFIXES)
            ):
                continue
            rel = path.relative_to(root_dir).as_posix()
            pkg_name, pkg_version = extract_package_coordinates(eco, rel)
            prov = provenance_map.get(rel) or {}
            cve_status = str(prov.get("cve_status", "UNKNOWN"))
            max_cvss = float(prov.get("max_cvss", 0.0) or 0.0)
            cve_ids = list(prov.get("cve_ids") or [])
            tag_entry = latest_tags.get(f"{eco}:{pkg_name or rel}", {})
            comp_tags = ["latest"] if tag_entry.get("latest_version") == (pkg_version or "unknown") else []
            cached_components.append(
                {
                    "ecosystem": eco,
                    "component": pkg_name or rel,
                    "version": pkg_version or "unknown",
                    "artifact": rel,
                    "tags": comp_tags,
                    "signature_valid": (
                        verify_artifact_signature(
                            path, path.with_name(f"{path.name}.asc"), settings.gnupghome
                        )
                        if verify_signatures
                        else path.with_name(f"{path.name}.asc").is_file()
                    ),
                    "pqc_signed": path.with_name(f"{path.name}.mldsa65").is_file(),
                    "clamav_status": str(prov.get("clamav_status", "UNKNOWN")),
                    "cve_status": cve_status,
                    "max_cvss": max_cvss,
                    "cve_ids": cve_ids,
                    "vulnerability_status": _classify_vulnerability_status(
                        cve_status, max_cvss, settings.cvss_fail_threshold
                    ),
                    "last_scanned_at": str(prov.get("timestamp", "")),
                }
            )

    if eco_filters:
        cached_components = [c for c in cached_components if c.get("ecosystem") in eco_filters]
    if comp_filters:
        cached_components = [
            c
            for c in cached_components
            if _matches_component_filter(str(c.get("component", "")), comp_filters)
        ]

    history = _build_component_history(
        components=cached_components,
        quarantined=quarantined,
        provenance_log_path=settings.provenance_log_path,
        latest_tags=latest_tags,
        eco_filters=eco_filters,
        comp_filters=comp_filters,
    )

    summary = {
        "total": len(cached_components),
        "clean": sum(1 for c in cached_components if c["vulnerability_status"] == "CLEAN"),
        "vulnerable": sum(1 for c in cached_components if c["vulnerability_status"] == "VULNERABLE"),
        "unscanned": sum(1 for c in cached_components if c["vulnerability_status"] == "UNSCANNED"),
        "quarantined": len(quarantined),
    }
    return {
        "cvss_fail_threshold": settings.cvss_fail_threshold,
        "ecosystem_filter": ",".join(sorted(eco_filters)) if eco_filters else "all",
        "component_filter": ",".join(comp_filters) if comp_filters else "all",
        "summary": summary,
        "components": cached_components,
        "quarantined": quarantined,
        "latest_tags": latest_tags,
        "history": history,
    }


async def _try_upgrade_component(
    ecosystem: str,
    component: str,
    vulnerable_version: str,
    rel_path: str,
    settings: Settings,
    app_instance: FastAPI,
) -> dict[str, str] | None:
    """Fetch the newest clean upstream version and tag it 'latest'."""
    if ecosystem == "pypi":
        upstream_urls = [u.strip() for u in settings.upstream_pypi_simple_url.split(",") if u.strip()]
        dists = await fetch_upstream_pypi_distributions(upstream_urls, component)
        enriched: list[tuple[str, dict[str, str]]] = []
        for d in dists:
            fname = d.get("filename", "")
            ver = d.get("version") or extract_package_coordinates("pypi", f"{component}/{fname}")[1]
            if ver and ver != vulnerable_version:
                enriched.append((ver, d))
        enriched.sort(key=lambda pair: version_sort_key(pair[0]), reverse=True)
        seen_versions: set[str] = set()
        for ver, dist in enriched:
            if ver in seen_versions:
                continue
            seen_versions.add(ver)
            _get_pypi_upstream_map(app_instance).setdefault(component, {})[dist["filename"]] = dist["url"]
            try:
                await ensure_pypi_artifact_cached(component, dist["filename"], settings, app_instance=app_instance)
                update_latest_tag(settings, "pypi", component, ver, f"{component}/{dist['filename']}")
                logger.info(
                    "[CACHE] LATEST_TAG_UPDATED ecosystem=pypi component=%s version=%s superseded=%s",
                    component,
                    ver,
                    vulnerable_version,
                )
                return {"version": ver, "artifact": f"{component}/{dist['filename']}"}
            except HTTPException:
                continue
        return None

    if ecosystem == "maven" and ":" in component:
        group_id, artifact_id = component.split(":", 1)
        upstream_urls = [u.strip() for u in settings.upstream_maven_url.split(",") if u.strip()]
        versions = await fetch_upstream_maven_versions(upstream_urls, group_id, artifact_id)
        ext = ".pom" if rel_path.endswith(".pom") else ".jar"
        group_path = group_id.replace(".", "/")
        for ver in versions:
            if ver == vulnerable_version:
                continue
            candidate_rel = f"{group_path}/{artifact_id}/{ver}/{artifact_id}-{ver}{ext}"
            try:
                await ensure_maven_artifact_cached(candidate_rel, settings, app_instance=app_instance)
                update_latest_tag(settings, "maven", component, ver, candidate_rel)
                logger.info(
                    "[CACHE] LATEST_TAG_UPDATED ecosystem=maven component=%s version=%s superseded=%s",
                    component,
                    ver,
                    vulnerable_version,
                )
                return {"version": ver, "artifact": candidate_rel}
            except HTTPException:
                continue
        return None

    if ecosystem == "oci":
        try:
            await ensure_oci_manifest_cached(
                repo_path=component,
                base_ref="latest",
                settings=settings,
                app_instance=app_instance,
            )
            update_latest_tag(settings, "oci", component, "latest", f"chainguard-cache/{component}/manifests/latest")
            return {"version": "latest", "artifact": f"{component}/manifests/latest"}
        except HTTPException:
            return None

    return None


async def remediate_vulnerable_components(
    settings: Settings,
    app_instance: FastAPI,
    ecosystems: set[str] | None = None,
    comp_filters: list[str] | None = None,
    concurrency: int | None = None,
) -> dict[str, Any]:
    """Rescan cached artifacts concurrently for newly published CVEs, quarantine vulnerable versions, and fetch clean 'latest'."""
    import app.scanner as scanner_mod

    active_ecosystems = ecosystems or {"oci", "maven", "pypi"}
    c_filters = comp_filters or []
    sem = asyncio.Semaphore(max(1, concurrency or settings.warmup_concurrency))
    scanned = 0
    clean_count = 0
    quarantined_items: list[dict[str, Any]] = []
    upgraded_items: list[dict[str, Any]] = []
    failed_upgrades: list[dict[str, Any]] = []

    targets: list[tuple[str, Path, Path, str, str, str]] = []
    if "oci" in active_ecosystems:
        registry_root = settings.oss_data_root / "harbor" / "registry"
        if registry_root.is_dir():
            for ns_dir in sorted(registry_root.iterdir()):
                if not ns_dir.is_dir() or ns_dir.is_symlink():
                    continue
                for path in sorted(ns_dir.rglob("*")):
                    if (
                        not path.is_file()
                        or path.is_symlink()
                        or path.name.endswith(_SIDECAR_SUFFIXES)
                        or "/manifests/" not in path.as_posix()
                    ):
                        continue
                    rel = path.relative_to(ns_dir).as_posix()
                    repo_part, _, tag_part = rel.partition("/manifests/")
                    targets.append(("oci", ns_dir, path, rel, repo_part, tag_part or "latest"))

    for eco, root_dir in (("maven", settings.trusted_maven_dir), ("pypi", settings.trusted_pypi_dir)):
        if eco not in active_ecosystems or not root_dir.is_dir():
            continue
        for path in sorted(root_dir.rglob("*")):
            if not path.is_file() or path.is_symlink() or path.name.endswith(_SIDECAR_SUFFIXES):
                continue
            rel = path.relative_to(root_dir).as_posix()
            pkg_name, pkg_version = extract_package_coordinates(eco, rel)
            targets.append((eco, root_dir, path, rel, pkg_name or rel, pkg_version or "unknown"))

    async def _process_target(target: tuple[str, Path, Path, str, str, str]) -> None:
        nonlocal scanned, clean_count
        eco, root_dir, path, rel, component, version = target
        if not path.exists() or not _matches_component_filter(component, c_filters):
            return
        async with sem:
            scanned += 1
            mode = (settings.cve_scanner_mode or "auto").lower()
            max_cvss = 0.0
            cve_ids: list[str] = []
            cve_status = "OSV_SKIPPED"
            if mode in {"auto", "osv", "both"} and component and version not in {"", "unknown", "latest"}:
                _, max_cvss, cve_ids, cve_status = await scanner_mod.query_osv_vulnerabilities(
                    eco, component, version
                )
            if mode in {"trivy", "both"}:
                _, t_cvss, t_ids, t_status = await scanner_mod.scan_with_trivy(path)
                if t_cvss > max_cvss:
                    max_cvss = t_cvss
                cve_ids = sorted(set(cve_ids + t_ids))
                cve_status = f"{cve_status}+{t_status}"

            if max_cvss < settings.cvss_fail_threshold:
                clean_count += 1
                return

            upgrade = await _try_upgrade_component(
                ecosystem=eco,
                component=component,
                vulnerable_version=version,
                rel_path=rel,
                settings=settings,
                app_instance=app_instance,
            )
            superseded_by = upgrade["version"] if upgrade else ""
            if upgrade:
                upgraded_items.append(
                    {
                        "ecosystem": eco,
                        "component": component,
                        "previous_version": version,
                        "latest_version": upgrade["version"],
                        "artifact": upgrade["artifact"],
                    }
                )
            else:
                failed_upgrades.append({"ecosystem": eco, "component": component, "version": version})

            quarantine_artifact_with_sidecars(
                artifact_path=path,
                root_dir=root_dir,
                quarantine_root=settings.quarantine_dir,
                ecosystem=eco,
                component=component,
                version=version,
                max_cvss=max_cvss,
                cve_ids=cve_ids,
                cve_status=cve_status,
                superseded_by=superseded_by,
            )
            logger.warning(
                "[CACHE] QUARANTINED ecosystem=%s component=%s version=%s max_cvss=%.1f cves=%s superseded_by=%s",
                eco,
                component,
                version,
                max_cvss,
                ",".join(cve_ids) if cve_ids else "none",
                superseded_by or "none",
            )
            quarantined_items.append(
                {
                    "ecosystem": eco,
                    "component": component,
                    "version": version,
                    "max_cvss": max_cvss,
                    "cve_ids": cve_ids,
                    "superseded_by": superseded_by,
                }
            )

    if targets:
        await asyncio.gather(*(_process_target(t) for t in targets))

    return {
        "status": "remediated",
        "ecosystems": sorted(active_ecosystems),
        "scanned": scanned,
        "clean_count": clean_count,
        "quarantined_count": len(quarantined_items),
        "upgraded_count": len(upgraded_items),
        "quarantined": quarantined_items,
        "upgraded": upgraded_items,
        "failed_upgrades": failed_upgrades,
        "latest_tags": load_latest_tags(settings),
    }


@app.post("/catalog/remediate")
async def remediate_catalog_endpoint(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    ecosystem: str | None = None,
    components: str | None = None,
    concurrency: int | None = None,
    x_gatekeeper_token: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Rescan cached components (optionally comma-separated ecosystems/components) and upgrade vulnerable versions to clean 'latest'."""
    require_admin_token(x_gatekeeper_token, settings)
    ecosystems = _parse_ecosystem_filter(ecosystem)
    comp_filters = _parse_component_filter(components)
    return await remediate_vulnerable_components(
        settings=settings,
        app_instance=request.app,
        ecosystems=ecosystems,
        comp_filters=comp_filters,
        concurrency=concurrency,
    )


@app.api_route("/keys/trusted-oss-pubkey.asc", methods=["GET", "HEAD"], response_class=PlainTextResponse)
async def get_public_gpg_key(
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Return the ASCII-armored Trusted OSS GPG Public Key for client signature verification."""
    pubkey = initialize_storage_and_keys(settings)
    return pubkey.read_text(encoding="utf-8")


@app.api_route("/keys/trusted-oss-mldsa65.pub", methods=["GET", "HEAD"], response_class=PlainTextResponse)
async def get_public_mldsa65_key(
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Return the ASCII-armored Trusted OSS NIST FIPS 204 ML-DSA-65 Public Key."""
    initialize_storage_and_keys(settings)
    if not settings.mldsa_public_key_path.exists():
        raise HTTPException(status_code=404, detail="ML-DSA-65 public key not initialized")
    return settings.mldsa_public_key_path.read_text(encoding="utf-8")


@app.api_route("/keys/trusted-oss-mldsa65.fingerprint", methods=["GET", "HEAD"], response_class=PlainTextResponse)
async def get_mldsa65_fingerprint(
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Return SHA-256 and SHA-384 fingerprints for the ML-DSA-65 Public Key."""
    initialize_storage_and_keys(settings)
    fp_file = settings.public_keys_dir / "trusted-oss-mldsa65.fingerprint"
    if not fp_file.exists():
        raise HTTPException(status_code=404, detail="ML-DSA-65 fingerprint not initialized")
    return fp_file.read_text(encoding="utf-8")


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
    content = await file.read()
    staged_file.write_bytes(content)

    record = await quarantine_scan_sign_and_promote(
        staged_file=staged_file,
        dest_file=dest_file,
        ecosystem=ecosystem,
        artifact_rel_path=artifact_path,
        settings=settings,
        simulated_cvss=x_simulated_cvss if settings.allow_simulated_cvss else 0.0,
    )
    return JSONResponse(status_code=201, content=record)


async def _serve_maven_artifact(
    artifact_path: str,
    request: Request,
    settings: Settings,
) -> FileResponse:
    """Shared handler for Maven trusted & virtual repositories."""
    try:
        requested_file = resolve_safe_relative_path(
            settings.trusted_maven_dir, artifact_path
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if requested_file.name == "maven-metadata.xml" and requested_file.is_file():
        return FileResponse(requested_file, media_type="application/xml", headers={"X-Cache-Status": "HIT"})

    base_rel_path = artifact_path
    for suffix in (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512"):
        if artifact_path.endswith(suffix):
            base_rel_path = artifact_path[: -len(suffix)]
            break

    base_file, cache_status = await ensure_maven_artifact_cached(
        base_rel_path, settings, app_instance=request.app
    )

    if not requested_file.exists():
        raise HTTPException(status_code=404, detail="Trusted artifact not found")

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


@app.api_route("/maven/trusted/{artifact_path:path}", methods=["GET", "HEAD"])
async def get_maven_trusted_artifact(
    artifact_path: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Serve only GPG-signed Maven artifacts, dynamically pulling & scanning on cache miss."""
    return await _serve_maven_artifact(artifact_path, request, settings)


@app.api_route("/maven/virtual/{artifact_path:path}", methods=["GET", "HEAD"])
async def get_maven_virtual_artifact(
    artifact_path: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Virtual Maven Repository: fetch on miss, scan for High/Critical defects, sign, and serve."""
    if not settings.virtual_repo_enabled:
        raise HTTPException(status_code=404, detail="Virtual repository feature is disabled")
    return await _serve_maven_artifact(artifact_path, request, settings)


async def _serve_pypi_simple_index(
    package: str,
    request: Request,
    settings: Settings,
    package_route_prefix: str,
    force_virtual: bool = False,
) -> HTMLResponse:
    """Serve PEP 503 Simple index, proxying upstream distributions when virtual pull-through is enabled."""
    try:
        norm_pkg = normalize_pypi_name(package)
        pkg_dir = resolve_safe_relative_path(settings.trusted_pypi_dir, norm_pkg)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    local_html = render_pep503_simple_index(norm_pkg, pkg_dir)
    has_local_signed = "<a href=" in local_html

    if force_virtual or (
        not has_local_signed
        and settings.virtual_repo_enabled
        and settings.auto_promote_clean_artifacts
    ):
        upstream_urls = [
            u.strip() for u in settings.upstream_pypi_simple_url.split(",") if u.strip()
        ]
        dists = await fetch_upstream_pypi_distributions(upstream_urls, norm_pkg)
        if dists:
            _get_pypi_upstream_map(request.app)[norm_pkg] = {
                d["filename"]: d["url"] for d in dists
            }
            virtual_html = render_virtual_pep503_index(
                norm_pkg, dists, package_route_prefix=package_route_prefix
            )
            return HTMLResponse(content=virtual_html, headers={"X-Cache-Status": "VIRTUAL"})
        if force_virtual and not has_local_signed:
            raise HTTPException(status_code=404, detail=f"PyPI package not found upstream: {norm_pkg}")

    return HTMLResponse(content=local_html, headers={"X-Cache-Status": "HIT" if has_local_signed else "EMPTY"})


async def _serve_pypi_package_file(
    package: str,
    filename: str,
    request: Request,
    settings: Settings,
) -> FileResponse:
    """Shared handler for PyPI trusted & virtual package downloads with quarantine-scan-sign."""
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

    base_file, cache_status = await ensure_pypi_artifact_cached(
        norm_pkg=norm_pkg,
        base_filename=base_filename,
        settings=settings,
        app_instance=request.app,
    )

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


@app.api_route("/pypi/trusted/simple/{package}/", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def get_pypi_simple_package_index(
    package: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """Return PEP 503 Simple Repository index containing GPG-signed wheels/sdists (or virtual proxy on miss)."""
    return await _serve_pypi_simple_index(
        package=package,
        request=request,
        settings=settings,
        package_route_prefix="/pypi/trusted/packages",
        force_virtual=False,
    )


@app.api_route("/pypi/trusted/packages/{package}/{filename}", methods=["GET", "HEAD"])
async def get_pypi_trusted_package_file(
    package: str,
    filename: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Serve only GPG-signed Python wheels/sdists and their .asc/.sha256/.sha512 files."""
    return await _serve_pypi_package_file(package, filename, request, settings)


JIT_PROMOTION_JOBS: dict[str, dict[str, Any]] = {}


async def process_jit_promotion(
    job_id: str,
    image_uri: str,
    settings: Settings,
    app_instance: FastAPI,
) -> None:
    """Process a JIT OCI promotion request: validate trusted source, fetch, scan, sign, and cache."""
    try:
        parts = image_uri.split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            JIT_PROMOTION_JOBS[job_id]["status"] = "failed"
            JIT_PROMOTION_JOBS[job_id]["error"] = f"Invalid image URI: {image_uri}"
            return

        registry, repo_and_ref = parts
        if registry not in settings.trusted_sources:
            JIT_PROMOTION_JOBS[job_id]["status"] = "failed"
            JIT_PROMOTION_JOBS[job_id]["error"] = f"Registry {registry} is not in trusted_sources."
            return

        if ":" in repo_and_ref.rsplit("/", 1)[-1]:
            repo_path, reference = repo_and_ref.rsplit(":", 1)
        else:
            repo_path, reference = repo_and_ref, "latest"

        JIT_PROMOTION_JOBS[job_id]["status"] = "processing"
        JIT_PROMOTION_JOBS[job_id]["progress"] = "Fetching, scanning, and signing..."

        upstream_url = (
            settings.upstream_chainguard_url
            if registry == "cgr.dev"
            else f"https://{registry if registry != 'docker.io' else 'registry-1.docker.io'}"
        )
        ns = "chainguard-cache" if registry == "cgr.dev" else registry.replace(".", "-")
        await ensure_oci_manifest_cached(
            repo_path=repo_path,
            base_ref=reference,
            settings=settings,
            upstream_base_url=upstream_url,
            cache_namespace=ns,
            app_instance=app_instance,
        )

        JIT_PROMOTION_JOBS[job_id]["status"] = "completed"
        JIT_PROMOTION_JOBS[job_id]["progress"] = "Promoted"
    except Exception as exc:
        logger.error("JIT Promotion failed for %s: %s", job_id, exc)
        JIT_PROMOTION_JOBS[job_id]["status"] = "failed"
        JIT_PROMOTION_JOBS[job_id]["error"] = str(exc)


@app.post("/request-artifact")
async def request_artifact(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    x_gatekeeper_token: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """Just-In-Time (JIT) promotion endpoint for OCI images."""
    require_admin_token(x_gatekeeper_token, settings)

    data = await request.json()
    image_uri = str(data.get("image", "")).strip()
    if not image_uri:
        raise HTTPException(status_code=400, detail="Missing 'image' field in request body")

    job_id = str(uuid.uuid4())
    JIT_PROMOTION_JOBS[job_id] = {
        "image": image_uri,
        "status": "queued",
        "progress": "Waiting in queue",
        "error": None,
    }
    asyncio.create_task(process_jit_promotion(job_id, image_uri, settings, request.app))

    return JSONResponse(
        status_code=202,
        content={
            "job_id": job_id,
            "status": "queued",
            "message": f"Artifact {image_uri} has been queued for JIT promotion.",
        },
    )


@app.get("/status/{job_id}")
async def get_jit_status(
    job_id: str,
) -> JSONResponse:
    """Poll the status of a JIT promotion request."""
    job = JIT_PROMOTION_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job ID not found")
    return JSONResponse(content=job)


@app.api_route("/pypi/virtual/simple/{package}/", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def get_pypi_virtual_simple_index(
    package: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> HTMLResponse:
    """Virtual PyPI PEP 503 Simple Repository index: proxies upstream and routes downloads through Gatekeeper."""
    if not settings.virtual_repo_enabled:
        raise HTTPException(status_code=404, detail="Virtual repository feature is disabled")
    return await _serve_pypi_simple_index(
        package=package,
        request=request,
        settings=settings,
        package_route_prefix="/pypi/virtual/packages",
        force_virtual=True,
    )


@app.api_route("/pypi/virtual/packages/{package}/{filename}", methods=["GET", "HEAD"])
async def get_pypi_virtual_package_file(
    package: str,
    filename: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Virtual PyPI package download: fetch on miss, scan for High/Critical defects, sign, and serve."""
    if not settings.virtual_repo_enabled:
        raise HTTPException(status_code=404, detail="Virtual repository feature is disabled")
    return await _serve_pypi_package_file(package, filename, request, settings)


JIT_PROMOTION_JOBS: dict[str, dict[str, Any]] = {}


async def process_jit_promotion(
    job_id: str,
    image_uri: str,
    settings: Settings,
    app_instance: FastAPI,
) -> None:
    """Process a JIT OCI promotion request: validate trusted source, fetch, scan, sign, and cache."""
    try:
        parts = image_uri.split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            JIT_PROMOTION_JOBS[job_id]["status"] = "failed"
            JIT_PROMOTION_JOBS[job_id]["error"] = f"Invalid image URI: {image_uri}"
            return

        registry, repo_and_ref = parts
        if registry not in settings.trusted_sources:
            JIT_PROMOTION_JOBS[job_id]["status"] = "failed"
            JIT_PROMOTION_JOBS[job_id]["error"] = f"Registry {registry} is not in trusted_sources."
            return

        if ":" in repo_and_ref.rsplit("/", 1)[-1]:
            repo_path, reference = repo_and_ref.rsplit(":", 1)
        else:
            repo_path, reference = repo_and_ref, "latest"

        JIT_PROMOTION_JOBS[job_id]["status"] = "processing"
        JIT_PROMOTION_JOBS[job_id]["progress"] = "Fetching, scanning, and signing..."

        upstream_url = (
            settings.upstream_chainguard_url
            if registry == "cgr.dev"
            else f"https://{registry if registry != 'docker.io' else 'registry-1.docker.io'}"
        )
        ns = "chainguard-cache" if registry == "cgr.dev" else registry.replace(".", "-")
        await ensure_oci_manifest_cached(
            repo_path=repo_path,
            base_ref=reference,
            settings=settings,
            upstream_base_url=upstream_url,
            cache_namespace=ns,
            app_instance=app_instance,
        )

        JIT_PROMOTION_JOBS[job_id]["status"] = "completed"
        JIT_PROMOTION_JOBS[job_id]["progress"] = "Promoted"
    except Exception as exc:
        logger.error("JIT Promotion failed for %s: %s", job_id, exc)
        JIT_PROMOTION_JOBS[job_id]["status"] = "failed"
        JIT_PROMOTION_JOBS[job_id]["error"] = str(exc)


@app.post("/request-artifact")
async def request_artifact(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    x_gatekeeper_token: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    """Just-In-Time (JIT) promotion endpoint for OCI images."""
    require_admin_token(x_gatekeeper_token, settings)

    data = await request.json()
    image_uri = str(data.get("image", "")).strip()
    if not image_uri:
        raise HTTPException(status_code=400, detail="Missing 'image' field in request body")

    job_id = str(uuid.uuid4())
    JIT_PROMOTION_JOBS[job_id] = {
        "image": image_uri,
        "status": "queued",
        "progress": "Waiting in queue",
        "error": None,
    }
    asyncio.create_task(process_jit_promotion(job_id, image_uri, settings, request.app))

    return JSONResponse(
        status_code=202,
        content={
            "job_id": job_id,
            "status": "queued",
            "message": f"Artifact {image_uri} has been queued for JIT promotion.",
        },
    )


@app.get("/status/{job_id}")
async def get_jit_status(
    job_id: str,
) -> JSONResponse:
    """Poll the status of a JIT promotion request."""
    job = JIT_PROMOTION_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job ID not found")
    return JSONResponse(content=job)
