# Changelog

All notable changes to `trusted-oss-harbor` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **OCI Layer Crypto Risk Posture, X.509/JKS Certificate Auditing & ORAS/Catalog Reporting ([ADR-0013](docs/adr/0013-oci-layer-cbom-risk-posture-and-oras-catalog-reporting.md))**:
  - Added `gatekeeper/app/crypto_risk.py` with pure-Python PEM/DER/JKS X.509 certificate auditing, `openssl.cnf` / `java.security` policy analysis, `/lib/apk/db/installed` OS package parsing, Active vs. Passive risk classification, and PQC Compiled-vs-Coding risk tracking (`PQC_COMPILED_BUT_UNUSED`).
  - Updated `gatekeeper/app/bom_generator.py` and `gatekeeper/app/main.py` (`fetch_upstream_oci_layers_for_bom`) to inspect bounded OCI filesystem layers during pull-through (`OCI_BOM_DEEP_SCAN_ENABLED=true`) and record `MANIFEST_ONLY_UNINSPECTED` (instead of `VERIFIED_INERT`) when layers are absent.
  - Enriched OCI 1.1 Referrers CBOM descriptors (`GET /v2/{ns}/{repo}/referrers/{digest}`) with `trusted-oss.crypto.*` annotations, added `crypto_posture` and summary counters to `GET /catalog/vulnerabilities`, added filterable `GET /catalog/crypto-risk`, and added `risk_summary` to `/bom/lookup` and `/bom/batch`.
  - Updated `scripts/demo_container_acquisition_oras.ps1`, `scripts/trusted_container_demo.sh`, and `client-templates/github-actions-verify-component.yml` to report Active vs. Passive risks, certificate hygiene, and PQC compiled-vs-coding gaps.
- **Uncached Container Acquisition Report & Interactive PowerShell ORAS Demo**:
  - Added [`docs/reports/container-artifact-acquisition-and-oras-verification.md`](docs/reports/container-artifact-acquisition-and-oras-verification.md) documenting the end-to-end workflow for pulling uncached container artifacts with a bounded 15-second `HTTP 451` retry timer, `oras` OCI 1.1 Referrers SBOM/CBOM discovery and blob verification, dual GPG/ML-DSA-65 signature checks, and live vulnerability/provenance validation.
  - Added [`scripts/demo_container_acquisition_oras.ps1`](scripts/demo_container_acquisition_oras.ps1) supporting a combined `<repo>:<tag>` `-Image` parameter, auto-derived `<repo>-cache` namespace routing, no-parameter console usage examples, collapsed HTTP response headers (`-ShowHeaders` to expand + enable `oras --debug`), `[DOWNLOAD]` file status lines, `-Detailed` full JSON output, and ANSI-colored `-TranscriptPath` log capture.
  - Added `demo-detailed.log`, `demo-output.log`, and `demo-*.log` to `.gitignore`.

### Fixed
- **OCI 1.1 Referrers `Content-Type` Header (`gatekeeper/app/main.py`)**: Set `media_type="application/vnd.oci.image.index.v1+json"` on `get_oci_referrers()` responses so `oras discover` v1.4+ populates attached CycloneDX SBOM/CBOM referrers natively without falling back to the OCI 1.0 `sha256-<hex>` tag lookup.

## [1.7.0] - 2026-11-23

### Added
- **End-to-End Signed Container Verification Demo, Selectable Signature Modes & FAQ ([ADR-0012](docs/adr/0012-selectable-signature-verification-modes-and-oci-container-demo.md))**:
  - Added [`scripts/trusted_container_demo.sh`](scripts/trusted_container_demo.sh) demonstrating the complete zero-trust container lifecycle (default sample: `apache/airflow:slim-latest-python3.12`) using `curl` + `jq`, rendering the full OCI Index, platform manifest, config, all 24 immutable layers, CycloneDX 1.6 SBOM/CBOM digests, and signature layer hashes.
  - Added `--sig-mode <both|classic|pqc>` (and `SIG_MODE` env var) plus `EXPECTED_GPG_FPR` / `EXPECTED_PQC_FPR` fingerprint pinning and GPG `:6:` ultimate ownertrust so teams can verify Classical PGP/GPG only (`classic`), Post-Quantum NIST FIPS 204 ML-DSA-65 only (`pqc`), or hybrid dual signatures (`both`) with fail-closed 1-byte tamper detection and tail-first `/audit/provenance` lookup.
  - Added RFC 6750 `WWW-Authenticate: Bearer` token exchange in `gatekeeper/app/main.py` (`fetch_upstream_oci_manifest`) and safe canonical OCI digest segment validation (`sha256:<64-hex>`) in `gatekeeper/app/storage.py` for multi-registry virtual pull-through (Docker Hub, GHCR, Quay, Chainguard).
  - Added **Section 7 (End-to-End Trusted Container Demo)** and **Section 8 (FAQ)** to `docs/operations-manual.md`, standalone [`docs/FAQ.md`](docs/FAQ.md), and 5-stage pipeline infographic [`docs/images/trusted-container-verification-flow.png`](docs/images/trusted-container-verification-flow.png).
- **Vulnerability Advisory Center & Real-Time Alerts ([SecADR-0011](docs/adr/0011-security-assessment-remediation-and-governance.md))**:
  - Added `gatekeeper/app/advisories.py` and frontend endpoints `GET /catalog/advisories` (filterable JSON with PURLs, severity, OSV/NVD links, and upgrade guidance), `GET /catalog/advisories.rss` (RSS 2.0 subscription feed), and `GET /catalog/advisories/dashboard` (zero-JS, CSP-safe HTML Security Advisory Center).
  - Added real-time deduplicated vulnerability alert dispatch (`audit/vuln_alerts.jsonl`) supporting HMAC-SHA256 signed webhooks (`VULN_ALERT_WEBHOOK_URL`, `VULN_ALERT_WEBHOOK_SECRET`) and optional immediate Microsoft Graph email alerts (`VULN_ALERT_IMMEDIATE_EMAIL=true`).
  - Added `--advisories` CLI option to `scripts/catalog_frontend.py`.
- **Automated Security Governance CI & Posture Documentation**:
  - Added `.github/workflows/security-governance.yml` (SHA-pinned, least-privilege Gitleaks, Bandit, Semgrep, and `pip-audit` gates) and updated `.github/dependabot.yml` with the mandatory 7-day cooldown across `github-actions`, `pip`, and `docker`.
  - Added [SECURITY_POSTURE.md](SECURITY_POSTURE.md), [SecADR-0011](docs/adr/0011-security-assessment-remediation-and-governance.md), and regression test suite `gatekeeper/tests/test_security_assessment_fixes.py`.

### Changed
- **Daily Digest Upgrade-Path Reporting (`gatekeeper/app/notifications.py`)**: Updated both plain-text and HTML daily digests to show all vulnerable/quarantined component versions alongside clickable OSV advisory links and the **newest `CLEAN` (passing-scan) version available for upgrade**.

### Security
- **Path Traversal & Symlink Containment**: Hardened `/v2/{namespace}/{repo_path}/referrers/{digest}`, `/v2/{namespace}/{repo_path}/blobs/{digest}`, `resolve_purl_to_bom_file()`, and `update_latest_tag()` with strict `resolve_safe_relative_path()` and symlink checks.
- **Archive DoS, Backslash Zip-Slip & Streaming Limits**: Restored `MAX_ARTIFACT_BYTES` (250 MB, HTTP `413`), `MAX_ARCHIVE_MEMBERS` (10,000), `MAX_UNCOMPRESSED_BYTES` (512 MB), streaming ZIP/EICAR reads, Windows backslash/drive-letter Zip-Slip rejection, and `TRIVY_REQUIRED` fail-closed mode (closing ADR-0002 regressions).
- **SSRF, Auth & Pagination**: Enforced `settings.trusted_sources` in dynamic OCI warmup and strict `http`/`https` URL validation across Gatekeeper and CLI scripts; capped `POST /bom/batch` to 500 PURLs and gated `trigger_pull_on_miss` behind admin auth; deduplicated JIT routes, authenticated `GET /status/{job_id}`, bounded `JIT_PROMOTION_JOBS`, and paginated `GET /audit/provenance`.
- **Cryptographic, XML & Gateway Hardening**: Restored persistent `0o600` provenance HMAC key (`keys/provenance.hmac.key`), switched GPG passphrase passing to `--passphrase-fd 0` stdin, migrated XML parsing to `defusedxml`, hardened Nginx headers (`server_tokens off`, CSP, `Permissions-Policy`), pinned `oras-project/setup-oras` to its commit SHA, and added least-privilege `permissions` to `probe-wan-connectivity.yml`.

## [1.6.0] - 2026-11-20

### Added
- **Per-Artifact Dual-Signed CycloneDX 1.6 SBOM & CBOM Attestations ([ADR 0010](docs/adr/0010-signed-artifact-cbom-attestations-and-purl-batch-api.md))**:
  - Added `gatekeeper/app/bom_generator.py` to inspect promoted Maven, PyPI, and OCI artifacts in pure Python and emit CycloneDX 1.6 `.sbom.cdx.json` and `.cbom.cdx.json` sidecars (including `VERIFIED_INERT` attestations when zero cryptographic primitives are present).
  - Dual-signs all generated BOM sidecars with **GPG** (`.asc`) and **NIST FIPS 204 ML-DSA-65** (`.mldsa65`), atomically promotes them in `gatekeeper/app/storage.py`, excludes them from PEP 503 Simple indices, and tracks them in `provenance.jsonl` and `_ARTIFACT_SIDECARS` (CVE quarantine & GC).
- **PURL Lookup, Batch CBOM API & Backfill**:
  - Added `GET /bom/lookup?purl=...`, `POST /bom/batch` (single round-trip resolution with detached signatures and optional `trigger_pull_on_miss`), and `POST /catalog/backfill-boms` (admin-gated backfill for previously cached artifacts, supporting Valkey engine bus `backfill_boms` jobs).
  - Routed `location /bom/` in `config/nginx/oss-gateway.conf` and `config/nginx/appliance-gateway.conf`.
- **OCI 1.1 Referrers API**:
  - Added `GET /v2/{namespace}/{repo_path}/referrers/{digest}` and `GET /v2/{namespace}/{repo_path}/blobs/{digest}` exposing attached CycloneDX CBOM/SBOM descriptors for cached OCI manifests.
- **Tests**: Added `gatekeeper/tests/test_bom_attestations.py`.

## [1.5.0] - 2026-11-20

### Added
- **Standardized HTML Email Digests ([ADR 0009](docs/adr/0009-standardized-html-email-notifications.md))**: Added `render_daily_digest_html()` in `gatekeeper/app/notifications.py` using the JSIGROUP Standardized HTML Notification Format (dark-slate header, status pill, `Total / Clean / Unscanned / Quarantined` KPI cards, Cache Capacity Runway, Quarantined CVEs, and Recent Activity tables with strict `html.escape()` sanitization).
- **HTML & Multipart Transport Support**: Added `content_type="HTML"` support in `send_graph_mail()` (keeping `content_type="Text"` for ≤160-char Email-to-SMS) and `multipart/alternative` (`html_body`) support in `send_smtp_starttls()`, wired into `scripts/daily_digest.py` and `run_daily_digest_loop()`.
- **Daily Digest Artifact Activity Telemetry**: Emits `ARTIFACT_REQUESTED` (`HIT`/`MISS`), `NEW_ARTIFACT_ADDED`, and `NEW_VERSION_ADDED` events in `gatekeeper/app/main.py` and reports `Requested`, `New Artifacts`, and `New Versions` in `build_daily_digest` (`gatekeeper/app/notifications.py`).
- **Scheduled LAN Cache Primer (`scripts/install_prime_timer.sh`)**: Installs `trusted-oss-prime.timer` (`systemd --user`, daily at `06:00`) to run `scripts/prime_cache.py` against `http://oss.jsigroup.local:8080`.
- **Architecture Infographics & ADR-0008**: Added `docs/images/trusted-oss-dataflow-hardware-infographic.png` and `docs/images/trusted-oss-architecture-infographic.png` to `README.md`, and recorded [ADR 0008](docs/adr/0008-digest-artifact-telemetry-and-scheduled-lan-priming.md).

## [1.4.0] - 2026-11-15

### Added
- **pfSense GitHub-Only mTLS Setup Guide (`docs/pfsense-haproxy-mtls-guide.md`)**: Detailed step-by-step instructions to expose `trusted-oss-gatekeeper:8080` via pfSense HAProxy with ACME TLS, `Trusted-OSS-GitHub-Client-CA` mTLS (`has_client_cert`), and WAN firewall rules restricted exclusively to `github_actions_cidrs`.
- **Opt-In Per-Repo Cache Switcher (`scripts/configure_trusted_cache.py`)**: Repositories default to public upstream registries (Maven Central, PyPI, `cgr.dev`) when `TRUSTED_OSS_CACHE_URL` is unset. Running `scripts/configure_trusted_cache.py --interactive` or `--url <URL>` configures `.mvn/settings.xml`, `.mvn/maven.config`, `uv.toml`, `.env`, and optional GitHub Actions variable `TRUSTED_OSS_CACHE_URL` in one step; `--public` reverts back to public repos.
- **Documentation & ADRs**: Recorded [ADR 0007](docs/adr/0007-pfsense-github-mtls-and-opt-in-cache-routing.md) and updated `docs/operations-manual.md`, `README.md`, and `.env.example`.

### Changed
- **Conditional GitHub Actions mTLS Trigger (`client-templates/github-actions-trusted-oss.yml`)**: Activates mTLS and Maven/PyPI cache routing only when `vars.TRUSTED_OSS_CACHE_URL` (or legacy `vars.HARBOR_DOMAIN`) is set; otherwise exits cleanly and uses public upstream repos.
- **Parameterized `Dockerfile` Base Image**: Added `ARG BASE_IMAGE=cgr.dev/chainguard/wolfi-base:latest` so builds default to public `cgr.dev` and can be redirected with a single build-arg.

## [1.3.0] - 2026-11-15

### Added
- **Incremental Local Cache Primer (`scripts/prime_cache.py`)**: Scans local project workspaces (`discover_local_projects`) for Maven, PyPI, Chainguard, and OCI dependencies, compares them against Gatekeeper's `/catalog/vulnerabilities` inventory, prints **Already Cached** vs. **Will Be Queued & Fetched** tables (or `--json`), and queues only missing components via `POST /catalog/warm` (supporting `--dry-run`, `--wait`, and `--roots`).
- **Docker Image Version Tagging**: Added `ARG APP_VERSION` and `org.opencontainers.image.version` OCI label to `Dockerfile` and wired `APP_VERSION` build-arg in `.github/workflows/publish-nas-appliance.yml` alongside `:1.3.0`, `:v1.3.0`, and `:latest` GHCR tags.
- **Documentation & Tests**: Updated `docs/operations-manual.md` (Section 3.2) with `scripts/prime_cache.py` usage and added `test_prime_cache_identifies_cached_vs_missing_components` to `gatekeeper/tests/test_virtual_and_warmup.py`.

## [1.2.0] - 2026-11-15

### Changed
- **90-Day Inactivity-TTL Retention & Capacity Runway Digest**: Replaced fixed `N-2` version eviction with `GC_RETENTION_VERSIONS=0`, `GC_MAX_UNUSED_DAYS=90`, and `GC_WARN_UNUSED_DAYS=75`, added `audit/last_accessed.json` tracking and `GET /catalog/retention`, and recorded [ADR 0006](docs/adr/0006-inactivity-ttl-cache-retention-and-runway-digest.md).

### Fixed
- **Microsoft Graph OAuth2 Token Refresh (`fe451c5`)**: Prefer rotated `msgraph_token.json` and sanitize OAuth inputs in `resolve_msgraph_access_token` to eliminate `AADSTS90013` errors on TrueNAS daily digest runs.

## [1.0.0] - 2026-11-14

### Added
- **Decoupled Frontend, Engine Worker, and Message Bus (`oss-bus`)**:
  - Added `gatekeeper/app/bus.py` (`ValkeyJobBus` via Redis/Valkey Streams + `InMemoryJobBus` fallback) and `gatekeeper/app/worker.py` (`python -m app.worker`) to separate HTTP serving (`oss-frontend`, `GATEKEEPER_ROLE=frontend`) from background scanning, warming, and remediation (`oss-engine`, `GATEKEEPER_ROLE=engine`).
  - Added `oss-bus` (`valkey/valkey:8-alpine`), `oss-frontend`, and `oss-engine` services to `docker-compose.yml` with bounded worker concurrency (`ENGINE_MAX_CONCURRENCY=2`), and updated `config/nginx/oss-gateway.conf` and `config/nginx/appliance-gateway.conf` to route `/jobs`.
  - Added `GET /jobs` and `GET /jobs/{job_id}` endpoints, plus `202 Accepted` async job enqueuing on `POST /catalog/remediate` and `POST /catalog/warm` when running in `frontend` role (or `wait=false`).
- **Scheduled Unscanned Sweeps, `N-2` Garbage Collection & Activity Log**:
  - Added `gatekeeper/app/activity.py` (`audit/activity.jsonl`) and `GET /audit/activity` to record and serve scheduled scan, quarantine, `'latest'` tag, and GC events.
  - Added startup `only_unscanned=true` sweep and `GC_RETENTION_VERSIONS=2` (`N-2+` pruning via `gc_old_component_versions` and `POST /catalog/gc`) to `oss-engine` and `_hourly_cve_rescan_loop`.
  - Updated `scripts/catalog_frontend.py` with `--activity`, `--activity-limit`, `--activity-event`, `--scan-unscanned`, `--gc`, `--gc-dry-run`, `--gc-keep`, and `--wait`.
- **Auto-Quarantine, `'latest'` Tagging & Caching History**:
  - Added `gatekeeper/app/remediation.py`, `CVE_RESCAN_INTERVAL_SECONDS` (hourly background rescan), `maven-metadata.xml` resolution, quarantine tracking for newly vulnerable versions above `CVSS_FAIL_THRESHOLD`, and per-component caching history in `GET /catalog/vulnerabilities`.
  - Updated `scripts/catalog_frontend.py` to support comma-separated `--ecosystem` and `--components` filters, ASCII table formatting, opt-in `--remediate`, and `--wait` job polling.
- **Documentation & ADRs**:
  - Bumped major semantic version to `1.0.0` (`VERSION`, FastAPI `app.version`, `README.md`, `CHANGELOG.md`).
  - Recorded [ADR 0004](docs/adr/0004-frontend-engine-message-bus-architecture.md) with Mermaid architecture and sequence diagrams.

### Changed
- **Constrained Container Performance**: Eliminated 200+ synchronous `gpg --verify` subprocess forks in `GET /catalog/vulnerabilities` (`verify_signatures=false` default) and skipped redundant archive unpacking during OSV/Trivy CVE remediation rescans.

## [0.3.0] - 2026-11-14

### Added
- **Virtual Repository Pull-Through**: Added `/maven/virtual/{path}`, `/pypi/virtual/simple/{pkg}/`, `/pypi/virtual/packages/{pkg}/{file}`, and `/v2/virtual/{repo}/manifests/{ref}` with per-artifact `asyncio.Lock` single-flight deduplication and automatic Quarantine -> ClamAV -> OSV/Trivy CVE Gate -> Dual Sign -> Promote on cache miss.
- **Dynamic Project Discovery & Warmup**: Added `gatekeeper/app/discovery.py`, `POST /catalog/discover`, `POST /catalog/warm` (`discover=true`), and `scripts/dynamic_warmup.py` to scan local workspaces and GitHub repositories for Maven, Gradle, Python, and Docker/OCI dependencies and persist `dynamic-catalog.json`.
- **Per-Version Vulnerability & Cache Inventory**: Added `GET /catalog/vulnerabilities`, `scripts/catalog_frontend.py`, and `scripts/catalog_storage.py` to report all cached OCI, Maven, and PyPI components, GPG/ML-DSA-65 signature status, ClamAV status, and per-version CVE/CVSS findings (`CLEAN`, `VULNERABLE`, `UNSCANNED`).
- **TrueNAS Container App Cache Telemetry**: Configured `gatekeeper` stdout logging (`[CACHE] HIT`, `PROMOTED`, `BLOCKED`, `WARMUP_SUMMARY`) so all caching and security gate activity appears in `docker logs` and TrueNAS SCALE's App Logs UI.
- **Documentation & ADRs**: Added [ADR 0003](docs/adr/0003-chainguard-wolfi-virtual-repo-and-observability.md) and updated `README.md` with Mermaid architecture/pull-through diagrams.

### Changed
- **Chainguard Wolfi & Python 3.13 Multi-Stage Images**: Migrated `Dockerfile` and `gatekeeper/Dockerfile` to `cgr.dev/chainguard/wolfi-base:latest` with Python 3.13, `clamav-1.5`, `nginx-stable`, `gpg`, and `supervisor`, reducing the NAS appliance image from 467 MB to 317 MB (~32% smaller).
- **Version Bump**: Upgraded `VERSION` and `gatekeeper` FastAPI application version to `0.3.0`.
- **ClamAV & Entrypoint Fixes**: Replaced deprecated `ArchiveBlockEncrypted` with `AlertEncrypted yes` in `config/clamav/clamd.conf` and initialized `${OSS_DATA_ROOT}/catalog` permissions in `scripts/nas_entrypoint.sh`.

### Security
- **Fail-Closed Admin Authentication**: Removed default `ChangeMe_GatekeeperToken_2026!` fallback from `Settings` and `docker-compose.yml`; admin endpoints now return HTTP `503` if `GATEKEEPER_ADMIN_TOKEN` is unset or a known placeholder, and `scripts/bootstrap_host.sh` requires `.env` before rendering `harbor.yml`.
- **Trivy Vulnerability Gate & Simulation Guard**: Added `trivy fs` vulnerability scanning in `gatekeeper/app/scanner.py` (`TRIVY_REQUIRED` support) and gated `X-Simulated-Cvss` behind `ALLOW_SIMULATED_CVSS=false` by default.
- **Instance-Unique Provenance HMAC Key**: Replaced the hardcoded HMAC key in `gatekeeper/app/signer.py` with `PROVENANCE_HMAC_KEY` or an auto-generated `0o600` key in `<OSS_DATA_ROOT>/keys/provenance.hmac.key`.
- **DoS, Zip-Bomb, & Encrypted Archive Protections**: Streamed uploads/downloads with `MAX_ARTIFACT_BYTES` (250 MB, HTTP `413`), enforced archive member/uncompressed-size caps, rejected encrypted ZIP entries, enabled `ArchiveBlockEncrypted yes` in `clamd.conf`, and added pagination to `/audit/provenance`.
- **Container & Gateway Hardening**: Configured the NAS appliance `gatekeeper` service to run as non-root user `gatekeeper` (`10001`), added Nginx `limit_req_zone` rate limiting on `/ingest/` and `/catalog/`, fixed undefined `logger` in `main.py`, and escaped `sha256` attributes in PEP 503 HTML responses.
- **Documentation**: Added [ADR 0002](docs/adr/0002-gatekeeper-security-hardening-and-fail-closed-controls.md) and updated `README.md` and `.env.example`.

## [0.2.0] - 2026-11-11

### Added
- **Post-Quantum Cryptography (PQC) Dual-Signing Engine**:
  - Integrated NIST FIPS 204 **ML-DSA-65** detached signing alongside legacy GPG RSA-3072.
  - Automatically signs promoted Maven and PyPI artifacts with both `.asc` and `.mldsa65` signatures, ensuring seamless zero-breaking-change backwards compatibility for classical clients while securing quantum-resistant verification.
- **PQC Public Key Distribution Endpoints**:
  - Exposed `GET /keys/trusted-oss-mldsa65.pub` serving ASCII-armored ML-DSA-65 public key material.
  - Exposed `GET /keys/trusted-oss-mldsa65.fingerprint` with SHA-256 and SHA-384 key fingerprints.
- **Grover-Resistant Hashing**:
  - Upgraded provenance logging (`audit/provenance.jsonl`) to compute and record SHA-384 digests and HMAC-SHA384 attestations alongside SHA-256 and SHA-512.
  - Automatically generated companion `.sha384` files alongside `.sha256` and `.sha512` during artifact promotion.
- **Client PQC Verification CLI**:
  - Added standalone `client-templates/pqc-verify.py` for client-side detached ML-DSA-65 verification.
- **Automated PQC Test Suite**:
  - Added unit and HTTP integration tests validating ML-DSA-65 key generation, signing, positive verification, tamper rejection, and dual-signature delivery.

### Changed
- Upgraded `gatekeeper` FastAPI application version to `0.2.0`.
- Updated `scripts/generate_signing_keys.sh` and `scripts/verify_e2e_pipeline.sh` to include ML-DSA-65 key generation and end-to-end verification.

## [0.1.0] - 2026-11-10

### Added
- Initial standalone release of `trusted-oss-harbor` supply chain platform.
- Dynamic pull-through quarantine for Maven and PyPI packages.
- ClamAV antivirus inspection via TCP `INSTREAM`.
- GPG RSA-3072 signing authority and read-time detached signature verification.
- Harbor Chainguard Proxy Cache configuration and shared Spring Boot catalog pre-warming.
- Automated 5-stage end-to-end verification harness.
