# Changelog

All notable changes to `trusted-oss-harbor` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
