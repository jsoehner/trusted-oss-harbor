# ADR 0010: Per-Artifact Dual-Signed CycloneDX 1.6 SBOM/CBOM Attestations, PURL Batch API, and OCI 1.1 Referrers

- **Status:** Accepted
- **Date:** 2026-11-20
- **Supersedes / Extends:** Extends [ADR 0001](0001-trusted-oss-harbor-supply-chain-architecture.md) and [ADR 0007](0007-pfsense-github-mtls-and-opt-in-cache-routing.md)

## Context and Problem Statement

Downstream cryptographic governance pipelines (specifically `jsoehner/jsi-bom-actions`) audit third-party dependencies to compute Post-Quantum Cryptography (PQC) migration readiness and an Audit Confidence Score. Any dependency without an upstream Cryptographic Bill of Materials (CBOM) appears under **Unassimilated Third-Party Binaries & Cryptographic Blind Spots**, depressing confidence scores even when the artifact was already downloaded, malware-scanned, CVE-gated, and dual-signed by `trusted-oss-harbor`.

Previously, `quarantine_scan_sign_and_promote()` produced `.asc`, `.mldsa65`, and `.sha256/.sha384/.sha512` sidecars, but did **not** generate or expose per-artifact SBOM/CBOM documents or a PURL-indexed lookup API.

## Decision

1. **Pure-Python Per-Artifact CycloneDX 1.6 BOM Generation (`gatekeeper/app/bom_generator.py`):**
   - During `quarantine_scan_sign_and_promote()` (controlled by `BOM_GENERATION_ENABLED=true`), Gatekeeper generates two CycloneDX 1.6 JSON sidecars per promoted artifact:
     - `<artifact>.sbom.cdx.json`: Canonical PURL, SHA-256/384/512 hashes, and extracted declared dependencies (`METADATA` / `pom.xml`).
     - `<artifact>.cbom.cdx.json`: Cryptographic primitives discovered across archive source, bytecode (`.class`), native symbol tables (`.so`/`.dylib`), and embedded certificates, plus an explicit `trusted-oss:crypto-scan-status` property (`CRYPTO_ASSETS_DETECTED` or `VERIFIED_INERT`) so cryptographically inert packages are credited rather than left as blind spots.
   - Pure-Python archive inspection preserves the minimal Chainguard/Wolfi container footprint without adding Node.js/`cdxgen` runtime overhead.
2. **Dual Cryptographic Signing & Atomic Lifecycle:**
   - Both `.sbom.cdx.json` and `.cbom.cdx.json` are dual-signed with **RSA-3072 GPG** (`.asc`) and **NIST FIPS 204 ML-DSA-65** (`.mldsa65`), atomically promoted via `atomic_promote_artifact()`, excluded from PEP 503 Simple indices, and included in `_ARTIFACT_SIDECARS` so CVE quarantine and inactivity-TTL GC clean them up atomically.
   - `provenance.jsonl` records `sbom_file`, `cbom_file`, `cbom_sha256`, `cbom_asset_count`, and `cbom_scan_status`.
3. **PURL Lookup, Batch API, Backfill & OCI 1.1 Referrers:**
   - Expose `GET /bom/lookup?purl=...` and `POST /bom/batch` (routed through Nginx `location /bom/` behind pfSense mTLS) so CI runners resolve all SBOM PURLs in a single round-trip with detached GPG and ML-DSA-65 signatures.
   - Expose `POST /catalog/backfill-boms` (admin-token gated, supports async engine bus `backfill_boms` jobs) to generate and sign BOM sidecars for already-cached artifacts.
   - Expose OCI 1.1 Referrers (`GET /v2/{namespace}/{repo_path}/referrers/{digest}` and `/blobs/{digest}`) for cached OCI manifests.

## Consequences

- **Positive:** Eliminates third-party cryptographic blind spots for every dependency cached in `trusted-oss-harbor`; provides cryptographically verifiable (GPG + FIPS 204 ML-DSA-65) CBOM provenance to `jsi-bom-actions` over existing pfSense mTLS infrastructure; zero added container image bloat.
- **Negative:** Adds ~10–50ms of bounded archive inspection and two small JSON + signature sidecars per promoted artifact, mitigated by strict member/byte caps (`MAX_ARCHIVE_MEMBERS=250`, `MAX_MEMBER_BYTES=512 KiB`) and `BOM_GENERATION_ENABLED` toggle.
