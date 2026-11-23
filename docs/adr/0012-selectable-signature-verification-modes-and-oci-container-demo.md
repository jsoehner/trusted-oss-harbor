# ADR-0012: Selectable Signature Verification Modes (`classic` / `pqc` / `both`), Multi-Registry OCI Pull-Through & Signed-Only Container Demo

- **Status**: Accepted
- **Date**: 2026-11-23
- **Deciders**: Security Architecture & Platform Engineering
- **Release**: `v1.7.0`
- **Supersedes / Extends**: Extends [ADR-0010](0010-signed-artifact-cbom-attestations-and-purl-batch-api.md) and [SecADR-0011](0011-security-assessment-remediation-and-governance.md)

---

## 1. Context

`trusted-oss-harbor` dual-signs every promoted artifact and CycloneDX 1.6 SBOM/CBOM sidecar with both **classical RSA-3072 GPG (`.asc`)** and **NIST FIPS 204 ML-DSA-65 (`.mldsa65`)**. During real-world adoption and live container verification demos, three operational needs emerged:

1. **Multi-Registry OCI Pull-Through & Layer Inspection**:
   Upstream registries such as Docker Hub (`registry-1.docker.io`), GHCR, and Quay require standard RFC 6750 `WWW-Authenticate: Bearer realm="...",service="...",scope="..."` token negotiation rather than Chainguard's fixed `/token` path. In addition, inspecting a container image's concrete layers requires fetching platform manifests addressed by canonical OCI digest (`sha256:<64-hex>`).
2. **Phased Classical-to-PQC Client Verification**:
   Legacy CI runners and developer workstations may initially verify only classical PGP/GPG signatures (`--sig-mode classic`), while PQC-native or quantum-hardened pipelines want to verify **only** NIST FIPS 204 ML-DSA-65 (`--sig-mode pqc`) without requiring `gpg`, and high-assurance pipelines want hybrid dual verification (`--sig-mode both`).
3. **Explicit Trust Anchoring & Provenance Pagination**:
   Importing a GPG key into an ephemeral keyring without ownertrust displays `[unknown]`, which can confuse operators. Production ledgers also exceed 500 entries, requiring tail-first pagination when auditing newly promoted digests.

---

## 2. Decision

1. **RFC 6750 Bearer Token Negotiation & Safe OCI Digest Segments**:
   - Extend `fetch_upstream_oci_manifest()` in `gatekeeper/app/main.py` with `_parse_www_authenticate_bearer()` so virtual pull-through (`/v2/virtual/{docker-cache,ghcr-cache,quay-cache,chainguard-cache}/...`) works uniformly across all major OCI registries.
   - Extend `resolve_safe_relative_path()` in `gatekeeper/app/storage.py` to accept canonical OCI digest segments (`^sha(?:256|384|512):[0-9a-f]{64,128}(?:\.[A-Za-z0-9._+-]+)*$`) while preserving strict rejection of Windows drive letters (`C:`), arbitrary colons, and path traversal.
2. **Parameterized Signature Verification Modes (`--sig-mode <both|classic|pqc>`)**:
   - Standardize [`scripts/trusted_container_demo.sh`](../../scripts/trusted_container_demo.sh) on `--sig-mode` (and `SIG_MODE` env var) supporting:
     - `classic` (`pgp`/`gpg`): Fetches and verifies only `.asc` signatures using `/keys/trusted-oss-pubkey.asc` with explicit `:6:` ultimate ownertrust and optional `EXPECTED_GPG_FPR` pinning (zero Python PQC dependencies).
     - `pqc` (`mldsa65`): Fetches and verifies only `.mldsa65` signatures using `/keys/trusted-oss-mldsa65.pub`, `client-templates/pqc-verify.py`, and optional `EXPECTED_PQC_FPR` pinning (zero `gpg` dependency).
     - `both` (`dual`, default): Enforces both classical RSA-3072 GPG (`[ultimate]`) and NIST FIPS 204 ML-DSA-65 verification plus fail-closed 1-byte tamper rejection on both algorithms.
3. **Tail-First Provenance Lookup & Signed-Only Documentation**:
   - Query `/audit/provenance?limit=1` for `.total` and walk backward in 500-entry pages so Stage 4 always locates the exact HMAC-SHA384 provenance record regardless of ledger size.
   - Document the end-to-end demo (`apache/airflow:slim-latest-python3.12`), 5-stage visual pipeline (`docs/images/trusted-container-verification-flow.png`), and standalone FAQ (`docs/FAQ.md`), emphasizing immutable digest parity and signed-only execution (`docker run <repo>@sha256:<digest>`).

---

## 3. Consequences

- **Positive**:
  - Teams can adopt signed-only container verification today with classical PGP (`--sig-mode classic`), transition seamlessly to hybrid (`--sig-mode both`), and cut over to PQC-only (`--sig-mode pqc`) without changing registry architecture or container image digests.
  - Existing `docker pull` / `podman pull` pipelines retain byte-for-byte SHA-256 parity with upstream registries and gain faster local ZFS cache hits (`X-Cache-Status: HIT`).
- **Trade-offs**:
  - PQC-only mode (`--sig-mode pqc`) requires `dilithium-py` (or the repo `.venv`) on the verifying client until native OpenSSL/OS ML-DSA-65 CLI tooling is universally installed.
  - Operators must pin `EXPECTED_GPG_FPR` and/or `EXPECTED_PQC_FPR` in CI/CD variables to prevent key-substitution attacks over untrusted networks.
