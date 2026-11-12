# ADR 0002: Gatekeeper Security Hardening and Fail-Closed Controls

* **Status:** Accepted
* **Deciders:** Enterprise Architecture & Supply Chain Security Governance
* **Date:** 2026-11-12

---

## 1. Context & Problem Statement

A security assessment of `trusted-oss-harbor` identified several gaps between the documented defense-in-depth posture and the runtime implementation:

1. Administrative endpoints accepted a hardcoded default token (`ChangeMe_GatekeeperToken_2026!`), and `scripts/bootstrap_host.sh` fell back to `.env.example` when `.env` was absent.
2. The CVE gate (`evaluate_artifact_security`) relied solely on a `simulated_cvss` parameter (defaulting to `0.0` on pull-through routes and controllable via the `X-Simulated-Cvss` header on `/ingest`).
3. Provenance HMAC attestations used a static, publicly visible literal key (`b"trusted-oss-provenance-v1"`).
4. Uploads, upstream downloads, archive inspection, and `/audit/provenance` buffered entire payloads in memory without decompression-bomb or encrypted-archive guards.
5. The all-in-one NAS appliance container ran `uvicorn` as `root` under `supervisord`, and Nginx gateways lacked request rate limiting.

---

## 2. Decision Drivers

1. **Fail-Closed Defaults**: Misconfigured or unconfigured deployments must reject administrative operations rather than falling back to publicly documented placeholder credentials.
2. **Authentic Vulnerability Gating**: Production artifact promotion must invoke real vulnerability scanning (`trivy`) when available (and fail closed when `TRIVY_REQUIRED=true`), while preventing clients from injecting simulated CVSS scores.
3. **Cryptographic Isolation**: Provenance HMACs must use an instance-unique secret key (`PROVENANCE_HMAC_KEY` or auto-generated `0o600` key) rather than a hardcoded constant.
4. **Resource & Privilege Containment**: Stream I/O with bounded sizes (`MAX_ARTIFACT_BYTES`), reject encrypted/oversized archives, paginate audit logs, rate-limit admin/ingest routes in Nginx, and drop privileges to the `gatekeeper` user in the NAS appliance container.

---

## 3. Decision Outcome

1. **Fail-Closed Admin Authentication (`gatekeeper/app/config.py`, `gatekeeper/app/main.py`, `docker-compose.yml`, `scripts/bootstrap_host.sh`)**:
   - Removed the default `ChangeMe_GatekeeperToken_2026!` fallback in `Settings` and `docker-compose.yml`.
   - Added `require_admin_token()` returning HTTP `503` when `GATEKEEPER_ADMIN_TOKEN` is unset or matches a known placeholder.
   - Updated `scripts/bootstrap_host.sh` to require `.env` before rendering `config/harbor/harbor.yml`.
2. **Trivy Integration & Simulation Guard (`gatekeeper/app/scanner.py`, `gatekeeper/app/main.py`)**:
   - Implemented `scan_with_trivy()` in `evaluate_artifact_security()` with `TRIVY_REQUIRED` fail-closed support.
   - Gated `X-Simulated-Cvss` behind `ALLOW_SIMULATED_CVSS=false` by default so production deployments ignore client-supplied CVSS headers.
3. **Instance-Unique Provenance HMAC Key (`gatekeeper/app/signer.py`)**:
   - Added `ensure_provenance_hmac_key()`, using `PROVENANCE_HMAC_KEY` or generating a persistent 32-byte random key at `<OSS_DATA_ROOT>/keys/provenance.hmac.key` (`0o600`).
4. **Streaming I/O, Archive Guards, and Rate Limiting (`gatekeeper/app/scanner.py`, `config/clamav/clamd.conf`, `config/nginx/*.conf`)**:
   - Replaced full-file memory reads with chunked streaming capped by `MAX_ARTIFACT_BYTES` (250 MB default, HTTP `413` on overflow).
   - Added `MAX_ARCHIVE_MEMBERS` (10,000), `MAX_UNCOMPRESSED_BYTES` (512 MB), and encrypted ZIP entry rejection (`info.flag_bits & 0x1`), and enabled `ArchiveBlockEncrypted yes` in `clamd.conf`.
   - Added `limit_req_zone` rate limiting on `/catalog/` and `/ingest/` in Nginx, and pagination (`limit`, `offset`) on `/audit/provenance`.
5. **Least-Privilege NAS Container (`Dockerfile`, `config/supervisor/supervisord.conf`, `scripts/nas_entrypoint.sh`)**:
   - Added non-root user `gatekeeper` (`10001:10001`) to the NAS appliance image and configured `[program:gatekeeper]` in `supervisord.conf` to run as `user=gatekeeper`.

---

## 4. Consequences

* **Operational**: Deployments must explicitly set a strong `GATEKEEPER_ADMIN_TOKEN` (the placeholder in `.env.example` and old compose examples is now rejected at runtime).
* **Backwards Compatibility**: Test suites exercising simulated CVSS thresholds must explicitly set `ALLOW_SIMULATED_CVSS=true`.
