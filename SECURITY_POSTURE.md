# Security Posture Report — `trusted-oss-harbor`

- **Assessment Date**: 2026-11-22
- **Methodology**: `security-agent-orchestrator` + `security-governance-orchestrator` (STRIDE Threat Modeling, Semgrep SAST, Bandit SAST, `pip-audit`, Manual Security Code Review, CI/CD Governance Audit)
- **Architectural Record**: [SecADR-0011](docs/adr/0011-security-assessment-remediation-and-governance.md)

## Executive Summary

A full-lifecycle security assessment of `trusted-oss-harbor` identified **13 security defects** (6 High, 7 Medium/Governance), including path traversal in OCI Referrers/PURL resolution, archive decompression bomb & backslash Zip-Slip gaps, SSRF in dynamic OCI warmup, unauthenticated job-queue triggering, ephemeral provenance HMAC keys, untrusted stdlib XML parsing, and CI/CD governance gaps. **All 13 defects have been remediated** and verified with regression tests and zero remaining High/Medium Bandit findings, zero Semgrep ERROR findings, and zero `pip-audit` CVEs.

## Findings & Remediation Matrix

| ID | Severity | CWE | Component | Defect Summary | Remediation | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| SEC-01 | **High** | CWE-22 | `gatekeeper/app/main.py` | Unvalidated `namespace` in `/v2/{namespace}/{repo_path}/referrers/{digest}` & `/blobs/{digest}` allowed directory traversal outside `harbor/registry`. | Added `_resolve_oci_manifests_dir()` using `resolve_safe_relative_path()` returning HTTP 400 on invalid paths. | **Fixed** |
| SEC-02 | **High** | CWE-22 | `gatekeeper/app/bom_generator.py` | `resolve_purl_to_bom_file()` joined OCI `ref` and Maven segments without containment or symlink checks. | Enforced `SAFE_SEGMENT_RE`, `resolve_safe_relative_path()`, and symlink rejection across all ecosystems. | **Fixed** |
| SEC-03 | **High** | CWE-409 / CWE-22 | `gatekeeper/app/scanner.py`, `bom_generator.py`, `main.py`, `config.py` | Unbounded memory reads on upload/download/scan, missing archive member/uncompressed caps, unbounded `zf.read()`, and missing Windows backslash/drive-letter Zip-Slip checks. | Restored `MAX_ARTIFACT_BYTES` (250 MB, HTTP 413), `MAX_ARCHIVE_MEMBERS` (10,000), `MAX_UNCOMPRESSED_BYTES` (512 MB), streaming reads, and backslash/drive-letter rejection. | **Fixed** |
| SEC-04 | **High** | CWE-918 | `gatekeeper/app/main.py` | `_execute_catalog_warmup()` fetched `https://{registry}` from discovered Dockerfiles without `trusted_sources` validation. | Enforced `settings.trusted_sources` allowlist and strict `http`/`https` scheme validation. | **Fixed** |
| SEC-05 | **High** | CWE-306 / CWE-770 | `gatekeeper/app/main.py` | `POST /bom/batch` had no PURL count cap and allowed unauthenticated callers to enqueue `"warm"` jobs via `trigger_pull_on_miss=True`. | Capped batch size to 500 PURLs (HTTP 400) and gated `trigger_pull_on_miss=True` behind `require_admin_token()`. | **Fixed** |
| SEC-06 | **High** | CWE-306 / CWE-770 | `gatekeeper/app/main.py` | Duplicate `/request-artifact` & `/status/{job_id}` route definitions; `/status/{job_id}` lacked admin auth; `JIT_PROMOTION_JOBS` was unbounded. | Removed duplicate definitions, added `require_admin_token()` to `/status/{job_id}`, bounded dict to 500 entries, and validated JSON body. | **Fixed** |
| SEC-07 | **Medium** | CWE-321 | `gatekeeper/app/main.py`, `config.py` | `append_provenance_record()` was called without `hmac_key`, generating throwaway ephemeral keys per record (ADR 0002 regression). | Wired `ensure_provenance_hmac_key()` into startup and all provenance writes (`keys/provenance.hmac.key`, `0o600`). | **Fixed** |
| SEC-08 | **Medium** | CWE-611 | `bom_generator.py`, `discovery.py`, `remediation.py`, `requirements.txt` | Untrusted XML (`pom.xml`, `maven-metadata.xml`) parsed with stdlib `xml.etree.ElementTree`. | Migrated to `defusedxml.ElementTree` and added `defusedxml>=0.7.1` to `gatekeeper/requirements.txt`. | **Fixed** |
| SEC-09 | **Medium** | CWE-91 / CWE-22 | `gatekeeper/app/remediation.py` | `update_latest_tag()` wrote unescaped XML and unvalidated filesystem paths. | Added `resolve_safe_relative_path()` and `xml.sax.saxutils.escape()`. | **Fixed** |
| SEC-10 | **Medium** | CWE-214 / CWE-377 | `gatekeeper/app/signer.py`, `notifications.py` | GPG passphrase passed via CLI `--passphrase` argv; secret files created before `chmod 0600`. | Switched to `--passphrase-fd 0` stdin and atomic `os.open(..., 0o600)` secret writes. | **Fixed** |
| SEC-11 | **Medium** | CWE-347 / CWE-770 | `gatekeeper/app/main.py`, `scanner.py` | OCI `.mldsa65` verification broke on BOM sidecars; `TRIVY_REQUIRED` fail-closed mode and `/audit/provenance` pagination were missing; `backfill-boms` nested job dict under `job_id`. | Fixed OCI `.mldsa65` target resolution, restored `TRIVY_REQUIRED` and `/audit/provenance` pagination, and fixed `backfill-boms` response. | **Fixed** |
| SEC-12 | **Medium** | CWE-22 | `scripts/catalog_frontend.py`, `daily_digest.py`, `prime_cache.py` | Dynamic `urllib.request.urlopen()` calls lacked scheme validation (`file://` risk). | Added strict `http`/`https` scheme validation before all `urlopen()` calls. | **Fixed** |
| SEC-13 | **Medium** | Supply Chain | `.github/`, `client-templates/`, `config/nginx/` | Missing Dependabot 7-day cooldown & `pip`/`docker` ecosystems; missing `security-governance.yml`; missing `permissions` in `probe-wan-connectivity.yml`; mutable `@v1` tag in `github-actions-verify-component.yml`; missing Nginx CSP/Permissions-Policy/`server_tokens off`. | Updated `dependabot.yml`, added SHA-pinned `security-governance.yml`, added least-privilege `permissions`, pinned `oras-project/setup-oras` SHA, and hardened Nginx configs. | **Fixed** |

## Verification Status

- **Unit & Security Regression Tests**: `gatekeeper/tests/` (including `test_security_assessment_fixes.py`)
- **Bandit SAST (`-ll`)**: 0 Medium/High findings
- **Semgrep SAST (`p/security-audit`, `p/owasp-top-ten`, `--severity ERROR`)**: 0 ERROR findings
- **Dependency Audit (`pip-audit`)**: 0 known vulnerabilities
