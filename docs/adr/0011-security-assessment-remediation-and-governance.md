# SecADR-0011: Comprehensive Security Assessment Remediation & Governance Hardening

- **Status**: Accepted
- **Date**: 2026-11-22
- **Security Classification**: Internal
- **Decision Makers**: Security Governance & Platform Engineering
- **Consulted / Informed**: DevSecOps, Supply Chain Owners
- **Supersedes**: None (extends [ADR 0002](0002-gatekeeper-security-hardening-and-fail-closed-controls.md))

---

## 1. Context and Problem Statement

A full security assessment executed via the `security-agent-orchestrator` and `security-governance-orchestrator` skills (combining STRIDE threat modeling, Semgrep SAST, Bandit SAST, `pip-audit`, and manual source review) identified 13 security defects across `gatekeeper/app/`, `scripts/`, `config/nginx/`, and `.github/`:

1. **Path Traversal (CWE-22)**: OCI Referrers/Blobs endpoints (`/v2/{namespace}/{repo_path}/referrers/{digest}` & `/blobs/{digest}`) and `resolve_purl_to_bom_file()` (`oci`/`docker`/`maven`) concatenated user-controlled path segments without `resolve_safe_relative_path()` or symlink checks.
2. **Decompression Bombs & Backslash Zip-Slip (CWE-409, CWE-22, CWE-770)**: `inspect_archive_safety()` loaded full artifacts into memory, omitted `MAX_ARCHIVE_MEMBERS` (10,000) and `MAX_UNCOMPRESSED_BYTES` (512 MB) caps, and missed Windows backslash/drive-letter traversal. `bom_generator.py` called `zf.read(info)[:MAX_MEMBER_BYTES]` (unbounded decompression before slicing). Upload/download routes lacked `MAX_ARTIFACT_BYTES` (250 MB) streaming enforcement.
3. **SSRF in Dynamic Catalog Warmup (CWE-918)**: `_execute_catalog_warmup()` fetched `https://{registry}` from discovered `Dockerfile` `FROM` lines without checking `settings.trusted_sources`.
4. **Unauthenticated Job Queue Trigger & Unbounded Batch DoS (CWE-306, CWE-770)**: `POST /bom/batch` accepted unbounded PURL lists and allowed unauthenticated callers to enqueue `"warm"` jobs via `trigger_pull_on_miss=True`.
5. **Duplicate JIT Routes & Unauthenticated `/status/{job_id}` (CWE-306, CWE-770)**: Duplicate `/request-artifact` and `/status/{job_id}` definitions existed in `main.py`, `/status/{job_id}` lacked admin authentication, and `JIT_PROMOTION_JOBS` was unbounded.
6. **Ephemeral Provenance HMAC Key Regression (CWE-321)**: `append_provenance_record()` was called without `hmac_key`, causing a random throwaway key to be generated per record instead of using `ensure_provenance_hmac_key()`.
7. **Untrusted XML Parsing (CWE-611)**: `bom_generator.py`, `discovery.py`, and `remediation.py` parsed untrusted XML with stdlib `xml.etree.ElementTree`, and `update_latest_tag()` interpolated raw coordinates into `maven-metadata.xml` without XML escaping or path containment.
8. **Credential Exposure & File Permission Races (CWE-214, CWE-377)**: `sign_artifact_detached_gpg()` passed `--passphrase` on argv; ML-DSA, HMAC, and OAuth token files were written before `chmod 0600`.
9. **CI/CD Governance Gaps**: `.github/dependabot.yml` lacked the mandatory 7-day `cooldown` and `pip`/`docker` ecosystems; `.github/workflows/probe-wan-connectivity.yml` lacked top-level `permissions`; `client-templates/github-actions-verify-component.yml` used a mutable `@v1` action tag; and no dedicated `.github/workflows/security-governance.yml` gate existed.

### 1.1 Threat & Vulnerability Context
- **Threat Vectors (STRIDE)**: Tampering, Information Disclosure, Denial of Service, Elevation of Privilege, Repudiation.
- **Compliance Traceability**: OWASP Top 10 (A01, A03, A04, A05, A08, A10), SOC2 CC6.1 / CC6.6 / CC7.2, CIS Docker & GitHub Benchmarks.

---

## 2. Decision Outcome

All 13 defects were remediated in-place and verified with automated SAST (`bandit`, `semgrep`), dependency audit (`pip-audit`), and unit/integration regression tests:

1. **Path & Archive Containment**: Enforced `resolve_safe_relative_path()` on OCI Referrers/Blobs namespaces, `resolve_purl_to_bom_file()`, and `update_latest_tag()`. Restored streaming `MAX_ARTIFACT_BYTES` (250 MB, HTTP 413), `MAX_ARCHIVE_MEMBERS` (10,000), `MAX_UNCOMPRESSED_BYTES` (512 MB), streaming ZIP reads in `bom_generator.py`, and Windows backslash/drive-letter Zip-Slip checks.
2. **SSRF & Fail-Closed Scanning**: Enforced `settings.trusted_sources` allowlist in `_execute_catalog_warmup()`, strict `http`/`https` scheme validation in upstream downloads and CLI scripts, and restored `TRIVY_REQUIRED` fail-closed mode.
3. **Auth & DoS Bounds**: Capped `POST /bom/batch` to 500 PURLs and gated `trigger_pull_on_miss=True` behind `require_admin_token()`. Removed duplicate JIT routes, authenticated `GET /status/{job_id}`, bounded `JIT_PROMOTION_JOBS` to 500 entries, and paginated `GET /audit/provenance`.
4. **Cryptographic & XML Hardening**: Wired persistent `ensure_provenance_hmac_key()` into `initialize_storage_and_keys()` and all `append_provenance_record()` calls; switched GPG passphrase passing to `--passphrase-fd 0` stdin; wrote secret files atomically with `0o600`; migrated XML parsing to `defusedxml` and escaped generated XML.
5. **Gateway & CI/CD Governance**: Hardened Nginx configs (`server_tokens off`, CSP, Permissions-Policy, 260 MB cap), added `.github/workflows/security-governance.yml` (SHA-pinned, least-privilege), updated `.github/dependabot.yml` with `cooldown: default-days: 7`, pinned `oras-project/setup-oras` to its commit SHA, and added `permissions: contents: read` to `probe-wan-connectivity.yml`.
6. **Proactive Vulnerability Advisories & Upgrade Notifications (`gatekeeper/app/advisories.py`, `gatekeeper/app/notifications.py`)**:
   - **Architectural Rationale**: Previously, developers only discovered that a cached dependency became vulnerable via HTTP `451` build failures or up to 24 hours later in a daily summary that lacked resolved clean-upgrade recommendations. To close this feedback loop without coupling external chat/email transports into the synchronous pull-through request path, we introduced a dedicated advisory module (`app/advisories.py`) with:
     - Filterable JSON (`GET /catalog/advisories`), subscribable RSS 2.0 (`GET /catalog/advisories.rss`), and a zero-JS, CSP-safe HTML Security Advisory Center (`GET /catalog/advisories/dashboard`).
     - Deduplicated real-time alerting (`audit/vuln_alerts.jsonl`) triggered asynchronously during remediation sweeps (`VULN_ALERT_WEBHOOK_URL` with optional HMAC-SHA256 `X-Trusted-OSS-Signature`, plus optional `VULN_ALERT_IMMEDIATE_EMAIL`).
     - Enriched Daily Digest notifications (`build_daily_digest` / `render_daily_digest_html`) that pair every newly vulnerable or quarantined version with clickable OSV advisory links and the **newest `CLEAN` (passing-scan) version available for upgrade**.

### 2.1 Trade-offs & Negative Consequences
- **Operational Dependency**: Adding `defusedxml` introduces one lightweight pure-Python runtime dependency in `gatekeeper/requirements.txt`.
- **Stricter Limits**: Enforcing `MAX_ARTIFACT_BYTES` (250 MB), 500-PURL batch caps, and `trusted_sources` SSRF allowlists will reject oversized artifacts or unapproved registries that previously slipped through; operators must explicitly configure `MAX_ARTIFACT_BYTES` or `TRUSTED_SOURCES` for legitimate exceptions.
- **CSP Relaxation for Inline Styles**: Nginx CSP was set to `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'` so the zero-JS HTML dashboard renders without external CDNs while still blocking all script execution (`script-src 'none'`).

---

## 3. Residual Risk & Compensating Controls

- **Residual Risk**: Read-only inventory endpoints (`/catalog/vulnerabilities`, `/catalog/status`, `/audit/provenance`, `/audit/activity`) remain accessible without `X-Gatekeeper-Token` for LAN monitoring and backward compatibility with existing operational tooling.
- **Compensating Controls**: WAN ingress is restricted by pfSense to GitHub Actions CIDRs with HAProxy mTLS client certificate authentication, and Nginx enforces rate limiting and strict security headers.

---

## 4. Verification

- `pytest gatekeeper/tests` (including `gatekeeper/tests/test_security_assessment_fixes.py`)
- `bandit -r gatekeeper/app scripts client-templates -ll` (0 Medium/High findings)
- `semgrep --config=p/security-audit --config=p/owasp-top-ten --severity ERROR gatekeeper/app scripts client-templates` (0 ERROR findings)
- `pip-audit -r gatekeeper/requirements.txt` (0 known CVEs)
