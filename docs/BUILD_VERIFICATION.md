# Build & Functional Verification Report

- **Verification Date**: `2026-11-20`
- **Verified By**: **Jeffs' Automated build and deploy agent**
- **Repository**: `jsoehner/trusted-oss-harbor` (`main` @ `cfb8ccf`)
- **Mode**: **Non-Disruptive Live Infrastructure Verification** (production TrueNAS SCALE appliance at `http://oss.jsigroup.local:8080` was never stopped, restarted, or mutated)

---

## 1. Trusted OSS Split-Horizon Configuration

Configured via `setup_trusted_oss_repo.py` (`--mode virtual`):

| Scope | Setting | Value |
| :--- | :--- | :--- |
| Local LAN (`.env`, gitignored) | `TRUSTED_OSS_CACHE_URL` | `http://oss.jsigroup.local:8080` |
| GitHub Actions Variable | `TRUSTED_OSS_CACHE_URL` | `https://jsigroup-oss.duckdns.org` |
| GitHub Actions Variable | `TRUSTED_OSS_MODE` | `virtual` |
| GitHub Actions Variable | `TRUSTED_OSS_GPG_EMAIL` | `oss-signing@the-techy.com` |
| GitHub Actions Secrets | `OSS_MTLS_CLIENT_CERT`, `OSS_MTLS_CLIENT_KEY` | Synced from local `mtls-pki/` |
| Git Hygiene | `.git/info/exclude` | `.env`, `uv.toml`, `.mvn/settings.xml`, `.mvn/maven.config`, `.npmrc` excluded |

---

## 2. Build, Dependency & Static Verification

### Isolated Virtual Environment Install via Trusted OSS PyPI
```bash
uv venv /tmp/trusted-oss-harbor-verify-venv
uv pip install \
  --python /tmp/trusted-oss-harbor-verify-venv/bin/python \
  --default-index http://oss.jsigroup.local:8080/pypi/virtual/simple \
  --allow-insecure-host oss.jsigroup.local \
  -r gatekeeper/requirements.txt
```
- **Result**: **PASS** — Resolved and installed all **33 packages** (Python `3.15.2`) from `http://oss.jsigroup.local:8080/pypi/virtual/simple` (`pyyaml==6.0.3` built cleanly from source on CPython 3.15). Temporary venv removed after verification.

### Python & Shell Syntax Checks
```bash
python3 -m py_compile gatekeeper/app/*.py gatekeeper/tests/*.py scripts/*.py
for f in scripts/*.sh config/pfsense/*.sh; do bash -n "$f"; done
```
- **Result**: **PASS** — All Python modules (`gatekeeper/app/*.py`, `gatekeeper/tests/*.py`, `scripts/*.py`) and all **11** shell scripts passed syntax validation with zero errors.

### Unit & Integration Test Suite
```bash
PYTHONPATH=gatekeeper .venv/bin/pytest gatekeeper/tests -v
```
- **Result**: **PASS** — **44 passed, 0 failed** (`56.69s`), covering BOM/CBOM dual-signed attestations, path containment, archive security (zip-slip, symlinks, EICAR, encrypted zips), ClamAV TCP protocol, GPG + NIST FIPS 204 ML-DSA-65 dual signing, virtual repository pull-through, CVE gating, remediation/GC, and daily digest formatting.

---

## 3. Live Read-Only Functional Verification (`http://oss.jsigroup.local:8080`)

### Guided Headless Chrome Browser Verification (`browser_verify.py`)
| URL | HTTP Status | Page Title | Console Errors | JS Exceptions | Result |
| :--- | :---: | :--- | :---: | :---: | :---: |
| `http://oss.jsigroup.local:8080/` | `200` | `Welcome to nginx!` | `0` | `0` | **PASS** |
| `http://oss.jsigroup.local:8080/pypi/virtual/simple/pytest/` | `200` | `Links for pytest` | `0` | `0` | **PASS** |

### `curl` API Endpoint Verification (`api_verify.py`)
| Endpoint | Method | HTTP Status | Latency | Verified Behavior |
| :--- | :---: | :---: | :---: | :--- |
| `/healthz` | `GET` | `200` | `0.62s` | JSON `{"status":"ok","version":"1.6.0","role":"all","bus_backend":"memory","signing_authority_ready":true,"cvss_fail_threshold":7.0}` |
| `/` | `GET` | `200` | `0.003s` | Nginx gateway active (`text/html`) |
| `/keys/trusted-oss-pubkey.asc` | `GET` | `200` | `0.011s` | Valid PGP public key block (`1,347` bytes) |
| `/keys/trusted-oss-mldsa65.pub` | `GET` | `200` | `0.012s` | Valid NIST FIPS 204 ML-DSA-65 public key (`2,717` bytes) |
| `/catalog/status` | `GET` | `200` | `1.33s` | JSON catalog status (`50,029` bytes; `chainguard/jre:latest` & `chainguard/python:latest` cached & signature-valid) |
| `/catalog/vulnerabilities` | `GET` | `200` | `1.60s` | JSON vulnerability summary (`3,602` clean, `0` vulnerable, `0` unscanned, `32` quarantined) |
| `/pypi/virtual/simple/pytest/` | `GET` | `200` | `0.24s` | PEP 503 simple HTML index (`74,508` bytes) |
| `/maven/virtual/org/slf4j/slf4j-api/maven-metadata.xml` | `GET` | `200` | `0.71s` | Valid Maven XML metadata (`3,887` bytes) |
| `/bom/lookup?purl=pkg:pypi/pytest@9.0.0` | `GET` | `404` | `0.004s` | Expected `404` JSON response for uncached PURL |
