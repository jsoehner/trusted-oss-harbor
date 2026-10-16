# Trusted OSS Supply Chain Platform (`trusted-oss-harbor`)

Self-hosted, containerized **Trusted Open-Source Software (OSS) Supply Chain Platform** combining **CNCF Harbor** (for OCI containers, Helm charts, and ORAS artifacts) with an automated **Quarantine $\rightarrow$ ClamAV Antivirus $\rightarrow$ Trivy/NVD Vulnerability Gate $\rightarrow$ GPG/Cosign Cryptographic Signer** for **Java (Maven)** and **Python (PyPI)** packages, designed to run behind a **pfSense** firewall with a single persistent host mount (`/srv/trusted-oss`).

---

## Architecture Highlights

1. **Persistent Storage Mount (`OSS_DATA_ROOT=/srv/trusted-oss`)**:
   - `harbor/`: Harbor OCI blobs, PostgreSQL metadata, Redis cache, and job logs.
   - `packages/quarantine/`: Ephemeral staging area for dynamically fetched upstream Maven/PyPI artifacts.
   - `packages/trusted-maven/` & `packages/trusted-pypi/`: Immutable, ClamAV-scanned, CVE-verified, and GPG-signed (`.asc`) package repositories.
   - `scanners/`: Persistent ClamAV virus definitions (`freshclam`), Trivy DB, and OWASP NVD H2 cache (`jsoehner/nvd-cache`).
   - `audit/provenance.jsonl`: Append-only cryptographic provenance log for every promoted component.
2. **Defense-in-Depth Quarantine & Signing Pipeline (`oss-gatekeeper`)**:
   - **Dynamic Pull-Through**: Automatically fetches requested dependencies on cache miss into `quarantine/`.
   - **Antivirus & Archive Inspection**: Streams artifacts over TCP `INSTREAM` to `clamd` (`clamav/clamav:1.4`) and inspects `.jar`/`.whl`/`.tar.gz` archives for Zip-Slip path traversal and symlinks.
   - **Vulnerability Gate**: Blocks artifacts exceeding `CVSS_FAIL_THRESHOLD` (default `7.0`).
   - **Cryptographic Signing & Read-Time Verification**: Signs every promoted artifact with your **Trusted OSS GPG Key** (`.asc`) and verifies the detached signature before serving any file to a client.
3. **pfSense Edge Security (`config/pfsense/`)**:
   - Terminates TLS + Client Certificate Authentication (**mTLS**) at **pfSense HAProxy** and restricts WAN ingress to GitHub Actions IP ranges (`config/pfsense/update-github-cidrs.sh`).

---

## Quick Start

```bash
# 1. Copy and customize environment configuration
cp .env.example .env

# 2. Initialize persistent storage, seed NVD cache from jsoehner/nvd-cache, and prepare Harbor
make bootstrap-harbor

# 3. Generate Trusted OSS GPG Signing Authority & export public key
make generate-keys

# 4. Launch ClamAV, Harbor Scanner Adapter, OSS Gatekeeper, and Unified Gateway
make up

# 5. Run the automated verification suite
make verify-e2e
```

---

## Locking GitHub Projects to Signed-Only Components

Drop the templates in [`client-templates/`](client-templates/) into your GitHub repositories:
- **Java / Maven**: [`client-templates/maven-settings.xml`](client-templates/maven-settings.xml) (`<mirrorOf>*</mirrorOf>`) + [`client-templates/pgpverify-plugin-snippet.xml`](client-templates/pgpverify-plugin-snippet.xml) (`<failNoSignature>true</failNoSignature>` verified against `https://${HARBOR_DOMAIN}/keys/trusted-oss-pubkey.asc`).
- **Python (`uv` / `pip`)**: [`client-templates/uv.toml`](client-templates/uv.toml) pointing exclusively to `https://${HARBOR_DOMAIN}/pypi/trusted/simple` (which only indexes wheels carrying a valid `.asc` signature and `#sha256=` digest).
- **GitHub Actions Workflow**: [`client-templates/github-actions-trusted-oss.yml`](client-templates/github-actions-trusted-oss.yml).
