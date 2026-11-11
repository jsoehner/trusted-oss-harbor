# Trusted OSS Supply Chain Platform (`trusted-oss-harbor`)

Self-hosted, containerized **Trusted Open-Source Software (OSS) Supply Chain Platform** combining **CNCF Harbor** (for OCI containers, Helm charts, and ORAS artifacts) with an automated **Quarantine $\rightarrow$ ClamAV Antivirus $\rightarrow$ Trivy/NVD Vulnerability Gate $\rightarrow$ GPG/Cosign Cryptographic Signer** for **Java (Maven)** and **Python (PyPI)** packages, designed to run behind a **pfSense** firewall with a persistent host mount (`/home/jsoehner/trusted-oss-data` now, with seamless migration to a **TrueNAS iSCSI** external block/object store).

---

## Architecture Highlights

1. **Persistent Storage Mount (`OSS_DATA_ROOT=/home/jsoehner/trusted-oss-data`)**:
   - `harbor/`: Harbor OCI blobs, PostgreSQL metadata, Redis cache, and job logs.
   - `packages/quarantine/`: Lightweight staging area for dynamically fetched upstream Maven/PyPI artifacts.
   - `packages/trusted-maven/` & `packages/trusted-pypi/`: Immutable, ClamAV-scanned, CVE-verified, and GPG-signed (`.asc`) package repositories (with `AUTO_PROMOTE_CLEAN_ARTIFACTS=true`).
   - `scanners/`: Persistent ClamAV virus definitions (`freshclam`), Trivy DB, and OWASP NVD H2 cache (`jsoehner/nvd-cache`).
   - `audit/provenance.jsonl`: Append-only cryptographic provenance log for every promoted component.
2. **Defense-in-Depth Quarantine & Signing Pipeline (`oss-gatekeeper`)**:
   - **Dynamic Pull-Through**: Automatically fetches requested dependencies on cache miss into `quarantine/`.
   - **Antivirus & Archive Inspection**: Streams artifacts over TCP `INSTREAM` to `clamd` (`clamav/clamav:1.4`) and inspects `.jar`/`.whl`/`.tar.gz` archives for Zip-Slip path traversal and symlinks.
   - **Vulnerability Gate & Auto-Approval**: Automatically promotes clean artifacts (`CVSS < 7.0`, `AUTO_PROMOTE_CLEAN_ARTIFACTS=true`) and blocks vulnerable or infected packages.
   - **Cryptographic Signing & Read-Time Verification**: Signs every promoted artifact with your **Trusted OSS GPG Key** (`.asc`) and verifies the detached signature before serving any file to a client.
3. **pfSense Edge Security (`config/pfsense/`)**:
   - Terminates TLS + Client Certificate Authentication (**mTLS**) at **pfSense HAProxy** and restricts WAN ingress to GitHub Actions IP ranges (`config/pfsense/update-github-cidrs.sh`).
4. **TrueNAS iSCSI Block & Object Storage Roadmap (`docs/roadmap/truenas-iscsi-storage-roadmap.md`)**:
   - Currently operates out of `/home/jsoehner/trusted-oss-data`.
   - Includes [`scripts/setup_truenas_iscsi_mount.sh`](scripts/setup_truenas_iscsi_mount.sh) and [`docs/roadmap/truenas-iscsi-storage-roadmap.md`](docs/roadmap/truenas-iscsi-storage-roadmap.md) to attach a **TrueNAS iSCSI Zvol LUN** at `/mnt/truenas-iscsi-oss` (or configure Harbor `storage_service.s3` against TrueNAS MinIO/S3) and migrate data with zero configuration drift.
5. **Chainguard Zero-CVE Containers (`jre` & `python`) + Shared Spring Boot Catalog Cache**:
   - **Harbor Chainguard Proxy Cache**: [`scripts/configure_harbor_projects.sh`](scripts/configure_harbor_projects.sh) provisions the `chainguard-cache` Proxy Cache project in Harbor backed by `https://cgr.dev`, and [`containers/chainguard-jre-python/Dockerfile`](containers/chainguard-jre-python/Dockerfile) demonstrates building a polyglot Spring Boot JRE + Python runtime from `${HARBOR_REGISTRY}/chainguard-cache/chainguard/jre:latest` and `${HARBOR_REGISTRY}/chainguard-cache/chainguard/python:latest`.
   - **Shared Spring Boot Component Collection**: [`config/catalog/trusted-seed-catalog.json`](config/catalog/trusted-seed-catalog.json) and the `POST /catalog/warm` / `GET /catalog/status` endpoints pre-warm, ClamAV-scan, and GPG-sign the core Spring Boot starters shared across `enterprise-command-center` and `spring-ai-blog-agent` (`spring-boot-starter-web`, `actuator`, `security`, `validation`, `data-jpa`, `amqp`, `test`, and `slf4j-api`).

---

## Quick Start

```bash
# 1. Copy and customize environment configuration (defaults to /home/jsoehner/trusted-oss-data)
cp .env.example .env

# 2. Initialize persistent storage, seed NVD cache from jsoehner/nvd-cache, and prepare Harbor
make bootstrap-harbor

# 3. Generate Trusted OSS GPG Signing Authority & export public key
make generate-keys

# 4. Launch ClamAV, Harbor Scanner Adapter, OSS Gatekeeper, and Unified Gateway
make up

# 5. Run the 5-stage automated verification & live Chainguard/Spring Boot cache suite
make verify-e2e

# 6. (Roadmap) Preview TrueNAS iSCSI external block storage mount & migration
make iscsi-roadmap-dryrun
```

---

## NAS Appliance Deployment (TrueNAS SCALE / Synology / Unraid)

To run the entire platform as a 24/7 self-contained appliance on your NAS without maintaining multiple daemon containers:

### 1. Pull the Published Image
```bash
docker pull ghcr.io/jsoehner/trusted-oss-gatekeeper:latest
```

### 2. Run via Docker CLI on your NAS
```bash
docker run -d \
  --name trusted-oss-gatekeeper \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /mnt/tank/trusted-oss-data:/data \
  -e CVSS_FAIL_THRESHOLD=7.0 \
  -e AUTO_PROMOTE_CLEAN_ARTIFACTS=true \
  -e GATEKEEPER_ADMIN_TOKEN="ChangeMe_GatekeeperToken_2026!" \
  ghcr.io/jsoehner/trusted-oss-gatekeeper:latest
```

### 3. Or Deploy via Docker Compose on your NAS
```yaml
services:
  trusted-oss-gatekeeper:
    image: ghcr.io/jsoehner/trusted-oss-gatekeeper:latest
    container_name: trusted-oss-gatekeeper
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - /mnt/tank/trusted-oss-data:/data
    environment:
      OSS_DATA_ROOT: /data
      CVSS_FAIL_THRESHOLD: 7.0
      AUTO_PROMOTE_CLEAN_ARTIFACTS: "true"
      GATEKEEPER_ADMIN_TOKEN: "ChangeMe_GatekeeperToken_2026!"
```

The appliance automatically:
- Initializes the `/data` directory hierarchy on your NAS ZFS pool.
- Auto-generates RSA-3072 GPG and NIST FIPS 204 ML-DSA-65 PQC signing authorities on first boot.
- Auto-downloads and updates ClamAV virus signatures with persistent caching in `/data/scanners/clamav`.
- Serves the unified gateway on port `8080`.


---

## Locking GitHub Projects to Signed-Only Components

Drop the templates in [`client-templates/`](client-templates/) into your GitHub repositories:
- **Java / Maven**: [`client-templates/maven-settings.xml`](client-templates/maven-settings.xml) (`<mirrorOf>*</mirrorOf>`) + [`client-templates/pgpverify-plugin-snippet.xml`](client-templates/pgpverify-plugin-snippet.xml) (`<failNoSignature>true</failNoSignature>` verified against `https://${HARBOR_DOMAIN}/keys/trusted-oss-pubkey.asc`).
- **Python (`uv` / `pip`)**: [`client-templates/uv.toml`](client-templates/uv.toml) pointing exclusively to `https://${HARBOR_DOMAIN}/pypi/trusted/simple` (which only indexes wheels carrying a valid `.asc` signature and `#sha256=` digest).
- **GitHub Actions Workflow**: [`client-templates/github-actions-trusted-oss.yml`](client-templates/github-actions-trusted-oss.yml).
