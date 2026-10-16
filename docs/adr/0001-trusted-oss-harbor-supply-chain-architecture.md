# ADR 0001: Self-Hosted Trusted OSS Supply Chain Platform with Harbor, ClamAV, Trivy, and Cryptographic Signing

* **Status:** Accepted
* **Deciders:** Enterprise Architecture & Supply Chain Security Governance
* **Date:** 2026-10-16

---

## 1. Context & Problem Statement

Upstream open-source registries (Maven Central, PyPI, Docker Hub) expose downstream CI/CD pipelines to supply-chain attacks, typosquatting, malware payloads, and rate-limiting disruptions. We require a self-hosted **Trusted OSS Supply Chain Platform** running behind our **pfSense** firewall, backed by a persistent host storage volume (`/home/jsoehner/trusted-oss-data` initially, migrating to a **TrueNAS iSCSI** external block storage LUN `/mnt/truenas-iscsi-oss` and/or TrueNAS S3 object store), that dynamically fetches upstream components on demand, scans them with **ClamAV** (antivirus) and **Trivy / OWASP NVD (`jsoehner/nvd-cache`)** (vulnerabilities), cryptographically signs clean artifacts with auto-approval (`AUTO_PROMOTE_CLEAN_ARTIFACTS=true`), and enforces that all GitHub projects fetch **only** signed components from this repository.

---

## 2. Decision Drivers

1. **Multi-Ecosystem Coverage**: Support OCI containers/Helm/ORAS via **Harbor** alongside native Java (`mvn` Maven2 layout) and Python (`pip`/`uv` PEP 503 Simple layout).
2. **Defense-in-Depth Quarantine Gate with Auto-Approval**: Every dynamically fetched package must pass ClamAV (`clamd` INSTREAM + archive Zip-Slip/symlink inspection) and CVE threshold checks (`CVSS < 7.0`) before automatic promotion.
3. **Single Cryptographic Root of Trust**: Sign all promoted Maven/PyPI artifacts with a dedicated Trusted OSS GPG Authority (`.asc`) and OCI images with **Cosign**, so downstream builds verify a single internal public key.
4. **Zero Unauthenticated WAN Exposure**: Terminate TLS + mTLS at **pfSense HAProxy** and restrict WAN ingress to official GitHub Actions CIDR ranges (`https://api.github.com/meta`).
5. **Phased Storage Evolution (Home Directory $\rightarrow$ TrueNAS iSCSI Block & Object Storage)**: Operate immediately in `/home/jsoehner/trusted-oss-data` without root partitioning, while parameterizing `${OSS_DATA_ROOT}` so all containers and Harbor can seamlessly cut over to a TrueNAS iSCSI Zvol block mount (`/mnt/truenas-iscsi-oss`) or TrueNAS MinIO/S3 object storage (`storage_service.s3`).

---

## 3. Decision Outcome

1. **Containerized Harbor + Pluggable Scanners**:
   - Configured Harbor (`config/harbor/harbor.yml.tmpl`) mounting `${OSS_DATA_ROOT}/harbor` persistently, paired with **Trivy** and **`harbor-scanner-clamav`** (`clamav/clamav:1.4`).
2. **Lightweight FastAPI Quarantine-Scan-Sign Gatekeeper (`gatekeeper/`)**:
   - Implemented an async FastAPI service that dynamically fetches missing Maven/PyPI artifacts into `${OSS_DATA_ROOT}/packages/quarantine`, runs ClamAV + archive safety + CVSS checks, generates detached GPG `.asc` signatures and `.sha256`/`.sha512` checksums, records HMAC-attested provenance in `${OSS_DATA_ROOT}/audit/provenance.jsonl`, and atomically promotes clean artifacts (`AUTO_PROMOTE_CLEAN_ARTIFACTS=true`) to `trusted-maven` and `trusted-pypi`.
   - Enforces runtime signature verification (`verify_artifact_signature`) before serving any artifact to downstream clients.
3. **pfSense Edge & GitHub Client Enforcement**:
   - Provided `config/pfsense/update-github-cidrs.sh` and `haproxy-mtls-guide.md` for pfSense HAProxy mTLS + IP allowlisting.
   - Provided drop-in `client-templates/` (`maven-settings.xml`, `pgpverify-plugin-snippet.xml`, `uv.toml`, `github-actions-trusted-oss.yml`) to lock GitHub projects exclusively to signed artifacts from the trusted host.
4. **TrueNAS iSCSI Storage Roadmap (`docs/roadmap/truenas-iscsi-storage-roadmap.md`)**:
   - Standardized on `/home/jsoehner/trusted-oss-data` for Phase 1 local operation and authored `scripts/setup_truenas_iscsi_mount.sh` to automate `open-iscsi` target discovery, CHAP login, XFS formatting (`LABEL=TRUSTED_OSS`), `/etc/fstab` `_netdev` persistence, and `rsync -aHAX` cutover to `/mnt/truenas-iscsi-oss`.
