# Trusted OSS Supply Chain Platform — Operations Manual (`v1.6.x`)

This manual documents every operational capability of `trusted-oss-harbor` (`v1.6.x`), how to run and maintain the decoupled **Frontend + Engine + Valkey Message Bus** stack and the single-container **TrueNAS / NAS Appliance** image (`ghcr.io/jsoehner/trusted-oss-gatekeeper:latest`, auto-versioned per commit on `main`), and how to integrate existing Java (Maven), Python (`uv`/`pip`), OCI/Docker, BOM consumers (`jsi-bom-actions`), and GitHub Actions projects.

---

## 1. Architecture & Components

`trusted-oss-harbor` separates **HTTP request serving** from **heavy scanning, CycloneDX 1.6 SBOM/CBOM generation, and remediation** so package managers and inventory queries stay fast even on resource-constrained NAS hosts (such as TrueNAS SCALE running on native ZFS dataset `Pool1/trusted-oss-data`).

![Trusted OSS Harbor Security Capabilities & Pluggable Service Map](images/trusted-oss-security-capabilities-map.png)

```mermaid
flowchart LR
    Dev["Developer / CI / Package Manager / jsi-bom-actions"] -->|":443 mTLS / :8080 LAN"| GW["oss-gateway (Nginx on Wolfi)"]
    GW --> FE["oss-frontend (FastAPI, GATEKEEPER_ROLE=frontend)"]
    FE -->|"Cache HIT / BOM Batch / OCI 1.1 Referrers"| Store[("TrueNAS Native ZFS /data (Trusted + BOMs + Quarantine + Keys)")]
    FE -->|"202 Accepted (XADD warm / remediate / backfill_boms)"| Bus["oss-bus (Valkey Streams)"]
    Bus -->|"XREADGROUP (ENGINE_MAX_CONCURRENCY=2)"| Eng["oss-engine (python -m app.worker)"]
    Eng --> Clam["oss-clamav (:3310 INSTREAM)"]
    Eng --> Up["Upstream (Maven Central / PyPI / cgr.dev) + OSV/Trivy"]
    Eng --> BOM["CycloneDX 1.6 SBOM/CBOM + GPG/ML-DSA-65 Signer"]
    BOM --> Store
```

| Service / Component | Role | Key Environment / Config |
| :--- | :--- | :--- |
| **`oss-gateway`** | Unified Nginx reverse proxy (`:8080` / `:8443`) | `config/nginx/oss-gateway.conf` |
| **`oss-frontend`** | Serves artifacts, PEP 503 / Maven metadata, keys, provenance, `/catalog/vulnerabilities`, and `/jobs` | `GATEKEEPER_ROLE=frontend`, `BUS_URL=redis://oss-bus:6379/0` |
| **`oss-bus`** | Lightweight Valkey Streams broker & job state store (~15–30 MB RAM) | `valkey/valkey:8-alpine` |
| **`oss-engine`** | Consumes `remediate` & `warm` jobs, runs hourly CVE rescans, ClamAV/OSV/Trivy checks, quarantine, and signing | `GATEKEEPER_ROLE=engine`, `ENGINE_MAX_CONCURRENCY=2`, `CVE_RESCAN_INTERVAL_SECONDS=3600` |
| **`oss-clamav`** | Antivirus daemon (`INSTREAM` TCP `:3310`) | `clamav/clamav:1.4` |

> [!NOTE]
> In single-container NAS appliance deployments (`Dockerfile` + `supervisord`), `GATEKEEPER_ROLE=all` runs with an automatic `InMemoryJobBus` fallback when `BUS_URL` is unset.

---

## 2. Core Functionality & Live Verification

### 2.1 Health Check & Post-Quantum Key Distribution

Every client and monitoring probe can verify service readiness, active role, bus backend, CVSS policy threshold, and the **GPG + NIST FIPS 204 ML-DSA-65** signing authorities:

- `GET /healthz` — Returns service status, version, role, bus backend, signing key readiness, and `cvss_fail_threshold`.
- `GET /keys/trusted-oss-pubkey.asc` — ASCII-armored Trusted OSS GPG public key.
- `GET /keys/trusted-oss-mldsa65.pub` — ML-DSA-65 post-quantum public key.
- `GET /keys/trusted-oss-mldsa65.fingerprint` — SHA-256 and SHA-384 key fingerprints.

![Health Check and PQC Key Fingerprint](images/01-healthz-and-keys.png)

### 2.2 Virtual Pull-Through & Trusted-Only Repositories

| Ecosystem | Virtual Pull-Through Endpoint (Auto-Quarantine -> Scan -> Sign) | Trusted-Only Endpoint (Pre-Signed Only) |
| :--- | :--- | :--- |
| **Maven** | `/maven/virtual/{group/artifact/version/file}` | `/maven/trusted/{group/artifact/version/file}` |
| **PyPI (PEP 503)** | `/pypi/virtual/simple/{pkg}/` | `/pypi/trusted/simple/{pkg}/` |
| **OCI (Chainguard)** | `/v2/chainguard-cache/{repo}/manifests/{ref}` | Harbor OCI Proxy Cache |

On a cache miss, `oss-frontend` / `oss-engine` uses per-artifact `asyncio.Lock` single-flight deduplication to:
1. Stream the upstream artifact into `packages/quarantine/` (enforcing `MAX_ARTIFACT_BYTES`).
2. Inspect `.jar`/`.whl`/`.tar.gz` archives for Zip-Slip traversal, symlinks, and encrypted entries.
3. Scan via ClamAV (`INSTREAM`) and OSV/Trivy (`CVSS_FAIL_THRESHOLD=7.0`).
4. Dual-sign clean artifacts with **GPG RSA-3072 (`.asc`)** and **ML-DSA-65 (`.mldsa65`)**, write `.sha256`/`.sha384`/`.sha512` digests, append an HMAC-SHA384 provenance entry to `audit/provenance.jsonl`, and atomically promote to `trusted-maven/` or `trusted-pypi/`.
5. Block infected or `CVSS >= 7.0` artifacts with `HTTP 451 Unavailable For Legal Reasons`.

### 2.3 Per-Version Vulnerability Catalog, Filtering & ASCII Tables

Use `scripts/catalog_frontend.py` to inspect cached components, signatures, ClamAV status, CVSS/CVE status, quarantined versions, and component caching history. It supports comma-separated `--ecosystem` and `--components` filters:

```bash
# PyPI components filtered by name
GATEKEEPER_ADMIN_TOKEN="<token>" \
  python3 scripts/catalog_frontend.py \
  --url http://oss.jsigroup.local:8080 \
  --ecosystem pypi \
  --components requests,httpx
```

![PyPI Catalog and Vulnerability Table](images/02-catalog-frontend-pypi.png)

```bash
# Maven components filtered by name
GATEKEEPER_ADMIN_TOKEN="<token>" \
  python3 scripts/catalog_frontend.py \
  --url http://oss.jsigroup.local:8080 \
  --ecosystem maven \
  --components spring-boot-starter-web,slf4j-api
```

![Maven Catalog and Vulnerability Table](images/03-catalog-frontend-maven.png)

### 2.4 Hourly CVE Rescan, Unscanned Sweeps, Auto-Quarantine & `N-2` Garbage Collection

`oss-engine` runs an initial `only_unscanned=true` sweep shortly after startup and an hourly rescan + garbage collection loop (`CVE_RESCAN_INTERVAL_SECONDS=3600`). Follow these four steps to inspect scheduled activity, scan `UNSCANNED` components, remediate newly vulnerable versions, and prune `N-2+` artifacts:

1. **Step 1 — Inspect the Scheduled Task & Engine Activity Log (`--activity`)**:
   Query `GET /audit/activity` to verify that `INITIAL_UNSCANNED_SCAN`, `HOURLY_CVE_RESCAN`, and `HOURLY_GC` ran and see what each run did:
   ```bash
   GATEKEEPER_ADMIN_TOKEN="<token>" \
     python3 scripts/catalog_frontend.py --url http://oss.jsigroup.local:8080 --activity
   ```
   ![Section 2.4 Step 1 — Activity Log](images/05-sec24-step1-activity-log.png)

2. **Step 2 — Force Scanning of `UNSCANNED` Components (`--scan-unscanned --wait --activity`)**:
   Trigger an immediate sweep of every cached component whose provenance status classifies as `UNSCANNED` (including legacy `OSV_SKIPPED` or `NO_VULN_HEADER` records), persist `CLEAN` verdicts, and print the updated `MANUAL_UNSCANNED_SCAN` event:
   ```bash
   GATEKEEPER_ADMIN_TOKEN="<token>" \
     python3 scripts/catalog_frontend.py --url http://oss.jsigroup.local:8080 --scan-unscanned --wait --activity
   ```
   ![Section 2.4 Step 2 — Force Scan Unscanned](images/06-sec24-step2-scan-unscanned.png)

3. **Step 3 — Auto-Quarantine Vulnerable Versions & Tag Clean `'latest'` (`--remediate --wait`)**:
   When a CVE exceeds `CVSS_FAIL_THRESHOLD` (`7.0`), `oss-engine` moves the vulnerable version to `packages/quarantine/`, fetches the newest clean upstream version, tags it `'latest'`, and displays `[Quarantined (Vulnerable)]` plus `[Component Caching History & Active 'latest' Resolution]`:
   ```bash
   GATEKEEPER_ADMIN_TOKEN="<token>" \
     python3 scripts/catalog_frontend.py --url http://oss.jsigroup.local:8080 \
     --ecosystem pypi --components requests --remediate --wait
   ```
   ![Section 2.4 Step 3 — Auto-Quarantine and Latest Tagging](images/07-sec24-step3-remediate-quarantine.png)

4. **Step 4 — `N-2` Garbage Collection (`--gc --wait --activity`)**:
   Prune cached versions that are 2+ versions older than `latest` (`GC_RETENTION_VERSIONS=2` keeps `N` and `N-1`; pass `--gc-dry-run` to preview or `--gc-keep <n>` to override):
   ```bash
   GATEKEEPER_ADMIN_TOKEN="<token>" \
     python3 scripts/catalog_frontend.py --url http://oss.jsigroup.local:8080 \
     --ecosystem pypi --gc --wait --activity
   ```
   ![Section 2.4 Step 4 — N-2 Garbage Collection](images/08-sec24-step4-gc-pruning.png)

### 2.5 Asynchronous Engine Jobs (`POST /catalog/remediate`, `GET /jobs`)

When `oss-frontend` runs with `GATEKEEPER_ROLE=frontend`, heavy mutations (`POST /catalog/remediate` and `POST /catalog/warm`) enqueue a job onto `oss-bus` and return `HTTP 202 Accepted` with a `job_id`:

```bash
# Trigger immediate targeted remediation asynchronously (returns 202 Accepted)
GATEKEEPER_ADMIN_TOKEN="<token>" \
  python3 scripts/catalog_frontend.py \
  --url http://oss.jsigroup.local:8080 \
  --ecosystem pypi \
  --components requests \
  --remediate

# Trigger remediation and wait for oss-engine to complete via GET /jobs/{job_id}
GATEKEEPER_ADMIN_TOKEN="<token>" \
  python3 scripts/catalog_frontend.py \
  --url http://oss.jsigroup.local:8080 \
  --ecosystem pypi,maven \
  --remediate --wait
```

---

## 3. Maintenance & Operations

### 3.1 Starting, Stopping, and Viewing Logs

```bash
# Start full decoupled stack (oss-bus, oss-frontend, oss-engine, oss-clamav, oss-gateway)
docker compose up -d --build

# Check service health
docker compose ps
curl -fsS http://oss.jsigroup.local:8080/healthz

# Stream Frontend HTTP/cache logs vs. Engine worker/remediation logs
docker logs -f oss-frontend
docker logs -f oss-engine
```

On TrueNAS SCALE, `[CACHE]` and `[ENGINE]` stdout lines appear directly in the **Apps -> trusted-oss-gatekeeper -> Logs** panel.

### 3.2 Dynamic Workspace & GitHub Discovery Warmup

Automatically discover dependencies across local projects (`pom.xml`, `build.gradle`, `requirements.txt`, `pyproject.toml`, `Dockerfile`) and GitHub repositories, then warm the cache:

```bash
GATEKEEPER_ADMIN_TOKEN="<token>" \
  python3 scripts/dynamic_warmup.py \
  --roots "$HOME" \
  --github \
  --warm \
  --gatekeeper-url http://oss.jsigroup.local:8080
```

#### Incremental Cache Primer (`scripts/prime_cache.py`)

When you add a new project with new dependencies, run `scripts/prime_cache.py` to compare all discovered components in your workspace against Gatekeeper's `/catalog/vulnerabilities` inventory, report **Already Cached** vs. **Will Be Queued & Fetched**, and queue only the missing items via `POST /catalog/warm`:

```bash
# Preview what is already cached vs. what will be queued & fetched
python3 scripts/prime_cache.py --url http://oss.jsigroup.local:8080 --dry-run

# Queue missing components (and wait for the warmup job to finish)
GATEKEEPER_ADMIN_TOKEN="<token>" \
  python3 scripts/prime_cache.py --url http://oss.jsigroup.local:8080 --wait
```

Use `--roots /path/to/new-project` to scope discovery to a specific directory, or `--json` for machine-readable output.

To schedule this automatically every day against your LAN server (`http://oss.jsigroup.local:8080`), install the systemd user timer:

```bash
./scripts/install_prime_timer.sh http://oss.jsigroup.local:8080
```

This creates `~/.config/systemd/user/trusted-oss-prime.service` and `trusted-oss-prime.timer` (running daily at `06:00` local time, reading `GATEKEEPER_ADMIN_TOKEN` from `~/.config/trusted-oss-harbor/prime.env`).

### 3.3 Storage & Scanner Cache Inspection

Inspect the backing storage directory (`/mnt/Pool1/trusted-oss-data` on TrueNAS SCALE, or a local/iSCSI `OSS_DATA_ROOT`), GPG/ML-DSA keys, NVD/ClamAV/Trivy caches, and quarantine count:

```bash
python3 scripts/catalog_storage.py --data-root /mnt/Pool1/trusted-oss-data
```

### 3.4 Running the Automated Verification Suite

Run the full offline unit and integration suite (31 tests covering path containment, archive security, ClamAV, OSV/Trivy gates, ML-DSA-65 + GPG dual signing, virtual pull-through, auto-quarantine remediation, and `oss-bus` async job queuing):

```bash
PYTHONPATH=gatekeeper uv run --python 3.11 --with-requirements gatekeeper/requirements.txt \
  pytest gatekeeper/tests -k "not test_live_remote_chainguard_cgr_and_maven_central_spring_boot_caching" -q
```

![Offline Verification Suite](images/04-verification-ci-pytest.png)

### 3.5 Daily Email & SMS Notifications (Outlook Port 587 / Graph 443 / SMS)

`scripts/daily_digest.py` and the in-container `run_daily_digest_loop` summarize gateway health, vulnerability counts, **cache capacity & disk runway** (`GET /catalog/retention`), **replaced vulnerable components**, **90-day inactivity space recovery** (`GC_MAX_UNUSED_DAYS=90`, warning at `GC_WARN_UNUSED_DAYS=75`), and the last 24 hours of `/audit/activity` events. Clean cached components are retained until they become vulnerable or remain unaccessed for over 90 days.

Preview the digest locally without sending:

```bash
GATEKEEPER_ADMIN_TOKEN="<token>" \
  python3 scripts/daily_digest.py --url http://oss.jsigroup.local:8080 --dry-run
```

Send via personal Outlook.com (`smtp-mail.outlook.com:587`) or Microsoft 365 (`smtp.office365.com:587`) using an app password, plus optional carrier Email-to-SMS (`@vtext.com`, `@txt.att.net`, `@tmomail.net`):

```bash
GATEKEEPER_ADMIN_TOKEN="<token>" \
  SMTP_HOST="smtp-mail.outlook.com" \
  SMTP_PORT=587 \
  SMTP_USER="you@outlook.com" \
  SMTP_PASSWORD="<app-password>" \
  python3 scripts/daily_digest.py \
    --url http://oss.jsigroup.local:8080 \
    --to "ops@example.com" \
    --sms-to "5551234567@vtext.com"
```

Alternative HTTPS port `443` transports (recommended when **MFA is enabled** or SMTP AUTH / port `587` is blocked):
- **Microsoft Graph OAuth2 Device Code + Long-Lived Refresh Token** (supports MFA, works over HTTPS `443`, and auto-rotates the refresh token on every daily run):
  1. Register a free Entra ID / Azure AD App Registration (Public client / native, **Allow public client flows = Yes**) with delegated Microsoft Graph permissions `Mail.Send` and `offline_access`.
  2. Run the one-time interactive MFA login to store the refresh token in `~/.config/trusted-oss-harbor/msgraph_token.json` (`chmod 600`):
     ```bash
     python3 scripts/daily_digest.py \
       --graph-auth \
       --graph-client-id "<your-app-client-id>" \
       --graph-tenant-id "common"
     ```
  3. Send daily email + carrier Email-to-SMS over HTTPS `443` using the cached refresh token:
     ```bash
     GATEKEEPER_ADMIN_TOKEN="<token>" \
       python3 scripts/daily_digest.py \
         --url http://oss.jsigroup.local:8080 \
         --to "ops@example.com" \
         --sms-to "5551234567@vtext.com"
     ```
  4. Or run it automatically inside the `oss-engine` Docker container by setting these in `.env` and restarting `docker compose up -d --build oss-engine` (rotated tokens persist in `/data/trusted-oss/audit/msgraph_token.json` and send timestamps in `last_digest_sent.txt`, controlled by `DIGEST_INTERVAL_SECONDS=86400`):
     ```dotenv
     DIGEST_ENABLED=true
     DIGEST_TO=ops@example.com
     DIGEST_SMS_TO=5551234567@vtext.com
     GRAPH_CLIENT_ID=<your-app-client-id>
     GRAPH_TENANT_ID=common
     GRAPH_REFRESH_TOKEN=<refresh_token_from_msgraph_token.json>
     ```
  5. Or enable it in the single-container **TrueNAS / NAS Appliance** (`ghcr.io/jsoehner/trusted-oss-gatekeeper:1.4.0` or `:latest`, where `/data` is your persistent volume):
     ```yaml
     environment:
       - DIGEST_ENABLED=true
       - DIGEST_INTERVAL_SECONDS=86400
       - DIGEST_TO=ops@example.com
       - DIGEST_SMS_TO=5551234567@vtext.com
       - GRAPH_CLIENT_ID=<your-app-client-id>
       - GRAPH_TENANT_ID=<your-tenant-id-or-common>
       - GRAPH_REFRESH_TOKEN=<refresh_token_from_msgraph_token.json>
       - GRAPH_TOKEN_FILE=/data/audit/msgraph_token.json
     ```
- **Microsoft Graph (direct token)**: pass `--graph-token "$GRAPH_ACCESS_TOKEN"` and `--to "ops@example.com"`.
- **Twilio SMS**: pass `--twilio-sid`, `--twilio-token`, `--twilio-from`, and `--twilio-to "+15551234567"`.

Schedule a daily cron job on the host (e.g., 07:30 every day, using the cached Graph refresh token) in `crontab -e`:

```cron
30 7 * * * cd /home/jsoehner/trusted-oss-harbor && GATEKEEPER_ADMIN_TOKEN="<token>" /usr/bin/python3 scripts/daily_digest.py --url http://oss.jsigroup.local:8080 --to "ops@example.com" --sms-to "5551234567@vtext.com" >> /var/log/oss-harbor-digest.log 2>&1
```

---

## 4. Integrating Existing Software Projects

### 4.0 Public-by-Default & Single-Variable Opt-In (`scripts/configure_trusted_cache.py`)

Every repository defaults to **public upstream repositories** (Maven Central, PyPI, `cgr.dev`) when `TRUSTED_OSS_CACHE_URL` is unset. When you download or onboard a repository and want to route it to your Trusted OSS Cache (or switch it back to public), run:

```bash
# Interactive prompt (defaults to public repos; enter your Trusted Cache URL to opt in)
python3 scripts/configure_trusted_cache.py --repo /path/to/repo --interactive

# Non-interactive switch (updates .mvn/settings.xml, .mvn/maven.config, uv.toml, .env)
python3 scripts/configure_trusted_cache.py --repo /path/to/repo --url https://oss.yourdomain.com

# Also set the GitHub Actions variable TRUSTED_OSS_CACHE_URL on the remote repo
python3 scripts/configure_trusted_cache.py --repo /path/to/repo --github-repo owner/repo --url https://oss.yourdomain.com

# Revert back to public upstream repositories
python3 scripts/configure_trusted_cache.py --repo /path/to/repo --public
```

### 4.1 Java / Maven Projects

1. Copy [`client-templates/maven-settings.xml`](../client-templates/maven-settings.xml) to `~/.m2/settings.xml` and set `HARBOR_DOMAIN` (or point `<url>` to `http://oss.jsigroup.local:8080/maven/virtual` for pull-through or `/maven/trusted` for pre-approved artifacts only).
2. *(Optional strict signature enforcement)* Add [`client-templates/pgpverify-plugin-snippet.xml`](../client-templates/pgpverify-plugin-snippet.xml) to your project's `pom.xml` under `<build><plugins>` so Maven fails the build if any dependency lacks a valid `.asc` signature from `/keys/trusted-oss-pubkey.asc`.

### 4.2 Python Projects (`uv` and `pip`)

Drop [`client-templates/uv.toml`](../client-templates/uv.toml) into your project root (or `~/.config/uv/uv.toml`):

```toml
index-url = "http://oss.jsigroup.local:8080/pypi/virtual/simple"
no-build = true
```

For `pip`, export:

```bash
export PIP_INDEX_URL="http://oss.jsigroup.local:8080/pypi/virtual/simple"
```

Use `/pypi/trusted/simple` instead of `/pypi/virtual/simple` in production CI if you only want pre-warmed, already-signed wheels.

### 4.3 Post-Quantum (ML-DSA-65) Client Verification

Verify any downloaded artifact against its `.mldsa65` signature using [`client-templates/pqc-verify.py`](../client-templates/pqc-verify.py):

```bash
curl -fsSLO http://oss.jsigroup.local:8080/keys/trusted-oss-mldsa65.pub
python3 client-templates/pqc-verify.py \
  --pubkey trusted-oss-mldsa65.pub \
  --artifact my-package.whl \
  --sig my-package.whl.mldsa65
```

### 4.4 Container Builds (Chainguard Zero-CVE Base Images)

Point Dockerfiles to the Harbor Chainguard proxy cache (see [`containers/chainguard-jre-python/Dockerfile`](../containers/chainguard-jre-python/Dockerfile)):

```dockerfile
FROM ${HARBOR_REGISTRY}/chainguard-cache/chainguard/jre:latest
```

### 4.5 Setting Up a GitHub Repository for the Local Trusted Container Cache

Repositories remain **public-by-default** (Maven Central, PyPI, `cgr.dev`) until you opt a repository in with `TRUSTED_OSS_CACHE_URL`. Follow these steps to connect any GitHub repository to your local TrueNAS `trusted-oss-gatekeeper` container behind pfSense:

1. **Ensure pfSense Edge & mTLS PKI Are Ready**:
   - Complete [`docs/pfsense-haproxy-mtls-guide.md`](pfsense-haproxy-mtls-guide.md) so pfSense WAN `:443` accepts GitHub Actions CIDRs with mTLS (`Trusted-OSS-GitHub-Client-CA`) and forwards to `<TRUENAS_LAN_IP>:8080`.
   - Locate `./mtls-pki/client.crt` and `./mtls-pki/client.key` generated by `./scripts/generate_mtls_keys.sh`.

2. **Add mTLS Client Secrets to the GitHub Repository (or Organization)**:
   ```bash
   gh secret set OSS_MTLS_CLIENT_CERT -R owner/repo < mtls-pki/client.crt
   gh secret set OSS_MTLS_CLIENT_KEY  -R owner/repo < mtls-pki/client.key
   ```
   *(In GitHub WebUI: **Settings → Secrets and variables → Actions → Secrets → New repository secret**.)*

3. **Opt the Repository In via `TRUSTED_OSS_CACHE_URL`**:
   ```bash
   # Enable trusted cache routing for this repo (use --mode virtual or trusted)
   gh variable set TRUSTED_OSS_CACHE_URL -R owner/repo --body "https://oss.yourdomain.com"
   gh variable set TRUSTED_OSS_MODE      -R owner/repo --body "virtual"

   # Or configure both local files (.mvn/settings.xml, uv.toml, .env) and GitHub variable together:
   python3 scripts/configure_trusted_cache.py \
     --repo /path/to/repo \
     --github-repo owner/repo \
     --url https://oss.yourdomain.com
   ```
   *(To revert a repository back to public upstream registries, delete `TRUSTED_OSS_CACHE_URL` or run `configure_trusted_cache.py --public`.)*

4. **Add the Trusted OSS Step to `.github/workflows/*.yml`**:
   - Copy [`client-templates/github-actions-trusted-oss.yml`](../client-templates/github-actions-trusted-oss.yml) into your workflow before `mvn`, `pip`, or `uv` commands (and include [`client-templates/maven-settings.xml`](../client-templates/maven-settings.xml) if building Maven projects).
   - When `vars.TRUSTED_OSS_CACHE_URL` is **unset**, the step exits `0` and uses public upstream registries.
   - When `vars.TRUSTED_OSS_CACHE_URL` is **set**, the step writes `~/.oss-tls/client.{crt,key,p12}`, imports `/keys/trusted-oss-pubkey.asc`, exports `MAVEN_OPTS`, `PIP_INDEX_URL`, and `UV_INDEX_URL`, and generates `~/.m2/settings.xml`.

5. **Verify End-to-End Connectivity**:
   - Run [`.github/workflows/probe-wan-connectivity.yml`](../.github/workflows/probe-wan-connectivity.yml) (`gh workflow run probe-wan-connectivity.yml`) and confirm `/healthz` returns `HTTP/2 200` with mTLS while unauthenticated requests without a client certificate are rejected.

6. **Signed Upstream SBOM/CBOM Attestations & Backfill (`v1.6.0+`)**:
   - Every newly promoted Maven, PyPI, or OCI artifact automatically generates dual-signed CycloneDX 1.6 `.sbom.cdx.json` and `.cbom.cdx.json` sidecars (`.asc` + `.mldsa65`), including explicit `VERIFIED_INERT` attestations when zero cryptographic primitives are present.
   - To backfill signed SBOM/CBOM sidecars for artifacts cached prior to `v1.6.0`:
     ```bash
     curl -fsSL -X POST \
       -H "X-Gatekeeper-Token: ${GATEKEEPER_ADMIN_TOKEN}" \
       "http://oss.jsigroup.local:8080/catalog/backfill-boms?wait=true"
     ```
   - Downstream `jsoehner/jsi-bom-actions@v1.2.0` workflows query `POST /bom/batch` over mTLS (using `trusted-oss-url`, `trusted-oss-mtls-cert`, and `trusted-oss-mtls-key`) to eliminate third-party cryptographic blind spots.

### 4.6 Querying Signed SBOM/CBOM Components with ORAS & Automated CI Health Gate

Developers and pipeline owners can query `trusted-oss-harbor` directly to verify that a requested container image or package (1) carries **cryptographically signed CycloneDX 1.6 SBOM and CBOM attestations** and (2) holds a **verified `CLEAN` health record** (ClamAV malware scan + OSV/Trivy CVE gate below `CVSS_FAIL_THRESHOLD`) before pulling it into a build or deployment.

#### 1. Developer CLI — Discover & Pull Attached SBOM/CBOM with ORAS (OCI 1.1 Referrers)

Every cached OCI manifest exposes attached CycloneDX 1.6 SBOM and CBOM descriptors via the **OCI Distribution Spec v1.1 Referrers API** (`GET /v2/{namespace}/{repo}/referrers/{digest}` and `/blobs/{digest}`):

```bash
# 1. Discover attached CycloneDX 1.6 SBOM & CBOM referrers (LAN HTTP example; omit --plain-http over HTTPS)
oras discover --plain-http \
  --artifact-type application/vnd.cyclonedx+json \
  --format tree \
  oss.jsigroup.local:8080/chainguard-cache/chainguard/jre:latest

# 2. Emit machine-readable JSON to extract the CBOM / SBOM blob digests
oras discover --plain-http \
  --artifact-type application/vnd.cyclonedx+json \
  --format json \
  oss.jsigroup.local:8080/chainguard-cache/chainguard/jre:latest

# 3. Pull an attached CycloneDX CBOM or SBOM blob by digest
oras blob fetch --plain-http --output cbom.cdx.json \
  oss.jsigroup.local:8080/chainguard-cache/chainguard/jre@sha256:<cbom_digest>
```

> [!TIP]
> Over WAN behind pfSense HAProxy mTLS (`https://oss.yourdomain.com`), pass your client certificate and key directly with `curl --cert ~/.oss-tls/client.crt --key ~/.oss-tls/client.key` to `GET /v2/{namespace}/{repo}/referrers/{digest}?artifactType=application/vnd.cyclonedx%2Bjson`.

#### 2. Verify Detached Signatures (GPG + ML-DSA-65) & Health Record (Any Ecosystem: OCI, Maven, PyPI)

Use `/bom/lookup` (single component) or `/bom/batch` (multi-PURL) to retrieve the CycloneDX 1.6 SBOM/CBOM with detached **RSA-3072 GPG (`.asc`)** and **NIST FIPS 204 ML-DSA-65 (`.mldsa65`)** signatures, and query `/catalog/vulnerabilities?verify_signatures=true` for the live health record:

```bash
# 1. Fetch signed CycloneDX 1.6 CBOM (with detached .asc & .mldsa65 signatures)
curl -fsSL "http://oss.jsigroup.local:8080/bom/lookup?purl=pkg:oci/chainguard/jre@latest&bom_type=cbom&include_signatures=true" | jq '{
  purl,
  artifact_sha256,
  has_gpg_sig: (.signature_gpg | length > 0),
  has_pqc_sig: (.signature_mldsa65 | length > 0),
  crypto_status: (.cbom.metadata.component.properties[] | select(.name=="trusted-oss:crypto-scan-status") | .value)
}'

# 2. Query the component's live health record (signatures, ClamAV, CVE/CVSS, quarantine state)
curl -fsSL "http://oss.jsigroup.local:8080/catalog/vulnerabilities?ecosystem=oci&components=chainguard/jre&verify_signatures=true" | jq '.components[0] | {
  component, version, signature_valid, pqc_signed, clamav_status, vulnerability_status, max_cvss, cve_ids
}'
```

A component is **approved for use** only when all four checks pass:
1. **ORAS / BOM Presence**: Both CycloneDX 1.6 **SBOM** and **CBOM** exist (with `CRYPTO_ASSETS_DETECTED` or `VERIFIED_INERT` status).
2. **Cryptographic Signature**: Detached **GPG (`.asc`)** verifies against `/keys/trusted-oss-pubkey.asc` and **ML-DSA-65 (`.mldsa65`)** is present and verifiable via `client-templates/pqc-verify.py`.
3. **Malware & CVE Health Record**: `clamav_status == "CLEAN"`, `vulnerability_status == "CLEAN"`, and `max_cvss < 7.0`.
4. **Zero Active Quarantine**: Component is not listed under `quarantined_components`.

#### 3. Automated GitHub Action Decision Gate (`client-templates/github-actions-verify-component.yml`)

Pipeline owners can drop in the reusable workflow template [`client-templates/github-actions-verify-component.yml`](../client-templates/github-actions-verify-component.yml) to automatically decide whether a requested component is signed, carries verified CycloneDX SBOM/CBOM attestations (discovered via ORAS for OCI), and has a `CLEAN` health record before allowing downstream build/deploy jobs to proceed:

```yaml
jobs:
  verify-base-image:
    uses: jsoehner/trusted-oss-harbor/client-templates/github-actions-verify-component.yml@main
    with:
      ecosystem: oci
      component_name: chainguard/jre
      component_ref: chainguard-cache/chainguard/jre:latest
      purl: pkg:oci/chainguard/jre@latest
      require_pqc: true
      max_cvss: "7.0"
    secrets:
      OSS_MTLS_CLIENT_CERT: ${{ secrets.OSS_MTLS_CLIENT_CERT }}
      OSS_MTLS_CLIENT_KEY: ${{ secrets.OSS_MTLS_CLIENT_KEY }}

  build-and-deploy:
    needs: verify-base-image
    if: ${{ needs.verify-base-image.outputs.approved == 'true' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building with verified digest ${{ needs.verify-base-image.outputs.artifact_sha256 }}"
```

The action fails closed (exits non-zero) if any signature, SBOM/CBOM referrer, malware check, or CVE threshold fails, and publishes a Markdown **Trusted OSS Component Verification Decision** table directly to `$GITHUB_STEP_SUMMARY`.

---

## 5. Troubleshooting HTTP 451 & Debugging Component Lifecycle

### 5.1 Why Automation Loops on HTTP `451` (and How to Stop Wasting Retries/Tokens)

`HTTP 451 Unavailable For Legal Reasons` (RFC 7725) is **never a transient network error**. In `trusted-oss-harbor`, `451` means Gatekeeper **intentionally blocked** the requested version because it failed a supply-chain policy gate (ClamAV malware detection, Zip-Slip/encrypted archive violation, or a High/Critical vulnerability with `CVSS >= 7.0`).

Because package managers (`mvn`, `pip`, `uv`) and AI/CI upgrade bots often treat non-200 HTTP responses as retryable failures, they can burn retries, build minutes, and LLM tokens repeatedly requesting the same quarantined version. **Before letting automation retry**, a human (or pre-flight gate) should inspect the component's lifecycle in the registry to see:
1. **How many versions are cached locally**
2. **Which versions are clean and releasable** (`SERVING_LATEST` / `CACHED`)
3. **Which versions are blocked/quarantined** (`QUARANTINED`, with exact CVE IDs, CVSS score, and clean replacement)

### 5.2 Human-Readable Endpoints (Gatekeeper vs. Underlying Harbor)

| Tool / Layer | Human-Readable Path / Command | Ecosystems Covered | What It Shows |
| :--- | :--- | :--- | :--- |
| **Gatekeeper Security Advisory Dashboard** | `http://oss.jsigroup.local:8080/catalog/advisories/dashboard` | **OCI, Maven, PyPI** | Zero-JS, CSP-safe HTML Security Advisory Center showing `CRITICAL`/`HIGH` badges, OSV/NVD links, and clean `UPGRADE_TO` versions |
| **Gatekeeper Advisories RSS 2.0 Feed** | `http://oss.jsigroup.local:8080/catalog/advisories.rss` | **OCI, Maven, PyPI** | Subscribable RSS 2.0 feed for Slack, Teams, or feed readers (supports `?ecosystem=`, `?component=`, `?min_cvss=`) |
| **Gatekeeper Interactive Web UI (Swagger)** | `http://oss.jsigroup.local:8080/docs` | **OCI, Maven, PyPI** | Browser UI to query `/catalog/vulnerabilities`, `/catalog/advisories`, `/catalog/retention`, `/audit/activity`, and `/bom/lookup` without writing `curl` commands |
| **Gatekeeper CLI Table Viewer** | `python3 scripts/catalog_frontend.py --url http://oss.jsigroup.local:8080 --components <name>` | **OCI, Maven, PyPI** | Formatted ASCII tables: **Cached (Releasable)**, **Quarantined (Blocked)**, and **Component Caching History (`SERVING_LATEST` / `CACHED` / `QUARANTINED` / `HISTORICAL`)** |
| **Gatekeeper Lifecycle JSON API** | `GET /catalog/vulnerabilities?ecosystem=<eco>&components=<name>` | **OCI, Maven, PyPI** | `summary` counts, `components` (releasable), `quarantined` (blocked + CVEs + replacement), and `history` (full version lifecycle) |
| **Gatekeeper Retention & TTL API** | `GET /catalog/retention` | **OCI, Maven, PyPI** | Every cached version's inactivity age and 90-day TTL runway (`active`, `expiring_soon`, `expired`) |
| **Gatekeeper Activity Audit Log** | `GET /audit/activity?limit=50` | **OCI, Maven, PyPI** | Recent `BLOCKED`, `QUARANTINED`, `ARTIFACT_REQUESTED`, and `HOURLY_CVE_RESCAN` events |
| **Harbor Web Portal** *(when full Harbor is deployed)* | `https://<harbor-host>/harbor/projects` | **OCI / Helm / ORAS only** | Browser UI showing container tags, Trivy CVE summaries, signatures, and OCI 1.1 Referrer accessories |
| **Harbor API Explorer / REST v2.0** *(full Harbor)* | `https://<harbor-host>/devcenter-api-2.0` & `GET /api/v2.0/projects/chainguard-cache/repositories/{repo}/artifacts?with_scan_overview=true&with_signature=true&with_accessory=true` | **OCI / Helm / ORAS only** | Per-digest Trivy scan overview, signature status, and attached SBOM/CBOM accessories |

> [!NOTE]
> Underlying **CNCF Harbor** only tracks OCI container/Helm/ORAS artifacts. **Gatekeeper's `/docs`, `/catalog/vulnerabilities`, and `scripts/catalog_frontend.py`** are the unified human-readable interface covering **Maven, PyPI, and OCI** together, including quarantine status and clean replacements.

### 5.3 Step-by-Step Human Debugging Playbook

#### Step 1 — Inspect the Component's Full Lifecycle Table (Recommended First Step)

Run `scripts/catalog_frontend.py` filtered to the component that returned `451` (for example, `requests` or `spring-boot-starter-web`):

```bash
GATEKEEPER_ADMIN_TOKEN="<token>" \
  python3 scripts/catalog_frontend.py \
  --url http://oss.jsigroup.local:8080 \
  --ecosystem pypi \
  --components requests
```

This prints three human-readable tables:
1. **Cached Components (Releasable)** — Every version currently in `/data/packages/trusted-*` that **can be downloaded**, with signature status, ClamAV status, CVSS, and tags (`latest`).
2. **Quarantined (Vulnerable / Blocked)** — Every version that **cannot be downloaded** (`HTTP 451`), showing `MAX_CVSS`, `FAILING_CVES`, and `LATEST_REPLACEMENT`.
3. **Component Caching History** — The complete version timeline showing `SERVING_LATEST`, `CACHED`, `QUARANTINED`, and `HISTORICAL` states.

#### Step 2 — Query Counts, Releasable Versions & Blocked Versions via `curl` + `jq`

If you only have `curl` and `jq` (or want to inspect over WAN mTLS using `--cert ~/.oss-tls/client.crt --key ~/.oss-tls/client.key`):

```bash
curl -fsSL "http://oss.jsigroup.local:8080/catalog/vulnerabilities?ecosystem=pypi&components=requests" | jq '{
  cvss_threshold: .cvss_fail_threshold,
  cached_locally_count: .summary.total,
  clean_releasable_count: .summary.clean,
  quarantined_blocked_count: .summary.quarantined,
  recommended_latest: (.history[0].serving_latest_version // "none"),
  releasable_versions: [.components[] | select(.vulnerability_status == "CLEAN") | {version, tags, max_cvss}],
  blocked_quarantined_versions: [.quarantined[] | {version, max_cvss, cve_ids, latest_replacement}],
  full_lifecycle: (.history[0].versions // [])
}'
```

#### Step 3 — Check Why a Pull-Through Request Was Blocked in Real Time

Inspect the recent activity log to see the exact block reason (e.g., `CVSS >= 7.0`, ClamAV signature, or archive guard) for an uncached version that never made it into the trusted store:

```bash
curl -fsSL "http://oss.jsigroup.local:8080/audit/activity?limit=25" | jq '.events[] | select(.event | test("BLOCKED|QUARANTINED")) | {timestamp, event, ecosystem, component, version, details}'
```

#### Step 4 — Resolve the Block & Prevent Future Retry Loops

1. **Pin to a Releasable Version**: Update the project's dependency (`pom.xml`, `pyproject.toml`, `Dockerfile`) to `recommended_latest` (a version listed under `releasable_versions` with `SERVING_LATEST` or `CLEAN`).
2. **Trigger Auto-Remediation if No Clean Version Is Cached Yet**:
   ```bash
   GATEKEEPER_ADMIN_TOKEN="<token>" \
     python3 scripts/catalog_frontend.py \
     --url http://oss.jsigroup.local:8080 \
     --ecosystem pypi --components requests --remediate --wait
   ```
   This instructs `oss-engine` to find the newest clean upstream version below `CVSS_FAIL_THRESHOLD`, scan & dual-sign it, and tag it `latest`.
3. **Gate Automation Up Front**: Wire [`client-templates/github-actions-verify-component.yml`](../client-templates/github-actions-verify-component.yml) into CI/CD pipelines so jobs check `/catalog/vulnerabilities` and fail fast with a clear `$GITHUB_STEP_SUMMARY` instead of retrying `451` downloads.

---

### 5.4 Proactive Vulnerability Advisories, RSS Subscriptions & Real-Time Alerts ([SecADR-0011](adr/0011-security-assessment-remediation-and-governance.md))

Rather than waiting for a developer build to fail with `HTTP 451`, operators and engineering teams can monitor newly vulnerable cached components and their verified clean upgrade targets through four channels:

#### 1. Browser Security Advisory Center (Zero-JS HTML Dashboard)
Open `http://oss.jsigroup.local:8080/catalog/advisories/dashboard` (or `https://oss.yourdomain.com/catalog/advisories/dashboard` over WAN mTLS).
- Renders a self-contained, CSP-safe (`script-src 'none'`) HTML dashboard with KPI summary cards (`Total`, `Clean`, `Quarantined`, `Unscanned`), severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), clickable **OSV.dev / NVD** links, and the **newest `CLEAN` cached version** available for upgrade.
- Supports query-string filters directly in the URL:
  - `?ecosystem=maven` (or `pypi`, `oci`)
  - `?component=spring` (substring match)
  - `?min_cvss=7.0`
  - `?since_hours=24`

#### 2. Subscribable RSS 2.0 Feed (Slack / Microsoft Teams / RSS Readers)
Subscribe to `http://oss.jsigroup.local:8080/catalog/advisories.rss` (supports the same `?ecosystem=`, `?component=`, `?min_cvss=`, and `?since_hours=` filters):
- **Slack**: `/feed subscribe http://oss.jsigroup.local:8080/catalog/advisories.rss?min_cvss=7.0`
- **Microsoft Teams**: Add the **RSS** connector to a Security/Platform channel and point it to `/catalog/advisories.rss`.
- Nginx forwards `Host: $http_host` and `X-Forwarded-Proto` on `/catalog/` so `<link>` URLs inside the RSS feed preserve `:8080` on LAN and stay portless over WAN HTTPS `:443`.

#### 3. Operator CLI & Filterable JSON API
```bash
# Formatted ASCII table of all active advisories, CVE IDs, UPGRADE_TO versions, and OSV links
python3 scripts/catalog_frontend.py \
  --url http://oss.jsigroup.local:8080 \
  --advisories

# Filter to Maven High/Critical advisories only
python3 scripts/catalog_frontend.py \
  --url http://oss.jsigroup.local:8080 \
  --ecosystem maven \
  --advisories

# Filterable JSON API (e.g., Critical/High advisories discovered in the last 24h)
curl -fsSL "http://oss.jsigroup.local:8080/catalog/advisories?min_cvss=7.0&since_hours=24" | jq '{
  count,
  summary,
  advisories: [.advisories[] | {id, severity, max_cvss, cve_ids, superseded_by, guidance}]
}'
```

#### 4. Real-Time Webhook Alerts, Immediate Email & Enriched Daily Digest
Configure real-time push alerts in `.env`, `docker-compose.yml`, or TrueNAS container environment variables:

```dotenv
# Optional Slack / Teams / Generic JSON webhook endpoint (must be http:// or https://)
VULN_ALERT_WEBHOOK_URL=https://hooks.example.com/services/T000/B000/XXXX
# Optional HMAC-SHA256 signing secret (sends X-Trusted-OSS-Signature: sha256=<hex>)
VULN_ALERT_WEBHOOK_SECRET=replace-with-random-32-byte-secret
# Optional: also send an immediate Microsoft Graph HTML email on newly quarantined CVEs
VULN_ALERT_IMMEDIATE_EMAIL=false
```

- **Deduplication**: Sent alerts are tracked in `/data/audit/vuln_alerts.jsonl` (keyed by ecosystem, component, version, and CVE set) so repeated hourly scans do not spam channels.
- **Webhook Signature Verification**: When `VULN_ALERT_WEBHOOK_SECRET` is set, receivers can verify authenticity by computing `HMAC-SHA256(secret, raw_request_body)` and comparing it in constant time against the `X-Trusted-OSS-Signature` header (`sha256=<hexdigest>`).
- **Daily Digest Upgrade Paths**: Both plain-text and HTML Daily Digests (`scripts/daily_digest.py` and the in-container `oss-engine` digest loop) automatically pair every vulnerable/quarantined version with clickable OSV links and the **newest `CLEAN` (passing-scan) version** available for upgrade.

---

## 6. Security Controls, Operational Limits & Hardening Reference ([SecADR-0011](adr/0011-security-assessment-remediation-and-governance.md))

Starting with `v1.6.x` (see [SECURITY_POSTURE.md](../SECURITY_POSTURE.md) and [SecADR-0011](adr/0011-security-assessment-remediation-and-governance.md)), Gatekeeper and the Nginx gateway enforce strict fail-closed bounds. Operators should be aware of these defaults and how to tune them when legitimate exceptions arise:

| Control / Setting | Default | Behavior When Triggered | How to Tune / Operate |
| :--- | :--- | :--- | :--- |
| **`MAX_ARTIFACT_BYTES`** | `262144000` (250 MB) | Streaming upload/pull-through aborts with `HTTP 413 Payload Too Large` (Nginx cap: `260M`) | Raise `MAX_ARTIFACT_BYTES` in `.env` and `client_max_body_size` in Nginx if caching large ML wheels/JARs |
| **Archive Bomb Guard** | `10,000` members / `512 MB` uncompressed | Blocks oversized ZIP/TAR archives, symlinks, encrypted entries, and Windows backslash/drive-letter Zip-Slip paths | Hardcoded defense-in-depth in `gatekeeper/app/scanner.py` |
| **`POST /bom/batch` Limits** | Max `500` PURLs; `trigger_pull_on_miss` admin-gated | `>500` PURLs returns `HTTP 400`; `trigger_pull_on_miss=true` without `X-Gatekeeper-Token` returns `HTTP 403` | Chunk large BOM manifests into batches of `<= 500` PURLs; pass `X-Gatekeeper-Token` only for CI warmups |
| **Admin-Gated Endpoints** | `X-Gatekeeper-Token` required | `GET /jobs`, `GET /jobs/{id}`, `GET /status/{job_id}`, `POST /catalog/remediate`, `POST /catalog/warm`, `POST /catalog/gc`, `POST /catalog/backfill-boms`, `POST /ingest/*` return `HTTP 403` without a valid token | Set a strong random `GATEKEEPER_ADMIN_TOKEN` (default placeholder tokens are rejected on startup) |
| **`TRUSTED_SOURCES` SSRF Allowlist** | Approved upstream registries | Dynamic OCI warmup (`POST /catalog/warm`) skips untrusted `Dockerfile` registries | Add private/approved upstream registries explicitly via `TRUSTED_SOURCES` in `.env` |
| **`TRIVY_REQUIRED`** | `false` | When `true`, Gatekeeper fails closed if `trivy` is unavailable or errors during scanning | Set `TRIVY_REQUIRED=true` in strict high-assurance environments |
| **Paginated Provenance Log** | `offset=0`, `limit=100` (max `1000`) | `GET /audit/provenance?offset=0&limit=100` returns `{count, total, offset, limit, records}` | Page through large provenance ledgers using `offset` & `limit` |
| **Persistent Provenance HMAC Key** | `/data/keys/provenance.hmac.key` (`0600`) | Every entry in `audit/provenance.jsonl` is signed with a persistent key (or `PROVENANCE_HMAC_KEY`) | Back up `/data/keys/` alongside GPG/ML-DSA keys to preserve long-term ledger verifiability |
| **CI Security Governance Gate** | `.github/workflows/security-governance.yml` | Runs Gitleaks, Bandit (`-ll`), Semgrep (`ERROR`), and `pip-audit` on every push/PR; Dependabot enforces a 7-day cooldown across `github-actions`, `pip`, and `docker` | Review findings in the GitHub **Security -> Code scanning** tab |



