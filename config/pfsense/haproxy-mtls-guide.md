# pfSense Edge Security Guide: HAProxy + ACME TLS + mTLS & GitHub Actions CIDR Allowlist

This guide configures your **pfSense** firewall to securely expose the **Trusted OSS Supply Chain Platform** (`Harbor` + `oss-gateway`) to your GitHub Actions runners without exposing unauthenticated endpoints to the public internet.

---

## 1. Automated GitHub Actions IP Firewall Alias (`github_actions_cidrs`)

1. Copy [`update-github-cidrs.sh`](update-github-cidrs.sh) to `/usr/local/bin/update-github-cidrs.sh` on your pfSense box (or serve the generated `/var/db/aliastables/github_actions_cidrs.txt` via a local URL Table Alias).
2. In pfSense WebGUI, navigate to **Firewall $\rightarrow$ Aliases $\rightarrow$ URLs**:
   - **Name**: `github_actions_cidrs`
   - **Type**: `URL Table (IPs)`
   - **Update Frequency**: `1` day
3. Create a **WAN Firewall Rule** permitting inbound TCP `:443` **only** from source `github_actions_cidrs` (plus your internal admin LAN/VPN subnets) to `WAN address`.

---

## 2. ACME Let's Encrypt Server Certificate & mTLS Client CA

1. **Server Certificate (`Services $\rightarrow$ ACME Certificates`)**:
   - Issue a Let's Encrypt certificate for `oss.<your-domain>` using DNS-01 validation (Cloudflare / Route53 / DigitalOcean).
2. **Client Certificate Authority (`System $\rightarrow$ Cert. Manager $\rightarrow$ CAs`)**:
   - Create an internal CA named `Trusted-OSS-GitHub-Client-CA`.
   - Issue a client certificate (`github-actions-runner-client`) signed by `Trusted-OSS-GitHub-Client-CA`.
   - Export the client certificate and key as Base64 PEM strings and store them in your GitHub organization/repository secrets (`OSS_MTLS_CLIENT_CERT`, `OSS_MTLS_CLIENT_KEY`).

---

## 3. HAProxy Frontend & Backend Configuration (`Services $\rightarrow$ HAProxy`)

### Backends
1. **`be_harbor_oci`**:
   - **Server**: `<LAN_HOST_IP>:8880` (Harbor HTTP port)
   - **Health Check**: HTTP `GET /api/v2.0/ping`
2. **`be_oss_gatekeeper`**:
   - **Server**: `<LAN_HOST_IP>:8080` (`oss-gateway` container port)
   - **Health Check**: HTTP `GET /healthz`

### Frontend (`fe_trusted_oss_https`)
- **Listen Address**: `WAN address:443` (`SSL Offloading` checked)
- **Server Certificate**: `oss.<your-domain>` (ACME)
- **Client Verification (mTLS)**:
  - Check **Verify Client Certificate**
  - **Client Verification CA**: `Trusted-OSS-GitHub-Client-CA`
- **Access Control Lists (ACLs)**:
  - `is_package_route`: `Path starts with:` `/maven/` OR `/pypi/` OR `/keys/` OR `/audit/` OR `/oci/` OR `/healthz`
- **Actions**:
  - `Use Backend` $\rightarrow$ `be_oss_gatekeeper` if `is_package_route`
  - **Default Backend**: `be_harbor_oci` (handles `/v2/`, `/api/`, `/service/`, `/c/`, and Harbor UI)
