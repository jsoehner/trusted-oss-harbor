# ADR 0007: pfSense GitHub-Only mTLS Ingress and Opt-In Per-Repo Cache Routing

- **Status:** Accepted
- **Date:** 2026-11-15
- **Version:** 1.4.0

## Context

1. The single-container TrueNAS appliance (`trusted-oss-gatekeeper` on `:8080`) serves Maven, PyPI, OCI (`/v2/`), signing keys (`/keys/`), and catalog endpoints behind a **pfSense** edge firewall. Only GitHub Actions runners should be permitted to reach the container over WAN, enforced by both source IP allowlisting and mutual TLS (mTLS).
2. When repositories are cloned or downloaded, builds should **default to public upstream repositories** (Maven Central, PyPI, `cgr.dev`) so they work out of the box with zero external infrastructure dependencies, while allowing users to switch all ecosystem configurations in a repository to their own Trusted OSS Cache using a single variable (`TRUSTED_OSS_CACHE_URL`) and setup script.

## Decision

1. **pfSense Two-Layer GitHub-Only Gate (`docs/pfsense-haproxy-mtls-guide.md`)**:
   - **Layer 1 (WAN Firewall)**: Permit TCP `:443` **only** from the `github_actions_cidrs` URL Table alias refreshed via `config/pfsense/update-github-cidrs.sh`.
   - **Layer 2 (HAProxy mTLS)**: Terminate ACME TLS on `WAN address:443`, require a valid client certificate signed by `Trusted-OSS-GitHub-Client-CA` (`has_client_cert`), and proxy `/maven/`, `/pypi/`, `/v2/`, `/keys/`, `/audit/`, `/catalog/`, and `/healthz` to `<TRUENAS_LAN_IP>:8080`.
2. **Public-by-Default, Single-Variable Opt-In (`scripts/configure_trusted_cache.py`)**:
   - Repositories default to public upstream registries when `TRUSTED_OSS_CACHE_URL` is unset.
   - `scripts/configure_trusted_cache.py` accepts `--url <TRUSTED_OSS_CACHE_URL>` (or `--interactive` / `--public`) and updates `.mvn/settings.xml`, `.mvn/maven.config`, `uv.toml`, `.env` (`TRUSTED_OSS_CACHE_URL`, `TRUSTED_OSS_MODE`, `PIP_INDEX_URL`, `UV_INDEX_URL`, `BASE_IMAGE`), and optionally the GitHub Actions repository variable `TRUSTED_OSS_CACHE_URL` via `gh variable set`.
   - `Dockerfile` parameterizes `ARG BASE_IMAGE=cgr.dev/chainguard/wolfi-base:latest` so builds default to public `cgr.dev` and can be redirected with one build-arg.
   - `client-templates/github-actions-trusted-oss.yml` activates mTLS and Maven/PyPI cache routing only when `vars.TRUSTED_OSS_CACHE_URL` (or legacy `vars.HARBOR_DOMAIN`) is set.

## Consequences

- Any freshly downloaded repository works immediately against public upstream OSS registries with no manual teardown.
- Switching a repository (locally or in GitHub Actions) to a self-hosted Trusted OSS Cache requires only setting `TRUSTED_OSS_CACHE_URL` or running `scripts/configure_trusted_cache.py`.
- WAN exposure is limited strictly to verified GitHub Actions CIDRs presenting a valid mTLS client certificate.
