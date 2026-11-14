# ADR 0005: Standalone and Engine-Scheduled Daily Digest Notifications via Microsoft Graph OAuth2

- **Status:** Accepted
- **Date:** 2026-11-14
- **Version:** 1.0.0

## Context and Problem Statement

Operators need a daily summary of cached component status, quarantined CVEs, and scheduled task events (`/audit/activity`) delivered via email and SMS. However:
1. Many residential and enterprise networks block outbound SMTP port `25` and lack a local mail relay.
2. Microsoft 365 and Outlook.com disable basic username/password SMTP AUTH (`5.7.139`) on accounts protected by Multi-Factor Authentication (MFA).

## Decision Drivers

1. **MFA Compatibility**: Authentication must work with MFA-enforced Microsoft 365 and personal Outlook accounts without relying on deprecated basic auth.
2. **Firewall Resilience**: Delivery must succeed over standard HTTPS port `443` when outbound ports `25` and `587` are blocked or restricted.
3. **Unattended Daily Execution**: Scheduled `cron` runs and the `oss-engine` Docker worker must authenticate non-interactively using a long-lived, rotating refresh token.
4. **Email & SMS Coverage**: Operators must receive both full-text email digests and ≤160-character SMS summaries (via carrier Email-to-SMS gateways or Twilio).

## Decision

We implement outbound notification delivery in `gatekeeper/app/notifications.py`, exposed both as a standalone CLI (`scripts/daily_digest.py`) and as an optional background loop inside `oss-engine` (`gatekeeper/app/worker.py`):

1. **Primary Transport — Microsoft Graph OAuth2 Device Code + Refresh Token (`HTTPS 443`)**:
   - `scripts/daily_digest.py --graph-auth` performs a one-time interactive OAuth2 Device Code login (`offline_access` + `https://graph.microsoft.com/Mail.Send`), storing the refresh token in a `0600` JSON cache (`~/.config/trusted-oss-harbor/msgraph_token.json` on host, or `/data/trusted-oss/audit/msgraph_token.json` in Docker).
   - `resolve_msgraph_access_token` exchanges the refresh token for a fresh access token on each run and persists any rotated refresh token back to the cache.
   - `send_graph_mail` posts to `https://graph.microsoft.com/v1.0/me/sendMail` for both email (`--to` / `DIGEST_TO`) and carrier Email-to-SMS (`--sms-to` / `DIGEST_SMS_TO`, e.g., `@vtext.com`).
2. **Secondary Transports**:
   - **SMTP `STARTTLS` (`587`)**: `send_smtp_starttls` remains available for non-MFA SMTP submission servers.
   - **Twilio SMS (`HTTPS 443`)**: `send_twilio_sms` supports direct E.164 SMS delivery.
3. **Docker `oss-engine` Integration**:
   - `docker-compose.yml` passes `DIGEST_ENABLED`, `DIGEST_INTERVAL_SECONDS`, `DIGEST_TO`, `DIGEST_SMS_TO`, `GRAPH_CLIENT_ID`, `GRAPH_TENANT_ID`, `GRAPH_REFRESH_TOKEN`, `GRAPH_ACCESS_TOKEN`, and `GRAPH_TOKEN_FILE` to `oss-engine`.
   - When `DIGEST_ENABLED=true`, `_daily_digest_loop` tracks `/data/trusted-oss/audit/last_digest_sent.txt` so container restarts do not duplicate daily digests.

## Consequences

- **Positive**: Works reliably behind restrictive firewalls (HTTPS `443` only) and with MFA-protected Microsoft 365 / Outlook accounts; refresh tokens self-rotate on daily runs.
- **Negative**: Requires a one-time Entra ID App Registration (`Mail.Send`, `offline_access`, public client flows enabled) and `--graph-auth` login; if no digest runs for >90 days, the refresh token expires and `--graph-auth` must be re-run.
- **Verification**: Covered by `test_daily_digest_formatting_and_smtp_starttls` and `test_msgraph_refresh_token_rotation_and_mail_send` in `gatekeeper/tests/test_virtual_and_warmup.py`.
