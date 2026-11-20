# ADR 0009: Standardized HTML Email Notifications Across Operational Digests

- **Status:** Accepted
- **Date:** 2026-11-20
- **Supersedes / Extends:** Extends [ADR 0005](0005-daily-digest-oauth2-notifications.md)

## Context and Problem Statement

[ADR 0005](0005-daily-digest-oauth2-notifications.md) established reliable daily digest delivery over Microsoft Graph API (`HTTPS 443`) and SMTP STARTTLS (`587`) using plain-text bodies (`contentType: "Text"`). As operational alerts expanded across projects (including `jsoehner/rootCA` Phase 6 PKI monitoring and `jsoehner/trusted-oss-harbor` daily supply chain digests), plain-text emails became harder to scan quickly on desktop Outlook and mobile clients.

## Decision

Adopt the organizational **JSIGROUP Standardized HTML Notification Format** in `gatekeeper/app/notifications.py` and `scripts/daily_digest.py`:
1. **`render_daily_digest_html(...)`:** Generates an Outlook/M365/Gmail-compatible inline-CSS, table-layout HTML email featuring a dark-slate header (`#0f172a`), dynamic status badge (`ALL HEALTHY` / `ATTENTION`), KPI cards (`Total`, `Clean`, `Unscanned`, `Quarantined`), and structured zebra-striped tables for Cache Capacity Runway, Quarantined CVEs, and Recent Activity, with strict `html.escape()` sanitization.
2. **Transport Content-Type Handling:**
   - `send_graph_mail` supports `content_type="HTML"` for regular email recipients while keeping `content_type="Text"` for ≤160-char Email-to-SMS gateway recipients.
   - `send_smtp_starttls` accepts optional `html_body` and attaches `multipart/alternative` (`text/plain` + `text/html`) when present.
3. **Backwards Compatibility:** `build_daily_digest(...)` continues returning `(subject, body_text, sms_text)` so all existing callers and unit tests remain compatible.

## Consequences

- **Positive:** Immediate visual triage of status, KPIs, and quarantined CVEs across Outlook, Gmail, and mobile clients; consistent visual branding across `trusted-oss-harbor`, `rootCA`, and future projects.
- **Negative:** Slightly larger email payload (~5–8 KB HTML), mitigated by keeping SMS strictly ≤160-char plain text.
