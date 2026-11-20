"""Standalone daily digest builder and outbound email/SMS notification senders.

Supports Outlook / Microsoft 365 authenticated SMTP submission (port 587 STARTTLS,
bypassing blocked port 25), Microsoft Graph API (HTTPS 443), Twilio SMS (HTTPS 443),
and carrier Email-to-SMS gateways.
"""

from __future__ import annotations

import asyncio
import datetime
import html
import json
import logging
import os
import smtplib
import ssl
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx

GRAPH_DEFAULT_SCOPES = "offline_access https://graph.microsoft.com/Mail.Send"
DEFAULT_TOKEN_CACHE_PATH = (
    Path.home() / ".config" / "trusted-oss-harbor" / "msgraph_token.json"
)


def _fmt_bytes(num: int | float) -> str:
    val = float(max(0, num))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0 or unit == "TB":
            return f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} TB"


def build_daily_digest(
    *,
    health: dict[str, Any],
    vuln_data: dict[str, Any],
    activity_events: list[dict[str, Any]],
    retention_data: dict[str, Any] | None = None,
    hours: int = 24,
) -> tuple[str, str, str]:
    """Build (subject, body_text, sms_text) for the daily supply chain summary."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(hours=max(1, hours))

    recent_events: list[dict[str, Any]] = []
    for ev in activity_events:
        ts_raw = str(ev.get("timestamp", ""))
        try:
            ts = datetime.datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            if ts >= cutoff:
                recent_events.append(ev)
        except ValueError:
            recent_events.append(ev)

    summary = vuln_data.get("summary") or {}
    quarantined = vuln_data.get("quarantined") or []
    total = int(summary.get("total", 0))
    clean = int(summary.get("clean", 0))
    unscanned = int(summary.get("unscanned", 0))
    q_count = int(summary.get("quarantined", len(quarantined)))
    threshold = health.get("cvss_fail_threshold", 7.0)

    event_counts: dict[str, int] = {}
    for ev in recent_events:
        name = str(ev.get("event", "UNKNOWN"))
        event_counts[name] = event_counts.get(name, 0) + 1

    requested_events = [
        ev for ev in recent_events if str(ev.get("event", "")) == "ARTIFACT_REQUESTED"
    ]
    req_hits = sum(1 for ev in requested_events if "cache=HIT" in str(ev.get("details", "")))
    req_misses = len(requested_events) - req_hits
    new_artifact_events = [
        ev for ev in recent_events if str(ev.get("event", "")) == "NEW_ARTIFACT_ADDED"
    ]
    new_version_events = [
        ev for ev in recent_events if str(ev.get("event", "")) == "NEW_VERSION_ADDED"
    ]

    date_str = now.strftime("%Y-%m-%d")
    subject = (
        f"[Trusted-OSS] Daily Digest {date_str}: "
        f"CLEAN={clean} UNSCANNED={unscanned} QUARANTINED={q_count} "
        f"REQ={len(requested_events)} NEW={len(new_artifact_events)} NEW_VER={len(new_version_events)}"
    )

    lines = [
        f"Trusted OSS Supply Chain — Daily Digest ({now.strftime('%Y-%m-%d %H:%M UTC')})",
        f"Status: {health.get('status', 'unknown')} | Role: {health.get('role', 'all')} | CVSS Threshold: >= {threshold}",
        "",
        f"Cached Components : Total={total} | CLEAN={clean} | UNSCANNED={unscanned} | QUARANTINED={q_count}",
        (
            f"Artifact Activity (last {hours}h): "
            f"Requested={len(requested_events)} (hits={req_hits}, misses={req_misses}) | "
            f"New Artifacts={len(new_artifact_events)} | New Versions={len(new_version_events)}"
        ),
        f"Events (last {hours}h) : {len(recent_events)}",
    ]
    if event_counts:
        lines.append("Event Breakdown   : " + ", ".join(f"{k}={v}" for k, v in sorted(event_counts.items())))

    if new_artifact_events or new_version_events:
        lines.append("")
        lines.append(f"New Artifacts & Versions Added (last {hours}h):")
        for ev in new_artifact_events[:10]:
            lines.append(
                f"  - [NEW ARTIFACT] {ev.get('ecosystem')}:{ev.get('component')}@{ev.get('version')}"
            )
        for ev in new_version_events[:10]:
            lines.append(
                f"  - [NEW VERSION]  {ev.get('ecosystem')}:{ev.get('component')}@{ev.get('version')}"
            )

    if retention_data:
        ttl_days = int(retention_data.get("max_unused_days", 90))
        disk_used = int(retention_data.get("disk_used_bytes", 0))
        disk_total = int(retention_data.get("disk_total_bytes", 0))
        disk_free = int(retention_data.get("disk_free_bytes", 0))
        disk_pct = float(retention_data.get("disk_used_pct", 0.0))
        cache_bytes = int(retention_data.get("cache_bytes", 0))
        daily_growth = int(retention_data.get("daily_growth_bytes", 0))
        est_days = retention_data.get("estimated_days_remaining")
        runway_str = (
            f"~{est_days} days at {_fmt_bytes(daily_growth)}/day"
            if est_days is not None
            else "steady (0 B/day net growth)"
        )
        lines.append("")
        lines.append("Cache Capacity & Runway:")
        lines.append(
            f"  - Retention Policy : Keep clean until vulnerable or >{ttl_days}d unused"
        )
        lines.append(
            f"  - Disk Usage       : {_fmt_bytes(disk_used)} / {_fmt_bytes(disk_total)} ({disk_pct:.1f}% used, {_fmt_bytes(disk_free)} free)"
        )
        lines.append(
            f"  - Trusted Cache    : {_fmt_bytes(cache_bytes)} | Estimated Runway: {runway_str}"
        )

    replaced_events = [
        ev
        for ev in recent_events
        if str(ev.get("event", "")) in {"QUARANTINED", "LATEST_TAG_UPDATED", "AUTO_REMEDIATE", "COMPONENT_REPLACED"}
    ]
    if replaced_events:
        lines.append("")
        lines.append(f"Replaced / Upgraded Vulnerable Components (last {hours}h):")
        for ev in replaced_events[:15]:
            lines.append(
                f"  - {ev.get('ecosystem')}:{ev.get('component')}@{ev.get('version')} "
                f"[{ev.get('event')}] {ev.get('details') or ''}"
            )

    unused_removed = [
        ev
        for ev in recent_events
        if str(ev.get("event", "")) in {"GC_UNUSED_REMOVED", "GC_REMOVED"}
    ]
    expiring_soon = (retention_data or {}).get("expiring_soon") or []
    expired_pending = (retention_data or {}).get("expired") or []
    if unused_removed or expiring_soon or expired_pending:
        lines.append("")
        lines.append("90-Day Inactivity Space Recovery:")
        for ev in unused_removed[:15]:
            lines.append(
                f"  - [REMOVED] {ev.get('ecosystem')}:{ev.get('component')}@{ev.get('version')} ({ev.get('details') or ''})"
            )
        for item in expired_pending[:15]:
            lines.append(
                f"  - [DUE FOR REMOVAL] {item.get('ecosystem')}:{item.get('component')}@{item.get('version')} "
                f"(unused={item.get('unused_days')}d, size={_fmt_bytes(item.get('size_bytes', 0))})"
            )
        for item in expiring_soon[:15]:
            lines.append(
                f"  - [EXPIRING SOON] {item.get('ecosystem')}:{item.get('component')}@{item.get('version')} "
                f"(unused={item.get('unused_days')}d, removes in {item.get('days_until_removal')}d, size={_fmt_bytes(item.get('size_bytes', 0))})"
            )

    if quarantined:
        seen_q: set[tuple[str, str, str]] = set()
        unique_q: list[dict[str, Any]] = []
        for q in quarantined:
            q_key = (
                str(q.get("ecosystem", "")),
                str(q.get("component", "")),
                str(q.get("version", "")),
            )
            if q_key not in seen_q:
                seen_q.add(q_key)
                unique_q.append(q)
        lines.append("")
        lines.append("Quarantined (Vulnerable) Components:")
        for q in unique_q[:15]:
            cves = ",".join(q.get("cve_ids") or []) or "none"
            lines.append(
                f"  - {q.get('ecosystem')}:{q.get('component')}@{q.get('version')} "
                f"(CVSS={q.get('max_cvss', 0.0):.1f}, CVEs={cves}, latest={q.get('superseded_by') or '-'})"
            )
        if len(unique_q) > 15:
            lines.append(f"  ... and {len(unique_q) - 15} more")

    if recent_events:
        lines.append("")
        lines.append(f"Recent Activity (last {hours}h, newest first):")
        for ev in recent_events[:25]:
            ts = str(ev.get("timestamp", ""))[:19]
            comp = str(ev.get("component") or "-")
            ver = str(ev.get("version") or "-")
            lines.append(
                f"  - [{ts}] {ev.get('event')} ({ev.get('source')}) "
                f"{ev.get('ecosystem') or '-'}:{comp}@{ver} — {ev.get('details') or ''}"
            )
    else:
        lines.append("")
        lines.append(f"No scheduled or engine events recorded in the last {hours}h.")

    sms_text = (
        f"Trusted-OSS {date_str}: Total={total} CLEAN={clean} UNSCANNED={unscanned} "
        f"QUAR={q_count} Events({hours}h)={len(recent_events)} "
        f"REQ={len(requested_events)} NEW={len(new_artifact_events)}+{len(new_version_events)}v"
    )
    return subject, "\n".join(lines), sms_text[:160]


def render_daily_digest_html(
    *,
    subject: str,
    body_text: str,
    health: dict[str, Any],
    vuln_data: dict[str, Any],
    activity_events: list[dict[str, Any]],
    retention_data: dict[str, Any] | None = None,
    hours: int = 24,
) -> str:
    """Render an Outlook/M365/Gmail-compatible inline-CSS HTML email for the daily digest."""
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = vuln_data.get("summary") or {}
    quarantined = vuln_data.get("quarantined") or []
    clean = int(summary.get("clean", 0))
    unscanned = int(summary.get("unscanned", 0))
    q_count = int(summary.get("quarantined", len(quarantined)))
    total = int(summary.get("total", clean + unscanned + q_count))
    status_str = str(health.get("status", "unknown"))
    role_str = str(health.get("role", "all"))

    if q_count > 0 or status_str.lower() not in ("ok", "healthy"):
        badge_bg, badge_fg, badge_label, accent = "#d97706", "#ffffff", "ATTENTION", "#d97706"
    else:
        badge_bg, badge_fg, badge_label, accent = "#059669", "#ffffff", "ALL HEALTHY", "#059669"

    sections_html: list[str] = []
    if retention_data:
        disk_used = _fmt_bytes(int(retention_data.get("disk_used_bytes", 0)))
        disk_total = _fmt_bytes(int(retention_data.get("disk_total_bytes", 0)))
        disk_free = _fmt_bytes(int(retention_data.get("disk_free_bytes", 0)))
        disk_pct = float(retention_data.get("disk_used_pct", 0.0))
        cache_size = _fmt_bytes(int(retention_data.get("cache_bytes", 0)))
        est_days = retention_data.get("estimated_days_remaining")
        runway = f"~{est_days} days" if est_days is not None else "steady (0 B/day growth)"
        sections_html.append(
            '<div style="margin-top:16px;">'
            '<div style="font-size:12px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;color:#475569;margin-bottom:8px;">Cache Capacity &amp; Runway</div>'
            '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;border-collapse:separate;">'
            f'<tr style="background:#ffffff;"><td style="padding:9px 14px;border-bottom:1px solid #e2e8f0;font-size:12px;font-weight:700;color:#475569;width:160px;">Disk Usage</td>'
            f'<td style="padding:9px 14px;border-bottom:1px solid #e2e8f0;font-size:13px;color:#1e293b;">{html.escape(disk_used)} / {html.escape(disk_total)} ({disk_pct:.1f}% used, {html.escape(disk_free)} free)</td></tr>'
            f'<tr style="background:#f8fafc;"><td style="padding:9px 14px;font-size:12px;font-weight:700;color:#475569;">Trusted Cache</td>'
            f'<td style="padding:9px 14px;font-size:13px;color:#1e293b;">{html.escape(cache_size)} &nbsp;|&nbsp; Estimated Runway: {html.escape(runway)}</td></tr>'
            "</table></div>"
        )

    if quarantined:
        q_rows: list[str] = []
        seen: set[tuple[str, str, str]] = set()
        for q in quarantined:
            key = (str(q.get("ecosystem", "")), str(q.get("component", "")), str(q.get("version", "")))
            if key in seen:
                continue
            seen.add(key)
            cves = ", ".join(q.get("cve_ids") or []) or "none"
            bg = "#ffffff" if len(q_rows) % 2 == 0 else "#f8fafc"
            q_rows.append(
                f'<tr style="background:{bg};">'
                f'<td style="padding:9px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#991b1b;font-weight:700;">{html.escape(key[0])}:{html.escape(key[1])}@{html.escape(key[2])}</td>'
                f'<td style="padding:9px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#1e293b;">CVSS {float(q.get("max_cvss", 0.0)):.1f} &bull; {html.escape(cves)}</td>'
                f"</tr>"
            )
            if len(q_rows) >= 15:
                break
        sections_html.append(
            '<div style="margin-top:16px;">'
            '<div style="font-size:12px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;color:#991b1b;margin-bottom:8px;">Quarantined (Vulnerable) Components</div>'
            '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border:1px solid #fecaca;border-radius:8px;overflow:hidden;border-collapse:separate;">'
            + "".join(q_rows)
            + "</table></div>"
        )

    if activity_events:
        ev_rows: list[str] = []
        for idx, ev in enumerate(activity_events[:20]):
            bg = "#ffffff" if idx % 2 == 0 else "#f8fafc"
            ev_name = html.escape(str(ev.get("event", "EVENT")))
            ts = html.escape(str(ev.get("timestamp", ""))[:19])
            target = f"{ev.get('ecosystem') or '-'}:{ev.get('component') or '-'}@{ev.get('version') or '-'}"
            details = html.escape(str(ev.get("details") or ""))
            ev_rows.append(
                f'<tr style="background:{bg};">'
                f'<td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-size:11px;color:#64748b;white-space:nowrap;">{ts}</td>'
                f'<td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;"><span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;background:#e0f2fe;color:#075985;">{ev_name}</span></td>'
                f'<td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#1e293b;">{html.escape(target)} {details}</td>'
                f"</tr>"
            )
        sections_html.append(
            '<div style="margin-top:16px;">'
            f'<div style="font-size:12px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;color:#475569;margin-bottom:8px;">Recent Activity (Last {hours}h)</div>'
            '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;border-collapse:separate;">'
            + "".join(ev_rows)
            + "</table></div>"
        )
    else:
        sections_html.append(
            '<div style="margin-top:16px;padding:12px 14px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;color:#475569;">'
            f"No scheduled or engine events recorded in the last {hours}h."
            "</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:24px;background-color:#eef2f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:740px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #cbd5e1;box-shadow:0 4px 16px rgba(15,23,42,0.08);">
    <tr>
      <td style="background:#0f172a;padding:22px 26px;border-bottom:4px solid {accent};">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr>
            <td>
              <div style="font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#38bdf8;">Trusted OSS Harbor &bull; Supply Chain Gatekeeper</div>
              <div style="font-size:20px;font-weight:700;color:#ffffff;margin-top:4px;">Daily Supply Chain Digest</div>
              <div style="font-size:12px;color:#94a3b8;margin-top:4px;">Status: {html.escape(status_str)} &nbsp;|&nbsp; Role: {html.escape(role_str)} &nbsp;|&nbsp; Generated: {now_utc}</div>
            </td>
            <td align="right" valign="middle">
              <span style="display:inline-block;padding:6px 14px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:0.6px;background:{badge_bg};color:{badge_fg};">{badge_label}</span>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr>
      <td style="padding:20px 26px 8px 26px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr>
            <td width="25%" style="padding-right:6px;">
              <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:8px;padding:12px 10px;text-align:center;">
                <div style="font-size:22px;font-weight:800;color:#0f172a;">{total}</div>
                <div style="font-size:10px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;color:#475569;">Total</div>
              </div>
            </td>
            <td width="25%" style="padding:0 4px;">
              <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 10px;text-align:center;">
                <div style="font-size:22px;font-weight:800;color:#15803d;">{clean}</div>
                <div style="font-size:10px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;color:#166534;">Clean</div>
              </div>
            </td>
            <td width="25%" style="padding:0 4px;">
              <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px 10px;text-align:center;">
                <div style="font-size:22px;font-weight:800;color:#b45309;">{unscanned}</div>
                <div style="font-size:10px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;color:#92400e;">Unscanned</div>
              </div>
            </td>
            <td width="25%" style="padding-left:6px;">
              <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 10px;text-align:center;">
                <div style="font-size:22px;font-weight:800;color:#b91c1c;">{q_count}</div>
                <div style="font-size:10px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;color:#991b1b;">Quarantined</div>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr>
      <td style="padding:8px 26px 22px 26px;">
        {''.join(sections_html)}
      </td>
    </tr>
    <tr>
      <td style="background:#f8fafc;padding:14px 26px;border-top:1px solid #e2e8f0;font-size:11px;color:#64748b;">
        <strong>Subject:</strong> {html.escape(subject)}<br>
        Automated digest delivered via Microsoft Graph / SMTP STARTTLS &bull; JSIGROUP Standardized HTML Notification Format
      </td>
    </tr>
  </table>
</body>
</html>"""


def send_smtp_starttls(
    *,
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    sender: str,
    recipients: list[str],
    subject: str,
    body: str,
    html_body: str = "",
    timeout: float = 20.0,
) -> None:
    """Send email (or Email-to-SMS) via authenticated SMTP STARTTLS (e.g. Outlook port 587)."""
    msg = EmailMessage()
    msg["From"] = sender or username
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(username, password)
        server.send_message(msg)


def send_graph_mail(
    *,
    access_token: str,
    recipients: list[str],
    subject: str,
    body: str,
    content_type: str = "Text",
    timeout: float = 20.0,
) -> None:
    """Send email via Microsoft Graph API over HTTPS port 443 (no SMTP required)."""
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": content_type, "content": body},
            "toRecipients": [{"emailAddress": {"address": r}} for r in recipients],
        },
        "saveToSentItems": True,
    }
    resp = httpx.post(
        "https://graph.microsoft.com/v1.0/me/sendMail",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeout,
    )
    resp.raise_for_status()


def send_twilio_sms(
    *,
    account_sid: str,
    auth_token: str,
    from_number: str,
    to_number: str,
    body: str,
    timeout: float = 20.0,
) -> None:
    """Send SMS via Twilio REST API over HTTPS port 443."""
    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    resp = httpx.post(
        url,
        auth=(account_sid, auth_token),
        data={"From": from_number, "To": to_number, "Body": body},
        timeout=timeout,
    )
    resp.raise_for_status()


def load_msgraph_token_cache(path: Path) -> dict[str, Any]:
    """Load cached Microsoft Graph OAuth2 token payload from disk."""
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_msgraph_token_cache(path: Path, data: dict[str, Any]) -> None:
    """Persist Microsoft Graph OAuth2 token payload with 0600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def request_msgraph_device_code(
    *,
    client_id: str,
    tenant_id: str = "common",
    scopes: str = GRAPH_DEFAULT_SCOPES,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Initiate OAuth2 Device Code flow for MFA-compatible delegated Mail.Send."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    resp = httpx.post(
        url,
        data={"client_id": client_id, "scope": scopes},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def poll_msgraph_device_token(
    *,
    client_id: str,
    device_code: str,
    tenant_id: str = "common",
    interval: int = 5,
    expires_in: int = 900,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Poll Microsoft identity platform until device code login completes."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    deadline = time.monotonic() + max(30, expires_in)
    wait_seconds = max(1, interval)
    while time.monotonic() < deadline:
        resp = httpx.post(
            url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code,
            },
            timeout=timeout,
        )
        payload = resp.json()
        if resp.status_code == 200 and "access_token" in payload:
            payload["obtained_at"] = int(time.time())
            return payload
        err = payload.get("error", "")
        if err == "authorization_pending":
            time.sleep(wait_seconds)
            continue
        if err == "slow_down":
            wait_seconds += 5
            time.sleep(wait_seconds)
            continue
        raise RuntimeError(
            f"Microsoft Graph device login failed ({err}): "
            f"{payload.get('error_description', resp.text)}"
        )
    raise TimeoutError("Timed out waiting for Microsoft Graph device login.")


def refresh_msgraph_access_token(
    *,
    client_id: str,
    refresh_token: str,
    tenant_id: str = "common",
    scopes: str = GRAPH_DEFAULT_SCOPES,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Exchange a long-lived refresh token for a fresh Microsoft Graph access token."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    resp = httpx.post(
        url,
        data={
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scopes,
        },
        timeout=timeout,
    )
    payload = resp.json()
    if resp.status_code != 200 or "access_token" not in payload:
        raise RuntimeError(
            f"Microsoft Graph token refresh failed ({payload.get('error', resp.status_code)}): "
            f"{payload.get('error_description', resp.text)}"
        )
    payload["obtained_at"] = int(time.time())
    return payload


def _clean_oauth_value(val: str, prefix: str = "") -> str:
    cleaned = val.strip().strip('"').strip("'").strip()
    if prefix and cleaned.startswith(prefix):
        cleaned = cleaned[len(prefix) :].strip().strip('"').strip("'").strip()
    return cleaned


def resolve_msgraph_access_token(
    *,
    access_token: str = "",
    refresh_token: str = "",
    client_id: str = "",
    tenant_id: str = "common",
    token_file: Path = DEFAULT_TOKEN_CACHE_PATH,
    timeout: float = 20.0,
) -> str:
    """Resolve a usable Microsoft Graph access token, refreshing and rotating cache if needed."""
    cleaned_access = _clean_oauth_value(access_token, "GRAPH_ACCESS_TOKEN=")
    if cleaned_access:
        return cleaned_access

    cached = load_msgraph_token_cache(token_file)
    eff_client_id = _clean_oauth_value(client_id, "GRAPH_CLIENT_ID=") or _clean_oauth_value(
        str(cached.get("client_id", ""))
    )
    cleaned_tenant = _clean_oauth_value(tenant_id, "GRAPH_TENANT_ID=") or "common"
    eff_tenant_id = (
        cleaned_tenant
        if cleaned_tenant != "common"
        else (_clean_oauth_value(str(cached.get("tenant_id", "common"))) or "common")
    )
    # Prefer the persisted rotated refresh token in token_file over a static env var
    eff_refresh = _clean_oauth_value(str(cached.get("refresh_token", ""))) or _clean_oauth_value(
        refresh_token, "GRAPH_REFRESH_TOKEN="
    )

    if not eff_refresh:
        return ""
    if not eff_client_id:
        raise ValueError(
            "Microsoft Graph refresh token requires --graph-client-id (or GRAPH_CLIENT_ID)."
        )

    refreshed = refresh_msgraph_access_token(
        client_id=eff_client_id,
        refresh_token=eff_refresh,
        tenant_id=eff_tenant_id,
        timeout=timeout,
    )
    merged = {
        **cached,
        **refreshed,
        "client_id": eff_client_id,
        "tenant_id": eff_tenant_id,
    }
    if "refresh_token" not in merged:
        merged["refresh_token"] = eff_refresh
    save_msgraph_token_cache(token_file, merged)
    return str(merged["access_token"])


async def run_daily_digest_loop(
    *,
    oss_data_root: Path,
    admin_token: str,
    stop_event: asyncio.Event,
    default_frontend_url: str = "http://127.0.0.1:8000",
    logger: logging.Logger | None = None,
) -> None:
    """Periodically send a daily Microsoft Graph email / Email-to-SMS digest."""
    log = logger or logging.getLogger("gatekeeper.notifications")
    interval = max(300, int(os.getenv("DIGEST_INTERVAL_SECONDS", "86400")))
    frontend_url = os.getenv("DIGEST_FRONTEND_URL", default_frontend_url).rstrip("/")
    token_file = Path(
        os.getenv("GRAPH_TOKEN_FILE", str(oss_data_root / "audit" / "msgraph_token.json"))
    )
    stamp_file = oss_data_root / "audit" / "last_digest_sent.txt"
    email_to = [x.strip() for x in os.getenv("DIGEST_TO", "").split(",") if x.strip()]
    sms_to = [x.strip() for x in os.getenv("DIGEST_SMS_TO", "").split(",") if x.strip()]

    if not (email_to or sms_to):
        log.warning("[DIGEST] DIGEST_ENABLED=true but DIGEST_TO and DIGEST_SMS_TO are empty")
        return

    # Brief startup delay so local FastAPI/uvicorn is listening before first check
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=5.0)
        return
    except asyncio.TimeoutError:
        pass

    while not stop_event.is_set():
        now = time.time()
        last_sent = 0.0
        if stamp_file.exists():
            try:
                last_sent = float(stamp_file.read_text(encoding="utf-8").strip())
            except ValueError:
                last_sent = 0.0

        if now - last_sent >= interval:
            try:
                headers = {"X-Gatekeeper-Token": admin_token}
                async with httpx.AsyncClient(timeout=15.0) as client:
                    h_resp = await client.get(f"{frontend_url}/healthz", headers=headers)
                    v_resp = await client.get(
                        f"{frontend_url}/catalog/vulnerabilities", headers=headers
                    )
                    a_resp = await client.get(
                        f"{frontend_url}/audit/activity?limit=200", headers=headers
                    )
                    r_resp = await client.get(
                        f"{frontend_url}/catalog/retention", headers=headers
                    )
                    h_resp.raise_for_status()
                    v_resp.raise_for_status()
                    a_resp.raise_for_status()
                    retention_data = r_resp.json() if r_resp.status_code == 200 else None

                health_data = h_resp.json()
                vuln_data = v_resp.json()
                act_events = a_resp.json().get("events", [])
                lookback_h = max(1, interval // 3600)
                subject, body_text, sms_text = build_daily_digest(
                    health=health_data,
                    vuln_data=vuln_data,
                    activity_events=act_events,
                    retention_data=retention_data,
                    hours=lookback_h,
                )
                body_html = render_daily_digest_html(
                    subject=subject,
                    body_text=body_text,
                    health=health_data,
                    vuln_data=vuln_data,
                    activity_events=act_events,
                    retention_data=retention_data,
                    hours=lookback_h,
                )
                graph_token = await asyncio.to_thread(
                    resolve_msgraph_access_token,
                    access_token=os.getenv("GRAPH_ACCESS_TOKEN", ""),
                    refresh_token=os.getenv("GRAPH_REFRESH_TOKEN", ""),
                    client_id=os.getenv("GRAPH_CLIENT_ID", ""),
                    tenant_id=os.getenv("GRAPH_TENANT_ID", "common"),
                    token_file=token_file,
                )
                if not graph_token:
                    log.warning("[DIGEST] Daily digest skipped: no Graph token available")
                else:
                    if email_to:
                        await asyncio.to_thread(
                            send_graph_mail,
                            access_token=graph_token,
                            recipients=email_to,
                            subject=subject,
                            body=body_html,
                            content_type="HTML",
                        )
                    if sms_to:
                        await asyncio.to_thread(
                            send_graph_mail,
                            access_token=graph_token,
                            recipients=sms_to,
                            subject="OSS Harbor Digest",
                            body=sms_text,
                        )
                    stamp_file.parent.mkdir(parents=True, exist_ok=True)
                    stamp_file.write_text(str(now), encoding="utf-8")
                    log.info(
                        "[DIGEST] Daily digest sent via Graph (email=%d sms=%d)",
                        len(email_to),
                        len(sms_to),
                    )
            except Exception as exc:
                log.warning("[DIGEST] Daily digest error: %s", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=min(3600, interval))
        except asyncio.TimeoutError:
            pass
