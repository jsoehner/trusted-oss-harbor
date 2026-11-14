"""Standalone daily digest builder and outbound email/SMS notification senders.

Supports Outlook / Microsoft 365 authenticated SMTP submission (port 587 STARTTLS,
bypassing blocked port 25), Microsoft Graph API (HTTPS 443), Twilio SMS (HTTPS 443),
and carrier Email-to-SMS gateways.
"""

from __future__ import annotations

import datetime
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import httpx


def build_daily_digest(
    *,
    health: dict[str, Any],
    vuln_data: dict[str, Any],
    activity_events: list[dict[str, Any]],
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

    date_str = now.strftime("%Y-%m-%d")
    subject = (
        f"[Trusted-OSS] Daily Digest {date_str}: "
        f"CLEAN={clean} UNSCANNED={unscanned} QUARANTINED={q_count}"
    )

    lines = [
        f"Trusted OSS Supply Chain — Daily Digest ({now.strftime('%Y-%m-%d %H:%M UTC')})",
        f"Status: {health.get('status', 'unknown')} | Role: {health.get('role', 'all')} | CVSS Threshold: >= {threshold}",
        "",
        f"Cached Components : Total={total} | CLEAN={clean} | UNSCANNED={unscanned} | QUARANTINED={q_count}",
        f"Events (last {hours}h) : {len(recent_events)}",
    ]
    if event_counts:
        lines.append("Event Breakdown   : " + ", ".join(f"{k}={v}" for k, v in sorted(event_counts.items())))

    if quarantined:
        lines.append("")
        lines.append("Quarantined (Vulnerable) Components:")
        for q in quarantined[:15]:
            cves = ",".join(q.get("cve_ids") or []) or "none"
            lines.append(
                f"  - {q.get('ecosystem')}:{q.get('component')}@{q.get('version')} "
                f"(CVSS={q.get('max_cvss', 0.0):.1f}, CVEs={cves}, latest={q.get('superseded_by') or '-'})"
            )
        if len(quarantined) > 15:
            lines.append(f"  ... and {len(quarantined) - 15} more")

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
        f"QUAR={q_count} Events({hours}h)={len(recent_events)}"
    )
    return subject, "\n".join(lines), sms_text[:160]


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
    timeout: float = 20.0,
) -> None:
    """Send email (or Email-to-SMS) via authenticated SMTP STARTTLS (e.g. Outlook port 587)."""
    msg = EmailMessage()
    msg["From"] = sender or username
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body)

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
    timeout: float = 20.0,
) -> None:
    """Send email via Microsoft Graph API over HTTPS port 443 (no SMTP required)."""
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body},
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
