"""Standalone daily digest builder and outbound email/SMS notification senders.

Supports Outlook / Microsoft 365 authenticated SMTP submission (port 587 STARTTLS,
bypassing blocked port 25), Microsoft Graph API (HTTPS 443), Twilio SMS (HTTPS 443),
and carrier Email-to-SMS gateways.
"""

from __future__ import annotations

import datetime
import json
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
    if access_token:
        return access_token

    cached = load_msgraph_token_cache(token_file)
    eff_client_id = client_id or str(cached.get("client_id", ""))
    eff_tenant_id = (
        tenant_id if tenant_id != "common" else str(cached.get("tenant_id", "common"))
    )
    eff_refresh = refresh_token or str(cached.get("refresh_token", ""))

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
