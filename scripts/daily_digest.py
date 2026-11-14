#!/usr/bin/env python3
"""Standalone daily email & SMS digest for Trusted OSS Harbor.

Fetches gateway health, vulnerability counts, and recent scheduled/engine
activity events, then prints (--dry-run) or sends a daily digest over:
  1. Microsoft Graph API over HTTPS port 443 with MFA-compatible OAuth2 Device
     Code + long-lived Refresh Token (--graph-auth / --token-file).
     Supports both regular email (--to) and carrier Email-to-SMS (--sms-to).
  2. Outlook / M365 SMTP STARTTLS on port 587 (for non-MFA / SMTP AUTH accounts).
  3. Twilio SMS REST API over HTTPS port 443 (--twilio-*).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
GATEKEEPER_DIR = REPO_ROOT / "gatekeeper"
if str(GATEKEEPER_DIR) not in sys.path:
    sys.path.insert(0, str(GATEKEEPER_DIR))

from app.notifications import (  # noqa: E402
    DEFAULT_TOKEN_CACHE_PATH,
    build_daily_digest,
    poll_msgraph_device_token,
    request_msgraph_device_code,
    resolve_msgraph_access_token,
    save_msgraph_token_cache,
    send_graph_mail,
    send_smtp_starttls,
    send_twilio_sms,
)


def _fetch_json(url: str, token: str = "", timeout: float = 15.0) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _split_recipients(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send or preview the daily Trusted OSS Harbor activity digest."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("HARBOR_URL", "http://127.0.0.1:8080"),
        help="Gateway base URL (default: HARBOR_URL or http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GATEKEEPER_ADMIN_TOKEN", ""),
        help="Admin bearer token (default: GATEKEEPER_ADMIN_TOKEN)",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=int(os.environ.get("DIGEST_HOURS", "24")),
        help="Lookback window in hours for activity events (default: 24)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Max activity events to fetch from /audit/activity (default: 200)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the email subject, body, and SMS summary without sending",
    )

    # Microsoft Graph OAuth2 (MFA + long-lived refresh token over HTTPS 443)
    parser.add_argument(
        "--graph-auth",
        action="store_true",
        help="Run interactive OAuth2 Device Code login (MFA) and save a long-lived refresh token",
    )
    parser.add_argument(
        "--graph-client-id",
        default=os.environ.get("GRAPH_CLIENT_ID", ""),
        help="Microsoft Entra ID App Registration (Client) ID for Graph Mail.Send",
    )
    parser.add_argument(
        "--graph-tenant-id",
        default=os.environ.get("GRAPH_TENANT_ID", "common"),
        help="Microsoft Entra ID Tenant ID or 'common' (default: common)",
    )
    parser.add_argument(
        "--graph-token",
        default=os.environ.get("GRAPH_ACCESS_TOKEN", ""),
        help="Microsoft Graph OAuth2 access token with Mail.Send scope",
    )
    parser.add_argument(
        "--graph-refresh-token",
        default=os.environ.get("GRAPH_REFRESH_TOKEN", ""),
        help="Microsoft Graph OAuth2 long-lived refresh token",
    )
    parser.add_argument(
        "--token-file",
        default=os.environ.get("GRAPH_TOKEN_FILE", str(DEFAULT_TOKEN_CACHE_PATH)),
        help=f"Path to cached Graph OAuth2 token JSON (default: {DEFAULT_TOKEN_CACHE_PATH})",
    )

    # Outlook / M365 SMTP STARTTLS (port 587)
    parser.add_argument(
        "--smtp-host",
        default=os.environ.get("SMTP_HOST", "smtp-mail.outlook.com"),
        help="SMTP server hostname (default: smtp-mail.outlook.com)",
    )
    parser.add_argument(
        "--smtp-port",
        type=int,
        default=int(os.environ.get("SMTP_PORT", "587")),
        help="SMTP STARTTLS port (default: 587)",
    )
    parser.add_argument(
        "--smtp-user",
        default=os.environ.get("SMTP_USER", ""),
        help="SMTP login username / Outlook email address",
    )
    parser.add_argument(
        "--smtp-password",
        default=os.environ.get("SMTP_PASSWORD", ""),
        help="SMTP password or Outlook app password",
    )
    parser.add_argument(
        "--from",
        dest="sender",
        default=os.environ.get("DIGEST_FROM", ""),
        help="From address (defaults to --smtp-user)",
    )
    parser.add_argument(
        "--to",
        default=os.environ.get("DIGEST_TO", ""),
        help="Comma-separated email recipients",
    )
    parser.add_argument(
        "--sms-to",
        default=os.environ.get("DIGEST_SMS_TO", ""),
        help="Comma-separated carrier Email-to-SMS addresses (e.g. 5551234567@vtext.com)",
    )

    # Twilio SMS API (HTTPS 443)
    parser.add_argument(
        "--twilio-sid",
        default=os.environ.get("TWILIO_ACCOUNT_SID", ""),
        help="Twilio Account SID",
    )
    parser.add_argument(
        "--twilio-token",
        default=os.environ.get("TWILIO_AUTH_TOKEN", ""),
        help="Twilio Auth Token",
    )
    parser.add_argument(
        "--twilio-from",
        default=os.environ.get("TWILIO_FROM", ""),
        help="Twilio sender phone number (E.164, e.g. +15551234567)",
    )
    parser.add_argument(
        "--twilio-to",
        default=os.environ.get("TWILIO_TO", ""),
        help="Comma-separated SMS recipient phone numbers (E.164)",
    )
    return parser.parse_args()


def _run_graph_device_auth(args: argparse.Namespace) -> int:
    if not args.graph_client_id:
        print(
            "ERROR: --graph-auth requires --graph-client-id (or GRAPH_CLIENT_ID).",
            file=sys.stderr,
        )
        return 2

    dc = request_msgraph_device_code(
        client_id=args.graph_client_id,
        tenant_id=args.graph_tenant_id,
    )
    print(dc.get("message") or f"Open {dc.get('verification_uri')} and enter code: {dc.get('user_code')}")
    sys.stdout.flush()

    token_payload = poll_msgraph_device_token(
        client_id=args.graph_client_id,
        device_code=str(dc["device_code"]),
        tenant_id=args.graph_tenant_id,
        interval=int(dc.get("interval", 5)),
        expires_in=int(dc.get("expires_in", 900)),
    )
    token_payload["client_id"] = args.graph_client_id
    token_payload["tenant_id"] = args.graph_tenant_id
    token_path = Path(args.token_file).expanduser()
    save_msgraph_token_cache(token_path, token_payload)
    print(f"Saved Microsoft Graph refresh token to {token_path} (chmod 600).")
    return 0


def main() -> int:
    args = parse_args()
    if args.graph_auth:
        return _run_graph_device_auth(args)

    base = args.url.rstrip("/")

    try:
        health = _fetch_json(f"{base}/healthz", token=args.token)
        vuln_data = _fetch_json(f"{base}/catalog/vulnerabilities", token=args.token)
        activity_data = _fetch_json(
            f"{base}/audit/activity?limit={args.limit}", token=args.token
        )
    except urllib.error.HTTPError as exc:
        print(f"ERROR: Gateway returned HTTP {exc.code}: {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"ERROR: Could not reach {base}: {exc.reason}", file=sys.stderr)
        return 1

    events = activity_data.get("events", [])
    subject, body_text, sms_text = build_daily_digest(
        health=health,
        vuln_data=vuln_data,
        activity_events=events,
        hours=args.hours,
    )

    if args.dry_run:
        print(f"Subject: {subject}")
        print("=" * 72)
        print(body_text)
        print("=" * 72)
        print(f"SMS ({len(sms_text)} chars): {sms_text}")
        return 0

    email_recipients = _split_recipients(args.to)
    sms_gateway_recipients = _split_recipients(args.sms_to)
    twilio_recipients = _split_recipients(args.twilio_to)

    token_path = Path(args.token_file).expanduser()
    graph_access_token = resolve_msgraph_access_token(
        access_token=args.graph_token,
        refresh_token=args.graph_refresh_token,
        client_id=args.graph_client_id,
        tenant_id=args.graph_tenant_id,
        token_file=token_path,
    )

    sent_any = False

    if graph_access_token and (email_recipients or sms_gateway_recipients):
        if email_recipients:
            send_graph_mail(
                access_token=graph_access_token,
                recipients=email_recipients,
                subject=subject,
                body=body_text,
            )
            print(f"Sent Microsoft Graph email (HTTPS 443) to {', '.join(email_recipients)}")
            sent_any = True
        if sms_gateway_recipients:
            send_graph_mail(
                access_token=graph_access_token,
                recipients=sms_gateway_recipients,
                subject="OSS Harbor Digest",
                body=sms_text,
            )
            print(
                f"Sent Microsoft Graph Email-to-SMS (HTTPS 443) to "
                f"{', '.join(sms_gateway_recipients)}"
            )
            sent_any = True
    elif args.smtp_user and args.smtp_password:
        sender = args.sender or args.smtp_user
        if email_recipients:
            send_smtp_starttls(
                smtp_host=args.smtp_host,
                smtp_port=args.smtp_port,
                username=args.smtp_user,
                password=args.smtp_password,
                sender=sender,
                recipients=email_recipients,
                subject=subject,
                body=body_text,
            )
            print(
                f"Sent SMTP STARTTLS email via {args.smtp_host}:{args.smtp_port} "
                f"to {', '.join(email_recipients)}"
            )
            sent_any = True
        if sms_gateway_recipients:
            send_smtp_starttls(
                smtp_host=args.smtp_host,
                smtp_port=args.smtp_port,
                username=args.smtp_user,
                password=args.smtp_password,
                sender=sender,
                recipients=sms_gateway_recipients,
                subject="OSS Harbor Digest",
                body=sms_text,
            )
            print(
                f"Sent Email-to-SMS via {args.smtp_host}:{args.smtp_port} "
                f"to {', '.join(sms_gateway_recipients)}"
            )
            sent_any = True
    elif sms_gateway_recipients:
        print(
            "ERROR: --sms-to requires Microsoft Graph auth (--graph-auth / --token-file) "
            "or SMTP (--smtp-user, --smtp-password).",
            file=sys.stderr,
        )
        return 2

    if args.twilio_sid and args.twilio_token and args.twilio_from and twilio_recipients:
        for dest in twilio_recipients:
            send_twilio_sms(
                account_sid=args.twilio_sid,
                auth_token=args.twilio_token,
                from_number=args.twilio_from,
                to_number=dest,
                body=sms_text,
            )
        print(f"Sent Twilio SMS to {', '.join(twilio_recipients)}")
        sent_any = True

    if not sent_any:
        print(
            "ERROR: No transport configured. Run --graph-auth (recommended for MFA), "
            "--dry-run, or provide (--smtp-user, --smtp-password, --to) / "
            "(--twilio-sid, --twilio-token, --twilio-from, --twilio-to).",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
