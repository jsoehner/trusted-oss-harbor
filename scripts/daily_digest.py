#!/usr/bin/env python3
"""Standalone daily email & SMS digest for Trusted OSS Harbor.

Fetches gateway health, vulnerability counts, and recent scheduled/engine
activity events, then prints (--dry-run) or sends a daily digest over:
  1. Outlook / M365 SMTP STARTTLS on port 587 (bypasses blocked port 25),
     optionally also delivering to carrier Email-to-SMS gateways (--sms-to).
  2. Microsoft Graph API over HTTPS port 443 (--graph-token).
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
    build_daily_digest,
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

    # Microsoft Graph API (HTTPS 443)
    parser.add_argument(
        "--graph-token",
        default=os.environ.get("GRAPH_ACCESS_TOKEN", ""),
        help="Microsoft Graph OAuth2 access token with Mail.Send scope",
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


def main() -> int:
    args = parse_args()
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

    sent_any = False

    if args.graph_token and email_recipients:
        send_graph_mail(
            access_token=args.graph_token,
            recipients=email_recipients,
            subject=subject,
            body=body_text,
        )
        print(f"Sent Graph email to {', '.join(email_recipients)}")
        sent_any = True
    elif args.smtp_user and args.smtp_password and email_recipients:
        sender = args.sender or args.smtp_user
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
        if not (args.smtp_user and args.smtp_password):
            print(
                "ERROR: --sms-to requires --smtp-user and --smtp-password",
                file=sys.stderr,
            )
            return 2
        sender = args.sender or args.smtp_user
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
        print(f"Sent Email-to-SMS via {args.smtp_host}:{args.smtp_port} to {', '.join(sms_gateway_recipients)}")
        sent_any = True

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
            "ERROR: No transport configured. Pass --dry-run, or provide "
            "(--smtp-user, --smtp-password, --to), (--graph-token, --to), "
            "or (--twilio-sid, --twilio-token, --twilio-from, --twilio-to).",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
