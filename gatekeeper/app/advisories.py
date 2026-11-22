"""Vulnerability advisories, RSS feed, HTML dashboard, and real-time alert dispatch."""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import hmac
import html
import json
import logging
import os
from email.utils import format_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from app.bom_generator import build_canonical_purl
from app.config import Settings

logger = logging.getLogger("gatekeeper.advisories")


def _xml_escape(text: str) -> str:
    """Escape XML special characters without importing stdlib xml.*."""
    return html.escape(text, quote=True)


def classify_severity(max_cvss: float) -> str:
    """Map a CVSS v3 score to a standard severity label."""
    if max_cvss >= 9.0:
        return "CRITICAL"
    if max_cvss >= 7.0:
        return "HIGH"
    if max_cvss >= 4.0:
        return "MEDIUM"
    if max_cvss > 0.0:
        return "LOW"
    return "UNKNOWN"


def build_advisory_urls(cve_ids: list[str]) -> list[dict[str, str]]:
    """Build clickable OSV.dev and NVD reference links for vulnerability IDs."""
    links: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_id in cve_ids:
        vid = str(raw_id or "").strip()
        if not vid or vid in seen:
            continue
        seen.add(vid)
        links.append(
            {
                "id": vid,
                "source": "OSV",
                "url": f"https://osv.dev/vulnerability/{vid}",
            }
        )
        if vid.upper().startswith("CVE-"):
            links.append(
                {
                    "id": vid,
                    "source": "NVD",
                    "url": f"https://nvd.nist.gov/vuln/detail/{vid}",
                }
            )
    return links


def build_remediation_guidance(
    ecosystem: str,
    component: str,
    version: str,
    superseded_by: str = "",
) -> str:
    """Generate actionable upgrade or mitigation guidance for developers."""
    eco = ecosystem.lower()
    if superseded_by:
        if eco == "pypi":
            return f"Upgrade to clean cached version: pip install '{component}=={superseded_by}' (or uv add '{component}>={superseded_by}')"
        if eco == "maven":
            return f"Update dependency {component} from {version} to clean cached version {superseded_by} in pom.xml / build.gradle"
        if eco == "oci":
            return f"Rebuild base image using updated clean tag {component}:{superseded_by}"
        return f"Upgrade {component} from {version} to {superseded_by}"
    return (
        f"Component {component}@{version} is quarantined with no clean cached replacement yet. "
        "Check upstream advisories for a patched release or evaluate an alternative dependency."
    )


def build_vulnerability_advisories(
    *,
    quarantined: list[dict[str, Any]],
    vulnerable_components: list[dict[str, Any]] | None = None,
    ecosystem: str | None = None,
    component_filter: str | None = None,
    min_cvss: float = 0.0,
    since_hours: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Build a deduplicated, newest-first list of enriched vulnerability advisories."""
    eco_filter = (ecosystem or "").strip().lower()
    comp_sub = (component_filter or "").strip().lower()
    cutoff: datetime.datetime | None = None
    if since_hours is not None and since_hours > 0:
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=since_hours)

    advisories: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def _add_record(
        *,
        eco: str,
        comp: str,
        ver: str,
        status: str,
        max_cvss: float,
        cve_ids: list[str],
        detected_at: str,
        superseded_by: str,
        artifact: str,
    ) -> None:
        if eco_filter and eco_filter != "all" and eco.lower() != eco_filter:
            return
        if comp_sub and comp_sub not in comp.lower():
            return
        if max_cvss < min_cvss:
            return
        if cutoff is not None and detected_at:
            try:
                ts = datetime.datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=datetime.timezone.utc)
                if ts < cutoff:
                    return
            except ValueError:
                pass
        key = (eco, comp, ver, status)
        if key in seen:
            return
        seen.add(key)
        clean_cves = sorted({str(c).strip() for c in cve_ids if str(c).strip()})
        advisories.append(
            {
                "id": f"{eco}:{comp}@{ver}",
                "ecosystem": eco,
                "component": comp,
                "version": ver,
                "purl": build_canonical_purl(eco, comp, ver, artifact),
                "status": status,
                "severity": classify_severity(max_cvss),
                "max_cvss": round(max_cvss, 1),
                "cve_ids": clean_cves,
                "advisory_urls": build_advisory_urls(clean_cves),
                "superseded_by": superseded_by,
                "remediation_guidance": build_remediation_guidance(eco, comp, ver, superseded_by),
                "detected_at": detected_at,
                "artifact": artifact,
            }
        )

    for q in quarantined:
        _add_record(
            eco=str(q.get("ecosystem", "")),
            comp=str(q.get("component", "")),
            ver=str(q.get("version", "")),
            status="QUARANTINED",
            max_cvss=float(q.get("max_cvss", 0.0) or 0.0),
            cve_ids=list(q.get("cve_ids") or []),
            detected_at=str(q.get("quarantined_at", "")),
            superseded_by=str(q.get("superseded_by", "")),
            artifact=str(q.get("artifact", "")),
        )

    for item in vulnerable_components or []:
        if str(item.get("vulnerability_status", "")).upper() != "VULNERABLE":
            continue
        _add_record(
            eco=str(item.get("ecosystem", "")),
            comp=str(item.get("component", "")),
            ver=str(item.get("version", "")),
            status="VULNERABLE",
            max_cvss=float(item.get("max_cvss", 0.0) or 0.0),
            cve_ids=list(item.get("cve_ids") or []),
            detected_at=str(item.get("last_scanned_at", "")),
            superseded_by="",
            artifact=str(item.get("artifact", "")),
        )

    advisories.sort(
        key=lambda a: (a["detected_at"], a["max_cvss"], a["component"]),
        reverse=True,
    )
    return advisories[: max(1, min(limit, 500))]


def render_advisories_rss(
    advisories: list[dict[str, Any]],
    base_url: str = "http://localhost:8080",
) -> str:
    """Render vulnerability advisories as a standards-compliant RSS 2.0 XML feed."""
    clean_base = base_url.rstrip("/")
    now_rfc = format_datetime(datetime.datetime.now(datetime.timezone.utc))
    items_xml: list[str] = []

    for adv in advisories:
        title = (
            f"[{adv['severity']}] {adv['ecosystem']}:{adv['component']}@{adv['version']} "
            f"(CVSS {adv['max_cvss']:.1f})"
        )
        cves_str = ", ".join(adv["cve_ids"]) if adv["cve_ids"] else "CVSS threshold exceeded"
        primary_link = (
            adv["advisory_urls"][0]["url"]
            if adv["advisory_urls"]
            else f"{clean_base}/catalog/advisories/dashboard"
        )
        desc = (
            f"Status: {adv['status']} | Severity: {adv['severity']} (CVSS {adv['max_cvss']:.1f}) | "
            f"CVEs: {cves_str} | PURL: {adv['purl']} | "
            f"Remediation: {adv['remediation_guidance']}"
        )
        pub_date = now_rfc
        if adv["detected_at"]:
            try:
                dt = datetime.datetime.fromisoformat(adv["detected_at"].replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                pub_date = format_datetime(dt)
            except ValueError:
                pass
        guid = f"trusted-oss:advisory:{adv['id']}:{adv['status']}"
        items_xml.append(
            "    <item>\n"
            f"      <title>{_xml_escape(title)}</title>\n"
            f"      <link>{_xml_escape(primary_link)}</link>\n"
            f"      <guid isPermaLink=\"false\">{_xml_escape(guid)}</guid>\n"
            f"      <pubDate>{_xml_escape(pub_date)}</pubDate>\n"
            f"      <description>{_xml_escape(desc)}</description>\n"
            "    </item>"
        )

    items_block = "\n".join(items_xml)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n'
        "  <channel>\n"
        "    <title>Trusted OSS Harbor — Vulnerability Advisories</title>\n"
        f"    <link>{_xml_escape(clean_base + '/catalog/advisories/dashboard')}</link>\n"
        "    <description>Real-time feed of cached OSS components newly flagged or quarantined for High/Critical CVEs.</description>\n"
        f"    <lastBuildDate>{_xml_escape(now_rfc)}</lastBuildDate>\n"
        f"{items_block}\n"
        "  </channel>\n"
        "</rss>\n"
    )


def render_advisories_dashboard_html(
    advisories: list[dict[str, Any]],
    summary: dict[str, Any],
    cvss_threshold: float = 7.0,
) -> str:
    """Render a zero-JS, CSP-safe HTML dashboard for exploring vulnerable components."""
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = int(summary.get("total", 0))
    clean = int(summary.get("clean", 0))
    unscanned = int(summary.get("unscanned", 0))
    quarantined = int(summary.get("quarantined", len(advisories)))

    sev_colors = {
        "CRITICAL": ("#991b1b", "#fee2e2"),
        "HIGH": ("#9a3412", "#ffedd5"),
        "MEDIUM": ("#854d0e", "#fef9c3"),
        "LOW": ("#1e40af", "#dbeafe"),
    }

    rows_html: list[str] = []
    for adv in advisories:
        fg, bg = sev_colors.get(adv["severity"], ("#334155", "#f1f5f9"))
        cve_links = " ".join(
            f'<a href="{html.escape(link["url"], quote=True)}" target="_blank" rel="noopener noreferrer" '
            f'style="color:#0369a1;text-decoration:none;margin-right:6px;">{html.escape(link["id"])} ({html.escape(link["source"])})</a>'
            for link in adv["advisory_urls"]
        ) or '<span style="color:#64748b;">CVSS threshold</span>'
        upgrade_badge = (
            f'<span style="background:#dcfce7;color:#166534;padding:2px 8px;border-radius:999px;font-weight:600;font-size:12px;">'
            f'Upgrade &rarr; {html.escape(adv["superseded_by"])}</span>'
            if adv["superseded_by"]
            else '<span style="background:#fef2f2;color:#991b1b;padding:2px 8px;border-radius:999px;font-weight:600;font-size:12px;">No clean version cached</span>'
        )
        rows_html.append(
            "<tr>"
            f'<td style="padding:12px;border-bottom:1px solid #e2e8f0;"><span style="background:{bg};color:{fg};padding:3px 8px;border-radius:6px;font-weight:700;font-size:11px;">{html.escape(adv["severity"])} ({adv["max_cvss"]:.1f})</span></td>'
            f'<td style="padding:12px;border-bottom:1px solid #e2e8f0;"><strong>{html.escape(adv["ecosystem"])}:{html.escape(adv["component"])}</strong><br><code style="font-size:12px;color:#475569;">{html.escape(adv["version"])}</code></td>'
            f'<td style="padding:12px;border-bottom:1px solid #e2e8f0;font-size:13px;">{cve_links}</td>'
            f'<td style="padding:12px;border-bottom:1px solid #e2e8f0;font-size:13px;">{upgrade_badge}<div style="margin-top:4px;color:#475569;font-size:12px;">{html.escape(adv["remediation_guidance"])}</div></td>'
            f'<td style="padding:12px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#64748b;white-space:nowrap;">{html.escape(adv["detected_at"][:19])}</td>'
            "</tr>"
        )

    table_body = (
        "\n".join(rows_html)
        if rows_html
        else '<tr><td colspan="5" style="padding:24px;text-align:center;color:#059669;font-weight:600;">No vulnerable or quarantined components detected. All cached artifacts are clean.</td></tr>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Trusted OSS Harbor — Vulnerability Advisories</title>
</head>
<body style="margin:0;padding:24px;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;">
  <div style="max-width:1120px;margin:0 auto;">
    <div style="background:#0f172a;color:#ffffff;padding:24px 28px;border-radius:12px;margin-bottom:20px;">
      <div style="font-size:12px;letter-spacing:1px;text-transform:uppercase;color:#38bdf8;font-weight:700;">Trusted OSS Harbor &bull; Security Advisory Center</div>
      <h1 style="margin:6px 0 8px 0;font-size:24px;">Vulnerable &amp; Quarantined Components</h1>
      <div style="font-size:13px;color:#cbd5e1;">
        CVSS Block Threshold: &ge; {cvss_threshold:.1f} &nbsp;|&nbsp; Updated: {html.escape(now_str)} &nbsp;|&nbsp;
        <a href="/catalog/advisories" style="color:#7dd3fc;">JSON API</a> &nbsp;&bull;&nbsp;
        <a href="/catalog/advisories.rss" style="color:#7dd3fc;">Subscribe via RSS</a>
      </div>
    </div>

    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;">
      <div style="flex:1;min-width:160px;background:#ffffff;border:1px solid #cbd5e1;border-radius:10px;padding:14px 18px;">
        <div style="font-size:11px;text-transform:uppercase;color:#64748b;font-weight:700;">Total Cached</div>
        <div style="font-size:26px;font-weight:800;margin-top:4px;">{total}</div>
      </div>
      <div style="flex:1;min-width:160px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:14px 18px;">
        <div style="font-size:11px;text-transform:uppercase;color:#166534;font-weight:700;">Clean</div>
        <div style="font-size:26px;font-weight:800;color:#15803d;margin-top:4px;">{clean}</div>
      </div>
      <div style="flex:1;min-width:160px;background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:14px 18px;">
        <div style="font-size:11px;text-transform:uppercase;color:#92400e;font-weight:700;">Unscanned</div>
        <div style="font-size:26px;font-weight:800;color:#b45309;margin-top:4px;">{unscanned}</div>
      </div>
      <div style="flex:1;min-width:160px;background:#fef2f2;border:1px solid #fecaca;border-radius:10px;padding:14px 18px;">
        <div style="font-size:11px;text-transform:uppercase;color:#991b1b;font-weight:700;">Quarantined / Vulnerable</div>
        <div style="font-size:26px;font-weight:800;color:#b91c1c;margin-top:4px;">{quarantined}</div>
      </div>
    </div>

    <div style="background:#ffffff;border:1px solid #cbd5e1;border-radius:12px;overflow:hidden;">
      <table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;text-align:left;">
        <thead>
          <tr style="background:#f1f5f9;font-size:12px;text-transform:uppercase;color:#475569;">
            <th style="padding:12px;">Severity</th>
            <th style="padding:12px;">Component</th>
            <th style="padding:12px;">Advisories</th>
            <th style="padding:12px;">Remediation Guidance</th>
            <th style="padding:12px;">Detected (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {table_body}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""


def _load_sent_alert_keys(alerts_log_path: Path) -> set[str]:
    keys: set[str] = set()
    if not alerts_log_path.is_file():
        return keys
    for line in alerts_log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            key = str(rec.get("alert_key", ""))
            if key:
                keys.add(key)
        except json.JSONDecodeError:
            continue
    return keys


async def dispatch_vulnerability_alerts(
    settings: Settings,
    newly_quarantined: list[dict[str, Any]],
) -> dict[str, Any]:
    """Record newly vulnerable components and dispatch real-time webhook/email alerts (deduplicated)."""
    if not newly_quarantined:
        return {"new_alerts": 0, "webhook_sent": False, "email_sent": False}

    alerts_log_path = settings.oss_data_root / "audit" / "vuln_alerts.jsonl"
    sent_keys = _load_sent_alert_keys(alerts_log_path)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    new_advisories: list[dict[str, Any]] = []
    for item in newly_quarantined:
        eco = str(item.get("ecosystem", ""))
        comp = str(item.get("component", ""))
        ver = str(item.get("version", ""))
        cves = sorted({str(c).strip() for c in (item.get("cve_ids") or []) if str(c).strip()})
        alert_key = f"{eco}:{comp}@{ver}:{','.join(cves)}"
        if alert_key in sent_keys:
            continue
        sent_keys.add(alert_key)
        max_cvss = float(item.get("max_cvss", 0.0) or 0.0)
        superseded_by = str(item.get("superseded_by", ""))
        advisory = {
            "alert_key": alert_key,
            "detected_at": now_iso,
            "ecosystem": eco,
            "component": comp,
            "version": ver,
            "purl": build_canonical_purl(eco, comp, ver),
            "severity": classify_severity(max_cvss),
            "max_cvss": round(max_cvss, 1),
            "cve_ids": cves,
            "advisory_urls": build_advisory_urls(cves),
            "superseded_by": superseded_by,
            "remediation_guidance": build_remediation_guidance(eco, comp, ver, superseded_by),
        }
        new_advisories.append(advisory)

    if not new_advisories:
        return {"new_alerts": 0, "webhook_sent": False, "email_sent": False}

    alerts_log_path.parent.mkdir(parents=True, exist_ok=True)
    with alerts_log_path.open("a", encoding="utf-8") as fh:
        for adv in new_advisories:
            fh.write(json.dumps(adv, sort_keys=True) + "\n")

    webhook_sent = False
    webhook_url = settings.vuln_alert_webhook_url.strip()
    if webhook_url:
        parsed = urlparse(webhook_url)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            lines = [
                f"- [{a['severity']} CVSS {a['max_cvss']:.1f}] {a['ecosystem']}:{a['component']}@{a['version']} "
                f"({', '.join(a['cve_ids']) or 'CVSS threshold'}) -> "
                f"{'Upgraded to ' + a['superseded_by'] if a['superseded_by'] else 'No clean cached replacement'}"
                for a in new_advisories
            ]
            payload = {
                "event": "VULNERABLE_COMPONENTS_DETECTED",
                "timestamp": now_iso,
                "count": len(new_advisories),
                "text": "Trusted OSS Harbor Vulnerability Alert:\n" + "\n".join(lines),
                "advisories": new_advisories,
            }
            body_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if settings.vuln_alert_webhook_secret:
                sig = hmac.new(
                    settings.vuln_alert_webhook_secret.encode("utf-8"),
                    body_bytes,
                    hashlib.sha256,
                ).hexdigest()
                headers["X-Trusted-OSS-Signature"] = f"sha256={sig}"
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(webhook_url, content=body_bytes, headers=headers)
                    webhook_sent = 200 <= resp.status_code < 300
                    if not webhook_sent:
                        logger.warning("[ALERT] Webhook returned HTTP %s", resp.status_code)
            except Exception as exc:
                logger.warning("[ALERT] Webhook dispatch failed: %s", exc)
        else:
            logger.warning("[ALERT] Ignoring invalid VULN_ALERT_WEBHOOK_URL scheme")

    email_sent = False
    if settings.vuln_alert_immediate_email:
        email_to = [x.strip() for x in os.getenv("DIGEST_TO", "").split(",") if x.strip()]
        if email_to:
            try:
                from app.notifications import resolve_msgraph_access_token, send_graph_mail

                token_file = Path(
                    os.getenv("GRAPH_TOKEN_FILE", str(settings.oss_data_root / "audit" / "msgraph_token.json"))
                )
                graph_token = await asyncio.to_thread(
                    resolve_msgraph_access_token,
                    access_token=os.getenv("GRAPH_ACCESS_TOKEN", ""),
                    refresh_token=os.getenv("GRAPH_REFRESH_TOKEN", ""),
                    client_id=os.getenv("GRAPH_CLIENT_ID", ""),
                    tenant_id=os.getenv("GRAPH_TENANT_ID", "common"),
                    token_file=token_file,
                )
                if graph_token:
                    subject = (
                        f"[Trusted-OSS ALERT] {len(new_advisories)} Newly Vulnerable Component(s) Quarantined"
                    )
                    html_body = render_advisories_dashboard_html(
                        advisories=new_advisories,
                        summary={
                            "total": len(new_advisories),
                            "clean": 0,
                            "unscanned": 0,
                            "quarantined": len(new_advisories),
                        },
                        cvss_threshold=settings.cvss_fail_threshold,
                    )
                    await asyncio.to_thread(
                        send_graph_mail,
                        access_token=graph_token,
                        recipients=email_to,
                        subject=subject,
                        body=html_body,
                        content_type="HTML",
                    )
                    email_sent = True
            except Exception as exc:
                logger.warning("[ALERT] Immediate email alert failed: %s", exc)

    return {
        "new_alerts": len(new_advisories),
        "webhook_sent": webhook_sent,
        "email_sent": email_sent,
    }
