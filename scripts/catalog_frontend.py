#!/usr/bin/env python3
"""Frontend HTTP catalog and per-version vulnerability inventory."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def _build_ssl_context(ca_bundle: str = "", insecure: bool = False) -> ssl.SSLContext | None:
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    return None


def _get_json(
    url: str,
    timeout: float = 60.0,
    ssl_ctx: ssl.SSLContext | None = None,
    token: str = "",
) -> dict[str, Any]:
    headers = {"X-Gatekeeper-Token": token} if token else {}
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_json(
    url: str,
    timeout: float = 300.0,
    ssl_ctx: ssl.SSLContext | None = None,
    token: str = "",
) -> dict[str, Any]:
    headers = {"X-Gatekeeper-Token": token} if token else {}
    req = urllib.request.Request(url, method="POST", data=b"", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _head_or_get_ok(
    url: str,
    timeout: float = 5.0,
    ssl_ctx: ssl.SSLContext | None = None,
    token: str = "",
) -> tuple[bool, str]:
    headers = {"X-Gatekeeper-Token": token} if token else {}
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
            return resp.status == 200, body
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, str(exc)


def _fallback_vulnerabilities_from_status(
    status: dict[str, Any],
    provenance: dict[str, Any],
    threshold: float,
) -> dict[str, Any]:
    """Synthesize per-version vulnerability rows when /catalog/vulnerabilities is unavailable."""
    prov_map: dict[str, dict[str, Any]] = {}
    for rec in provenance.get("records", []):
        art = str(rec.get("artifact", ""))
        if art:
            prov_map[art] = rec

    components: list[dict[str, Any]] = []
    for item in status.get("chainguard_containers", []):
        if not item.get("cached"):
            continue
        image = str(item.get("image", ""))
        repo, _, tag = image.partition(":")
        rel = f"{repo}/manifests/{tag or 'latest'}"
        prov = prov_map.get(f"chainguard-cache/{rel}") or prov_map.get(rel) or {}
        components.append(
            {
                "ecosystem": "oci",
                "component": repo,
                "version": tag or "latest",
                "artifact": rel,
                "signature_valid": bool(item.get("signature_valid")),
                "pqc_signed": bool(prov.get("signature_file_mldsa")),
                "clamav_status": str(prov.get("clamav_status", "UNKNOWN")),
                "cve_status": str(prov.get("cve_status", "UNKNOWN")),
                "max_cvss": float(prov.get("max_cvss", 0.0) or 0.0),
                "cve_ids": list(prov.get("cve_ids") or []),
                "vulnerability_status": "UNSCANNED" if prov.get("cve_status", "NONE") in ("NONE", "UNKNOWN", "") else "CLEAN",
                "last_scanned_at": str(prov.get("timestamp", "")),
            }
        )

    for item in status.get("spring_boot_components", []):
        if not item.get("cached"):
            continue
        rel = str(item.get("artifact", ""))
        coord = str(item.get("coordinate", ""))
        parts = coord.split(":")
        comp_name = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else rel
        ver = parts[2] if len(parts) >= 3 else "unknown"
        prov = prov_map.get(rel) or {}
        components.append(
            {
                "ecosystem": "maven",
                "component": comp_name,
                "version": ver,
                "artifact": rel,
                "signature_valid": bool(item.get("signature_valid")),
                "pqc_signed": bool(prov.get("signature_file_mldsa")),
                "clamav_status": str(prov.get("clamav_status", "UNKNOWN")),
                "cve_status": str(prov.get("cve_status", "UNKNOWN")),
                "max_cvss": float(prov.get("max_cvss", 0.0) or 0.0),
                "cve_ids": list(prov.get("cve_ids") or []),
                "vulnerability_status": "UNSCANNED" if prov.get("cve_status", "NONE") in ("NONE", "UNKNOWN", "") else "CLEAN",
                "last_scanned_at": str(prov.get("timestamp", "")),
            }
        )

    for item in status.get("pypi_components", []):
        if not item.get("cached"):
            continue
        pkg = str(item.get("package", ""))
        for fname in item.get("files", []):
            rel = f"{pkg}/{fname}"
            prov = prov_map.get(rel) or {}
            components.append(
                {
                    "ecosystem": "pypi",
                    "component": pkg,
                    "version": fname,
                    "artifact": rel,
                    "signature_valid": bool(item.get("signature_valid")),
                    "pqc_signed": bool(prov.get("signature_file_mldsa")),
                    "clamav_status": str(prov.get("clamav_status", "UNKNOWN")),
                    "cve_status": str(prov.get("cve_status", "UNKNOWN")),
                    "max_cvss": float(prov.get("max_cvss", 0.0) or 0.0),
                    "cve_ids": list(prov.get("cve_ids") or []),
                    "vulnerability_status": "UNSCANNED" if prov.get("cve_status", "NONE") in ("NONE", "UNKNOWN", "") else "CLEAN",
                    "last_scanned_at": str(prov.get("timestamp", "")),
                }
            )

    return {
        "cvss_fail_threshold": threshold,
        "summary": {
            "total": len(components),
            "clean": sum(1 for c in components if c["vulnerability_status"] == "CLEAN"),
            "vulnerable": sum(1 for c in components if c["vulnerability_status"] == "VULNERABLE"),
            "unscanned": sum(1 for c in components if c["vulnerability_status"] == "UNSCANNED"),
        },
        "components": components,
    }


def _post_and_maybe_wait(
    url: str,
    *,
    base: str,
    ssl_ctx: ssl.SSLContext | None,
    token: str,
    wait: bool,
) -> dict[str, Any] | None:
    """POST to an engine-backed endpoint and optionally poll /jobs/{job_id} on 202 Accepted."""
    try:
        res = _post_json(url, ssl_ctx=ssl_ctx, token=token)
        if wait and res.get("job_id") and res.get("status") in ("queued", "running"):
            job_id = str(res["job_id"])
            for _ in range(150):
                time.sleep(2.0)
                job_state = _get_json(f"{base}/jobs/{job_id}", ssl_ctx=ssl_ctx, token=token)
                if job_state.get("status") == "completed" and isinstance(job_state.get("result"), dict):
                    return job_state["result"]
                if job_state.get("status") == "failed":
                    return job_state
        return res
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 403, 503):
            return None
        raise


def catalog_frontend(
    base_url: str,
    ca_bundle: str = "",
    insecure: bool = False,
    token: str = "",
    ecosystem: str = "all",
    components_filter: str = "",
    remediate: bool = False,
    scan_unscanned: bool = False,
    gc: bool = False,
    gc_dry_run: bool = False,
    gc_keep: int | None = None,
    activity: bool = False,
    activity_limit: int = 50,
    activity_event: str = "",
    wait: bool = False,
) -> dict[str, Any]:
    """Optionally force unscanned scans, remediation, or N-2 GC, then return inventory & activity."""
    base = base_url.rstrip("/")
    ssl_ctx = _build_ssl_context(ca_bundle=ca_bundle, insecure=insecure)

    eco_tokens = [t.strip().lower() for t in ecosystem.split(",") if t.strip()]
    eco_param = "" if (not eco_tokens or "all" in eco_tokens) else ",".join(eco_tokens)
    comp_tokens = [c.strip().lower() for c in components_filter.split(",") if c.strip()]
    comp_param = ",".join(comp_tokens)

    remediation_result: dict[str, Any] | None = None
    if (remediate or scan_unscanned) and token:
        rem_params: dict[str, str] = {}
        if eco_param:
            rem_params["ecosystem"] = eco_param
        if comp_param:
            rem_params["components"] = comp_param
        if scan_unscanned and not remediate:
            rem_params["only_unscanned"] = "true"
        if wait:
            rem_params["wait"] = "true"
        rem_qs = urllib.parse.urlencode(rem_params)
        rem_url = f"{base}/catalog/remediate" + (f"?{rem_qs}" if rem_qs else "")
        remediation_result = _post_and_maybe_wait(
            rem_url, base=base, ssl_ctx=ssl_ctx, token=token, wait=wait
        )

    gc_result: dict[str, Any] | None = None
    if gc and token:
        gc_params: dict[str, str] = {}
        if eco_param:
            gc_params["ecosystem"] = eco_param
        if comp_param:
            gc_params["components"] = comp_param
        if gc_keep is not None:
            gc_params["keep_versions"] = str(gc_keep)
        if gc_dry_run:
            gc_params["dry_run"] = "true"
        if wait:
            gc_params["wait"] = "true"
        gc_qs = urllib.parse.urlencode(gc_params)
        gc_url = f"{base}/catalog/gc" + (f"?{gc_qs}" if gc_qs else "")
        gc_result = _post_and_maybe_wait(
            gc_url, base=base, ssl_ctx=ssl_ctx, token=token, wait=wait
        )

    health = _get_json(f"{base}/healthz", ssl_ctx=ssl_ctx, token=token)
    provenance = _get_json(f"{base}/audit/provenance", ssl_ctx=ssl_ctx, token=token)

    vuln_params: dict[str, str] = {}
    if eco_param:
        vuln_params["ecosystem"] = eco_param
    if comp_param:
        vuln_params["components"] = comp_param
    vuln_qs = urllib.parse.urlencode(vuln_params)
    vuln_url = f"{base}/catalog/vulnerabilities" + (f"?{vuln_qs}" if vuln_qs else "")

    try:
        vuln_data = _get_json(vuln_url, ssl_ctx=ssl_ctx, token=token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            status = _get_json(f"{base}/catalog/status", ssl_ctx=ssl_ctx, token=token)
            vuln_data = _fallback_vulnerabilities_from_status(
                status, provenance, float(health.get("cvss_fail_threshold", 7.0))
            )
        else:
            raise

    gpg_ok, _ = _head_or_get_ok(f"{base}/keys/trusted-oss-pubkey.asc", ssl_ctx=ssl_ctx, token=token)
    mldsa_ok, _ = _head_or_get_ok(f"{base}/keys/trusted-oss-mldsa65.pub", ssl_ctx=ssl_ctx, token=token)
    mldsa_fp_ok, mldsa_fp_body = _head_or_get_ok(
        f"{base}/keys/trusted-oss-mldsa65.fingerprint", ssl_ctx=ssl_ctx, token=token
    )

    components = vuln_data.get("components", [])
    quarantined = vuln_data.get("quarantined", [])
    history = vuln_data.get("history", [])
    if eco_tokens and "all" not in eco_tokens:
        eco_set = set(eco_tokens)
        components = [c for c in components if c.get("ecosystem") in eco_set]
        quarantined = [q for q in quarantined if q.get("ecosystem") in eco_set]
        history = [h for h in history if h.get("ecosystem") in eco_set]
    if comp_tokens:
        components = [
            c for c in components if any(t in str(c.get("component", "")).lower() for t in comp_tokens)
        ]
        quarantined = [
            q for q in quarantined if any(t in str(q.get("component", "")).lower() for t in comp_tokens)
        ]
        history = [
            h for h in history if any(t in str(h.get("component", "")).lower() for t in comp_tokens)
        ]

    activity_data: dict[str, Any] | None = None
    if activity:
        act_params: dict[str, str] = {"limit": str(max(1, activity_limit))}
        if activity_event.strip():
            act_params["event"] = activity_event.strip()
        act_qs = urllib.parse.urlencode(act_params)
        try:
            activity_data = _get_json(f"{base}/audit/activity?{act_qs}", ssl_ctx=ssl_ctx, token=token)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                activity_data = {"count": 0, "events": [], "note": "/audit/activity not available on this server"}
            else:
                raise

    return {
        "frontend_url": base,
        "health": health,
        "remediation": remediation_result,
        "gc": gc_result,
        "activity": activity_data,
        "activity_only": bool(activity and not comp_param and not eco_param),
        "filters": {
            "ecosystem": eco_param or "all",
            "components": comp_param or "all",
        },
        "keys": {
            "gpg_public_key": gpg_ok,
            "mldsa65_public_key": mldsa_ok,
            "mldsa65_fingerprint": mldsa_fp_body.splitlines()[0] if mldsa_fp_ok and mldsa_fp_body else "",
        },
        "counts": {
            "cached_total": len(components),
            "oci_cached": sum(1 for c in components if c.get("ecosystem") == "oci"),
            "maven_cached": sum(1 for c in components if c.get("ecosystem") == "maven"),
            "pypi_cached": sum(1 for c in components if c.get("ecosystem") == "pypi"),
            "quarantined": len(quarantined),
            "provenance_records": provenance.get("count", 0),
        },
        "vulnerability_summary": {
            "total": len(components),
            "clean": sum(1 for c in components if c.get("vulnerability_status") == "CLEAN"),
            "vulnerable": sum(1 for c in components if c.get("vulnerability_status") == "VULNERABLE"),
            "unscanned": sum(1 for c in components if c.get("vulnerability_status") == "UNSCANNED"),
            "quarantined": len(quarantined),
        },
        "components": components,
        "quarantined": quarantined,
        "history": history,
    }


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    """Format rows into a clean aligned ASCII table."""
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    header_line = "| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |"
    lines = [sep, header_line, sep]
    for row in rows:
        lines.append("| " + " | ".join(row[i].ljust(widths[i]) for i in range(len(headers))) + " |")
    lines.append(sep)
    return "\n".join(lines)


def _print_report(report: dict[str, Any]) -> None:
    health = report["health"]
    keys = report["keys"]
    c = report["counts"]
    vs = report["vulnerability_summary"]
    filt = report.get("filters", {})

    print(f"Frontend Gateway URL : {report['frontend_url']} (status={health.get('status', 'unknown')})")
    print(
        f"Signing Keys         : GPG={'ready' if keys['gpg_public_key'] else 'missing'}, "
        f"ML-DSA-65={'ready' if keys['mldsa65_public_key'] else 'missing'}"
        + (f" ({keys['mldsa65_fingerprint']})" if keys["mldsa65_fingerprint"] else "")
    )
    print(f"Policy Threshold     : CVSS >= {health.get('cvss_fail_threshold', 'N/A')}")
    print(
        f"Filters              : ecosystem={filt.get('ecosystem', 'all')} | "
        f"components={filt.get('components', 'all')}"
    )
    print(
        f"Cached Components    : Total={c['cached_total']} (OCI={c['oci_cached']}, "
        f"Maven={c['maven_cached']}, PyPI={c['pypi_cached']}) | "
        f"Quarantined={c.get('quarantined', 0)} | Provenance={c['provenance_records']}"
    )
    print(
        f"Vulnerability Status : CLEAN={vs['clean']} | VULNERABLE={vs['vulnerable']} | "
        f"UNSCANNED={vs['unscanned']} | QUARANTINED={vs.get('quarantined', 0)}"
    )

    rem = report.get("remediation")
    if rem:
        if rem.get("job_id") and rem.get("status") in ("queued", "running", "failed"):
            print(
                f"Auto-Remediation     : job_id={rem.get('job_id')} status={rem.get('status')} "
                "(engine processing asynchronously via message bus)"
            )
        else:
            print(
                f"Auto-Remediation     : scanned={rem.get('scanned', 0)}, clean={rem.get('clean_count', 0)}, "
                f"quarantined={rem.get('quarantined_count', 0)}, upgraded_to_latest={rem.get('upgraded_count', 0)}"
            )

    gc = report.get("gc")
    if gc:
        if gc.get("job_id") and gc.get("status") in ("queued", "running", "failed"):
            print(
                f"Garbage Collection   : job_id={gc.get('job_id')} status={gc.get('status')} "
                "(engine processing asynchronously via message bus)"
            )
        else:
            print(
                f"Garbage Collection   : removed_versions={gc.get('removed_count', 0)}, "
                f"files_removed={gc.get('files_removed_total', 0)}, keep_versions={gc.get('keep_versions', 2)}, "
                f"dry_run={gc.get('dry_run', False)}"
            )

    act = report.get("activity")
    if act is not None:
        events = act.get("events") or []
        print(f"\n[Scheduled Task & Engine Activity Log] (events={len(events)})")
        if act.get("note"):
            print(f"  {act['note']}")
        elif events:
            a_rows = [
                [
                    str(ev.get("timestamp", ""))[:19],
                    str(ev.get("source", "")),
                    str(ev.get("event", "")),
                    str(ev.get("ecosystem", "") or "-"),
                    str(ev.get("component", "") or "-"),
                    str(ev.get("version", "") or "-"),
                    str(ev.get("details", "") or "-"),
                ]
                for ev in events
            ]
            print(
                _render_table(
                    ["TIMESTAMP", "SOURCE", "EVENT", "ECOSYSTEM", "COMPONENT", "VERSION", "DETAILS"],
                    a_rows,
                )
            )
        else:
            print("  (no activity events recorded yet)")

    if report.get("activity_only"):
        return

    print("\n[Active Cached Components]")
    if report["components"]:
        active_rows = []
        for item in report["components"]:
            sig = "GPG-VALID" if item.get("signature_valid") else "UNSIGNED"
            if item.get("pqc_signed"):
                sig += "+PQC"
            tags = ",".join(item.get("tags") or []) or "-"
            cves = ",".join(item.get("cve_ids") or []) or "none"
            active_rows.append(
                [
                    str(item.get("ecosystem", "")),
                    str(item.get("component", "")),
                    str(item.get("version", "")),
                    tags,
                    sig,
                    str(item.get("vulnerability_status", "UNSCANNED")),
                    f"{float(item.get('max_cvss', 0.0) or 0.0):.1f}",
                    cves,
                    str(item.get("clamav_status", "UNKNOWN")),
                ]
            )
        print(
            _render_table(
                ["ECOSYSTEM", "COMPONENT", "VERSION", "TAGS", "SIGNATURE", "VULN_STATUS", "CVSS", "CVES", "CLAMAV"],
                active_rows,
            )
        )
    else:
        print("  (empty)")

    quarantined = report.get("quarantined") or []
    print(f"\n[Quarantined (Vulnerable)] (count={len(quarantined)})")
    if quarantined:
        q_rows = []
        for q in quarantined:
            cves = ",".join(q.get("cve_ids") or []) or "none"
            q_rows.append(
                [
                    str(q.get("ecosystem", "")),
                    str(q.get("component", "")),
                    str(q.get("version", "")),
                    str(q.get("status", "QUARANTINED")),
                    f"{float(q.get('max_cvss', 0.0) or 0.0):.1f}",
                    cves,
                    str(q.get("superseded_by") or "-"),
                ]
            )
        print(
            _render_table(
                ["ECOSYSTEM", "COMPONENT", "VERSION", "STATUS", "MAX_CVSS", "FAILING_CVES", "LATEST_REPLACEMENT"],
                q_rows,
            )
        )
    else:
        print("  (none)")

    history = report.get("history") or []
    print(f"\n[Component Caching History & Active 'latest' Resolution] (components={len(history)})")
    if history:
        h_rows = []
        for bucket in history:
            eco = str(bucket.get("ecosystem", ""))
            comp = str(bucket.get("component", ""))
            for ver in bucket.get("versions", []):
                cves = ",".join(ver.get("cve_ids") or []) or "none"
                ts = str(ver.get("timestamp", ""))[:19] or "-"
                h_rows.append(
                    [
                        eco,
                        comp,
                        str(ver.get("version", "")),
                        str(ver.get("state", "")),
                        str(ver.get("vulnerability_status", "")),
                        f"{float(ver.get('max_cvss', 0.0) or 0.0):.1f}",
                        cves,
                        ts,
                    ]
                )
        print(
            _render_table(
                ["ECOSYSTEM", "COMPONENT", "VERSION", "STATE", "VULN_STATUS", "CVSS", "CVES", "TIMESTAMP"],
                h_rows,
            )
        )
    else:
        print("  (empty)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Catalog all cached components and per-version vulnerability status via frontend HTTP endpoints."
    )
    parser.add_argument(
        "--url",
        default=os.getenv("GATEKEEPER_URL", "http://127.0.0.1:8080"),
        help="Frontend Gateway or Gatekeeper base URL (default: http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("GATEKEEPER_ADMIN_TOKEN", ""),
        help="Optional X-Gatekeeper-Token header",
    )
    parser.add_argument(
        "--ecosystem",
        default="all",
        help="Comma-separated component types to scan/filter: oci,maven,pypi or all (default: all)",
    )
    parser.add_argument(
        "--components",
        default="",
        help="Comma-separated component names/substrings to filter (e.g. requests,spring-boot-starter-web)",
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="Force POST /catalog/remediate CVE rescan/auto-upgrade before listing",
    )
    parser.add_argument(
        "--scan-unscanned",
        action="store_true",
        help="Force scanning of only UNSCANNED cached components (POST /catalog/remediate?only_unscanned=true)",
    )
    parser.add_argument(
        "--gc",
        action="store_true",
        help="Force N-2+ version garbage collection (POST /catalog/gc)",
    )
    parser.add_argument(
        "--gc-dry-run",
        action="store_true",
        help="Preview N-2+ garbage collection without deleting files",
    )
    parser.add_argument(
        "--gc-keep",
        type=int,
        default=None,
        help="Override number of newest versions to keep during --gc (default: server GC_RETENTION_VERSIONS=2)",
    )
    parser.add_argument(
        "--activity",
        action="store_true",
        help="Show scheduled task, rescan, quarantine, and GC activity log events (GET /audit/activity)",
    )
    parser.add_argument(
        "--activity-limit",
        type=int,
        default=50,
        help="Maximum number of recent activity events to display (default: 50)",
    )
    parser.add_argument(
        "--activity-event",
        default="",
        help="Comma-separated activity event filter (e.g. HOURLY_CVE_RESCAN,GC_REMOVED,QUARANTINED)",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for async engine job to finish when --remediate, --scan-unscanned, or --gc is used",
    )
    parser.add_argument("--ca-bundle", default="", help="Path to custom CA certificate bundle")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    parser.add_argument("--json", action="store_true", help="Output JSON inventory")
    args = parser.parse_args()

    try:
        report = catalog_frontend(
            args.url,
            ca_bundle=args.ca_bundle,
            insecure=args.insecure,
            token=args.token,
            ecosystem=args.ecosystem,
            components_filter=args.components,
            remediate=args.remediate,
            scan_unscanned=args.scan_unscanned,
            gc=args.gc,
            gc_dry_run=args.gc_dry_run,
            gc_keep=args.gc_keep,
            activity=args.activity,
            activity_limit=args.activity_limit,
            activity_event=args.activity_event,
            wait=args.wait,
        )
    except Exception as exc:
        print(f"[ERROR] Could not reach frontend at {args.url}: {exc}")
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
