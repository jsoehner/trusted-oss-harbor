#!/usr/bin/env python3
"""Frontend HTTP catalog and per-version vulnerability inventory."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import urllib.error
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
    timeout: float = 15.0,
    ssl_ctx: ssl.SSLContext | None = None,
    token: str = "",
) -> dict[str, Any]:
    headers = {"X-Gatekeeper-Token": token} if token else {}
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_json(
    url: str,
    timeout: float = 120.0,
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


def catalog_frontend(
    base_url: str,
    ca_bundle: str = "",
    insecure: bool = False,
    token: str = "",
    ecosystem: str = "all",
    remediate: bool = True,
) -> dict[str, Any]:
    """Optionally remediate newly vulnerable cached versions, then return per-version inventory."""
    base = base_url.rstrip("/")
    ssl_ctx = _build_ssl_context(ca_bundle=ca_bundle, insecure=insecure)

    remediation_result: dict[str, Any] | None = None
    if remediate and token:
        try:
            remediation_result = _post_json(
                f"{base}/catalog/remediate", ssl_ctx=ssl_ctx, token=token
            )
        except urllib.error.HTTPError as exc:
            if exc.code not in (404, 403, 503):
                raise

    health = _get_json(f"{base}/healthz", ssl_ctx=ssl_ctx, token=token)
    status = _get_json(f"{base}/catalog/status", ssl_ctx=ssl_ctx, token=token)
    provenance = _get_json(f"{base}/audit/provenance", ssl_ctx=ssl_ctx, token=token)

    try:
        vuln_data = _get_json(f"{base}/catalog/vulnerabilities", ssl_ctx=ssl_ctx, token=token)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
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
    if ecosystem != "all":
        components = [c for c in components if c.get("ecosystem") == ecosystem]
        quarantined = [q for q in quarantined if q.get("ecosystem") == ecosystem]

    return {
        "frontend_url": base,
        "health": health,
        "remediation": remediation_result,
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
    }


def _print_report(report: dict[str, Any]) -> None:
    health = report["health"]
    keys = report["keys"]
    c = report["counts"]
    vs = report["vulnerability_summary"]

    print(f"Frontend Gateway URL : {report['frontend_url']} (status={health.get('status', 'unknown')})")
    print(
        f"Signing Keys         : GPG={'ready' if keys['gpg_public_key'] else 'missing'}, "
        f"ML-DSA-65={'ready' if keys['mldsa65_public_key'] else 'missing'}"
        + (f" ({keys['mldsa65_fingerprint']})" if keys["mldsa65_fingerprint"] else "")
    )
    print(f"Policy Threshold     : CVSS >= {health.get('cvss_fail_threshold', 'N/A')}")
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
    if rem and (rem.get("quarantined_count") or rem.get("upgraded_count")):
        print(
            f"Auto-Remediation     : quarantined={rem.get('quarantined_count', 0)}, "
            f"upgraded_to_latest={rem.get('upgraded_count', 0)}"
        )

    for eco, label in (("oci", "OCI / Harbor Cache"), ("maven", "Trusted Maven"), ("pypi", "Trusted PyPI")):
        rows = [item for item in report["components"] if item.get("ecosystem") == eco]
        print(f"\n[{label}] (cached={len(rows)})")
        if not rows:
            print("  (empty)")
            continue
        for item in rows:
            sig = "GPG-VALID" if item.get("signature_valid") else "UNSIGNED"
            pqc = "+PQC" if item.get("pqc_signed") else ""
            tags = item.get("tags") or []
            tag_str = f" [tag:{','.join(tags)}]" if tags else ""
            vstat = item.get("vulnerability_status", "UNSCANNED")
            cve_status = item.get("cve_status", "UNKNOWN")
            cvss = float(item.get("max_cvss", 0.0) or 0.0)
            cves = ",".join(item.get("cve_ids") or []) or "none"
            print(
                f"  - {item.get('component')}@{item.get('version')}{tag_str} "
                f"[{sig}{pqc}] vuln={vstat} (scanner={cve_status}, max_cvss={cvss:.1f}, cves={cves}) "
                f"clamav={item.get('clamav_status', 'UNKNOWN')}"
            )

    quarantined = report.get("quarantined") or []
    print(f"\n[Quarantined (Vulnerable)] (count={len(quarantined)})")
    if not quarantined:
        print("  (none)")
    for q in quarantined:
        cves = ",".join(q.get("cve_ids") or []) or "none"
        cvss = float(q.get("max_cvss", 0.0) or 0.0)
        sup = f" -> superseded_by={q['superseded_by']} (tag:latest)" if q.get("superseded_by") else ""
        print(
            f"  - [{q.get('ecosystem')}] {q.get('component')}@{q.get('version')} "
            f"[QUARANTINED] max_cvss={cvss:.1f} failing_cves={cves}{sup}"
        )


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
        choices=("all", "oci", "maven", "pypi"),
        default="all",
        help="Filter output to a specific ecosystem (default: all)",
    )
    parser.add_argument(
        "--no-remediate",
        action="store_true",
        help="Skip POST /catalog/remediate CVE rescan/auto-upgrade before listing",
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
            remediate=not args.no_remediate,
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
