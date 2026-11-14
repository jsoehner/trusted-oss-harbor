#!/usr/bin/env python3
"""Frontend HTTP catalog inventory (queries Gatekeeper/Gateway HTTP endpoints only)."""

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
    timeout: float = 10.0,
    ssl_ctx: ssl.SSLContext | None = None,
    token: str = "",
) -> dict[str, Any]:
    headers = {"X-Gatekeeper-Token": token} if token else {}
    req = urllib.request.Request(url, method="GET", headers=headers)
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


def catalog_frontend(
    base_url: str,
    ca_bundle: str = "",
    insecure: bool = False,
    token: str = "",
) -> dict[str, Any]:
    """Query frontend HTTP endpoints and return a structured catalog report."""
    base = base_url.rstrip("/")
    ssl_ctx = _build_ssl_context(ca_bundle=ca_bundle, insecure=insecure)
    health = _get_json(f"{base}/healthz", ssl_ctx=ssl_ctx, token=token)
    status = _get_json(f"{base}/catalog/status", ssl_ctx=ssl_ctx, token=token)
    provenance = _get_json(f"{base}/audit/provenance", ssl_ctx=ssl_ctx, token=token)

    gpg_ok, _ = _head_or_get_ok(f"{base}/keys/trusted-oss-pubkey.asc", ssl_ctx=ssl_ctx, token=token)
    mldsa_ok, _ = _head_or_get_ok(f"{base}/keys/trusted-oss-mldsa65.pub", ssl_ctx=ssl_ctx, token=token)
    mldsa_fp_ok, mldsa_fp_body = _head_or_get_ok(
        f"{base}/keys/trusted-oss-mldsa65.fingerprint", ssl_ctx=ssl_ctx, token=token
    )

    oci_items = status.get("chainguard_containers", [])
    maven_items = status.get("spring_boot_components", [])
    pypi_items = status.get("pypi_components", [])

    cached_oci = [i for i in oci_items if i.get("cached")]
    cached_maven = [i for i in maven_items if i.get("cached")]
    cached_pypi = [i for i in pypi_items if i.get("cached")]

    return {
        "frontend_url": base,
        "health": health,
        "keys": {
            "gpg_public_key": gpg_ok,
            "mldsa65_public_key": mldsa_ok,
            "mldsa65_fingerprint": mldsa_fp_body.splitlines()[0] if mldsa_fp_ok and mldsa_fp_body else "",
        },
        "counts": {
            "oci_cached": len(cached_oci),
            "oci_catalog_total": len(oci_items),
            "maven_cached": len(cached_maven),
            "maven_catalog_total": len(maven_items),
            "pypi_cached": len(cached_pypi),
            "pypi_catalog_total": len(pypi_items),
            "provenance_records": provenance.get("count", 0),
        },
        "oci": oci_items,
        "maven": maven_items,
        "pypi": pypi_items,
    }


def _print_report(report: dict[str, Any]) -> None:
    health = report["health"]
    keys = report["keys"]
    c = report["counts"]
    print(f"Frontend Gateway URL : {report['frontend_url']} (status={health.get('status', 'unknown')})")
    print(
        f"Signing Keys         : GPG={'ready' if keys['gpg_public_key'] else 'missing'}, "
        f"ML-DSA-65={'ready' if keys['mldsa65_public_key'] else 'missing'}"
        + (f" ({keys['mldsa65_fingerprint']})" if keys["mldsa65_fingerprint"] else "")
    )
    print(f"Policy Threshold     : CVSS >= {health.get('cvss_fail_threshold', 'N/A')}")
    print(
        f"Cached Components    : OCI={c['oci_cached']}/{c['oci_catalog_total']} | "
        f"Maven={c['maven_cached']}/{c['maven_catalog_total']} | "
        f"PyPI={c['pypi_cached']}/{c['pypi_catalog_total']} | "
        f"Provenance={c['provenance_records']}"
    )

    for section, label, key_field in (
        ("oci", "OCI / Harbor Cache", "image"),
        ("maven", "Trusted Maven", "artifact"),
        ("pypi", "Trusted PyPI", "package"),
    ):
        items = report[section]
        cached_only = [i for i in items if i.get("cached")]
        print(f"\n[{label}] (cached={len(cached_only)} / catalog={len(items)})")
        if not cached_only:
            print("  (empty)")
        for item in cached_only:
            sig = "GPG-VALID" if item.get("signature_valid") else "UNSIGNED/INVALID"
            print(f"  - {item.get(key_field)} ({sig})")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Catalog warmed-up components using only frontend Gatekeeper/Gateway HTTP endpoints."
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
        )
    except Exception as exc:
        print(f"[ERROR] Could not reach frontend at {args.url}: {exc}", file=sys.stderr if hasattr(sys, "stderr") else None)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main())
