#!/usr/bin/env python3
"""Cache primer CLI for Trusted OSS Harbor.

Scans local projects (default: $HOME) for Maven, PyPI, and OCI/Chainguard
dependencies, compares them against the live gateway's cached inventory,
reports which components are already cached vs. which will be queued and
fetched, and optionally triggers POST /catalog/warm for missing items.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
GATEKEEPER_DIR = REPO_ROOT / "gatekeeper"
if str(GATEKEEPER_DIR) not in sys.path:
    sys.path.insert(0, str(GATEKEEPER_DIR))

from app.discovery import discover_local_projects  # noqa: E402


def _http_json(
    url: str,
    *,
    method: str = "GET",
    token: str = "",
    payload: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, Any]]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Unsupported URL scheme: {url!r}")
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Gatekeeper-Token"] = token
    data: bytes | None = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    fmt = "| " + " | ".join(f"{{:<{w}}}" for w in widths) + " |"
    out = [sep, fmt.format(*headers), sep]
    for row in rows:
        out.append(fmt.format(*row))
    out.append(sep)
    return "\n".join(out)


def _build_cached_index(
    vuln_data: dict[str, Any],
) -> tuple[dict[tuple[str, str, str], str], dict[tuple[str, str], tuple[str, str]]]:
    """Return exact (eco, comp, ver)->status and (eco, comp)->(ver, status) maps."""
    exact: dict[tuple[str, str, str], str] = {}
    by_comp: dict[tuple[str, str], tuple[str, str]] = {}
    for item in vuln_data.get("components", []):
        eco = str(item.get("ecosystem", "")).lower()
        comp = str(item.get("component", "")).lower()
        ver = str(item.get("version", "")).lower()
        status = str(item.get("vulnerability_status", "CLEAN"))
        exact[(eco, comp, ver)] = status
        by_comp[(eco, comp)] = (str(item.get("version", "")), status)
        if eco == "oci":
            short_comp = comp.split("/", 1)[-1] if "/" in comp else comp
            exact[(eco, short_comp, ver)] = status
            by_comp[(eco, short_comp)] = (str(item.get("version", "")), status)
    for q in vuln_data.get("quarantined", []):
        eco = str(q.get("ecosystem", "")).lower()
        comp = str(q.get("component", "")).lower()
        ver = str(q.get("version", "")).lower()
        exact[(eco, comp, ver)] = "QUARANTINED"
    return exact, by_comp


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan local projects for dependencies, report cached vs. missing, and prime the cache."
    )
    parser.add_argument(
        "--roots",
        nargs="*",
        default=[str(Path.home())],
        help="Workspace directories to scan (default: $HOME)",
    )
    parser.add_argument(
        "--max-projects",
        type=int,
        default=100,
        help="Maximum projects to scan under --roots (default: 100)",
    )
    parser.add_argument(
        "--url",
        default=os.getenv("GATEKEEPER_URL", os.getenv("HARBOR_URL", "http://127.0.0.1:8080")),
        help="Gateway base URL (default: GATEKEEPER_URL, HARBOR_URL, or http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("GATEKEEPER_ADMIN_TOKEN", ""),
        help="Admin token for POST /catalog/warm (default: GATEKEEPER_ADMIN_TOKEN)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report already-cached vs. missing components without queuing fetches",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for the warmup job to finish synchronously (?wait=true)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base = args.url.rstrip("/")

    discovered = discover_local_projects(
        [Path(r).expanduser() for r in args.roots],
        max_projects=args.max_projects,
    )

    try:
        _, vuln_data = _http_json(f"{base}/catalog/vulnerabilities", token=args.token)
    except urllib.error.HTTPError as exc:
        print(f"ERROR: Gateway returned HTTP {exc.code}: {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"ERROR: Could not reach {base}: {exc.reason}", file=sys.stderr)
        return 1

    exact_index, by_comp_index = _build_cached_index(vuln_data)
    already_cached: list[dict[str, str]] = []
    to_fetch_maven: list[dict[str, Any]] = []
    to_fetch_pypi: list[dict[str, Any]] = []
    to_fetch_chainguard: list[dict[str, Any]] = []
    to_fetch_oci: list[dict[str, Any]] = []
    to_fetch_rows: list[dict[str, str]] = []

    for item in discovered.get("spring_boot_maven_components", []):
        g = str(item.get("groupId") or item.get("group_id") or "")
        a = str(item.get("artifactId") or item.get("artifact_id") or "")
        v = str(item.get("version") or "")
        projects = ", ".join(item.get("projects") or [])
        comp = f"{g}:{a}"
        key = ("maven", comp.lower(), v.lower())
        if key in exact_index:
            already_cached.append(
                {
                    "ecosystem": "maven",
                    "component": comp,
                    "version": v,
                    "status": exact_index[key],
                    "projects": projects,
                }
            )
        else:
            to_fetch_maven.append(item)
            to_fetch_rows.append(
                {"ecosystem": "maven", "component": comp, "version": v or "(unpinned)", "projects": projects}
            )

    for item in discovered.get("pypi_components", []):
        name = str(item.get("name") or "")
        pinned = str(item.get("pinned_version") or item.get("version") or "")
        spec = str(item.get("spec") or "")
        projects = ", ".join(item.get("projects") or [])
        norm_name = name.lower().replace("_", "-")
        if pinned:
            status = exact_index.get(("pypi", norm_name, pinned.lower())) or exact_index.get(
                ("pypi", name.lower(), pinned.lower())
            )
            matched_ver = pinned
        else:
            hit = by_comp_index.get(("pypi", norm_name)) or by_comp_index.get(("pypi", name.lower()))
            matched_ver, status = hit if hit else (spec or "latest", "")
        if status:
            already_cached.append(
                {
                    "ecosystem": "pypi",
                    "component": name,
                    "version": matched_ver,
                    "status": status,
                    "projects": projects,
                }
            )
        else:
            to_fetch_pypi.append(item)
            to_fetch_rows.append(
                {
                    "ecosystem": "pypi",
                    "component": name,
                    "version": pinned or spec or "latest",
                    "projects": projects,
                }
            )

    for key_name, bucket in (
        ("chainguard_containers", to_fetch_chainguard),
        ("oci_containers", to_fetch_oci),
    ):
        for item in discovered.get(key_name, []):
            reg = str(item.get("registry") or "")
            repo = str(item.get("repository") or "")
            ref = str(item.get("reference") or "latest")
            projects = ", ".join(item.get("projects") or [])
            full_repo = f"{reg}/{repo}" if reg else repo
            status = (
                exact_index.get(("oci", full_repo.lower(), ref.lower()))
                or exact_index.get(("oci", repo.lower(), ref.lower()))
            )
            if status:
                already_cached.append(
                    {
                        "ecosystem": "oci",
                        "component": full_repo,
                        "version": ref,
                        "status": status,
                        "projects": projects,
                    }
                )
            else:
                bucket.append(item)
                to_fetch_rows.append(
                    {"ecosystem": "oci", "component": full_repo, "version": ref, "projects": projects}
                )

    warm_result: dict[str, Any] | None = None
    if not args.dry_run and to_fetch_rows:
        if not args.token:
            print(
                "ERROR: GATEKEEPER_ADMIN_TOKEN (or --token) is required to queue cache fetches. "
                "Re-run with --dry-run to preview only.",
                file=sys.stderr,
            )
            return 2
        wait_q = "?wait=true" if args.wait else ""
        status_code, warm_result = _http_json(
            f"{base}/catalog/warm{wait_q}",
            method="POST",
            token=args.token,
            payload={
                "spring_boot_maven_components": to_fetch_maven,
                "pypi_components": to_fetch_pypi,
                "chainguard_containers": to_fetch_chainguard,
                "oci_containers": to_fetch_oci,
            },
            timeout=300.0 if args.wait else 30.0,
        )
        warm_result["_http_status"] = status_code

    if args.json:
        print(
            json.dumps(
                {
                    "gateway_url": base,
                    "projects_scanned": len(discovered.get("source_projects", [])),
                    "source_projects": discovered.get("source_projects", []),
                    "already_cached_count": len(already_cached),
                    "to_fetch_count": len(to_fetch_rows),
                    "already_cached": already_cached,
                    "to_fetch": to_fetch_rows,
                    "warm_result": warm_result,
                },
                indent=2,
            )
        )
        return 0

    print(f"Gateway URL       : {base}")
    print(f"Projects Scanned  : {len(discovered.get('source_projects', []))} (under {', '.join(args.roots)})")
    print(
        f"Component Summary : Discovered={len(already_cached) + len(to_fetch_rows)} | "
        f"Already Cached={len(already_cached)} | "
        f"{'Would Queue' if args.dry_run else 'Queued to Fetch'}={len(to_fetch_rows)}"
    )

    print(f"\n[Already Cached] ({len(already_cached)})")
    if already_cached:
        print(
            _render_table(
                ["ECOSYSTEM", "COMPONENT", "VERSION", "CACHE_STATUS", "PROJECTS"],
                [
                    [r["ecosystem"], r["component"], r["version"], r["status"], r["projects"]]
                    for r in already_cached
                ],
            )
        )
    else:
        print("  (none)")

    label = "[Will Be Queued & Fetched]" if args.dry_run else "[Queued & Fetched]"
    print(f"\n{label} ({len(to_fetch_rows)})")
    if to_fetch_rows:
        print(
            _render_table(
                ["ECOSYSTEM", "COMPONENT", "VERSION", "PROJECTS"],
                [
                    [r["ecosystem"], r["component"], r["version"], r["projects"]]
                    for r in to_fetch_rows
                ],
            )
        )
    else:
        print("  (all discovered components are already cached!)")

    if warm_result is not None:
        http_code = warm_result.get("_http_status")
        job_id = warm_result.get("job_id")
        if job_id:
            print(f"\n[Warmup Job Enqueued] http={http_code} job_id={job_id} status={warm_result.get('status')}")
        else:
            print(f"\n[Warmup Completed] http={http_code} status={warm_result.get('status')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
