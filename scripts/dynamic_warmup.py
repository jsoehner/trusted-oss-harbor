#!/usr/bin/env python3
"""Dynamic component discovery and cache warmup CLI for trusted-oss-harbor."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "gatekeeper"))

from app.discovery import discover_github_projects, discover_local_projects, merge_catalogs  # noqa: E402


async def run_discovery(
    roots: list[Path],
    include_github: bool,
    github_user: str,
    github_token: str,
    max_projects: int,
    seed_path: Path,
) -> dict:
    base_catalog = json.loads(seed_path.read_text(encoding="utf-8")) if seed_path.is_file() else {}
    discovered = discover_local_projects(roots, max_projects=max_projects)
    if include_github:
        gh_discovered = await discover_github_projects(
            username=github_user,
            token=github_token,
            max_repos=max_projects,
        )
        discovered = merge_catalogs(discovered, gh_discovered)
    return merge_catalogs(base_catalog, discovered)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discover components across recent projects and dynamically warm Trusted OSS Harbor caches."
    )
    parser.add_argument(
        "--roots",
        nargs="*",
        default=[str(Path.home())],
        help="Local workspace root directories to scan for project manifests (default: $HOME)",
    )
    parser.add_argument("--github", action="store_true", help="Also query GitHub API for recent repositories")
    parser.add_argument("--github-user", default=os.getenv("GITHUB_USERNAME", "jsoehner"))
    parser.add_argument("--max-projects", type=int, default=30)
    parser.add_argument(
        "--seed-catalog",
        type=Path,
        default=REPO_ROOT / "config" / "catalog" / "trusted-seed-catalog.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSON path to write the merged catalog",
    )
    parser.add_argument(
        "--update-seed",
        action="store_true",
        help="Update config/catalog/trusted-seed-catalog.json in place with discovered components",
    )
    parser.add_argument(
        "--warm",
        action="store_true",
        help="Send the discovered catalog to Gatekeeper POST /catalog/warm",
    )
    parser.add_argument(
        "--gatekeeper-url",
        default=os.getenv("GATEKEEPER_URL", "http://127.0.0.1:8080"),
    )
    parser.add_argument(
        "--token",
        default=os.getenv("GATEKEEPER_ADMIN_TOKEN", "ChangeMe_GatekeeperToken_2026!"),
    )
    args = parser.parse_args()

    catalog = asyncio.run(
        run_discovery(
            roots=[Path(r) for r in args.roots],
            include_github=args.github,
            github_user=args.github_user,
            github_token=os.getenv("GITHUB_TOKEN", ""),
            max_projects=args.max_projects,
            seed_path=args.seed_catalog,
        )
    )

    print(
        f"[DISCOVER] Projects={len(catalog.get('source_projects', []))} "
        f"Chainguard={len(catalog.get('chainguard_containers', []))} "
        f"OCI={len(catalog.get('oci_containers', []))} "
        f"Maven={len(catalog.get('spring_boot_maven_components', []))} "
        f"PyPI={len(catalog.get('pypi_components', []))}"
    )

    if args.update_seed:
        args.seed_catalog.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        print(f"[SAVED] Updated seed catalog: {args.seed_catalog}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        print(f"[SAVED] Wrote discovered catalog: {args.output}")

    if args.warm:
        endpoint = f"{args.gatekeeper_url.rstrip('/')}/catalog/discover"
        resp = httpx.post(
            endpoint,
            headers={"X-Gatekeeper-Token": args.token},
            json={
                "scan_roots": args.roots,
                "include_github": args.github,
                "github_username": args.github_user,
                "max_projects": args.max_projects,
                "save_to_catalog": True,
                "warm": True,
            },
            timeout=300.0,
        )
        if resp.status_code >= 400:
            print(f"[ERROR] {endpoint} returned {resp.status_code}: {resp.text[:1000]}")
            return 1
        summary = resp.json().get("warmup") or {}
        print(
            f"[WARM] OCI={summary.get('chainguard_containers_cached', 0)} "
            f"Maven={summary.get('spring_boot_artifacts_cached', 0)} "
            f"PyPI={summary.get('pypi_artifacts_cached', 0)} "
            f"Failures={summary.get('failures_count', 0)}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
