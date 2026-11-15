#!/usr/bin/env python3
"""Configure a local/downloaded repository to use public upstream repos (default)
or opt into a Trusted OSS Harbor / Gatekeeper cache via a single URL variable.

Usage examples:
  # Interactive prompt when setting up a freshly downloaded repo
  python3 scripts/configure_trusted_cache.py --repo /path/to/my-repo --interactive

  # Point a repo (Maven, Python uv/pip, .env, Docker) to your trusted cache
  python3 scripts/configure_trusted_cache.py --repo /path/to/my-repo --url https://oss.yourdomain.com

  # Revert a repo back to public upstream repositories (Maven Central, PyPI, cgr.dev)
  python3 scripts/configure_trusted_cache.py --repo /path/to/my-repo --public
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PUBLIC_MAVEN_URL = "https://repo.maven.apache.org/maven2"
PUBLIC_PYPI_URL = "https://pypi.org/simple"
PUBLIC_BASE_IMAGE = "cgr.dev/chainguard/wolfi-base:latest"

MAVEN_SETTINGS_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 https://maven.apache.org/xsd/settings-1.2.0.xsd">
  <!-- Managed by trusted-oss-harbor configure_trusted_cache.py -->
  <mirrors>
    <mirror>
      <id>trusted-oss-harbor</id>
      <name>Trusted OSS Supply Chain Cache</name>
      <url>{maven_url}</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
"""


def normalize_cache_url(raw_url: str) -> str:
    url = raw_url.strip().rstrip("/")
    if url and "://" not in url:
        url = f"https://{url}"
    return url


def _update_env_file(env_path: Path, updates: dict[str, str], remove_keys: set[str] | None = None, dry_run: bool = False) -> str:
    remove_keys = remove_keys or set()
    existing_lines: list[str] = []
    if env_path.exists():
        existing_lines = env_path.read_text(encoding="utf-8").splitlines()

    seen: set[str] = set()
    new_lines: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in remove_keys:
            continue
        if key in updates:
            new_lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            new_lines.append(line)

    for key, value in updates.items():
        if key not in seen:
            new_lines.append(f"{key}={value}")

    content = "\n".join(new_lines).rstrip() + "\n"
    if not dry_run:
        env_path.write_text(content, encoding="utf-8")
    return "updated" if env_path.exists() else "created"


def configure_repository(
    repo_dir: Path,
    cache_url: str | None,
    mode: str = "virtual",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Configure a single repository for either a trusted cache URL or public upstream repos."""
    repo_dir = repo_dir.resolve()
    actions: list[str] = []
    normalized_url = normalize_cache_url(cache_url or "")
    use_public = not bool(normalized_url)

    has_maven = (repo_dir / "pom.xml").exists() or (repo_dir / "build.gradle").exists() or (repo_dir / ".mvn").exists()
    has_python = (
        (repo_dir / "pyproject.toml").exists()
        or (repo_dir / "requirements.txt").exists()
        or (repo_dir / "uv.toml").exists()
    )
    has_docker = (repo_dir / "Dockerfile").exists() or (repo_dir / "docker-compose.yml").exists()

    if use_public:
        mvn_settings = repo_dir / ".mvn" / "settings.xml"
        mvn_config = repo_dir / ".mvn" / "maven.config"
        if mvn_settings.exists():
            if not dry_run:
                mvn_settings.unlink()
            actions.append("removed .mvn/settings.xml (reverted to public Maven Central)")
        if mvn_config.exists() and mvn_config.read_text(encoding="utf-8").strip() == "-s .mvn/settings.xml":
            if not dry_run:
                mvn_config.unlink()
            actions.append("removed .mvn/maven.config")

        uv_toml = repo_dir / "uv.toml"
        if uv_toml.exists() and "Managed by trusted-oss-harbor" in uv_toml.read_text(encoding="utf-8"):
            if not dry_run:
                uv_toml.unlink()
            actions.append("removed managed uv.toml (reverted to public PyPI)")

        env_path = repo_dir / ".env"
        if env_path.exists():
            _update_env_file(
                env_path,
                updates={"BASE_IMAGE": PUBLIC_BASE_IMAGE},
                remove_keys={"TRUSTED_OSS_CACHE_URL", "TRUSTED_OSS_MODE", "PIP_INDEX_URL", "UV_INDEX_URL"},
                dry_run=dry_run,
            )
            actions.append("cleared TRUSTED_OSS_CACHE_URL/PIP_INDEX_URL/UV_INDEX_URL in .env")

        return {
            "repo": str(repo_dir),
            "target": "public",
            "cache_url": None,
            "detected": {"maven": has_maven, "python": has_python, "docker": has_docker},
            "actions": actions or ["no changes needed (already using public upstream repos)"],
        }

    # Trusted cache configuration
    maven_url = f"{normalized_url}/maven/{mode}"
    pypi_url = f"{normalized_url}/pypi/{mode}/simple"
    parsed = urlparse(normalized_url)
    registry_host = parsed.netloc or normalized_url
    base_image = f"{registry_host}/v2/{mode}/chainguard/wolfi-base:latest"

    if has_maven:
        mvn_dir = repo_dir / ".mvn"
        if not dry_run:
            mvn_dir.mkdir(parents=True, exist_ok=True)
            (mvn_dir / "settings.xml").write_text(
                MAVEN_SETTINGS_TEMPLATE.format(maven_url=maven_url),
                encoding="utf-8",
            )
            (mvn_dir / "maven.config").write_text("-s .mvn/settings.xml\n", encoding="utf-8")
        actions.append(f"configured .mvn/settings.xml & .mvn/maven.config -> {maven_url}")

    if has_python:
        uv_content = (
            "# Managed by trusted-oss-harbor configure_trusted_cache.py\n"
            f'index-url = "{pypi_url}"\n'
            "no-build = true\n"
        )
        if not dry_run:
            (repo_dir / "uv.toml").write_text(uv_content, encoding="utf-8")
        actions.append(f"configured uv.toml -> {pypi_url}")

    env_updates = {
        "TRUSTED_OSS_CACHE_URL": normalized_url,
        "TRUSTED_OSS_MODE": mode,
    }
    if has_python:
        env_updates["PIP_INDEX_URL"] = pypi_url
        env_updates["UV_INDEX_URL"] = pypi_url
    if has_docker:
        env_updates["BASE_IMAGE"] = base_image

    env_status = _update_env_file(repo_dir / ".env", updates=env_updates, dry_run=dry_run)
    actions.append(f"{env_status} .env with TRUSTED_OSS_CACHE_URL={normalized_url}")

    return {
        "repo": str(repo_dir),
        "target": "trusted_cache",
        "cache_url": normalized_url,
        "mode": mode,
        "detected": {"maven": has_maven, "python": has_python, "docker": has_docker},
        "actions": actions,
    }


def configure_github_variable(
    github_repo: str,
    cache_url: str | None,
    mode: str = "virtual",
    dry_run: bool = False,
) -> list[str]:
    actions: list[str] = []
    normalized = normalize_cache_url(cache_url or "")
    if not normalized:
        cmd = ["gh", "variable", "delete", "TRUSTED_OSS_CACHE_URL", "-R", github_repo]
        if not dry_run:
            subprocess.run(cmd, check=False, capture_output=True, text=True)
        actions.append(f"deleted GitHub Actions variable TRUSTED_OSS_CACHE_URL on {github_repo} (public default)")
        return actions

    for name, val in [("TRUSTED_OSS_CACHE_URL", normalized), ("TRUSTED_OSS_MODE", mode)]:
        cmd = ["gh", "variable", "set", name, "--body", val, "-R", github_repo]
        if not dry_run:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        actions.append(f"set GitHub Actions variable {name}={val} on {github_repo}")
    return actions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Switch a repository between public upstream OSS repos (default) and a Trusted OSS Cache URL."
    )
    parser.add_argument(
        "--repo",
        action="append",
        default=[],
        help="Target repository path (repeatable; defaults to current directory)",
    )
    parser.add_argument(
        "--url",
        default=os.getenv("TRUSTED_OSS_CACHE_URL", ""),
        help="Trusted OSS Cache base URL (e.g. https://oss.yourdomain.com or http://oss.jsigroup.local:8080)",
    )
    parser.add_argument(
        "--mode",
        choices=["virtual", "trusted"],
        default=os.getenv("TRUSTED_OSS_MODE", "virtual"),
        help="Cache route mode: 'virtual' (pull-through + scan, default) or 'trusted' (pre-signed only)",
    )
    parser.add_argument(
        "--public",
        action="store_true",
        help="Reset repository configuration to use public upstream repos (Maven Central, PyPI, cgr.dev)",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt the user to choose public upstream repos (default) or enter a Trusted OSS Cache URL",
    )
    parser.add_argument(
        "--github-repo",
        default="",
        help="Optional GitHub repo (owner/name) to set/delete TRUSTED_OSS_CACHE_URL via gh CLI",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying files or GitHub variables",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON summary",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repos = [Path(r) for r in args.repo] if args.repo else [Path.cwd()]

    selected_url = "" if args.public else args.url
    if args.interactive and not args.public:
        print("Select OSS repository source for this project:")
        print("  [1] Public upstream repositories (Maven Central, PyPI, Docker Hub / cgr.dev) [default]")
        print("  [2] Trusted OSS Cache URL (self-hosted Harbor / Gatekeeper)")
        choice = input("Choice [1]: ").strip() or "1"
        if choice == "2":
            default_hint = selected_url or "https://oss.yourdomain.com"
            entered = input(f"Enter Trusted OSS Cache URL [{default_hint}]: ").strip()
            selected_url = entered or default_hint
        else:
            selected_url = ""

    results = [
        configure_repository(repo, cache_url=selected_url, mode=args.mode, dry_run=args.dry_run)
        for repo in repos
    ]

    gh_actions: list[str] = []
    if args.github_repo:
        gh_actions = configure_github_variable(
            args.github_repo, cache_url=selected_url, mode=args.mode, dry_run=args.dry_run
        )

    if args.json:
        print(json.dumps({"repositories": results, "github_actions": gh_actions, "dry_run": args.dry_run}, indent=2))
        return 0

    prefix = "[DRY-RUN] " if args.dry_run else ""
    for res in results:
        print(f"{prefix}Repository: {res['repo']} -> target={res['target']}")
        for act in res["actions"]:
            print(f"  - {act}")
    for act in gh_actions:
        print(f"{prefix}GitHub: {act}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
