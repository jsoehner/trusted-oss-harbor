"""Automated CVE remediation, vulnerable artifact quarantine, and 'latest' tag management."""

from __future__ import annotations

import datetime
import json
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import httpx

from app.activity import append_activity_event
from app.config import Settings
from app.virtual_repo import extract_package_coordinates

logger = logging.getLogger("gatekeeper.remediation")

_ARTIFACT_SIDECARS = ("", ".asc", ".mldsa65", ".sha256", ".sha384", ".sha512", ".metadata.json")


def version_sort_key(version: str) -> tuple[tuple[int, int, str], ...]:
    """Convert a version string into a sortable tuple (newest-first when reversed)."""
    parts = re.split(r"[.\-_+]", version.strip())
    key: list[tuple[int, int, str]] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            key.append((1, int(part), ""))
        else:
            m = re.match(r"^(\d+)(.*)$", part)
            if m:
                key.append((1, int(m.group(1)), m.group(2).lower()))
            else:
                key.append((0, 0, part.lower()))
    return tuple(key)


async def fetch_upstream_maven_versions(
    upstream_urls: list[str],
    group_id: str,
    artifact_id: str,
) -> list[str]:
    """Fetch candidate versions from upstream Maven metadata, ordered newest-first."""
    group_path = group_id.replace(".", "/")
    versions: list[str] = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
        for base_url in upstream_urls:
            meta_url = f"{base_url.rstrip('/')}/{group_path}/{artifact_id}/maven-metadata.xml"
            try:
                resp = await client.get(meta_url)
                if resp.status_code != 200:
                    continue
                root = ET.fromstring(resp.text)
                for node in root.findall("./versioning/versions/version"):
                    if node.text and node.text.strip():
                        versions.append(node.text.strip())
                if versions:
                    break
            except Exception:
                continue

    deduped = sorted(set(versions), key=version_sort_key, reverse=True)
    return deduped


def quarantine_artifact_with_sidecars(
    artifact_path: Path,
    root_dir: Path,
    quarantine_root: Path,
    ecosystem: str,
    component: str,
    version: str,
    max_cvss: float,
    cve_ids: list[str],
    cve_status: str,
    superseded_by: str = "",
) -> Path:
    """Move a newly vulnerable artifact and its sidecars out of trusted storage into quarantine."""
    rel = artifact_path.relative_to(root_dir).as_posix()
    dest_base = quarantine_root / "cve-quarantined" / ecosystem / rel
    dest_base.parent.mkdir(parents=True, exist_ok=True)

    for suffix in _ARTIFACT_SIDECARS:
        src = artifact_path if not suffix else artifact_path.with_name(f"{artifact_path.name}{suffix}")
        dst = dest_base if not suffix else dest_base.with_name(f"{dest_base.name}{suffix}")
        if src.exists() and not src.is_symlink():
            shutil.move(str(src), str(dst))

    meta_file = dest_base.with_name(f"{dest_base.name}.quarantine.json")
    meta = {
        "ecosystem": ecosystem,
        "component": component,
        "version": version,
        "artifact": rel,
        "status": "QUARANTINED",
        "max_cvss": max_cvss,
        "cve_ids": list(cve_ids),
        "cve_status": cve_status,
        "quarantined_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "superseded_by": superseded_by,
    }
    meta_file.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return dest_base


def load_quarantined_components(quarantine_root: Path) -> list[dict[str, Any]]:
    """Load metadata for all CVE-quarantined artifacts."""
    q_dir = quarantine_root / "cve-quarantined"
    if not q_dir.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for meta_file in sorted(q_dir.rglob("*.quarantine.json")):
        if meta_file.is_symlink():
            continue
        try:
            records.append(json.loads(meta_file.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return records


def _latest_tags_path(settings: Settings) -> Path:
    return settings.oss_data_root / "audit" / "latest-tags.json"


def load_latest_tags(settings: Settings) -> dict[str, dict[str, Any]]:
    """Return mapping of '<ecosystem>:<component>' -> latest tag metadata."""
    path = _latest_tags_path(settings)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def update_latest_tag(
    settings: Settings,
    ecosystem: str,
    component: str,
    version: str,
    rel_artifact_path: str,
) -> None:
    """Persist 'latest' tag pointer in audit/latest-tags.json and ecosystem metadata."""
    tags = load_latest_tags(settings)
    tags[f"{ecosystem}:{component}"] = {
        "ecosystem": ecosystem,
        "component": component,
        "latest_version": version,
        "artifact": rel_artifact_path,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    path = _latest_tags_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tags, indent=2) + "\n", encoding="utf-8")

    if ecosystem == "pypi":
        pkg_dir = settings.trusted_pypi_dir / component
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / "latest.json").write_text(
            json.dumps({"tag": "latest", "version": version, "artifact": rel_artifact_path}, indent=2) + "\n",
            encoding="utf-8",
        )
    elif ecosystem == "maven" and ":" in component:
        group_id, artifact_id = component.split(":", 1)
        art_dir = settings.trusted_maven_dir / group_id.replace(".", "/") / artifact_id
        art_dir.mkdir(parents=True, exist_ok=True)
        xml = (
            "<metadata>\n"
            f"  <groupId>{group_id}</groupId>\n"
            f"  <artifactId>{artifact_id}</artifactId>\n"
            "  <versioning>\n"
            f"    <latest>{version}</latest>\n"
            f"    <release>{version}</release>\n"
            "  </versioning>\n"
            "</metadata>\n"
        )
        (art_dir / "maven-metadata.xml").write_text(xml, encoding="utf-8")


_SKIP_GC_SUFFIXES = (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512", ".metadata.json", ".html")


def gc_old_component_versions(
    settings: Settings,
    keep_versions: int | None = None,
    ecosystems: set[str] | None = None,
    comp_filters: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Garbage-collect cached versions that are N-2 or older (2+ versions older than latest)."""
    keep = max(1, keep_versions if keep_versions is not None else settings.gc_retention_versions)
    active_ecosystems = ecosystems or {"maven", "pypi"}
    c_filters = [c.lower() for c in (comp_filters or []) if c]
    latest_tags = load_latest_tags(settings)

    removed_items: list[dict[str, Any]] = []
    files_removed_total = 0

    for eco, root_dir in (("maven", settings.trusted_maven_dir), ("pypi", settings.trusted_pypi_dir)):
        if eco not in active_ecosystems or not root_dir.is_dir():
            continue

        # Group artifact files by (component, version)
        grouped: dict[str, dict[str, list[Path]]] = {}
        for path in sorted(root_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if path.name in {"maven-metadata.xml", "latest.json"} or path.name.endswith(_SKIP_GC_SUFFIXES):
                continue
            rel = path.relative_to(root_dir).as_posix()
            pkg_name, pkg_version = extract_package_coordinates(eco, rel)
            if not pkg_name or not pkg_version or pkg_version in {"unknown", "latest"}:
                continue
            if c_filters and not any(f in pkg_name.lower() for f in c_filters):
                continue
            grouped.setdefault(pkg_name, {}).setdefault(pkg_version, []).append(path)

        for component, versions_map in sorted(grouped.items()):
            if len(versions_map) <= keep:
                continue

            sorted_versions = sorted(versions_map.keys(), key=version_sort_key, reverse=True)
            tag_entry = latest_tags.get(f"{eco}:{component}") or {}
            pinned_latest = str(tag_entry.get("latest_version", "")).strip()

            kept: list[str] = []
            if pinned_latest and pinned_latest in versions_map:
                kept.append(pinned_latest)
            for ver in sorted_versions:
                if len(kept) >= keep:
                    break
                if ver not in kept:
                    kept.append(ver)
            kept_set = set(kept)

            for ver in sorted_versions:
                if ver in kept_set:
                    continue
                ver_files = versions_map[ver]
                removed_paths: list[str] = []
                for art_path in ver_files:
                    parent_dir = art_path.parent
                    for suffix in _ARTIFACT_SIDECARS:
                        candidate = art_path.with_name(f"{art_path.name}{suffix}") if suffix else art_path
                        if candidate.exists() and not candidate.is_symlink():
                            if not dry_run:
                                candidate.unlink(missing_ok=True)
                            removed_paths.append(candidate.relative_to(root_dir).as_posix())
                    if eco == "maven" and not dry_run and parent_dir.is_dir():
                        try:
                            if not any(parent_dir.iterdir()):
                                parent_dir.rmdir()
                        except OSError:
                            pass

                files_removed_total += len(removed_paths)
                removed_items.append(
                    {
                        "ecosystem": eco,
                        "component": component,
                        "version": ver,
                        "kept_versions": kept,
                        "files_removed": len(removed_paths),
                    }
                )
                logger.info(
                    "[CACHE] GC_REMOVED ecosystem=%s component=%s version=%s kept=%s files=%d dry_run=%s",
                    eco,
                    component,
                    ver,
                    ",".join(kept),
                    len(removed_paths),
                    dry_run,
                )
                if not dry_run:
                    append_activity_event(
                        settings.activity_log_path,
                        source="gc",
                        event="GC_REMOVED",
                        ecosystem=eco,
                        component=component,
                        version=ver,
                        details=f"kept={','.join(kept)} files={len(removed_paths)}",
                    )

    return {
        "status": "gc_completed",
        "keep_versions": keep,
        "dry_run": dry_run,
        "removed_count": len(removed_items),
        "files_removed_total": files_removed_total,
        "removed": removed_items,
    }
