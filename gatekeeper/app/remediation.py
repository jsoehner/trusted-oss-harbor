"""Automated CVE remediation, vulnerable artifact quarantine, and 'latest' tag management."""

from __future__ import annotations

import datetime
import html
import json
import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET
import httpx

from app.activity import append_activity_event
from app.config import Settings
from app.storage import normalize_pypi_name, resolve_safe_relative_path
from app.virtual_repo import extract_package_coordinates

logger = logging.getLogger("gatekeeper.remediation")

_ARTIFACT_SIDECARS = (
    "",
    ".asc",
    ".mldsa65",
    ".sha256",
    ".sha384",
    ".sha512",
    ".metadata.json",
    ".sbom.cdx.json",
    ".sbom.cdx.json.asc",
    ".sbom.cdx.json.mldsa65",
    ".cbom.cdx.json",
    ".cbom.cdx.json.asc",
    ".cbom.cdx.json.mldsa65",
)


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
        norm_pkg = normalize_pypi_name(component)
        pkg_dir = resolve_safe_relative_path(settings.trusted_pypi_dir, norm_pkg)
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / "latest.json").write_text(
            json.dumps({"tag": "latest", "version": version, "artifact": rel_artifact_path}, indent=2) + "\n",
            encoding="utf-8",
        )
    elif ecosystem == "maven" and ":" in component:
        group_id, artifact_id = component.split(":", 1)
        if not group_id or not artifact_id or "/" in group_id or "\\" in group_id or ".." in group_id or "/" in artifact_id or "\\" in artifact_id or ".." in artifact_id:
            raise ValueError(f"Invalid Maven coordinate: {component!r}")
        art_dir = resolve_safe_relative_path(
            settings.trusted_maven_dir, f"{group_id.replace('.', '/')}/{artifact_id}"
        )
        art_dir.mkdir(parents=True, exist_ok=True)
        xml = (
            "<metadata>\n"
            f"  <groupId>{html.escape(group_id)}</groupId>\n"
            f"  <artifactId>{html.escape(artifact_id)}</artifactId>\n"
            "  <versioning>\n"
            f"    <latest>{html.escape(version)}</latest>\n"
            f"    <release>{html.escape(version)}</release>\n"
            "  </versioning>\n"
            "</metadata>\n"
        )
        (art_dir / "maven-metadata.xml").write_text(xml, encoding="utf-8")


_SKIP_GC_SUFFIXES = (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512", ".metadata.json", ".html")


def _access_log_path(settings: Settings) -> Path:
    return settings.oss_data_root / "audit" / "last_accessed.json"


def load_component_access_map(settings: Settings) -> dict[str, float]:
    """Load per-(ecosystem:component@version) last-accessed epoch timestamps."""
    path = _access_log_path(settings)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return {str(k): float(v) for k, v in raw.items() if isinstance(v, (int, float))}
    except Exception:
        pass
    return {}


def record_component_access(
    settings: Settings,
    ecosystem: str,
    rel_path: str,
    timestamp: float | None = None,
) -> None:
    """Record last-accessed timestamp for a served/cached component version (throttled to 60s)."""
    pkg_name, pkg_version = extract_package_coordinates(ecosystem, rel_path)
    if not pkg_name or not pkg_version or pkg_version in {"unknown", "latest"}:
        return
    key = f"{ecosystem}:{pkg_name}@{pkg_version}"
    now = timestamp if timestamp is not None else time.time()
    access_map = load_component_access_map(settings)
    prev = access_map.get(key, 0.0)
    if timestamp is None and (now - prev) < 60.0:
        return
    access_map[key] = now
    path = _access_log_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(access_map, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _version_last_accessed(
    access_map: dict[str, float],
    eco: str,
    component: str,
    version: str,
    files: list[Path],
) -> float:
    key = f"{eco}:{component}@{version}"
    if key in access_map:
        return access_map[key]
    mtimes: list[float] = []
    for f in files:
        try:
            mtimes.append(f.stat().st_mtime)
        except OSError:
            pass
    return max(mtimes) if mtimes else time.time()


def _unlink_version_files(
    *,
    eco: str,
    root_dir: Path,
    ver_files: list[Path],
    dry_run: bool,
) -> tuple[list[str], int]:
    removed_paths: list[str] = []
    bytes_reclaimed = 0
    for art_path in ver_files:
        parent_dir = art_path.parent
        for suffix in _ARTIFACT_SIDECARS:
            candidate = art_path.with_name(f"{art_path.name}{suffix}") if suffix else art_path
            if candidate.exists() and not candidate.is_symlink():
                try:
                    bytes_reclaimed += candidate.stat().st_size
                except OSError:
                    pass
                if not dry_run:
                    candidate.unlink(missing_ok=True)
                removed_paths.append(candidate.relative_to(root_dir).as_posix())
        if eco == "maven" and not dry_run and parent_dir.is_dir():
            try:
                if not any(parent_dir.iterdir()):
                    parent_dir.rmdir()
            except OSError:
                pass
    return removed_paths, bytes_reclaimed


def gc_old_component_versions(
    settings: Settings,
    keep_versions: int | None = None,
    max_unused_days: int | None = None,
    ecosystems: set[str] | None = None,
    comp_filters: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Garbage-collect cached versions unused for > max_unused_days (default 90d), or optional N-keep."""
    eff_keep = keep_versions if keep_versions is not None else settings.gc_retention_versions
    ttl_days = max(1, max_unused_days if max_unused_days is not None else settings.gc_max_unused_days)
    use_keep_policy = eff_keep is not None and eff_keep > 0
    keep = max(1, eff_keep) if use_keep_policy else 0

    active_ecosystems = ecosystems or {"maven", "pypi"}
    c_filters = [c.lower() for c in (comp_filters or []) if c]
    latest_tags = load_latest_tags(settings)
    access_map = load_component_access_map(settings)
    now = time.time()

    removed_items: list[dict[str, Any]] = []
    files_removed_total = 0
    bytes_reclaimed_total = 0

    for eco, root_dir in (("maven", settings.trusted_maven_dir), ("pypi", settings.trusted_pypi_dir)):
        if eco not in active_ecosystems or not root_dir.is_dir():
            continue

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
            sorted_versions = sorted(versions_map.keys(), key=version_sort_key, reverse=True)

            if use_keep_policy:
                if len(versions_map) <= keep:
                    continue
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
                    removed_paths, bytes_reclaimed = _unlink_version_files(
                        eco=eco, root_dir=root_dir, ver_files=versions_map[ver], dry_run=dry_run
                    )
                    files_removed_total += len(removed_paths)
                    bytes_reclaimed_total += bytes_reclaimed
                    removed_items.append(
                        {
                            "ecosystem": eco,
                            "component": component,
                            "version": ver,
                            "reason": "keep_versions",
                            "kept_versions": kept,
                            "files_removed": len(removed_paths),
                            "bytes_reclaimed": bytes_reclaimed,
                        }
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
            else:
                for ver in sorted_versions:
                    ver_files = versions_map[ver]
                    last_acc = _version_last_accessed(access_map, eco, component, ver, ver_files)
                    unused_days = (now - last_acc) / 86400.0
                    if unused_days <= float(ttl_days):
                        continue
                    removed_paths, bytes_reclaimed = _unlink_version_files(
                        eco=eco, root_dir=root_dir, ver_files=ver_files, dry_run=dry_run
                    )
                    files_removed_total += len(removed_paths)
                    bytes_reclaimed_total += bytes_reclaimed
                    removed_items.append(
                        {
                            "ecosystem": eco,
                            "component": component,
                            "version": ver,
                            "reason": "unused_ttl",
                            "unused_days": round(unused_days, 1),
                            "files_removed": len(removed_paths),
                            "bytes_reclaimed": bytes_reclaimed,
                        }
                    )
                    logger.info(
                        "[CACHE] GC_UNUSED_REMOVED ecosystem=%s component=%s version=%s unused_days=%.1f files=%d dry_run=%s",
                        eco,
                        component,
                        ver,
                        unused_days,
                        len(removed_paths),
                        dry_run,
                    )
                    if not dry_run:
                        append_activity_event(
                            settings.activity_log_path,
                            source="gc",
                            event="GC_UNUSED_REMOVED",
                            ecosystem=eco,
                            component=component,
                            version=ver,
                            details=f"unused_days={unused_days:.1f} ttl={ttl_days}d bytes={bytes_reclaimed}",
                        )

    return {
        "status": "gc_completed",
        "policy": "keep_versions" if use_keep_policy else "unused_ttl",
        "keep_versions": keep,
        "max_unused_days": ttl_days,
        "dry_run": dry_run,
        "removed_count": len(removed_items),
        "files_removed_total": files_removed_total,
        "bytes_reclaimed_total": bytes_reclaimed_total,
        "removed": removed_items,
    }


def _dir_size_bytes(root: Path) -> int:
    if not root.is_dir():
        return 0
    total = 0
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def build_cache_retention_report(settings: Settings) -> dict[str, Any]:
    """Summarize disk runway, cache growth, and components approaching/past the unused TTL."""
    settings.oss_data_root.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(settings.oss_data_root)
    cache_bytes = (
        _dir_size_bytes(settings.trusted_maven_dir)
        + _dir_size_bytes(settings.trusted_pypi_dir)
        + _dir_size_bytes(settings.oss_data_root / "harbor" / "registry")
        + _dir_size_bytes(settings.quarantine_dir)
    )

    # Estimate daily growth from provenance log over last 30 days
    now = time.time()
    recent_bytes = 0
    earliest_ts = now
    if settings.provenance_log_path.is_file():
        cutoff = now - (30 * 86400)
        for line in settings.provenance_log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                ts_str = str(rec.get("timestamp", "")).replace("Z", "+00:00")
                ts_val = datetime.datetime.fromisoformat(ts_str).timestamp()
                if ts_val >= cutoff:
                    recent_bytes += int(rec.get("size_bytes", 0) or 0)
                    earliest_ts = min(earliest_ts, ts_val)
            except Exception:
                continue

    span_days = max(1.0, (now - earliest_ts) / 86400.0)
    daily_growth_bytes = recent_bytes / span_days if recent_bytes > 0 else 0.0
    estimated_days_remaining: int | None = (
        int(usage.free / daily_growth_bytes) if daily_growth_bytes > 0 else None
    )

    ttl_days = max(1, settings.gc_max_unused_days)
    warn_days = max(1, min(ttl_days, settings.gc_warn_unused_days))
    access_map = load_component_access_map(settings)

    expiring_soon: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    for eco, root_dir in (("maven", settings.trusted_maven_dir), ("pypi", settings.trusted_pypi_dir)):
        if not root_dir.is_dir():
            continue
        grouped: dict[tuple[str, str], list[Path]] = {}
        for path in sorted(root_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if path.name in {"maven-metadata.xml", "latest.json"} or path.name.endswith(_SKIP_GC_SUFFIXES):
                continue
            rel = path.relative_to(root_dir).as_posix()
            pkg_name, pkg_version = extract_package_coordinates(eco, rel)
            if not pkg_name or not pkg_version or pkg_version in {"unknown", "latest"}:
                continue
            grouped.setdefault((pkg_name, pkg_version), []).append(path)

        for (comp, ver), ver_files in sorted(grouped.items()):
            last_acc = _version_last_accessed(access_map, eco, comp, ver, ver_files)
            unused_days = (now - last_acc) / 86400.0
            size_bytes = sum(f.stat().st_size for f in ver_files if f.exists())
            entry = {
                "ecosystem": eco,
                "component": comp,
                "version": ver,
                "unused_days": round(unused_days, 1),
                "days_until_removal": max(0, int(ttl_days - unused_days)),
                "size_bytes": size_bytes,
            }
            if unused_days > float(ttl_days):
                expired.append(entry)
            elif unused_days >= float(warn_days):
                expiring_soon.append(entry)

    expiring_soon.sort(key=lambda x: x["unused_days"], reverse=True)
    expired.sort(key=lambda x: x["unused_days"], reverse=True)

    return {
        "policy": "keep_clean_until_vulnerable_or_unused_ttl",
        "max_unused_days": ttl_days,
        "warn_unused_days": warn_days,
        "disk_total_bytes": usage.total,
        "disk_used_bytes": usage.used,
        "disk_free_bytes": usage.free,
        "disk_used_pct": round((usage.used / usage.total) * 100.0, 1) if usage.total else 0.0,
        "cache_bytes": cache_bytes,
        "daily_growth_bytes": int(daily_growth_bytes),
        "estimated_days_remaining": estimated_days_remaining,
        "expiring_soon": expiring_soon,
        "expired": expired,
        "reclaimable_bytes": sum(x["size_bytes"] for x in expired),
    }
