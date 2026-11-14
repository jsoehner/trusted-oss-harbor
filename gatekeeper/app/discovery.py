"""Dynamic component discovery across local and GitHub project manifests."""

from __future__ import annotations

import logging
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("gatekeeper.discovery")

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "build",
    ".gradle",
    "__pycache__",
    ".pytest_cache",
    "dist",
}

GRADLE_COORD_RE = re.compile(
    r"""(?:implementation|api|testImplementation|compileOnly|runtimeOnly|annotationProcessor)\s*\(?\s*['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.+-]+)['"]\s*\)?"""
)
GRADLE_SPRING_BOOT_PLUGIN_RE = re.compile(
    r"""id\s*\(?\s*['"]org\.springframework\.boot['"]\s*\)?\s*version\s*['"]([0-9A-Za-z_.-]+)['"]"""
)
GRADLE_NO_VER_SPRING_RE = re.compile(
    r"""(?:implementation|api|testImplementation)\s*\(?\s*['"](org\.springframework\.boot):([A-Za-z0-9_.-]+)['"]\s*\)?"""
)
REQ_LINE_RE = re.compile(
    r"""^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(?:(==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9.*+!_-]+))?"""
)
DOCKER_FROM_RE = re.compile(r"""^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)""", re.IGNORECASE)


def _normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower().strip("-")


def _maven_artifact_paths(group_id: str, artifact_id: str, version: str) -> list[str]:
    group_path = group_id.replace(".", "/")
    base = f"{group_path}/{artifact_id}/{version}/{artifact_id}-{version}"
    return [f"{base}.pom", f"{base}.jar"]


def parse_pom_xml(text: str) -> list[dict[str, Any]]:
    """Extract Maven coordinates from pom.xml content, resolving parent & property versions."""
    results: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return results

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0] + "}"

    def find_text(elem: ET.Element | None, tag: str) -> str:
        if elem is None:
            return ""
        child = elem.find(f"{ns}{tag}")
        return child.text.strip() if child is not None and child.text else ""

    props: dict[str, str] = {}
    props_elem = root.find(f"{ns}properties")
    if props_elem is not None:
        for child in props_elem:
            key = child.tag.replace(ns, "")
            if child.text:
                props[key] = child.text.strip()

    parent_elem = root.find(f"{ns}parent")
    parent_group = find_text(parent_elem, "groupId")
    parent_version = find_text(parent_elem, "version")
    if parent_version:
        props.setdefault("project.parent.version", parent_version)
        if parent_group == "org.springframework.boot":
            props.setdefault("spring-boot.version", parent_version)

    proj_version = find_text(root, "version")
    if proj_version:
        props.setdefault("project.version", proj_version)

    def resolve_ver(raw: str, group_id: str) -> str:
        if not raw:
            if group_id == "org.springframework.boot" and parent_group == "org.springframework.boot":
                return parent_version
            return ""
        m = re.fullmatch(r"\$\{([^}]+)\}", raw)
        if m:
            return props.get(m.group(1), "")
        return raw

    for dep in root.findall(f".//{ns}dependencies/{ns}dependency"):
        group_id = find_text(dep, "groupId")
        artifact_id = find_text(dep, "artifactId")
        raw_ver = find_text(dep, "version")
        version = resolve_ver(raw_ver, group_id)
        if not group_id or not artifact_id or not version or "${" in version:
            continue
        results.append(
            {
                "groupId": group_id,
                "artifactId": artifact_id,
                "version": version,
                "artifacts": _maven_artifact_paths(group_id, artifact_id, version),
            }
        )
    return results


def parse_gradle_build(text: str) -> list[dict[str, Any]]:
    """Extract Maven coordinates from build.gradle or build.gradle.kts content."""
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    boot_ver_match = GRADLE_SPRING_BOOT_PLUGIN_RE.search(text)
    boot_ver = boot_ver_match.group(1) if boot_ver_match else ""

    for g, a, v in GRADLE_COORD_RE.findall(text):
        if "$" in v:
            continue
        key = (g, a, v)
        if key not in seen:
            seen.add(key)
            results.append(
                {
                    "groupId": g,
                    "artifactId": a,
                    "version": v,
                    "artifacts": _maven_artifact_paths(g, a, v),
                }
            )

    if boot_ver:
        for g, a in GRADLE_NO_VER_SPRING_RE.findall(text):
            key = (g, a, boot_ver)
            if key not in seen:
                seen.add(key)
                results.append(
                    {
                        "groupId": g,
                        "artifactId": a,
                        "version": boot_ver,
                        "artifacts": _maven_artifact_paths(g, a, boot_ver),
                    }
                )
    return results


def parse_requirements_txt(text: str) -> list[dict[str, Any]]:
    """Extract PyPI package specs from requirements.txt content."""
    results: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--", "git+", "http://", "https://")):
            continue
        line = line.split(";", 1)[0].strip()
        m = REQ_LINE_RE.match(line)
        if not m:
            continue
        name = _normalize_pypi(m.group(1))
        op = m.group(2) or ""
        ver = m.group(3) or ""
        results.append(
            {
                "name": name,
                "spec": f"{op}{ver}" if op and ver else "",
                "pinned_version": ver if op == "==" else "",
            }
        )
    return results


def parse_pyproject_toml(text: str) -> list[dict[str, Any]]:
    """Extract PyPI dependencies from pyproject.toml [project.dependencies]."""
    results: list[dict[str, Any]] = []
    try:
        data = tomllib.loads(text)
    except Exception:
        return results

    deps = data.get("project", {}).get("dependencies", [])
    if not isinstance(deps, list):
        return results
    for item in deps:
        if not isinstance(item, str):
            continue
        line = item.split(";", 1)[0].strip()
        m = REQ_LINE_RE.match(line)
        if not m:
            continue
        name = _normalize_pypi(m.group(1))
        op = m.group(2) or ""
        ver = m.group(3) or ""
        results.append(
            {
                "name": name,
                "spec": f"{op}{ver}" if op and ver else "",
                "pinned_version": ver if op == "==" else "",
            }
        )
    return results


def parse_dockerfile(text: str) -> list[dict[str, Any]]:
    """Extract OCI container base images from Dockerfile FROM instructions."""
    results: list[dict[str, Any]] = []
    for line in text.splitlines():
        m = DOCKER_FROM_RE.match(line)
        if not m:
            continue
        image_ref = m.group(1).strip()
        if image_ref.startswith("$") or image_ref.lower() == "scratch":
            continue
        # Strip @sha256:... digest if present alongside tag
        if "@" in image_ref:
            image_ref = image_ref.split("@", 1)[0]
        if ":" in image_ref.rsplit("/", 1)[-1]:
            repo_full, tag = image_ref.rsplit(":", 1)
        else:
            repo_full, tag = image_ref, "latest"

        parts = repo_full.split("/", 1)
        if len(parts) == 2 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
            registry, repo_path = parts[0], parts[1]
        else:
            registry = "registry-1.docker.io"
            repo_path = repo_full if "/" in repo_full else f"library/{repo_full}"

        results.append(
            {
                "registry": registry,
                "repository": repo_path,
                "reference": tag,
            }
        )
    return results


def _collect_from_manifest_map(
    manifest_files: dict[str, str],
    project_name: str,
    maven_map: dict[tuple[str, str, str], dict[str, Any]],
    pypi_map: dict[tuple[str, str], dict[str, Any]],
    oci_map: dict[tuple[str, str, str], dict[str, Any]],
    source_projects: set[str],
) -> None:
    """Parse a project's manifest file texts into deduplicated component maps."""
    found_any = False

    if "pom.xml" in manifest_files:
        for item in parse_pom_xml(manifest_files["pom.xml"]):
            key = (item["groupId"], item["artifactId"], item["version"])
            entry = maven_map.setdefault(key, {**item, "projects": []})
            if project_name not in entry["projects"]:
                entry["projects"].append(project_name)
            found_any = True

    for gradle_name in ("build.gradle", "build.gradle.kts"):
        if gradle_name in manifest_files:
            for item in parse_gradle_build(manifest_files[gradle_name]):
                key = (item["groupId"], item["artifactId"], item["version"])
                entry = maven_map.setdefault(key, {**item, "projects": []})
                if project_name not in entry["projects"]:
                    entry["projects"].append(project_name)
                found_any = True

    if "requirements.txt" in manifest_files:
        for item in parse_requirements_txt(manifest_files["requirements.txt"]):
            key = (item["name"], item["pinned_version"] or item["spec"])
            entry = pypi_map.setdefault(key, {**item, "projects": []})
            if project_name not in entry["projects"]:
                entry["projects"].append(project_name)
            found_any = True

    if "pyproject.toml" in manifest_files:
        for item in parse_pyproject_toml(manifest_files["pyproject.toml"]):
            key = (item["name"], item["pinned_version"] or item["spec"])
            entry = pypi_map.setdefault(key, {**item, "projects": []})
            if project_name not in entry["projects"]:
                entry["projects"].append(project_name)
            found_any = True

    if "Dockerfile" in manifest_files:
        for item in parse_dockerfile(manifest_files["Dockerfile"]):
            key = (item["registry"], item["repository"], item["reference"])
            entry = oci_map.setdefault(key, {**item, "projects": []})
            if project_name not in entry["projects"]:
                entry["projects"].append(project_name)
            found_any = True

    if found_any:
        source_projects.add(project_name)


def discover_local_projects(
    scan_roots: list[Path],
    max_projects: int = 30,
) -> dict[str, Any]:
    """Scan local project directories (sorted by most recently modified) for dependencies."""
    maven_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    pypi_map: dict[tuple[str, str], dict[str, Any]] = {}
    oci_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    source_projects: set[str] = set()

    candidate_dirs: list[Path] = []
    for root in scan_roots:
        if not root.exists() or not root.is_dir():
            continue
        # Check if root itself is a project
        if any(
            (root / fname).is_file()
            for fname in ("pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt", "pyproject.toml", "Dockerfile")
        ):
            candidate_dirs.append(root)
        for child in root.iterdir():
            if child.is_dir() and child.name not in SKIP_DIRS and not child.name.startswith("."):
                candidate_dirs.append(child)

    # Sort most recently modified first
    candidate_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)

    scanned = 0
    for proj_dir in candidate_dirs:
        if scanned >= max_projects:
            break
        manifests: dict[str, str] = {}
        for fname in ("pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt", "pyproject.toml", "Dockerfile"):
            fpath = proj_dir / fname
            if fpath.is_file():
                try:
                    manifests[fname] = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
        if manifests:
            scanned += 1
            _collect_from_manifest_map(
                manifests, proj_dir.name, maven_map, pypi_map, oci_map, source_projects
            )

    return _format_discovered_catalog(maven_map, pypi_map, oci_map, source_projects)


async def discover_github_projects(
    username: str,
    token: str = "",
    max_repos: int = 15,
) -> dict[str, Any]:
    """Fetch recent GitHub repositories for `username` and extract their dependencies."""
    maven_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    pypi_map: dict[tuple[str, str], dict[str, Any]] = {}
    oci_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    source_projects: set[str] = set()

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    manifest_names = ("pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt", "pyproject.toml", "Dockerfile")

    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
        repos_resp = await client.get(
            f"https://api.github.com/users/{username}/repos",
            params={"sort": "pushed", "direction": "desc", "per_page": max_repos},
            headers=headers,
        )
        if repos_resp.status_code != 200:
            logger.warning("GitHub repo listing failed (%s): HTTP %s", username, repos_resp.status_code)
            return _format_discovered_catalog(maven_map, pypi_map, oci_map, source_projects)

        for repo in repos_resp.json():
            if repo.get("archived"):
                continue
            repo_name = repo.get("name", "")
            default_branch = repo.get("default_branch", "main")
            if not repo_name:
                continue
            manifests: dict[str, str] = {}
            for fname in manifest_names:
                raw_url = f"https://raw.githubusercontent.com/{username}/{repo_name}/{default_branch}/{fname}"
                try:
                    resp = await client.get(raw_url, headers=headers)
                    if resp.status_code == 200:
                        manifests[fname] = resp.text
                except Exception:
                    continue
            if manifests:
                _collect_from_manifest_map(
                    manifests, repo_name, maven_map, pypi_map, oci_map, source_projects
                )

    return _format_discovered_catalog(maven_map, pypi_map, oci_map, source_projects)


def _format_discovered_catalog(
    maven_map: dict[tuple[str, str, str], dict[str, Any]],
    pypi_map: dict[tuple[str, str], dict[str, Any]],
    oci_map: dict[tuple[str, str, str], dict[str, Any]],
    source_projects: set[str],
) -> dict[str, Any]:
    chainguard_containers = [
        v for v in oci_map.values() if v.get("registry") == "cgr.dev"
    ]
    other_oci = [
        v for v in oci_map.values() if v.get("registry") != "cgr.dev"
    ]
    return {
        "description": "Dynamically discovered component catalog across recent projects",
        "source_projects": sorted(source_projects),
        "chainguard_containers": chainguard_containers,
        "oci_containers": other_oci,
        "spring_boot_maven_components": list(maven_map.values()),
        "pypi_components": list(pypi_map.values()),
    }


def merge_catalogs(base: dict[str, Any], discovered: dict[str, Any]) -> dict[str, Any]:
    """Merge a base seed catalog with dynamically discovered components without duplicates."""
    merged_cg: dict[tuple[str, str], dict[str, Any]] = {}
    for item in base.get("chainguard_containers", []) + discovered.get("chainguard_containers", []):
        key = (item["repository"], item.get("reference", "latest"))
        merged_cg.setdefault(key, item)

    merged_oci: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in base.get("oci_containers", []) + discovered.get("oci_containers", []):
        key = (item.get("registry", "registry-1.docker.io"), item["repository"], item.get("reference", "latest"))
        merged_oci.setdefault(key, item)

    merged_maven: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in base.get("spring_boot_maven_components", []) + discovered.get("spring_boot_maven_components", []):
        key = (item["groupId"], item["artifactId"], item["version"])
        merged_maven.setdefault(key, item)

    merged_pypi: dict[tuple[str, str], dict[str, Any]] = {}
    for item in base.get("pypi_components", []) + discovered.get("pypi_components", []):
        key = (_normalize_pypi(item["name"]), item.get("pinned_version") or item.get("spec", ""))
        merged_pypi.setdefault(key, item)

    projects = sorted(
        set(base.get("source_projects", [])) | set(discovered.get("source_projects", []))
    )

    return {
        "description": discovered.get("description") or base.get("description", ""),
        "source_projects": projects,
        "chainguard_containers": list(merged_cg.values()),
        "oci_containers": list(merged_oci.values()),
        "spring_boot_maven_components": list(merged_maven.values()),
        "pypi_components": list(merged_pypi.values()),
    }
