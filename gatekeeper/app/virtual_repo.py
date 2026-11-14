"""Virtual Repository helpers for PyPI PEP 503/691 proxy, Maven coordinates, and OCI registries."""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

import httpx

OCI_REGISTRY_ALIASES: dict[str, str] = {
    "chainguard-cache": "https://cgr.dev",
    "docker-cache": "https://registry-1.docker.io",
    "ghcr-cache": "https://ghcr.io",
    "quay-cache": "https://quay.io",
}

WHEEL_NAME_RE = re.compile(r"^([A-Za-z0-9._-]+?)-([0-9][A-Za-z0-9._!+-]*?)-(?:py|cp|pp|ip|jy)")
SDIST_NAME_RE = re.compile(r"^([A-Za-z0-9._-]+?)-([0-9][A-Za-z0-9._!+-]*?)\.(?:tar\.gz|tgz|zip)$")


class _Pep503LinkParser(HTMLParser):
    """Minimal HTML parser extracting distribution links from a PEP 503 Simple page."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[dict[str, str]] = []
        self._current_href: str | None = None
        self._current_attrs: dict[str, str] = {}
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            attr_map = {k.lower(): (v or "") for k, v in attrs}
            self._current_href = attr_map.get("href", "")
            self._current_attrs = attr_map
            self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            filename = "".join(self._text_parts).strip()
            full_url = urljoin(self.base_url, self._current_href)
            sha256 = ""
            if "#sha256=" in full_url:
                full_url, frag = full_url.split("#", 1)
                for part in frag.split("&"):
                    if part.startswith("sha256="):
                        sha256 = part.split("=", 1)[1]
            if filename:
                self.links.append(
                    {
                        "filename": filename,
                        "url": full_url,
                        "sha256": sha256,
                        "requires_python": self._current_attrs.get("data-requires-python", ""),
                    }
                )
            self._current_href = None
            self._current_attrs = {}
            self._text_parts = []


def extract_package_coordinates(ecosystem: str, artifact_rel_path: str) -> tuple[str, str]:
    """Extract (package_name, version) from a Maven or PyPI relative artifact path."""
    parts = [p for p in artifact_rel_path.strip("/").split("/") if p]
    if ecosystem == "maven" and len(parts) >= 4:
        # <group/parts>/<artifactId>/<version>/<filename>
        version = parts[-2]
        artifact_id = parts[-3]
        group_id = ".".join(parts[:-3])
        if group_id and artifact_id and version:
            return f"{group_id}:{artifact_id}", version
    elif ecosystem == "pypi" and parts:
        filename = parts[-1]
        m = WHEEL_NAME_RE.match(filename) or SDIST_NAME_RE.match(filename)
        if m:
            return m.group(1), m.group(2)
        if len(parts) >= 2:
            return parts[0], ""
    return "", ""


async def fetch_upstream_pypi_distributions(
    upstream_simple_urls: list[str],
    norm_pkg: str,
) -> list[dict[str, str]]:
    """Fetch available distribution files and upstream URLs from PEP 503/691 Simple API."""
    headers = {
        "Accept": "application/vnd.pypi.simple.v1+json, text/html;q=0.9",
    }
    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        for base_url in upstream_simple_urls:
            index_url = f"{base_url.rstrip('/')}/{norm_pkg}/"
            try:
                resp = await client.get(index_url, headers=headers)
            except Exception:
                continue
            if resp.status_code != 200:
                continue

            ctype = resp.headers.get("content-type", "").lower()
            if "application/vnd.pypi.simple.v1+json" in ctype or resp.text.lstrip().startswith("{"):
                try:
                    data = resp.json()
                    files: list[dict[str, str]] = []
                    for f in data.get("files", []):
                        fname = f.get("filename", "")
                        furl = urljoin(str(resp.url), f.get("url", ""))
                        sha256 = (f.get("hashes") or {}).get("sha256", "")
                        req_py = f.get("requires-python") or ""
                        if fname and furl:
                            files.append(
                                {
                                    "filename": fname,
                                    "url": furl,
                                    "sha256": sha256,
                                    "requires_python": str(req_py),
                                }
                            )
                    if files:
                        return files
                except Exception:
                    pass

            parser = _Pep503LinkParser(str(resp.url))
            parser.feed(resp.text)
            if parser.links:
                return parser.links
    return []


def render_virtual_pep503_index(
    norm_pkg: str,
    distributions: list[dict[str, str]],
    package_route_prefix: str = "/pypi/virtual/packages",
) -> str:
    """Render a PEP 503 Simple HTML page rewriting upstream links to the local virtual repo."""
    safe_pkg = html.escape(norm_pkg)
    links: list[str] = []
    for dist in distributions:
        fname = dist["filename"]
        safe_fname = html.escape(fname)
        sha256 = dist.get("sha256", "")
        frag = f"#sha256={html.escape(sha256)}" if sha256 else ""
        req_py = dist.get("requires_python", "")
        req_attr = f' data-requires-python="{html.escape(req_py)}"' if req_py else ""
        href = f"{package_route_prefix.rstrip('/')}/{safe_pkg}/{safe_fname}{frag}"
        links.append(f'    <a href="{href}"{req_attr}>{safe_fname}</a><br/>')

    body = "\n".join(links)
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        f"  <head><title>Links for {safe_pkg}</title></head>\n"
        "  <body>\n"
        f"    <h1>Links for {safe_pkg}</h1>\n"
        f"{body}\n"
        "  </body>\n"
        "</html>\n"
    )


def select_preferred_distribution(
    distributions: list[dict[str, str]],
    pinned_version: str = "",
) -> dict[str, str] | None:
    """Pick a wheel (preferred) or sdist matching pinned_version or the latest available."""
    if not distributions:
        return None

    candidates = distributions
    if pinned_version:
        ver_matched = [d for d in distributions if f"-{pinned_version}-" in d["filename"] or f"-{pinned_version}." in d["filename"]]
        if ver_matched:
            candidates = ver_matched

    wheels = [d for d in candidates if d["filename"].endswith(".whl")]
    if wheels:
        # Prefer pure-python universal wheel if available, else last (usually latest)
        universal = [w for w in wheels if "py3-none-any.whl" in w["filename"]]
        return universal[-1] if universal else wheels[-1]

    sdists = [d for d in candidates if d["filename"].endswith((".tar.gz", ".tgz", ".zip"))]
    return sdists[-1] if sdists else candidates[-1]
