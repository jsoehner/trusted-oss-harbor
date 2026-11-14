#!/usr/bin/env python3
"""Direct backend storage inventory for OSS_DATA_ROOT (no frontend HTTP calls)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any

COMPANION_SUFFIXES = (".asc", ".mldsa65", ".sha256", ".sha384", ".sha512", ".html")


def _verify_gpg_sig(artifact_path: Path, sig_path: Path, gnupghome: Path) -> bool:
    if not artifact_path.exists() or not sig_path.exists():
        return False
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    proc = subprocess.run(
        ["gpg", "--batch", "--verify", str(sig_path), str(artifact_path)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def _scan_primary_artifacts(
    root: Path,
    gnupghome: Path | None = None,
    verify_gpg: bool = False,
) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name.startswith(".") or path.name.endswith(COMPANION_SUFFIXES):
            continue
        rel = str(path.relative_to(root))
        sha256_file = path.with_name(f"{path.name}.sha256")
        asc_file = path.with_name(f"{path.name}.asc")
        mldsa_file = path.with_name(f"{path.name}.mldsa65")
        entry: dict[str, Any] = {
            "path": rel,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file.read_text(encoding="utf-8").strip() if sha256_file.exists() else "",
            "gpg_signed": asc_file.exists(),
            "mldsa65_signed": mldsa_file.exists(),
        }
        if verify_gpg and gnupghome and asc_file.exists():
            entry["gpg_valid"] = _verify_gpg_sig(path, asc_file, gnupghome)
        items.append(entry)
    return items


def catalog_backend_storage(
    oss_data_root: Path,
    verify_gpg: bool = False,
) -> dict[str, Any]:
    """Inspect OSS_DATA_ROOT directly on disk and return structured cache inventory."""
    gnupghome = oss_data_root / "keys" / "gnupg"
    packages_dir = oss_data_root / "packages"
    harbor_registry_dir = oss_data_root / "harbor" / "registry"
    public_keys_dir = oss_data_root / "keys" / "public"
    provenance_path = oss_data_root / "audit" / "provenance.jsonl"
    scanners_dir = oss_data_root / "scanners"

    maven_items = _scan_primary_artifacts(packages_dir / "trusted-maven", gnupghome, verify_gpg)
    pypi_items = _scan_primary_artifacts(packages_dir / "trusted-pypi", gnupghome, verify_gpg)
    oci_items = _scan_primary_artifacts(harbor_registry_dir, gnupghome, verify_gpg)

    quarantine_items: list[str] = []
    q_dir = packages_dir / "quarantine"
    if q_dir.exists():
        quarantine_items = [
            str(p.relative_to(q_dir))
            for p in sorted(q_dir.rglob("*"))
            if p.is_file() and not p.is_symlink()
        ]

    provenance_count = 0
    if provenance_path.is_file():
        provenance_count = sum(
            1 for line in provenance_path.read_text(encoding="utf-8").splitlines() if line.strip()
        )

    nvd_db = scanners_dir / "nvd-cache" / "11.0" / "odc.mv.db"
    if not nvd_db.is_file():
        nvd_db = scanners_dir / "nvd-cache" / "odc.mv.db"

    return {
        "oss_data_root": str(oss_data_root),
        "exists": oss_data_root.exists(),
        "keys": {
            "gpg_public_key": (public_keys_dir / "trusted-oss-pubkey.asc").is_file(),
            "gpg_fingerprint": (public_keys_dir / "trusted-oss-pubkey.fingerprint").read_text(encoding="utf-8").strip()
            if (public_keys_dir / "trusted-oss-pubkey.fingerprint").is_file()
            else "",
            "mldsa65_public_key": (public_keys_dir / "trusted-oss-mldsa65.pub").is_file(),
        },
        "scanners": {
            "nvd_cache_present": nvd_db.is_file(),
            "nvd_cache_size_mb": round(nvd_db.stat().st_size / (1024 * 1024), 2) if nvd_db.is_file() else 0.0,
            "clamav_db_files": len(list((scanners_dir / "clamav").glob("*"))) if (scanners_dir / "clamav").exists() else 0,
            "trivy_db_files": len(list((scanners_dir / "trivy").glob("*"))) if (scanners_dir / "trivy").exists() else 0,
        },
        "counts": {
            "maven": len(maven_items),
            "pypi": len(pypi_items),
            "oci": len(oci_items),
            "quarantine": len(quarantine_items),
            "provenance_records": provenance_count,
        },
        "maven": maven_items,
        "pypi": pypi_items,
        "oci": oci_items,
        "quarantine": quarantine_items,
    }


def _print_report(report: dict[str, Any]) -> None:
    print(f"Backend Storage Root : {report['oss_data_root']} (exists={report['exists']})")
    keys = report["keys"]
    print(
        f"Signing Keys         : GPG={'ready' if keys['gpg_public_key'] else 'missing'} "
        f"({keys['gpg_fingerprint'] or 'no fingerprint'}), "
        f"ML-DSA-65={'ready' if keys['mldsa65_public_key'] else 'missing'}"
    )
    sc = report["scanners"]
    print(
        f"Scanner Caches       : NVD={'ready' if sc['nvd_cache_present'] else 'missing'} "
        f"({sc['nvd_cache_size_mb']} MiB), ClamAV files={sc['clamav_db_files']}, Trivy files={sc['trivy_db_files']}"
    )
    c = report["counts"]
    print(
        f"Cached Components    : OCI={c['oci']} | Maven={c['maven']} | PyPI={c['pypi']} | "
        f"Quarantine={c['quarantine']} | Provenance={c['provenance_records']}"
    )

    for section, label in (("oci", "OCI / Harbor Cache"), ("maven", "Trusted Maven"), ("pypi", "Trusted PyPI")):
        items = report[section]
        print(f"\n[{label}] ({len(items)})")
        if not items:
            print("  (empty)")
        for item in items:
            sigs = []
            if item["gpg_signed"]:
                sigs.append("GPG")
            if item["mldsa65_signed"]:
                sigs.append("ML-DSA-65")
            sig_str = "+".join(sigs) if sigs else "UNSIGNED"
            print(f"  - {item['path']} ({item['size_bytes']} B, {sig_str})")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Catalog existing warmed-up components directly from backend OSS_DATA_ROOT storage."
    )
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path(os.getenv("OSS_DATA_ROOT", "/home/jsoehner/trusted-oss-data")),
        help="Backend storage root (default: $OSS_DATA_ROOT or /home/jsoehner/trusted-oss-data)",
    )
    parser.add_argument("--verify-gpg", action="store_true", help="Verify GPG .asc signatures on cached files")
    parser.add_argument("--json", action="store_true", help="Output JSON inventory")
    args = parser.parse_args()

    report = catalog_backend_storage(args.data_root, verify_gpg=args.verify_gpg)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
