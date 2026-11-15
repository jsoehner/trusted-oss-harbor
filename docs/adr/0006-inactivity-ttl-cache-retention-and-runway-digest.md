# ADR 0006: Inactivity-TTL Cache Retention (90-Day) and Capacity Runway Digest

- **Status:** Accepted
- **Date:** 2026-11-15
- **Version:** 1.2.0

## Context and Problem Statement

`N-2` version-count garbage collection (`GC_RETENTION_VERSIONS=2`) evicted clean, actively used older component versions whenever newer upstream releases existed. A trusted artifact cache should keep clean software components available until they become known vulnerable (at which point remediation quarantines and replaces them with a clean version) or remain unused long enough to warrant reclaiming disk space.

## Decision Drivers

1. **Zero Premature Eviction of Good Components**: Clean cached versions must remain available regardless of how many newer upstream versions exist.
2. **Automatic Replacement on Vulnerability**: When an existing cached version becomes vulnerable, auto-remediation quarantines it and promotes a clean replacement.
3. **Predictable Space Recovery**: Components not accessed for over `90` days (`GC_MAX_UNUSED_DAYS=90`) must be pruned to recover storage, even on `noatime` NAS filesystems (e.g., TrueNAS ZFS).
4. **Operational Visibility**: Daily digests must report cache disk runway, replaced vulnerable components, and components approaching or past the 90-day inactivity threshold.

## Decision

1. **Inactivity-TTL Default Policy (`GC_RETENTION_VERSIONS=0`, `GC_MAX_UNUSED_DAYS=90`)**:
   - `gc_old_component_versions` in `gatekeeper/app/remediation.py` defaults to `unused_ttl` (`90` days) instead of `N-2` version counting (`keep_versions` remains available as an explicit override).
   - `record_component_access` logs per-version last-accessed epoch timestamps to `audit/last_accessed.json` (throttled to 60s, falling back to file `mtime`) on Maven and PyPI serve paths.
   - Expired versions (`> 90` days unused) are removed with `GC_UNUSED_REMOVED` activity events.
2. **Capacity Runway & Retention Endpoint (`GET /catalog/retention`)**:
   - `build_cache_retention_report` computes disk usage/free space, trusted cache footprint, 30-day net daily growth from `provenance.jsonl`, `estimated_days_remaining`, `expiring_soon` (`>= 75` days unused via `GC_WARN_UNUSED_DAYS`), and `expired` (`> 90` days unused).
3. **Daily Digest Reporting (`gatekeeper/app/notifications.py`)**:
   - `build_daily_digest` includes **Cache Capacity & Runway**, **Replaced / Upgraded Vulnerable Components**, and **90-Day Inactivity Space Recovery** (`REMOVED`, `DUE FOR REMOVAL`, and `EXPIRING SOON`).

## Consequences

- **Positive**: Clean pinned dependencies stay cached indefinitely while active, vulnerable ones are replaced on discovery, and stale >90-day artifacts are reclaimed with advance warning in the daily digest.
- **Verification**: Covered by `test_keep_clean_versions_and_90_day_unused_ttl_gc_and_retention_digest` in `gatekeeper/tests/test_virtual_and_warmup.py`.
