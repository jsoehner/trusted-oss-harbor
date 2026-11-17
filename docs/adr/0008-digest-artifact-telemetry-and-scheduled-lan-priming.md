# ADR 0008: Daily Digest Artifact Activity Telemetry and Scheduled LAN Cache Priming

- **Status:** Accepted
- **Date:** 2026-11-17
- **Version:** 1.4.0

## Context

1. The daily digest (`build_daily_digest`) previously reported total cached component counts, capacity runway, and remediation/GC events, but did not distinguish how many artifacts were **requested** (cache hits vs. misses), how many **brand-new artifacts** were added, or how many **new versions** of existing components were cached during the reporting window.
2. When new projects or dependency versions are added locally on the workstation, waiting until a CI run causes avoidable cache misses. We need an automated, scheduled local discovery job that targets the LAN endpoint (`http://oss.jsigroup.local:8080`) directly (avoiding WAN NAT hairpinning).

## Decision

1. **Structured Artifact Activity Events (`gatekeeper/app/main.py` + `gatekeeper/app/notifications.py`)**:
   - Record `ARTIFACT_REQUESTED` (`cache=HIT` or `cache=MISS`) on every Maven, PyPI, and OCI virtual proxy request via `_record_artifact_requested`.
   - Before promoting a clean artifact in `quarantine_scan_sign_and_promote`, check `_has_existing_component_versions` and emit `NEW_ARTIFACT_ADDED` (first cached version) or `NEW_VERSION_ADDED` (subsequent version of an existing component).
   - Surface `Requested (hits, misses)`, `New Artifacts`, and `New Versions` in the daily digest subject, body (`Artifact Activity` + `New Artifacts & Versions Added` list), and SMS summary.
2. **Scheduled LAN Cache Priming (`scripts/install_prime_timer.sh`)**:
   - Install a `systemd --user` timer (`trusted-oss-prime.timer`, daily at `06:00` local time) running `scripts/prime_cache.py --roots $HOME --url http://oss.jsigroup.local:8080 --wait` with `GATEKEEPER_ADMIN_TOKEN` loaded from `~/.config/trusted-oss-harbor/prime.env`.

## Consequences

- Operators see exact daily cache demand (`REQ`, `hits`/`misses`) and growth (`NEW`, `NEW_VER`) in every daily digest email/SMS.
- Newly added local projects and updated dependencies are automatically discovered and pre-warmed overnight over LAN without NAT hairpinning.
