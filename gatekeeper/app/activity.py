"""Structured JSONL activity log for scheduled tasks, scans, remediation, and GC."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any


def append_activity_event(
    activity_log_path: Path,
    *,
    source: str,
    event: str,
    details: str = "",
    ecosystem: str = "",
    component: str = "",
    version: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append a structured activity event to audit/activity.jsonl."""
    record: dict[str, Any] = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source,
        "event": event,
        "ecosystem": ecosystem,
        "component": component,
        "version": version,
        "details": details,
    }
    if metadata:
        record["metadata"] = metadata

    activity_log_path.parent.mkdir(parents=True, exist_ok=True)
    with activity_log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def read_activity_events(
    activity_log_path: Path,
    *,
    limit: int = 50,
    events_filter: set[str] | None = None,
    sources_filter: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Read recent activity events (newest first) with optional event/source filters."""
    if not activity_log_path.is_file():
        return []

    records: list[dict[str, Any]] = []
    for line in activity_log_path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if events_filter and str(rec.get("event", "")).upper() not in events_filter:
            continue
        if sources_filter and str(rec.get("source", "")).lower() not in sources_filter:
            continue
        records.append(rec)

    records.reverse()
    return records[: max(1, limit)]
