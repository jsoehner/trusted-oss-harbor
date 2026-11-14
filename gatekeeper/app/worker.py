"""Standalone Engine worker entrypoint for Trusted OSS Gatekeeper.

Runs as the dedicated `oss-engine` container consuming jobs from the Valkey/Redis
Streams message bus (`BUS_URL`) and executing the hourly CVE rescan loop without
blocking the `oss-frontend` HTTP serving container.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path

import httpx

from app.bus import create_job_bus
from app.config import Settings
from app.main import (
    _hourly_cve_rescan_loop,
    app,
    handle_engine_job,
    initialize_storage_and_keys,
)
from app.notifications import (
    build_daily_digest,
    resolve_msgraph_access_token,
    send_graph_mail,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("gatekeeper.engine")


async def _daily_digest_loop(settings: Settings, stop_event: asyncio.Event) -> None:
    """Send a daily Graph email / Email-to-SMS digest when DIGEST_ENABLED=true."""
    interval = max(300, int(os.getenv("DIGEST_INTERVAL_SECONDS", "86400")))
    frontend_url = os.getenv("DIGEST_FRONTEND_URL", "http://oss-frontend:8000").rstrip("/")
    token_file = Path(
        os.getenv("GRAPH_TOKEN_FILE", str(settings.oss_data_root / "audit" / "msgraph_token.json"))
    )
    stamp_file = settings.oss_data_root / "audit" / "last_digest_sent.txt"
    email_to = [x.strip() for x in os.getenv("DIGEST_TO", "").split(",") if x.strip()]
    sms_to = [x.strip() for x in os.getenv("DIGEST_SMS_TO", "").split(",") if x.strip()]

    if not (email_to or sms_to):
        logger.warning("[ENGINE] DIGEST_ENABLED=true but DIGEST_TO and DIGEST_SMS_TO are empty")
        return

    while not stop_event.is_set():
        now = time.time()
        last_sent = 0.0
        if stamp_file.exists():
            try:
                last_sent = float(stamp_file.read_text(encoding="utf-8").strip())
            except ValueError:
                last_sent = 0.0

        if now - last_sent >= interval:
            try:
                headers = {"Authorization": f"Bearer {settings.admin_token}"}
                async with httpx.AsyncClient(timeout=15.0) as client:
                    h_resp = await client.get(f"{frontend_url}/healthz", headers=headers)
                    v_resp = await client.get(
                        f"{frontend_url}/catalog/vulnerabilities", headers=headers
                    )
                    a_resp = await client.get(
                        f"{frontend_url}/audit/activity?limit=200", headers=headers
                    )
                    h_resp.raise_for_status()
                    v_resp.raise_for_status()
                    a_resp.raise_for_status()

                subject, body_text, sms_text = build_daily_digest(
                    health=h_resp.json(),
                    vuln_data=v_resp.json(),
                    activity_events=a_resp.json().get("events", []),
                    hours=max(1, interval // 3600),
                )
                graph_token = await asyncio.to_thread(
                    resolve_msgraph_access_token,
                    access_token=os.getenv("GRAPH_ACCESS_TOKEN", ""),
                    refresh_token=os.getenv("GRAPH_REFRESH_TOKEN", ""),
                    client_id=os.getenv("GRAPH_CLIENT_ID", ""),
                    tenant_id=os.getenv("GRAPH_TENANT_ID", "common"),
                    token_file=token_file,
                )
                if not graph_token:
                    logger.warning("[ENGINE] Daily digest skipped: no Graph token available")
                else:
                    if email_to:
                        await asyncio.to_thread(
                            send_graph_mail,
                            access_token=graph_token,
                            recipients=email_to,
                            subject=subject,
                            body=body_text,
                        )
                    if sms_to:
                        await asyncio.to_thread(
                            send_graph_mail,
                            access_token=graph_token,
                            recipients=sms_to,
                            subject="OSS Harbor Digest",
                            body=sms_text,
                        )
                    stamp_file.parent.mkdir(parents=True, exist_ok=True)
                    stamp_file.write_text(str(now), encoding="utf-8")
                    logger.info(
                        "[ENGINE] Daily digest sent via Graph (email=%d sms=%d)",
                        len(email_to),
                        len(sms_to),
                    )
            except Exception as exc:
                logger.warning("[ENGINE] Daily digest error: %s", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=min(3600, interval))
        except asyncio.TimeoutError:
            pass


async def run_engine() -> None:
    """Start the background engine worker and hourly CVE rescan loop."""
    settings = Settings()
    app.state.settings = settings
    initialize_storage_and_keys(settings)

    bus = create_job_bus(settings.bus_url)
    app.state.job_bus = bus
    consumer_name = os.getenv("HOSTNAME", "oss-engine-1")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    logger.info(
        "[ENGINE] Starting oss-engine worker bus=%s concurrency=%d rescan_interval=%ds",
        bus.backend_name,
        settings.engine_max_concurrency,
        settings.cve_rescan_interval_seconds,
    )

    rescan_task: asyncio.Task[None] | None = None
    if settings.cve_rescan_interval_seconds > 0:
        rescan_task = asyncio.create_task(_hourly_cve_rescan_loop(app))

    digest_task: asyncio.Task[None] | None = None
    if os.getenv("DIGEST_ENABLED", "false").lower() in {"1", "true", "yes"}:
        digest_task = asyncio.create_task(_daily_digest_loop(settings, stop_event))

    try:
        await bus.run_worker(
            lambda job: handle_engine_job(job, settings, app),
            consumer_name=consumer_name,
            max_concurrency=settings.engine_max_concurrency,
            stop_event=stop_event,
        )
    finally:
        stop_event.set()
        for task in (rescan_task, digest_task):
            if task is not None:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        await bus.close()
        logger.info("[ENGINE] Shutdown complete")


def main() -> None:
    asyncio.run(run_engine())


if __name__ == "__main__":
    main()
