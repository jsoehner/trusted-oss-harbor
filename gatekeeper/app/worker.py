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

from app.bus import create_job_bus
from app.config import Settings
from app.main import (
    _hourly_cve_rescan_loop,
    app,
    handle_engine_job,
    initialize_storage_and_keys,
)
from app.notifications import run_daily_digest_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("gatekeeper.engine")


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
        digest_task = asyncio.create_task(
            run_daily_digest_loop(
                oss_data_root=settings.oss_data_root,
                admin_token=settings.admin_token,
                stop_event=stop_event,
                default_frontend_url="http://oss-frontend:8000",
                logger=logger,
            )
        )

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
