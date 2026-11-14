"""Message bus abstraction for decoupling Frontend HTTP serving from Engine background jobs.

Supports Valkey / Redis Streams (`BUS_URL=redis://...`) for multi-container
deployments and an in-process `InMemoryJobBus` fallback for single-container
and unit-test environments.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

logger = logging.getLogger("gatekeeper.bus")

JobHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BaseJobBus:
    """Interface for enqueuing, tracking, and consuming background engine jobs."""

    backend_name: str = "base"

    async def enqueue(self, job_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    async def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def update_job(self, job_id: str, **fields: Any) -> dict[str, Any] | None:
        raise NotImplementedError

    async def run_worker(
        self,
        handler: JobHandler,
        consumer_name: str = "engine-1",
        max_concurrency: int = 2,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class InMemoryJobBus(BaseJobBus):
    """In-process asyncio.Queue job bus for single-container and test deployments."""

    backend_name: str = "memory"

    def __init__(self, max_history: int = 500) -> None:
        self._queue: asyncio.Queue[str] | None = None
        self._queue_loop: asyncio.AbstractEventLoop | None = None
        self._jobs: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._max_history = max_history

    def _get_queue(self) -> asyncio.Queue[str]:
        loop = asyncio.get_running_loop()
        if self._queue is None or self._queue_loop is not loop:
            self._queue = asyncio.Queue()
            self._queue_loop = loop
        return self._queue

    async def enqueue(self, job_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        job_id = uuid.uuid4().hex
        now = _utc_now()
        record = {
            "job_id": job_id,
            "job_type": job_type,
            "status": "queued",
            "payload": payload,
            "result": None,
            "error": None,
            "created_at": now,
            "updated_at": now,
        }
        self._jobs[job_id] = record
        while len(self._jobs) > self._max_history:
            self._jobs.popitem(last=False)
        await self._get_queue().put(job_id)
        logger.info("[BUS] ENQUEUED backend=memory job_id=%s type=%s", job_id, job_type)
        return dict(record)

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        rec = self._jobs.get(job_id)
        return dict(rec) if rec is not None else None

    async def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        items = list(self._jobs.values())
        items.reverse()
        return [dict(item) for item in items[:limit]]

    async def update_job(self, job_id: str, **fields: Any) -> dict[str, Any] | None:
        rec = self._jobs.get(job_id)
        if rec is None:
            return None
        rec.update(fields)
        rec["updated_at"] = _utc_now()
        return dict(rec)

    async def run_worker(
        self,
        handler: JobHandler,
        consumer_name: str = "engine-memory",
        max_concurrency: int = 2,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        sem = asyncio.Semaphore(max(1, max_concurrency))
        active_tasks: set[asyncio.Task[None]] = set()

        async def _execute(job_id: str) -> None:
            async with sem:
                job = await self.get_job(job_id)
                if job is None:
                    return
                await self.update_job(job_id, status="running")
                try:
                    result = await handler(job)
                    await self.update_job(job_id, status="completed", result=result, error=None)
                    logger.info("[ENGINE] COMPLETED job_id=%s type=%s", job_id, job["job_type"])
                except Exception as exc:
                    logger.exception("[ENGINE] FAILED job_id=%s type=%s", job_id, job["job_type"])
                    await self.update_job(job_id, status="failed", error=str(exc))

        queue = self._get_queue()
        while not (stop_event and stop_event.is_set()):
            try:
                job_id = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            task = asyncio.create_task(_execute(job_id))
            active_tasks.add(task)
            task.add_done_callback(active_tasks.discard)

        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)


class ValkeyJobBus(BaseJobBus):
    """Valkey / Redis Streams job bus for decoupled Frontend + Engine containers."""

    backend_name: str = "valkey"
    STREAM_KEY = "trusted_oss:jobs:stream"
    GROUP_NAME = "oss-engine-group"
    RECENT_KEY = "trusted_oss:jobs:recent"
    JOB_KEY_PREFIX = "trusted_oss:job:"
    JOB_TTL_SECONDS = 86400

    def __init__(self, bus_url: str) -> None:
        import redis.asyncio as aioredis

        self._url = bus_url
        self._client = aioredis.from_url(bus_url, decode_responses=True)

    async def _save_job(self, record: dict[str, Any]) -> None:
        key = f"{self.JOB_KEY_PREFIX}{record['job_id']}"
        await self._client.set(key, json.dumps(record), ex=self.JOB_TTL_SECONDS)

    async def enqueue(self, job_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        job_id = uuid.uuid4().hex
        now = _utc_now()
        record = {
            "job_id": job_id,
            "job_type": job_type,
            "status": "queued",
            "payload": payload,
            "result": None,
            "error": None,
            "created_at": now,
            "updated_at": now,
        }
        await self._save_job(record)
        await self._client.lpush(self.RECENT_KEY, job_id)
        await self._client.ltrim(self.RECENT_KEY, 0, 199)
        await self._client.xadd(
            self.STREAM_KEY,
            {"job_id": job_id, "job_type": job_type, "payload": json.dumps(payload)},
        )
        logger.info("[BUS] ENQUEUED backend=valkey job_id=%s type=%s", job_id, job_type)
        return record

    async def get_job(self, job_id: str) -> dict[str, Any] | None:
        raw = await self._client.get(f"{self.JOB_KEY_PREFIX}{job_id}")
        if not raw:
            return None
        return json.loads(raw)

    async def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        ids = await self._client.lrange(self.RECENT_KEY, 0, max(0, limit - 1))
        if not ids:
            return []
        keys = [f"{self.JOB_KEY_PREFIX}{jid}" for jid in ids]
        raws = await self._client.mget(keys)
        return [json.loads(r) for r in raws if r]

    async def update_job(self, job_id: str, **fields: Any) -> dict[str, Any] | None:
        rec = await self.get_job(job_id)
        if rec is None:
            return None
        rec.update(fields)
        rec["updated_at"] = _utc_now()
        await self._save_job(rec)
        return rec

    async def _ensure_group(self) -> None:
        try:
            await self._client.xgroup_create(
                self.STREAM_KEY, self.GROUP_NAME, id="0", mkstream=True
            )
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def run_worker(
        self,
        handler: JobHandler,
        consumer_name: str = "engine-1",
        max_concurrency: int = 2,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        await self._ensure_group()
        sem = asyncio.Semaphore(max(1, max_concurrency))
        active_tasks: set[asyncio.Task[None]] = set()

        async def _execute(msg_id: str, fields: dict[str, str]) -> None:
            job_id = fields.get("job_id", "")
            async with sem:
                job = await self.get_job(job_id) if job_id else None
                if job is None:
                    job = {
                        "job_id": job_id or msg_id,
                        "job_type": fields.get("job_type", "unknown"),
                        "payload": json.loads(fields.get("payload", "{}")),
                    }
                await self.update_job(job["job_id"], status="running")
                try:
                    result = await handler(job)
                    await self.update_job(
                        job["job_id"], status="completed", result=result, error=None
                    )
                    logger.info(
                        "[ENGINE] COMPLETED job_id=%s type=%s",
                        job["job_id"],
                        job["job_type"],
                    )
                except Exception as exc:
                    logger.exception(
                        "[ENGINE] FAILED job_id=%s type=%s",
                        job["job_id"],
                        job["job_type"],
                    )
                    await self.update_job(job["job_id"], status="failed", error=str(exc))
                finally:
                    await self._client.xack(self.STREAM_KEY, self.GROUP_NAME, msg_id)

        while not (stop_event and stop_event.is_set()):
            try:
                entries = await self._client.xreadgroup(
                    self.GROUP_NAME,
                    consumer_name,
                    streams={self.STREAM_KEY: ">"},
                    count=max(1, max_concurrency),
                    block=2000,
                )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("[BUS] xreadgroup retry after error: %s", exc)
                await asyncio.sleep(2)
                continue

            for _stream, messages in entries or []:
                for msg_id, fields in messages:
                    task = asyncio.create_task(_execute(msg_id, fields))
                    active_tasks.add(task)
                    task.add_done_callback(active_tasks.discard)

        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)

    async def close(self) -> None:
        await self._client.aclose()


def create_job_bus(bus_url: str) -> BaseJobBus:
    """Create a Valkey/Redis Streams bus when BUS_URL is set, else an in-memory bus."""
    if bus_url.strip():
        return ValkeyJobBus(bus_url.strip())
    return InMemoryJobBus()
