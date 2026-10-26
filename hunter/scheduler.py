"""Scheduled, unattended hunting.

One process, one loop, no extra infrastructure. Each job has an interval; due jobs run in turn, each
under a timeout, and one job failing never stops the others (the failure is recorded in provider health).
A provider whose last `breaker_failures` runs all failed is skipped until a cool-down passes (circuit
breaker), and that shows in the coverage report as `circuit_open` rather than being retried into a ban.

Jobs
  certificate_transparency   every ct_minutes             new certificates for the brand's terms
  permutation                every permutation_hours      impersonation names (no-op when nothing changed)
  search_discovery           every search_discovery_hours public-search templates
  enrich                     every enrich_seconds         claims queued candidates: DNS/RDAP/TLS/page/score/pivot
  refresh                    every refresh_minutes        re-queues settled candidates that are due a re-check
  alerts                     every alerts_seconds         raises the few alerts that matter
  purge                      every purge_hours            retention

At startup, if the scoring configuration changed since the last run, every score is recomputed from stored
evidence (offline) and the change is attributed to the new config hash in score history.

The scheduler refuses to start on storage that will not survive (a serverless /tmp): a queue that silently
resets is a silent failure.
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any, Awaitable, Callable

from .coverage import breaker
from .enrich.pipeline import enrich_batch
from .ingest import run_discovery
from .retention import purge
from .scoring import config_hash, rescore_and_route


class SchedulerRefused(RuntimeError):
    pass


def check_persistent_storage(db_path: str, env=None) -> None:
    env = os.environ if env is None else env
    if env.get("VERCEL") and not env.get("WATCHTOWER_DATA_DIR"):
        raise SchedulerRefused("serverless storage is ephemeral: the queue, scores and campaigns would be lost between invocations. "
                               "Set WATCHTOWER_DATA_DIR to a persistent volume, or run the hunter on a host with a disk.")
    if str(db_path).startswith(("/tmp/", "/private/tmp/")) and not env.get("WATCHTOWER_ALLOW_EPHEMERAL"):
        raise SchedulerRefused(f"{db_path} is under /tmp, which is not durable. Set WATCHTOWER_DATA_DIR, or "
                               "WATCHTOWER_ALLOW_EPHEMERAL=1 to run anyway (for tests and demos).")


@dataclass
class Services:
    store: Any
    graph: Any
    ctx: Any                                 # EnrichContext
    ct: Any = None
    permutation: Any = None
    search_discovery: Any = None
    alerts: Any = None
    closers: list = field(default_factory=list)

    async def close(self) -> None:
        for fn in self.closers:
            try:
                await fn()
            except Exception:
                pass


@dataclass
class JobResult:
    name: str
    status: str            # ok | error | timeout | skipped_circuit_open | skipped_disabled
    detail: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class Job:
    name: str
    interval: float
    run: Callable[[], Awaitable[dict]]
    provider: str | None = None
    enabled: bool = True


def refresh_due(store, cfg, now: datetime) -> dict:
    """Re-queue settled candidates whose re-check is due. A parked domain that turned into a login page
    is only ever noticed by looking again."""
    due = 0
    for cand in store.settled_domains(5000):
        if due >= cfg.scheduler.refresh_batch:
            break
        days = cfg.scheduler.refresh_days.get((cand.get("classification") or "UNASSESSED").upper(), cfg.scheduler.refresh_days["LOW"])
        if cand.get("disposition") in {"BENIGN", "FALSE_POSITIVE"}:
            days = max(days, cfg.scheduler.benign_refresh_days)        # reviewed and cleared: look again, but rarely
        if datetime.fromisoformat(cand["last_investigated"]) <= now - timedelta(days=days):
            store.requeue(cand["id"], stage="none", reason=f"scheduled refresh ({cand.get('classification') or 'UNASSESSED'}, every {days:g}d)")
            due += 1
    return {"requeued": due}


class Scheduler:
    def __init__(self, services: Services, cfg, clock=None, sleep=asyncio.sleep):
        self.sv, self.cfg = services, cfg
        self.store, self.graph = services.store, services.graph
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._sleep = sleep
        self.jobs = self._build()

    # -- jobs ------------------------------------------------------------------------------------------------------
    def _build(self) -> list[Job]:
        c, sc, sv = self.cfg, self.cfg.scheduler, self.sv
        jobs = []
        for name, interval, provider, enabled in (
                ("certificate_transparency", sc.ct_minutes * 60, sv.ct, c.ct.enabled),
                ("permutation", sc.permutation_hours * 3600, sv.permutation, c.permutations.enabled),
                ("search_discovery", sc.search_discovery_hours * 3600, sv.search_discovery,
                 c.search_discovery.enabled and c.pivots.search)):
            if provider is not None:
                jobs.append(Job(name, interval, partial(self._discover, provider), name, enabled))
        jobs.append(Job("enrich", sc.enrich_seconds, self._enrich))
        jobs.append(Job("refresh", sc.refresh_minutes * 60, self._refresh))
        if sv.alerts is not None:
            jobs.append(Job("alerts", sc.alerts_seconds, self._alerts))
        jobs.append(Job("purge", sc.purge_hours * 3600, self._purge))
        return jobs

    async def _discover(self, provider) -> dict:
        out = []
        for brand in self.cfg.brands:
            out.append((await run_discovery(self.store, provider, brand, self.cfg, timeout=self.cfg.scheduler.job_timeout_seconds)).dict())
        return {"runs": out, "failed": [o["provider"] for o in out if o["status"] != "operational"]}

    async def _enrich(self) -> dict:
        limit, claimed, rounds = self.cfg.scheduler.enrich_limit, 0, 0
        outcomes: dict = {}
        while rounds < 5:                                   # a backlog drains within the tick instead of waiting a minute per batch
            s = await enrich_batch(self.sv.ctx, limit)
            rounds += 1
            claimed += s.claimed
            for k, v in s.outcomes.items():
                outcomes[k] = outcomes.get(k, 0) + v
            if s.claimed < limit:
                break
        return {"claimed": claimed, "rounds": rounds, "outcomes": outcomes}

    async def _refresh(self) -> dict:
        return refresh_due(self.store, self.cfg, self.clock())

    async def _alerts(self) -> dict:
        r = self.sv.alerts.evaluate()
        return {"raised": len(r["raised"]), "suppressed": r["suppressed"]}

    async def _purge(self) -> dict:
        return purge(self.store, self.graph, self.cfg, self.clock())

    # -- state ----------------------------------------------------------------------------------------------------------
    def _key(self, name: str) -> str:
        return f"schedule:last:{name}"

    def last_run(self, name: str) -> datetime | None:
        v = self.store.get_state(self._key(name)).get(self._key(name))
        return datetime.fromisoformat(v) if v else None

    def next_due(self, job: Job, now: datetime | None = None) -> datetime:
        """A job that has never run is due now. `now` is the caller's timestamp: re-reading a real clock here
        would return a later instant and the job would never look due."""
        last = self.last_run(job.name)
        return (now or self.clock()) if last is None else last + timedelta(seconds=job.interval)

    def startup(self) -> dict:
        """Recompute scores if the scoring configuration changed since the last run (offline, attributed)."""
        changed = {}
        for brand in self.cfg.brands:
            key, new = f"scoring:config:{brand.name}", config_hash(self.cfg, brand)
            old = self.store.get_state(key).get(key)
            if old is not None and old != new:
                n = 0
                for cand in self.store.list(limit=1_000_000):
                    if cand["indicator_type"] == "domain" and cand["brand"] == brand.name and self.store.latest_score(cand["id"]):
                        rescore_and_route(self.store, self.graph, self.cfg, self.sv.ctx.brands, cand["id"], "config_change", self.clock())
                        n += 1
                changed[brand.name] = n
            self.store.set_state({key: new})
        return changed

    # -- running ------------------------------------------------------------------------------------------------------------
    async def run_job(self, job: Job) -> JobResult:
        now = self.clock()
        if not job.enabled:
            return JobResult(job.name, "skipped_disabled")
        if job.provider:
            is_open, until = breaker(self.store.provider_health_row(job.provider), self.cfg.scheduler, now)
            if is_open:
                return JobResult(job.name, "skipped_circuit_open", {"until": until})
        # Discovery jobs bound each brand's run themselves; the outer limit must be larger or the two race.
        limit = self.cfg.scheduler.job_timeout_seconds * ((len(self.cfg.brands) + 1) if job.provider else 1)
        try:
            detail = await asyncio.wait_for(job.run(), limit)
            res = JobResult(job.name, "ok", detail)
        except asyncio.TimeoutError:
            res = JobResult(job.name, "timeout", error=f"exceeded {limit:g}s")
        except Exception as exc:                          # one job must never stop the others
            res = JobResult(job.name, "error", error=f"{type(exc).__name__}: {exc}"[:300])
        if res.status != "ok":
            self.store.record_run(job.name, None, status="provider_error" if res.status == "error" else res.status,
                                  started_at=now.isoformat(), duration_ms=None, error=res.error)
        self.store.set_state({self._key(job.name): self.clock().isoformat()})   # failed jobs wait their interval too
        return res

    async def run_due(self, only: set | None = None) -> list[JobResult]:
        now, out = self.clock(), []
        for job in self.jobs:
            if only and job.name not in only:
                continue
            if self.next_due(job, now) <= now:
                out.append(await self.run_job(job))
        return out

    async def run_once(self, only: set | None = None) -> list[JobResult]:
        """Run every job now regardless of interval (for demos, cron, and tests)."""
        out = []
        for job in self.jobs:
            if not only or job.name in only:
                out.append(await self.run_job(job))
        return out

    async def run_forever(self, stop: asyncio.Event) -> None:
        self.startup()
        while not stop.is_set():
            await self.run_due()
            wait = min([max((self.next_due(j) - self.clock()).total_seconds(), 0) for j in self.jobs] + [self.cfg.scheduler.tick_seconds])
            try:
                await asyncio.wait_for(stop.wait(), max(wait, 0.05))
            except asyncio.TimeoutError:
                pass

    def status(self) -> list[dict]:
        now = self.clock()
        rows = []
        for j in self.jobs:
            last = self.last_run(j.name)
            is_open, until = breaker(self.store.provider_health_row(j.provider), self.cfg.scheduler, now) if j.provider else (False, None)
            rows.append({"job": j.name, "enabled": j.enabled, "interval_seconds": j.interval,
                         "last_run": last.isoformat() if last else None,
                         "next_due": self.next_due(j).isoformat() if j.enabled else None, "circuit_open": is_open, "circuit_until": until})
        return rows
