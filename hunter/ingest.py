"""Run one discovery provider and feed the queue.

This is the failure-isolation boundary (spec phase 20): whatever a provider does,
raise, hang or return garbage, the caller gets a RunSummary back and the other
providers still run. The failure is stored, never swallowed.

Per candidate: official domains are skipped (counted), everything else is
pre-scored and submitted. The pre-score band sets the route: STORE stays `NEW`
(kept for correlation, not investigated), the rest are queued with the score as
priority. Cursors advance only if the whole batch was stored.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from watchtower.discovery.base import SourceHealth

from .config import Brand, HuntConfig
from .normalize import DOMAIN, InvalidIndicator, normalize
from .prescore import is_official, prescore
from .providers.base import HuntProvider
from .store import HuntStore


@dataclass
class RunSummary:
    provider: str
    brand: str
    status: str
    found: int = 0
    submitted: int = 0
    created: int = 0
    queued: int = 0
    stored_only: int = 0
    rejected: int = 0
    skipped_official: int = 0
    noise_filtered: int = 0
    truncated: bool = False
    error: str | None = None
    detail: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "operational"

    def dict(self) -> dict:
        return dict(self.__dict__)


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


async def run_discovery(store: HuntStore, provider: HuntProvider, brand: Brand, cfg: HuntConfig,
                        *, timeout: float = 300.0) -> RunSummary:
    started_at, t0 = _iso(), time.monotonic()
    summary = RunSummary(provider.name, brand.name, "operational")
    cursors = store.get_state(f"{provider.name}:{brand.name}:")
    health: SourceHealth | None = None
    result = None
    try:
        result = await asyncio.wait_for(provider.discover(brand, cfg, cursors), timeout)
        health = result.health
        summary.status, summary.error, summary.detail = health.status, health.error, health.detail
    except asyncio.TimeoutError:
        summary.status, summary.error = "timeout", f"provider exceeded {timeout:.0f}s"
    except Exception as exc:  # a provider must never stop the others
        summary.status, summary.error = "provider_error", f"{type(exc).__name__}: {exc}"[:500]

    if result is not None:
        summary.noise_filtered = result.noise_filtered
        summary.notes = list(result.notes)
        summary.found = len(result.candidates)
        summary.rejected += result.malformed
        _ingest(store, provider, brand, cfg, result, summary)
        if not summary.truncated:
            store.set_state(result.cursor_updates)
        else:
            summary.notes.append("cursor not advanced: run hit max_candidates_per_run")

    store.record_run(
        provider.name, brand.name, status=summary.status, started_at=started_at,
        duration_ms=int((time.monotonic() - t0) * 1000), found=summary.found,
        submitted=summary.submitted, created=summary.created, queued=summary.queued,
        stored_only=summary.stored_only, rejected=summary.rejected,
        skipped_official=summary.skipped_official, noise_filtered=summary.noise_filtered,
        truncated=summary.truncated,
        detail="; ".join(x for x in [summary.detail, *summary.notes] if x) or None,
        error=summary.error, last_success=health.last_success if health else None,
        rate_limit=provider.rate_limit_status(),
    )
    return summary


def _ingest(store, provider, brand, cfg, result, summary) -> None:
    budget = cfg.max_candidates_per_run
    for cand in result.candidates:
        if summary.submitted >= budget:
            summary.truncated = True
            break
        priority, enqueue, meta = cand.priority, True, dict(cand.metadata)
        try:
            ind = normalize(cand.indicator, hint=cand.indicator_type)
        except InvalidIndicator as exc:
            store.reject(cand.indicator, cand.source, str(exc))
            summary.rejected += 1
            continue
        if ind.type == DOMAIN:
            if is_official(ind.canonical, brand):
                summary.skipped_official += 1
                continue
            ps = prescore(ind.canonical, brand, cfg.prescore,
                          cert_age_days=meta.get("cert_age_days"),
                          domain_age_days=meta.get("domain_age_days"))
            meta["prescore"] = ps.dict()
            priority = ps.score if priority is None else priority
            enqueue = ps.band != "STORE"
        sub = store.submit(cand.indicator, cand.source, hint=cand.indicator_type, query=cand.query,
                           brand=brand.name, priority=priority or 0.0, confidence=cand.confidence,
                           metadata=meta, enqueue=enqueue)
        if not sub.accepted:
            summary.rejected += 1
            continue
        summary.submitted += 1
        summary.created += int(sub.created)
        if enqueue:
            summary.queued += 1
        else:
            summary.stored_only += 1
