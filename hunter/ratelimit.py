"""Centralised rate-limit awareness for free public services.

One limiter per upstream host. It spaces requests, and after a 429 it refuses
requests until the cool-down passes, so a rate-limited service is left alone
rather than retried into a longer ban. State is in-process; the scheduler is a
single process by design (see HUNTER_PLAN.md).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable


class RateLimiter:
    def __init__(self, min_interval: float = 1.0, *, monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Any] = asyncio.sleep):
        self.min_interval = min_interval
        self._monotonic, self._sleep = monotonic, sleep
        self._last: float | None = None
        self._blocked_until = 0.0
        self._lock: asyncio.Lock | None = None
        self.requests = 0
        self.throttled = 0

    @property
    def blocked(self) -> bool:
        return self._monotonic() < self._blocked_until

    def penalize(self, seconds: float) -> None:
        """Refuse requests for `seconds` (a 429, honouring Retry-After)."""
        self.throttled += 1
        self._blocked_until = max(self._blocked_until, self._monotonic() + seconds)

    async def wait(self) -> None:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._last is not None:
                delay = self.min_interval - (self._monotonic() - self._last)
                if delay > 0:
                    await self._sleep(delay)
            self._last = self._monotonic()
            self.requests += 1

    def status(self) -> dict:
        return {
            "min_interval_seconds": self.min_interval,
            "requests": self.requests,
            "rate_limited_count": self.throttled,
            "blocked": self.blocked,
            "retry_in_seconds": max(0.0, round(self._blocked_until - self._monotonic(), 1)),
        }
