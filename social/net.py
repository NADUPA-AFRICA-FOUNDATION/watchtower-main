"""HTTP for social discovery: honest identity, per-host pacing, a cache, and nothing clever.

No retries here. A retry inside the client would hide a rate limit from the breaker; the job
queue owns retrying, with backoff, where it is visible. PROXY_URL is honoured when set and is
off by default.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

DEFAULT_UA = "Mnara/1.0 (social discovery; +https://github.com/NADUPA-AFRICA-FOUNDATION/watchtower-main)"


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class Fetched:
    status: int
    body: str
    final_url: str
    error: str = ""
    from_cache: bool = False


class PoliteClient:
    def __init__(self, store, transport=None, clock=now_ms, sleep=time.sleep, timeout: float = 15.0):
        self.store, self.clock, self.sleep = store, clock, sleep
        kwargs = {"timeout": timeout, "follow_redirects": True, "transport": transport,
                  "headers": {"User-Agent": os.environ.get("WATCHTOWER_USER_AGENT") or DEFAULT_UA, "Accept-Language": "en"}}
        if os.environ.get("PROXY_URL") and transport is None:
            kwargs["proxy"] = os.environ["PROXY_URL"]
        self.http = httpx.Client(**kwargs)
        self._last: dict[str, int] = {}

    def close(self) -> None:
        self.http.close()

    def get(self, url: str, *, min_interval: float = 2.0, ttl: float = 0.0) -> Fetched:
        """One request, or the cached answer. Only 200s are cached: a block is never replayed as content."""
        key = hashlib.sha256(url.encode()).hexdigest()
        if ttl > 0:
            hit = self.store.cache_get(key, self.clock())
            if hit:
                return Fetched(hit["status"], hit["body"], url, from_cache=True)
        host = urlsplit(url).hostname or ""
        wait = min_interval * 1000 - (self.clock() - self._last.get(host, -10**12))
        if wait > 0:
            self.sleep(wait / 1000)
        try:
            r = self.http.get(url)
            out = Fetched(r.status_code, r.text, str(r.url))
        except Exception as exc:                                   # noqa: BLE001 - the error is the result
            out = Fetched(0, "", url, error=f"{type(exc).__name__}: {exc}"[:200])
        self._last[host] = self.clock()
        if ttl > 0 and out.status == 200 and out.body:
            self.store.cache_put(key, out.body, out.status, self.clock(), int(ttl * 1000))
        return out

    def post_json(self, url: str, payload: dict, headers: dict, *, min_interval: float = 1.0, ttl: float = 0.0) -> Fetched:
        """POST for keyed JSON APIs. Cached by URL and body, so a paid query asked twice is paid for once.
        The key travels in `headers` and is never part of the cache key."""
        body = json.dumps(payload, sort_keys=True)
        key = hashlib.sha256(f"POST {url} {body}".encode()).hexdigest()
        if ttl > 0:
            hit = self.store.cache_get(key, self.clock())
            if hit:
                return Fetched(hit["status"], hit["body"], url, from_cache=True)
        host = urlsplit(url).hostname or ""
        wait = min_interval * 1000 - (self.clock() - self._last.get(host, -10**12))
        if wait > 0:
            self.sleep(wait / 1000)
        try:
            r = self.http.post(url, content=body, headers={"Content-Type": "application/json", **headers})
            out = Fetched(r.status_code, r.text, str(r.url))
        except Exception as exc:                                   # noqa: BLE001 - the error is the result
            out = Fetched(0, "", url, error=f"{type(exc).__name__}"[:200])   # never echo a message that could hold the key
        self._last[host] = self.clock()
        if ttl > 0 and out.status == 200 and out.body:
            self.store.cache_put(key, out.body, out.status, self.clock(), int(ttl * 1000))
        return out
