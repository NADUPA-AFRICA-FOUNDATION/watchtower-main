"""Known-phishing feed check for one domain.

Two free, keyless lists, downloaded whole and matched locally, so a candidate's name is never
sent to a third party:

  phishing_database   github.com/Phishing-Database/Phishing.Database, active domains (open source)
  openphish           OpenPhish community feed (URLs; matched on hostname)

The rules the rest of the hunter relies on:

  * Unseen is not clean. A feed that could not be downloaded is reported in `errors` and the
    result is `partial` or `error`; it is never a quiet "no hit". Only `checked` means every
    feed was actually consulted.
  * Exact hostname match only (`www.` ignored). Parent-domain matching would flag every site
    on a shared host the moment one tenant is listed.
  * A hit is a fact about a list, not a verdict. It feeds `known_malicious_infrastructure`
    with the feed named in the reason.

Lists are cached in memory for `cache_hours`; a failed refresh keeps the previous copy and says
so (`stale`), because yesterday's list is better evidence than none.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

FEEDS = {
    "phishing_database": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "openphish": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
}
# A list this short is a truncated or error body, not a quiet day.
MIN_ENTRIES = {"phishing_database": 1000, "openphish": 20}


@dataclass
class ThreatResult:
    domain: str
    status: str                                   # checked | partial | error
    hits: list[str] = field(default_factory=list)
    feeds_checked: list[str] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def facts(self) -> dict:
        return {"status": self.status, "hits": self.hits, "feeds_checked": self.feeds_checked,
                "stale": self.stale, "errors": self.errors}


def _host(entry: str) -> str:
    entry = entry.strip().lower()
    if "://" in entry:
        entry = urlsplit(entry).hostname or ""
    return entry.removeprefix("www.").rstrip(".")


class ThreatFeeds:
    def __init__(self, client: httpx.AsyncClient | None = None, cache_hours: float = 12.0,
                 timeout: float = 45.0, feeds: dict[str, str] | None = None, clock=time.monotonic):
        self._client, self._own = client, client is None
        self._ttl, self._timeout, self._clock = cache_hours * 3600, timeout, clock
        self.feeds = dict(feeds or FEEDS)
        self._cache: dict[str, tuple[float, frozenset[str]]] = {}

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=True)
        return self._client

    async def close(self) -> None:
        if self._own and self._client is not None:
            await self._client.aclose()

    async def _load(self, name: str) -> tuple[frozenset[str] | None, bool, str | None]:
        """(entries, stale, error). `entries` is None only when there is no copy at all."""
        cached = self._cache.get(name)
        if cached and self._clock() - cached[0] < self._ttl:
            return cached[1], False, None
        try:
            res = await self._http().get(self.feeds[name], timeout=self._timeout)
            if res.status_code != 200:
                raise ValueError(f"HTTP {res.status_code}")
            entries = frozenset(h for h in (_host(line) for line in res.text.splitlines()
                                            if line.strip() and not line.startswith("#")) if h)
            if len(entries) < MIN_ENTRIES.get(name, 1):
                raise ValueError(f"only {len(entries)} entries; expected a full list")
        except Exception as exc:                                    # noqa: BLE001 - reported, never hidden
            error = f"{type(exc).__name__}: {exc}"[:200]
            return (cached[1], True, error) if cached else (None, False, error)
        self._cache[name] = (self._clock(), entries)
        return entries, False, None

    async def check(self, domain: str) -> ThreatResult:
        host = _host(domain)
        result = ThreatResult(domain, "checked")
        for name in self.feeds:
            entries, stale, error = await self._load(name)
            if error:
                result.errors[name] = error
            if entries is None:
                continue
            result.feeds_checked.append(name)
            if stale:
                result.stale.append(name)
            if host in entries:
                result.hits.append(name)
        if not result.feeds_checked:
            result.status = "error"
        elif len(result.feeds_checked) < len(self.feeds):
            result.status = "partial"
        return result
