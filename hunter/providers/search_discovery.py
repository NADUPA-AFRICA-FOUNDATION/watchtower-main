"""Discovery by public search templates.

Runs a rotating slice of brand-phrase queries ("{brand}" "verify account", ... plus operator-style
site: searches over free-hosting platforms) through a SearchBackend. Search ranking is not threat
confidence: every result is a low-confidence lead (0.4) that must earn its score by what its page shows.

Failure is explicit: a blocked or rate-limited engine ends the run with that status, an unparseable
page is an error, and "no results" is only reported when the backend's control-query check passed
(see hunter.search). The shared daily search budget is honoured through `queries_available`.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

from core.trusted_domains import is_trusted_domain
from watchtower.discovery.base import SourceHealth

from ..pivots import is_infra_host
from ..prescore import is_official, is_shared_hosting
from .base import Discovered, DiscoveryResult, HuntProvider, _now


class SearchDiscoveryProvider(HuntProvider):
    name = "search_discovery"

    def __init__(self, backend, queries_available=lambda: 10**9, on_query=lambda q: None):
        self.backend, self.queries_available, self.on_query = backend, queries_available, on_query

    def capabilities(self):
        return ("open_web", "operator_queries")

    def rate_limit_status(self):
        return self.backend.rate_limit_status()

    async def discover(self, brand, cfg, cursors):
        sc, t0 = cfg.search_discovery, time.monotonic()
        health = SourceHealth(self.name, "operational", self.capabilities(), last_attempt=_now())
        result = DiscoveryResult([], health)
        templates = sc.templates
        key = f"{self.name}:{brand.name}:rotation"
        start = int(cursors.get(key, "0")) % max(len(templates), 1)
        n = min(sc.max_queries_per_run, len(templates), max(self.queries_available(), 0))
        if n <= 0:
            health.status, health.error = "rate_limited", "daily search budget exhausted"
            return result
        picked = [templates[(start + i) % len(templates)] for i in range(n)]
        failures, ran, seen = [], 0, {}
        for tpl in picked:
            q = tpl.replace("{brand}", brand.name)
            self.on_query(q)
            out = await self.backend.search(q, sc.max_results_per_query)
            if not out.searched:
                failures.append(f"{out.status}: {out.error}")
                if out.status in {"blocked", "rate_limited"}:
                    break
                continue
            ran += 1
            for hit in out.hits:
                host = (urlsplit(hit.url).hostname or "").lower().removeprefix("www.")
                if (not host or host in seen or is_infra_host(host) or is_official(host, brand)
                        or (not is_shared_hosting(host) and is_trusted_domain(host))):
                    continue
                seen[host] = Discovered(host, "domain", self.name, query=q, confidence=0.4,
                                        metadata={"title": hit.title, "snippet": hit.snippet, "url": hit.url})
        result.candidates = list(seen.values())
        if failures and not ran:
            health.status = "rate_limited" if failures[0].startswith("rate_limited") else "provider_error"
        elif failures:
            health.status = "partial"
        if failures:
            health.error = "; ".join(failures)[:300]
        else:
            result.cursor_updates[key] = str((start + n) % len(templates))        # only a complete run advances the rotation
        health.results = len(result.candidates)
        health.duration_ms = int((time.monotonic() - t0) * 1000)
        health.rate_limit = self.backend.rate_limit_status()
        if health.status in {"operational", "partial"}:
            health.last_success = _now()
        health.detail = f"{ran}/{n} queries answered"
        return result
