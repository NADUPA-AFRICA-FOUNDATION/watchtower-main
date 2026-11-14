"""Newly registered domains: WhoisDS's free daily list.

Certificate Transparency only sees a domain once someone requests a TLS certificate for it.
A registration list sees it the day it is registered, often before the phishing page is up,
and it keeps working when crt.sh is down (which it often is).

Source: https://www.whoisds.com/newly-registered-domains. The page states the free lists may
be reused, including commercially, without a licence. Each list is a zip holding one text
file of domain names (a daily sample, about 70,000, not every registration in the world).

Rules kept:
  * Only names that carry a brand signal (the same pre-score test CT uses) become candidates;
    official domains are never candidates.
  * A day is marked done only through `cursor_updates`, which the runner applies after the
    candidates are stored, so a crash cannot skip a day.
  * A list not published yet is not an error; a download or zip that fails is, and says so.
  * The archive is untrusted: one expected member, a size ceiling, no extraction to disk.
"""
from __future__ import annotations

import base64
import io
import time
import zipfile
from datetime import datetime, timedelta, timezone

import httpx

from watchtower.discovery.base import SourceHealth

from ..normalize import InvalidIndicator, domain as normalize_domain
from ..prescore import is_official, prescore
from .base import Discovered, DiscoveryResult, HuntProvider, _now

MAX_UNZIPPED = 50_000_000          # bytes; a real list is about 1.2 MB


class NewlyRegisteredProvider(HuntProvider):
    name = "newly_registered"

    def __init__(self, client: httpx.AsyncClient | None = None, clock=None, user_agent: str = ""):
        self._client, self._own = client, client is None
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.user_agent = user_agent
        self._lists: dict[str, list[str]] = {}       # date -> names, shared across brands in one process

    def capabilities(self):
        return ("newly_registered_domains",)

    async def close(self):
        if self._own and self._client is not None:
            await self._client.aclose()

    def _http(self, cfg) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"User-Agent": self.user_agent} if self.user_agent else {}
            self._client = httpx.AsyncClient(timeout=cfg.newly_registered.timeout_seconds, follow_redirects=True, headers=headers)
        return self._client

    async def _list(self, day: str, cfg) -> list[str] | None:
        """Names registered on `day`, or None when that day's list is not published (yet)."""
        if day in self._lists:
            return self._lists[day]
        token = base64.b64encode(f"{day}.zip".encode()).decode()
        res = await self._http(cfg).get(cfg.newly_registered.url_template.format(token=token))
        if res.status_code == 404:
            return None
        if res.status_code != 200:
            raise ValueError(f"HTTP {res.status_code} for the {day} list")
        try:
            with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
                members = [m for m in zf.infolist() if m.filename.endswith(".txt")]
                if len(members) != 1:
                    raise ValueError(f"expected one text file in the {day} archive, found {len(members)}")
                if members[0].file_size > MAX_UNZIPPED:
                    raise ValueError(f"the {day} archive expands to {members[0].file_size} bytes; refusing")
                text = zf.read(members[0]).decode("utf-8", "replace")
        except zipfile.BadZipFile:
            # The site answers some missing days with an HTML page instead of a 404.
            if b"<html" in res.content[:500].lower():
                return None
            raise ValueError(f"the {day} download was not a zip archive")
        names = [line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")]
        self._lists[day] = names
        return names

    async def discover(self, brand, cfg, cursors):
        started = time.monotonic()
        nc = cfg.newly_registered
        health = SourceHealth(self.name, "operational", self.capabilities(), last_attempt=_now())
        result = DiscoveryResult([], health)
        today = self.clock().date()
        days = [(today - timedelta(days=n)).isoformat() for n in range(1, nc.days_back + 1)]
        done, missing, failed, scanned = [], [], [], 0
        seen: dict[str, Discovered] = {}
        for day in days:
            key = f"{self.name}:{brand.name}:{day}"
            if cursors.get(key) == "done":
                continue
            try:
                names = await self._list(day, cfg)
            except (httpx.HTTPError, ValueError) as exc:
                failed.append(f"{day}: {type(exc).__name__ if isinstance(exc, httpx.HTTPError) else exc}")
                continue
            if names is None:
                missing.append(day)
                continue
            scanned += len(names)
            for raw in names:
                try:
                    name = normalize_domain(raw).canonical
                except InvalidIndicator:
                    result.malformed += 1
                    continue
                if name in seen or is_official(name, brand):
                    continue
                if not prescore(name, brand, cfg.prescore).has_brand_signal:
                    result.noise_filtered += 1
                    continue
                seen[name] = Discovered(name, "domain", self.name, query=f"registered {day}", confidence=0.6,
                                        metadata={"registered_on": day, "list": "whoisds"})
            done.append(day)
            result.cursor_updates[key] = "done"
        candidates = list(seen.values())
        if len(candidates) > nc.max_candidates:
            result.notes.append(f"{len(candidates)} brand-like names; kept the first {nc.max_candidates}")
            candidates = candidates[: nc.max_candidates]
        result.candidates = candidates
        if failed and not done:
            health.status = "provider_error"
        elif failed:
            health.status = "partial"
        if failed:
            health.error = "; ".join(failed)[:500]
        health.results = len(candidates)
        health.duration_ms = int((time.monotonic() - started) * 1000)
        if health.status in {"operational", "partial"}:
            health.last_success = _now()
        health.detail = (f"{len(done)} day(s) scanned ({scanned} names), {len(candidates)} brand-like, "
                         f"{result.noise_filtered} unrelated filtered"
                         + (f"; not published yet: {', '.join(missing)}" if missing else "")
                         + ("; nothing new since the last run" if not done and not failed and not missing else ""))
        return result
