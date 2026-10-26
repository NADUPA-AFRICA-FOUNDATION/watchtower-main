"""Certificate Transparency discovery through crt.sh.

Differs from watchtower.discovery's CT provider on purpose: that one caches a
term for 30 days, which would hide every new certificate from a poller. This one
keeps a per-term cursor (newest entry timestamp seen) and returns only certificates
logged since, so running every 15-60 minutes costs one request per term and
yields only what is new.

Failure handling, per term:
  404            crt.sh's answer for "valid query, no matches": a searched zero.
  429            stop for this run, cool the limiter down, report `rate_limited`.
  5xx / timeout  this term failed; others still run; report `partial`/`provider_error`.
  bad body       crt.sh answers overload with HTML or an empty 200; that is an error,
                 not an empty result set.
A failed term never advances its cursor, so it is retried, not skipped.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import httpx

from watchtower.discovery.base import SourceHealth

from ..normalize import InvalidIndicator, domain as normalize_domain
from ..prescore import is_official, plain, prescore
from ..ratelimit import RateLimiter
from .base import Discovered, DiscoveryResult, HuntProvider, _now

CRT_URL = "https://crt.sh/"


class _RateLimited(Exception):
    def __init__(self, retry_after: float):
        self.retry_after = retry_after


class _TermFailed(Exception):
    pass


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class CertificateTransparencyProvider(HuntProvider):
    name = "certificate_transparency"

    def __init__(self, client: httpx.AsyncClient | None = None, limiter: RateLimiter | None = None,
                 clock=None):
        self._client = client
        self._owns_client = client is None
        self.limiter = limiter
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def capabilities(self):
        return ("domain_discovery", "certificate", "sibling_domains")

    def rate_limit_status(self):
        return self.limiter.status() if self.limiter else {}

    async def close(self):
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    def _http(self, cfg) -> httpx.AsyncClient:
        if self._client is None:
            contact = os.environ.get("WATCHTOWER_CONTACT", "unset")
            self._client = httpx.AsyncClient(
                timeout=cfg.ct.timeout_seconds, follow_redirects=False,
                headers={"User-Agent": os.environ.get(
                    "WATCHTOWER_USER_AGENT", f"Watchtower/1.0 OSINT (contact: {contact})")},
            )
        return self._client

    @staticmethod
    def terms(brand) -> list[str]:
        """crt.sh matches substrings of the identity, so `mpesa` misses `m-pesa`."""
        out: dict[str, None] = {}
        for name in (*brand.aliases, *brand.related_brands):
            for form in (name.lower().strip().replace(" ", "-"), plain(name)):
                if len(plain(form)) >= 4:
                    out[form] = None
        return list(out)

    async def _query(self, term: str, cfg) -> list[dict]:
        assert self.limiter is not None
        await self.limiter.wait()
        try:
            resp = await self._http(cfg).get(CRT_URL, params={"q": f"%{term}%", "output": "json",
                                                              "exclude": "expired"})
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise _TermFailed(f"{type(exc).__name__} for '{term}'") from exc
        if resp.status_code == 404:
            return []
        if resp.status_code == 429:
            try:
                retry = float(resp.headers.get("retry-after", ""))
            except ValueError:
                retry = 300.0
            raise _RateLimited(min(max(retry, 30.0), 3600.0))
        if resp.status_code >= 400:
            raise _TermFailed(f"HTTP {resp.status_code} for '{term}'")
        try:
            rows = resp.json()
        except ValueError as exc:
            raise _TermFailed(f"unparseable response for '{term}'") from exc
        if not isinstance(rows, list):
            raise _TermFailed(f"unexpected response shape for '{term}'")
        return rows

    async def discover(self, brand, cfg, cursors):
        started = time.monotonic()
        if self.limiter is None:
            self.limiter = RateLimiter(cfg.ct.min_interval_seconds)
        caps = tuple(self.capabilities())
        health = SourceHealth(self.name, "operational", caps, last_attempt=_now())
        result = DiscoveryResult([], health)
        if self.limiter.blocked:
            health.status = "rate_limited"
            health.error = "cooling down after HTTP 429"
            health.rate_limit = self.limiter.status()
            return result

        now = self.clock()
        seen: dict[str, Discovered] = {}
        terms, failed, ok = self.terms(brand), [], 0
        truncated_terms = []
        for term in terms:
            key = f"{self.name}:{brand.name}:{term}"
            cursor = _parse_ts(cursors.get(key, ""))
            try:
                rows = await self._query(term, cfg)
            except _RateLimited as exc:
                self.limiter.penalize(exc.retry_after)
                failed.append(f"HTTP 429 rate limited (retry in {int(exc.retry_after)}s)")
                health.status = "rate_limited"
                break
            except _TermFailed as exc:
                failed.append(str(exc))
                continue
            ok += 1

            dated = [(_parse_ts(str(r.get("entry_timestamp", ""))), r) for r in rows if isinstance(r, dict)]
            dated.sort(key=lambda x: x[0] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
            if len(dated) > cfg.ct.max_rows_per_term:
                truncated_terms.append(term)
                dated = dated[: cfg.ct.max_rows_per_term]
            newest = None
            for ts, row in dated:
                if ts and (newest is None or ts > newest):
                    newest = ts
                if cursor and ts and ts <= cursor:
                    continue  # seen on an earlier run
                self._read_cert(row, ts, term, brand, cfg, now, seen, result)
            if newest and (not cursor or newest > cursor):
                result.cursor_updates[key] = newest.isoformat()

        result.candidates = list(seen.values())
        if failed and ok == 0:
            health.status = health.status if health.status == "rate_limited" else "provider_error"
        elif failed:
            health.status = "partial"
        if failed:
            health.error = "; ".join(failed)[:500]
        if truncated_terms:
            result.notes.append(f"more rows than max_rows_per_term for: {', '.join(truncated_terms)}")
        health.results = len(result.candidates)
        health.duration_ms = int((time.monotonic() - started) * 1000)
        health.rate_limit = self.limiter.status()
        if health.status in {"operational", "partial"}:
            health.last_success = _now()
        health.detail = (f"{ok}/{len(terms)} terms queried, {result.noise_filtered} unrelated names filtered"
                         + (f", {result.malformed} non-domain names skipped (e.g. organisation names)" if result.malformed else ""))
        return result

    def _read_cert(self, row, ts, term, brand, cfg, now, seen, result):
        cert_id = str(row.get("min_cert_id") or row.get("id") or "")
        not_before = _parse_ts(str(row.get("not_before", ""))) or ts
        names = []
        for raw in str(row.get("name_value", "")).splitlines()[: cfg.ct.max_names_per_certificate]:
            name = raw.strip().lower().removeprefix("*.")
            if not name or "@" in name:
                continue
            try:
                names.append(normalize_domain(name).canonical)
            except InvalidIndicator:
                result.malformed += 1
        names = list(dict.fromkeys(names))
        for name in names:
            if is_official(name, brand) or name in seen:
                continue
            # crt.sh matches any identity on the certificate, so a shared cert drags in
            # unrelated names. Keep only those that themselves carry a brand signal.
            if not prescore(name, brand, cfg.prescore).has_brand_signal:
                result.noise_filtered += 1
                continue
            age = (now - not_before).total_seconds() / 86400 if not_before else None
            seen[name] = Discovered(
                indicator=name, indicator_type="domain", source=self.name, query=term,
                confidence=0.75,
                metadata={
                    "certificate_id": cert_id,
                    "issuer": row.get("issuer_name", ""),
                    "not_before": not_before.isoformat() if not_before else None,
                    "entry_timestamp": ts.isoformat() if ts else None,
                    "cert_age_days": round(age, 2) if age is not None else None,
                    "sibling_names": [n for n in names if n != name][:20],
                },
            )
