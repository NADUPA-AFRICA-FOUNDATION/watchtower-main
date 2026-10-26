"""RDAP registration lookup through the IANA bootstrap.

status: registered | not_found | unsupported | not_applicable | rate_limited | error

  not_found       the registry answered 404: no such registration.
  unsupported     the TLD has no RDAP service in the IANA bootstrap.
  not_applicable  subdomain of a shared-hosting platform; the registration is the platform's.
  error           we could not look (5xx, timeout, bad body). Never cached.

Missing or redacted registrant data is normal and is never evidence of anything.
Registrant email is kept only when visible, flagged personal_data, so the retention
purge can find it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import httpx

from ..normalize import is_public, normalize
from ..prescore import is_shared_hosting, registrable
from ..ratelimit import RateLimiter

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_REDACTED = re.compile(r"redacted|privacy|data protected|not disclosed|withheld|gdpr", re.I)
NOT_FOUND_TTL_HOURS = 1.0


@dataclass
class RdapResult:
    domain: str
    status: str
    registrable: str = ""
    registered_at: str | None = None
    expires_at: str | None = None
    last_changed: str | None = None
    registrar: str | None = None
    registrar_iana_id: str | None = None
    nameservers: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    registrant: dict = field(default_factory=dict)
    error: str | None = None
    retry_after: float | None = None
    source_url: str | None = None
    cached: bool = False

    def facts(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in {"error", "retry_after", "cached"}}
        d["nameservers"], d["statuses"] = sorted(self.nameservers), sorted(self.statuses)
        return d

    def age_days(self, now: datetime) -> float | None:
        if not self.registered_at:
            return None
        try:
            dt = datetime.fromisoformat(self.registered_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return max((now - dt).total_seconds() / 86400, 0.0)


def _vcard(entity: dict) -> dict:
    out: dict = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key, value = item[0], item[3]
        if key == "adr" and isinstance(value, list) and value and str(value[-1]).strip():
            out["country"] = str(value[-1]).strip()
        elif isinstance(value, str) and value.strip():
            out.setdefault(key, value.strip())
    return out


def _walk(entities):
    for e in entities or []:
        if isinstance(e, dict):
            yield e
            yield from _walk(e.get("entities"))


def parse(domain: str, reg: str, data: dict, url: str) -> RdapResult:
    res = RdapResult(domain, "registered", reg, source_url=url)
    for ev in data.get("events") or []:
        action, date = ev.get("eventAction"), ev.get("eventDate")
        if action == "registration":
            res.registered_at = res.registered_at or date
        elif action == "expiration":
            res.expires_at = date
        elif action == "last changed":
            res.last_changed = date
    res.statuses = [str(s) for s in data.get("status") or []]
    res.nameservers = sorted({str(n.get("ldhName", "")).lower().rstrip(".")
                              for n in data.get("nameservers") or [] if n.get("ldhName")})
    for e in _walk(data.get("entities")):
        roles = e.get("roles") or []
        card = _vcard(e)
        if "registrar" in roles and not res.registrar:
            res.registrar = card.get("fn") or card.get("org") or e.get("handle")
            for pid in e.get("publicIds") or []:
                if "iana" in str(pid.get("type", "")).lower():
                    res.registrar_iana_id = str(pid.get("identifier"))
        if "registrant" in roles and not res.registrant:
            text = " ".join(str(v) for v in card.values())
            redacted = bool(_REDACTED.search(text)) or not card
            res.registrant = {"redacted": redacted}
            if not redacted:
                if card.get("org"):
                    res.registrant["organization"] = card["org"]
                if card.get("country"):
                    res.registrant["country"] = card["country"]
                if card.get("email") and not _REDACTED.search(card["email"]):
                    res.registrant["email"] = card["email"].lower()
                    res.registrant["personal_data"] = True
    return res


class RdapClient:
    def __init__(self, client: httpx.AsyncClient, store, *, min_interval: float = 1.0,
                 cache_hours: float = 24.0, clock=None, sleep=None):
        self.client, self.store = client, store
        self.min_interval, self.cache_hours = min_interval, cache_hours
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._sleep = sleep
        self._limiters: dict[str, RateLimiter] = {}

    def limiter(self, host: str) -> RateLimiter:
        if host not in self._limiters:
            kw = {"sleep": self._sleep} if self._sleep else {}
            self._limiters[host] = RateLimiter(self.min_interval, **kw)
        return self._limiters[host]

    def rate_limit_status(self) -> dict:
        return {h: lim.status() for h, lim in self._limiters.items()}

    # -- cache in hunt_state: JSON with fetched_at --------------------------------------
    def _cached(self, key: str, ttl_hours: float):
        raw = self.store.get_state(key).get(key)
        if not raw:
            return None
        try:
            blob = json.loads(raw)
            fetched = datetime.fromisoformat(blob["fetched_at"])
        except (ValueError, KeyError):
            return None
        if (self.clock() - fetched).total_seconds() > ttl_hours * 3600:
            return None
        return blob["value"]

    def _cache(self, key: str, value) -> None:
        self.store.set_state({key: json.dumps({"fetched_at": self.clock().isoformat(), "value": value})})

    async def _get(self, url: str) -> httpx.Response:
        """GET with at most 3 redirects, each https and to a public hostname."""
        for _ in range(4):
            host = urlsplit(url).hostname or ""
            if urlsplit(url).scheme != "https" or not is_public(normalize(host)):
                raise httpx.UnsupportedProtocol(f"refusing to follow to {url}")
            lim = self.limiter(host)
            if lim.blocked:
                raise _Cooling(host, lim.status()["retry_in_seconds"])
            await lim.wait()
            resp = await self.client.get(url, headers={"Accept": "application/rdap+json"})
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                url = str(httpx.URL(url).join(resp.headers["location"]))
                continue
            if resp.status_code == 429:
                try:
                    wait = float(resp.headers.get("retry-after", ""))
                except ValueError:
                    wait = 300.0
                lim.penalize(min(max(wait, 30.0), 3600.0))
                raise _Cooling(host, min(max(wait, 30.0), 3600.0))
            return resp
        raise httpx.TooManyRedirects("more than 3 redirects")

    async def _bootstrap(self) -> dict[str, str]:
        cached = self._cached("rdap:bootstrap", 24.0)
        if cached is not None:
            return cached
        resp = await self._get(BOOTSTRAP_URL)
        resp.raise_for_status()
        table: dict[str, str] = {}
        for tlds, urls in resp.json().get("services", []):
            https = [u for u in urls if u.startswith("https://")]
            if https:
                for t in tlds:
                    table[t.lower()] = https[0]
        if not table:
            raise ValueError("empty RDAP bootstrap")
        self._cache("rdap:bootstrap", table)
        return table

    async def lookup(self, domain: str) -> RdapResult:
        reg = registrable(domain)
        if is_shared_hosting(domain):
            return RdapResult(domain, "not_applicable", reg,
                              error="subdomain of a shared-hosting platform; registration is the platform's")
        key = f"rdap:domain:{reg}"
        hit = self._cached(key, self.cache_hours)
        if hit is not None:
            res = RdapResult(**{**hit, "domain": domain, "cached": True})
            if res.status != "not_found" or self._cached(key, NOT_FOUND_TTL_HOURS) is not None:
                return res
        try:
            table = await self._bootstrap()
            base = table.get(reg.rsplit(".", 1)[-1])
            if not base:
                return RdapResult(domain, "unsupported", reg, error=f".{reg.rsplit('.', 1)[-1]} has no RDAP service")
            url = f"{base.rstrip('/')}/domain/{quote(reg)}"
            resp = await self._get(url)
        except _Cooling as exc:
            return RdapResult(domain, "rate_limited", reg, error=f"{exc.host} cooling down",
                              retry_after=exc.retry_in)
        except (httpx.HTTPError, ValueError) as exc:
            return RdapResult(domain, "error", reg, error=f"{type(exc).__name__}: {exc}"[:300])

        if resp.status_code == 404:
            res = RdapResult(domain, "not_found", reg, source_url=url)
        elif resp.status_code >= 400:
            return RdapResult(domain, "error", reg, error=f"HTTP {resp.status_code}", source_url=url)
        else:
            try:
                data = resp.json()
            except ValueError:
                return RdapResult(domain, "error", reg, error="unparseable RDAP body", source_url=url)
            if not isinstance(data, dict):
                return RdapResult(domain, "error", reg, error="unexpected RDAP shape", source_url=url)
            res = parse(domain, reg, data, url)
        self._cache(key, {k: v for k, v in res.__dict__.items() if k != "cached"})
        return res


class _Cooling(Exception):
    def __init__(self, host: str, retry_in: float):
        super().__init__(host)
        self.host, self.retry_in = host, retry_in
