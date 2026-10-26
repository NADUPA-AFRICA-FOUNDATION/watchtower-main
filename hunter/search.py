"""Public search and reverse-IP backends for indicator pivots.

Both report an explicit outcome and never turn a failure into an empty list:

  ok          results parsed
  no_results  the service answered and said there is nothing (a searched zero)
  blocked     a challenge / anomaly page: we were refused, not answered
  rate_limited
  error       HTTP error, timeout, or a page we could not parse. An unparseable
              page is never reported as "no results".

Search hits are leads only. Search ranking is not threat confidence: a lead becomes a
relationship only when the page itself, once fetched, is seen to carry the same indicator.
"""
from __future__ import annotations

import html
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

import httpx

from .ratelimit import RateLimiter


@dataclass
class SearchHit:
    url: str
    title: str = ""
    snippet: str = ""


@dataclass
class SearchOutcome:
    status: str
    hits: list = field(default_factory=list)
    error: str | None = None
    retry_after: float | None = None
    query: str = ""

    @property
    def searched(self) -> bool:
        return self.status in {"ok", "no_results"}


class SearchBackend(ABC):
    name = "search"

    @abstractmethod
    async def search(self, query: str, limit: int = 10) -> SearchOutcome: ...

    def rate_limit_status(self) -> dict:
        return {}

    async def close(self) -> None:
        return None


_RESULT = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.S | re.I)
_SNIPPET = re.compile(r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', re.S | re.I)
_TAGS = re.compile(r"<[^>]+>")
_CHALLENGE = re.compile(r"anomaly|unusual traffic|bots use duckduckgo|are you a (?:human|robot)|captcha", re.I)
_NONE = re.compile(r"no\s+results\.?|did not match any documents|no results found", re.I)


def _clean(s: str) -> str:
    return " ".join(html.unescape(_TAGS.sub("", s)).split())


def _target(href: str) -> str | None:
    href = html.unescape(href)
    if href.startswith("//"):
        href = "https:" + href
    parts = urlsplit(href)
    if parts.hostname and parts.hostname.endswith("duckduckgo.com") and parts.path.startswith("/l/"):
        href = unquote((parse_qs(parts.query).get("uddg") or [""])[0])
        parts = urlsplit(href)
    return href if parts.scheme in {"http", "https"} and parts.hostname else None


def parse_duckduckgo(body: str, limit: int) -> SearchOutcome:
    """Classify a DuckDuckGo HTML results page. Pure function, tested against fixtures."""
    if _CHALLENGE.search(body[:20000]) and not _RESULT.search(body):
        return SearchOutcome("blocked", error="search engine returned a bot challenge")
    hits, snippets = [], [_clean(m) for m in _SNIPPET.findall(body)]
    for i, (href, title) in enumerate(_RESULT.findall(body)):
        url = _target(href)
        if url and "duckduckgo.com" not in (urlsplit(url).hostname or ""):     # drop ads and self-links
            hits.append(SearchHit(url, _clean(title)[:200], (snippets[i] if i < len(snippets) else "")[:300]))
        if len(hits) >= limit:
            break
    if hits:
        return SearchOutcome("ok", hits)
    if _NONE.search(body):
        return SearchOutcome("no_results")
    return SearchOutcome("error", error="results page could not be parsed (layout change or soft block)")


class DuckDuckGoHtml(SearchBackend):
    name = "duckduckgo_html"
    URL = "https://html.duckduckgo.com/html/"

    def __init__(self, client: httpx.AsyncClient | None = None, limiter: RateLimiter | None = None,
                 user_agent: str = "Mozilla/5.0 (compatible; Watchtower/1.0)", timeout: float = 30.0, clock=None):
        self._clock = clock or __import__("time").monotonic
        self._canary_at: float | None = None
        self._client = client
        self._owns = client is None
        self.limiter = limiter or RateLimiter(2.0)
        self.user_agent, self.timeout = user_agent, timeout

    def rate_limit_status(self):
        return self.limiter.status()

    async def close(self):
        if self._owns and self._client is not None:
            await self._client.aclose()

    # DuckDuckGo answers a suspected bot with a normal-looking "No results" page (HTTP 200), and
    # exact-phrase queries are the ones it blocks first. So "no results" is only believed after a
    # control query that must have results, run with the same quoting, has just succeeded.
    CANARY = '"the free encyclopedia" "wikipedia"'
    CANARY_TTL = 900.0

    async def _fetch(self, query: str, limit: int) -> SearchOutcome:
        if self.limiter.blocked:
            return SearchOutcome("rate_limited", error="cooling down", retry_after=self.limiter.status()["retry_in_seconds"],
                                 query=query)
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, trust_env=False,
                                             headers={"User-Agent": self.user_agent})
        await self.limiter.wait()
        try:
            resp = await self._client.get(self.URL, params={"q": query})
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            return SearchOutcome("error", error=f"{type(exc).__name__}", query=query)
        if resp.status_code in (202, 403, 429):
            self.limiter.penalize(900)
            kind = "rate_limited" if resp.status_code == 429 else "blocked"
            return SearchOutcome(kind, error=f"HTTP {resp.status_code}", retry_after=900, query=query)
        if resp.status_code >= 400:
            return SearchOutcome("error", error=f"HTTP {resp.status_code}", query=query)
        out = parse_duckduckgo(resp.text, limit)
        out.query = query
        if out.status == "blocked":
            self.limiter.penalize(900)
            out.retry_after = 900
        return out

    async def _canary_ok(self) -> bool:
        now = self._clock()
        if self._canary_at is not None and now - self._canary_at < self.CANARY_TTL:
            return True
        out = await self._fetch(self.CANARY, 3)
        if out.status == "ok":
            self._canary_at = now
            return True
        self._canary_at = None
        return False

    async def search(self, query: str, limit: int = 10) -> SearchOutcome:
        out = await self._fetch(query, limit)
        if out.status == "no_results" and not await self._canary_ok():
            self.limiter.penalize(900)
            return SearchOutcome("blocked", error="empty answer, and a control query that must have results did not: "
                                 "the engine is soft-blocking us, so this is not a searched zero", retry_after=900, query=query)
        return out


@dataclass
class ReverseIpOutcome:
    status: str                    # ok | no_results | shared_hosting | rate_limited | error
    domains: list = field(default_factory=list)
    error: str | None = None
    total: int = 0


class ReverseIpBackend(ABC):
    name = "reverse_ip"

    @abstractmethod
    async def lookup(self, ip: str, max_domains: int) -> ReverseIpOutcome: ...

    async def close(self) -> None:
        return None


class HackerTargetReverseIp(ReverseIpBackend):
    """Free, unauthenticated, tightly rate limited. Its failures arrive as HTTP 200 text, which
    is exactly how an empty answer gets confused with an error, so they are matched explicitly."""
    name = "hackertarget"
    URL = "https://api.hackertarget.com/reverseiplookup/"

    def __init__(self, client: httpx.AsyncClient | None = None, limiter: RateLimiter | None = None):
        self._client, self._owns = client, client is None
        self.limiter = limiter or RateLimiter(2.0)

    async def close(self):
        if self._owns and self._client is not None:
            await self._client.aclose()

    async def lookup(self, ip: str, max_domains: int = 50) -> ReverseIpOutcome:
        if self.limiter.blocked:
            return ReverseIpOutcome("rate_limited", error="cooling down")
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=20, follow_redirects=False, trust_env=False)
        await self.limiter.wait()
        try:
            resp = await self._client.get(self.URL, params={"q": ip})
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            return ReverseIpOutcome("error", error=type(exc).__name__)
        text = resp.text.strip()
        low = text.lower()
        if resp.status_code == 429 or "api count exceeded" in low:
            self.limiter.penalize(3600)
            return ReverseIpOutcome("rate_limited", error="daily API limit reached")
        if resp.status_code >= 400 or low.startswith("error") or "invalid" in low[:60]:
            return ReverseIpOutcome("error", error=text[:120] or f"HTTP {resp.status_code}")
        if "no dns a records found" in low or not text:
            return ReverseIpOutcome("no_results")
        names = [ln.strip().lower() for ln in text.splitlines() if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", ln.strip().lower())]
        if not names:
            return ReverseIpOutcome("error", error="unrecognised reverse-IP response")
        if len(names) > max_domains:
            return ReverseIpOutcome("shared_hosting", total=len(names))
        return ReverseIpOutcome("ok", names, total=len(names))


# Cloudflare's published ranges (https://www.cloudflare.com/ips/); verify before relying on this list.
# An address inside one says "CDN", not "same actor".
COMMON_INFRA_NETS = tuple(__import__("ipaddress").ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"))


def is_common_infra_ip(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and any(addr in n for n in COMMON_INFRA_NETS)


def search_queries(ind_type: str, canonical: str) -> list[str]:
    """Quoted, exact-phrase queries for an indicator. A few spellings, not a flood."""
    if ind_type in {"phone_number", "whatsapp"} and canonical.startswith("+"):
        digits = canonical[1:]
        local = ("0" + digits[3:]) if digits.startswith("254") else None
        qs = [f'"{canonical}"'] + ([f'"{local}"'] if local else [])
        if ind_type == "whatsapp":
            qs.append(f'"wa.me/{digits}"')
        return qs
    if ind_type == "telegram" and not canonical.startswith("invite:"):
        return [f'"t.me/{canonical}"', f'"@{canonical}"']
    if ind_type == "payment_identifier":
        kind, number = canonical.split(":", 1)
        return [f'"{kind} {number}"', f'"{kind.capitalize()} number {number}"']
    if ind_type == "crypto_wallet":
        return [f'"{canonical.split(":", 1)[1]}"']
    if ind_type == "email":
        return [f'"{canonical}"']
    if ind_type == "social_account" and ":" in canonical:
        platform, handle = canonical.split(":", 1)
        return [f'"{handle}" {platform}']
    return []
