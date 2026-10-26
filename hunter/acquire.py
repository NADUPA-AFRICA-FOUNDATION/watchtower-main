"""Website content acquisition for the hunter.

`ContentAcquisitionProvider` is the seam: the pipeline only calls `capture()`.
`NativeFetcher` is the only implementation. A provider backed by an external
crawling service could subclass it later without touching the pipeline; none is
included, and no such SDK, key or dependency exists here.

Safety is inherited, not re-implemented: every request goes through
SafeFetcher (validated public addresses pinned for the connection, every redirect
revalidated, streamed size cap on decoded bytes, content-type allowlist). This
layer adds what it lacks: a wall-clock deadline, charset handling, robots.txt,
header fingerprints, and the rules below.

  * GET only. Nothing is submitted: forms are parsed, never filled.
  * No JavaScript is executed. A page that is an empty shell is flagged
    `js_shell_suspected` so missing content never reads as a clean page.
  * robots.txt follows the configured split: the landing page is a targeted
    inspection (verdict recorded, enforced only if configured); further pages are
    crawling and always enforced. robots.txt is fetched through SafeFetcher and
    parsed, never read with urllib's RobotFileParser.read() (see CLAUDE.md).
    RFC 9309: 4xx = no rules, 5xx or unreachable = do not crawl further.
  * A meta-refresh target is recorded, not followed.
"""
from __future__ import annotations

import asyncio
import codecs
import hashlib
import re
import urllib.robotparser
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from watchtower.discovery.page_analysis import analyze_page
from watchtower.discovery.safe_fetch import SafeFetcher, UnsafeTarget

from .config import AcquisitionConfig
from .prescore import registrable

USER_AGENT_TOKEN = "watchtower"
KEEP_HEADERS = frozenset({"content-type", "server", "location", "via", "x-powered-by",
                          "x-generator", "x-aspnet-version"})
_ASSET = re.compile(r"\.(png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|pdf|zip|rar|apk|exe|msi|dmg|mp[34]|webm|xml|json)$", re.I)
_LINK_WORDS = {"login": 6, "signin": 6, "verify": 6, "verification": 6, "otp": 6, "pin": 6, "account": 5,
               "pay": 5, "payment": 5, "kyc": 5, "activate": 5, "register": 4, "registration": 4, "loan": 4,
               "invest": 4, "wallet": 4, "reward": 4, "claim": 4, "withdraw": 4, "support": 3, "contact": 3}
_META_REFRESH = re.compile(r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*(\d+)\s*;\s*url=\s*['"]?([^'"\s>]+)""", re.I)
_GENERATOR = re.compile(r"""<meta[^>]+name=["']generator["'][^>]*content=["']([^"']{1,120})""", re.I)
_CHALLENGE = re.compile(r"incapsula|_incapsula_resource|cf-chl|just a moment|attention required|captcha|"
                        r"access denied|ddos protection|checking your browser|enable javascript and cookies", re.I)
_META_CHARSET = re.compile(rb"""charset=["']?([\w-]+)""", re.I)


@dataclass
class Page:
    requested_url: str
    final_url: str = ""
    status: int = 0
    content_type: str = ""
    headers: dict = field(default_factory=dict)
    redirect_chain: list = field(default_factory=list)
    error: str | None = None
    error_kind: str | None = None       # blocked dns_failed unreachable timeout robots_disallowed ...
    body_sha256: str | None = None
    body_bytes: int = 0
    robots: dict = field(default_factory=dict)
    analyzable: bool = False
    title: str = ""
    description: str = ""
    headings: list = field(default_factory=list)
    visible_text: str = ""
    links: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    favicon_url: str = ""
    html_fingerprint: str = ""
    simhash: int = 0
    js_shell_suspected: bool = False
    meta_refresh: str | None = None
    # Why the page's content could not be assessed (HTTP block, bot challenge, JS-only shell).
    # "We could not see it" must never read as "it is clean"; nothing here tries to get past it.
    unassessed_reason: str | None = None
    technology: dict = field(default_factory=dict)
    fetched_at: str = ""
    # Raw decoded HTML, kept only so signal extraction can see labels and anchor text. It is
    # excluded from facts() and cleared by the pipeline once extraction has run.
    html: str = ""

    @property
    def ok(self) -> bool:
        return self.error_kind is None and self.status > 0

    @property
    def final_host(self) -> str:
        return (urlsplit(self.final_url or self.requested_url).hostname or "").lower()

    def facts(self) -> dict:
        """Deterministic evidence content: no timestamps, form field names only, no values."""
        return {
            "requested_url": self.requested_url, "final_url": self.final_url, "status": self.status,
            "content_type": self.content_type, "headers": {k: self.headers[k] for k in sorted(self.headers)},
            "redirect_chain": self.redirect_chain, "error_kind": self.error_kind, "error": self.error,
            "body_sha256": self.body_sha256, "body_bytes": self.body_bytes, "robots": self.robots,
            "title": self.title, "description": self.description, "headings": self.headings[:10],
            "forms": [{"action": f.get("action"), "method": f.get("method"),
                       "fields": [{k: i.get(k, "") for k in ("name", "type", "autocomplete", "placeholder")}
                                  for i in f.get("inputs", [])][:30]} for f in self.forms[:10]],
            "links": self.links[:200], "scripts": self.scripts[:50], "favicon_url": self.favicon_url,
            "html_fingerprint": self.html_fingerprint, "simhash": str(self.simhash),
            "js_shell_suspected": self.js_shell_suspected, "meta_refresh": self.meta_refresh,
            "unassessed_reason": self.unassessed_reason,
            "technology": self.technology, "js_rendering": "not_available",
        }


@dataclass
class SiteCapture:
    domain: str
    pages: list = field(default_factory=list)      # pages[0] is the landing page that was used
    attempts: list = field(default_factory=list)   # earlier landing attempts that failed (https before http)
    notes: list = field(default_factory=list)

    @property
    def landing(self) -> Page | None:
        return self.pages[0] if self.pages else None


class ContentAcquisitionProvider(ABC):
    name = "acquisition"

    @abstractmethod
    async def fetch_page(self, url: str, *, landing: bool = True) -> Page: ...

    @abstractmethod
    async def map_domain(self, domain: str, landing: Page, limit: int) -> list[str]: ...

    @abstractmethod
    def extract_links(self, page: Page) -> list[str]: ...

    @abstractmethod
    async def capture(self, domain: str) -> SiteCapture: ...

    async def close(self) -> None:
        return None


def decode_body(body: bytes, content_type_header: str) -> str:
    charset = None
    m = re.search(r"charset=([\w-]+)", content_type_header or "", re.I)
    if m:
        charset = m.group(1)
    elif (sniff := _META_CHARSET.search(body[:2048])):
        charset = sniff.group(1).decode("ascii", "ignore")
    try:
        codecs.lookup(charset or "utf-8")
    except LookupError:
        charset = "utf-8"
    return body.decode(charset or "utf-8", errors="replace")


def _classify(message: str) -> str:
    low = message.lower()
    if "unsupported content type" in low:
        return "unsupported_content_type"
    if "size limit" in low:
        return "too_large"
    if "redirect" in low:
        return "redirect_error"
    if "timeout" in low:
        return "timeout"
    return "unreachable"


def _link_priority(url: str) -> tuple:
    path = urlsplit(url).path.lower()
    score = max((w for k, w in _LINK_WORDS.items() if k in path), default=0)
    return (-score, len(path), url)


class NativeFetcher(ContentAcquisitionProvider):
    name = "native"

    def __init__(self, fetcher: SafeFetcher, cfg: AcquisitionConfig, *, clock=None, sleep=asyncio.sleep):
        self.fetcher, self.cfg = fetcher, cfg
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._sleep = sleep
        self._robots: dict[str, tuple[dict, urllib.robotparser.RobotFileParser | None]] = {}

    @classmethod
    def create(cls, cfg: AcquisitionConfig, user_agent: str, **kw) -> "NativeFetcher":
        return cls(SafeFetcher(max_bytes=cfg.max_bytes, timeout=cfg.timeout_seconds, user_agent=user_agent,
                               keep_headers=KEEP_HEADERS), cfg, **kw)

    async def close(self):
        await self.fetcher.close()

    # -- robots ----------------------------------------------------------------------

    async def _robots_for(self, url: str):
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in self._robots:
            return self._robots[origin]
        robots_url = origin + "/robots.txt"
        info: dict = {"url": robots_url, "http_status": None}
        parser = None
        try:
            res = await asyncio.wait_for(self.fetcher.fetch(robots_url), self.cfg.total_timeout_seconds)
        except Exception as exc:
            info["status"] = "unreachable"
            info["error"] = f"{type(exc).__name__}: {exc}"[:200]
        else:
            info["http_status"] = res.status
            if res.error or res.status == 0:
                info["status"], info["error"] = "unreachable", (res.error or "no response")[:200]
            elif res.status == 200:
                parser = urllib.robotparser.RobotFileParser()
                parser.parse(decode_body(res.body[: self.cfg.robots_max_bytes], res.headers.get("content-type", ""))
                             .splitlines()[:5000])
                info["status"] = "present"
            elif 400 <= res.status < 500:
                info["status"] = "no_robots"          # RFC 9309: no rules, everything allowed
            else:
                info["status"], parser = "unreachable", None  # 5xx: the site is unwell, do not crawl
        self._robots[origin] = (info, parser)
        return self._robots[origin]

    async def _robots_verdict(self, url: str) -> tuple[dict, bool]:
        """(verdict to record, whether robots permits the fetch)."""
        info, parser = await self._robots_for(url)
        verdict = dict(info)
        if info["status"] == "present":
            allowed = parser.can_fetch(USER_AGENT_TOKEN, url)
            verdict["verdict"] = "allowed" if allowed else "disallowed"
        elif info["status"] == "no_robots":
            allowed, verdict["verdict"] = True, "allowed"
        else:
            allowed, verdict["verdict"] = False, "unreachable"
        return verdict, allowed

    # -- fetching ----------------------------------------------------------------------

    async def fetch_page(self, url: str, *, landing: bool = True) -> Page:
        page = Page(url, fetched_at=self.clock().isoformat())
        verdict, allowed = await self._robots_verdict(url)
        enforced = (not landing) or self.cfg.obey_robots_landing
        page.robots = {**verdict, "enforced": enforced}
        if enforced and not allowed:
            page.error_kind = "robots_disallowed"
            page.error = f"robots.txt {verdict['verdict']}: page not fetched"
            return page
        try:
            res = await asyncio.wait_for(self.fetcher.fetch(url), self.cfg.total_timeout_seconds)
        except UnsafeTarget as exc:
            page.error = str(exc)
            page.error_kind = "dns_failed" if str(exc).startswith("DNS resolution failed") else "blocked"
            return page
        except asyncio.TimeoutError:
            page.error, page.error_kind = f"exceeded {self.cfg.total_timeout_seconds:g}s", "timeout"
            return page
        page.final_url, page.status, page.content_type = res.final_url, res.status, res.content_type
        page.redirect_chain = list(res.redirect_chain)
        page.headers = {k: str(v)[:200] for k, v in res.headers.items() if k != "location"}
        if res.error:
            page.error, page.error_kind = res.error, _classify(res.error)
            return page
        page.body_bytes, page.body_sha256 = len(res.body), hashlib.sha256(res.body).hexdigest()
        page.technology = self._technology(page)
        if page.content_type in {"text/html", "application/xhtml+xml", ""}:
            self._analyze(page, decode_body(res.body, res.headers.get("content-type", "")))
        page.unassessed_reason = self._unassessed(page)
        return page

    @staticmethod
    def _unassessed(page: Page) -> str | None:
        if page.status >= 400:
            return f"HTTP {page.status}" + (" (bot challenge)" if _CHALLENGE.search(page.html[:6000]) else "")
        if page.analyzable and _CHALLENGE.search(page.html[:6000]) and len(page.visible_text) < 400:
            return "bot challenge"
        if page.js_shell_suspected:
            return "JavaScript-rendered content not available"
        return None

    def _technology(self, page: Page) -> dict:
        tech = {k: page.headers[h] for k, h in (("server", "server"), ("powered_by", "x-powered-by"),
                                                 ("generator", "x-generator")) if h in page.headers}
        return tech

    def _analyze(self, page: Page, html: str) -> None:
        try:
            a = analyze_page(html, page.final_url or page.requested_url)
        except Exception as exc:  # hostile markup must not take down the worker
            page.error, page.error_kind = f"unparseable HTML: {type(exc).__name__}", "parse_error"
            return
        page.analyzable = True
        page.html = html
        page.title, page.description, page.headings = a.title, a.description, a.headings
        page.visible_text, page.links, page.forms = a.visible_text, a.links, a.forms
        page.scripts, page.favicon_url = a.scripts, a.favicon_url
        page.html_fingerprint, page.simhash = a.html_fingerprint, a.simhash
        # Empty SPA shells carry almost no text; a short static page with one script (example.com) is not one.
        page.js_shell_suspected = len(page.visible_text) < 100 and bool(page.scripts)
        if (m := _META_REFRESH.search(html)):
            target = urljoin(page.final_url or page.requested_url, m.group(2))
            if urlsplit(target).scheme in {"http", "https"}:
                page.meta_refresh = target
        if (g := _GENERATOR.search(html)):
            page.technology["generator"] = g.group(1)
        hosts = sorted({h for s in page.scripts[:100] if (h := urlsplit(s).hostname)})
        if hosts:
            page.technology["script_hosts"] = hosts[:10]

    def extract_links(self, page: Page) -> list[str]:
        return list(page.links)

    async def map_domain(self, domain: str, landing: Page, limit: int) -> list[str]:
        """Same-site pages worth a second look, taken from the landing page's own links.

        Deliberately shallow: one hop, no sitemap, no recursion. Depth is the
        pivot engine's job (bounded by budgets), not the fetcher's.
        """
        base = registrable(landing.final_host or domain)
        seen, out = {landing.final_url, landing.requested_url}, []
        for link in sorted(self.extract_links(landing), key=_link_priority):
            parts = urlsplit(link)
            if (parts.hostname and registrable(parts.hostname) == base and link not in seen
                    and not _ASSET.search(parts.path) and parts.path not in {"", "/"}):
                seen.add(link)
                out.append(link)
        return out[:limit]

    async def capture(self, domain: str) -> SiteCapture:
        cap = SiteCapture(domain)
        landing = await self.fetch_page(f"https://{domain}/", landing=True)
        if landing.error_kind in {"unreachable", "timeout"}:
            cap.notes.append(f"https {landing.error_kind}; trying http")
            cap.attempts.append(landing)  # the failed attempt is evidence too
            landing = await self.fetch_page(f"http://{domain}/", landing=True)
        cap.pages.append(landing)
        # A block or challenge page's links are not the site's pages: only crawl past a real 2xx.
        if landing.ok and landing.analyzable and 200 <= landing.status < 300 and not landing.unassessed_reason \
                and self.cfg.max_pages_per_domain > 1:
            for url in await self.map_domain(domain, landing, self.cfg.max_pages_per_domain - 1):
                await self._sleep(self.cfg.page_delay_seconds)
                cap.pages.append(await self.fetch_page(url, landing=False))
        return cap
