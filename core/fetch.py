"""The fetch layer. This is where scrapers actually die, so it gets the care.

Three things that keep you unblocked and out of trouble, in order of importance:
  1. Respect robots.txt. Cheap to do, and it's the difference between
     "automated collection" and "unauthorised access" if anyone ever asks.
  2. Rate limit per domain, not globally. One domain hammered at 20 req/s gets
     you banned even if your overall rate looks polite.
  3. Identify yourself in the User-Agent with a contact address. Site owners
     who can reach you will email before they block you.
"""

from __future__ import annotations

import threading
import time
import urllib.robotparser
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx


# Minimum pause after a 429 that carries no Retry-After. Five seconds is the
# figure GDELT states in its own rate-limit body, and it is a reasonable floor
# for any host that bothered to say "slow down".
RATE_LIMIT_FLOOR = 5.0


@dataclass
class FetchResult:
    url: str
    status: int
    html: str = ""
    error: str = ""
    # Raw bytes and the declared type, for responses that are not text at all.
    # Regulator circulars are overwhelmingly PDFs, and decoding one into `html`
    # produces non-empty mojibake — which would satisfy the old `ok` check and
    # travel down the pipeline looking like an article body.
    content: bytes = b""
    content_type: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 200 and bool(self.html or self.content)


class Fetcher:
    def __init__(self, user_agent: str, delay: float = 2.0,
                 timeout: float = 20.0, obey_robots: bool = True,
                 transport=None):
        self.user_agent = user_agent
        self.delay = delay
        self.obey_robots = obey_robots
        self._last_hit: dict[str, float] = {}
        self._lock = threading.Lock()
        self.client = httpx.Client(
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-GB,en;q=0.9",
            },
            timeout=timeout,
            follow_redirects=True,
            transport=transport,          # tests inject a MockTransport here
        )
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    # ---------- politeness ----------

    def _throttle(self, domain: str) -> None:
        """Per domain, not global. Thread-safe: sweeps fetch concurrently, and
        without the lock two threads can both read a stale timestamp and hit the
        same host at once."""
        while True:
            with self._lock:
                last = self._last_hit.get(domain, 0.0)
                wait = self.delay - (time.monotonic() - last)
                if wait <= 0:
                    self._last_hit[domain] = time.monotonic()
                    return
            time.sleep(wait)

    def allowed(self, url: str) -> bool:
        """Check robots.txt, fetched through our own client.

        Deliberately NOT urllib's RobotFileParser.read(): that opens its own
        connection, ignoring our user agent, timeout and any proxy, and it
        treats a 403 on robots.txt as 'disallow everything'. Behind a corporate
        proxy that silently kills every fetch you make.

        RFC 9309 status handling: 4xx means allow all, 5xx means the site is
        unwell so back off, and anything unreachable means allow.
        """
        if not self.obey_robots:
            return True
        parsed = urlparse(url)
        domain = parsed.netloc

        with self._lock:
            cached = domain in self._robots
        if not cached:
            rp: urllib.robotparser.RobotFileParser | None = None
            try:
                r = self.client.get(f"{parsed.scheme}://{domain}/robots.txt",
                                    timeout=10.0)
                if r.status_code == 200:
                    rp = urllib.robotparser.RobotFileParser()
                    rp.parse(r.text.splitlines())
                elif 500 <= r.status_code < 600:
                    rp = urllib.robotparser.RobotFileParser()
                    rp.disallow_all = True
                # 4xx and anything else: no usable rules, so allowed.
            except Exception:
                pass
            with self._lock:
                self._robots[domain] = rp

        with self._lock:
            rp = self._robots[domain]
        return True if rp is None else rp.can_fetch(self.user_agent, url)

    # ---------- fetching ----------

    def get(self, url: str, retries: int = 2, api: bool = False,
            headers: dict | None = None,
            timeout: float | None = None) -> FetchResult:
        """`api=True` skips the robots check. Use it only for the declared
        public API endpoints in core/sources.py.

        `headers` are merged for this request only. Backends that need an API
        key MUST use this rather than assigning to `fetcher.client.headers`:
        the client is shared and the fan-out is concurrent, so mutating it
        leaks one source's credentials onto another source's request.

        robots.txt governs crawlers indexing pages; it is not the access
        control mechanism for a documented JSON API you are calling as an
        intended consumer. Applying it to both was a category error that cost
        us every hit from Wikipedia and Google News: en.wikipedia.org/robots.txt
        carries `Disallow: /w/`, which is the path of the API Wikipedia
        publishes *for this purpose* and governs with its own rate-limit and
        user-agent policy. The backends returned [] and nobody saw why.

        Crawling arbitrary article bodies — sweep.py step 3, and adapters/ —
        keeps `api=False` and stays governed by obey_robots. That is genuine
        crawling and the protection belongs there.
        """
        if not api and not self.allowed(url):
            return FetchResult(url, 0, error="blocked by robots.txt")

        domain = urlparse(url).netloc
        backoff = 1.0

        for attempt in range(retries + 1):
            self._throttle(domain)
            try:
                request_options: dict[str, Any] = {"headers": headers or None}
                if timeout is not None:
                    request_options["timeout"] = timeout
                r = self.client.get(url, **request_options)
            except httpx.HTTPError as e:
                if attempt == retries:
                    return FetchResult(url, 0, error=f"{type(e).__name__}: {e}")
                time.sleep(backoff)
                backoff *= 2
                continue

            # 429/5xx are worth retrying; 403/404 are not.
            if r.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                retry_after = r.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    wait = float(retry_after)
                elif r.status_code == 429:
                    # 429 means "you are going too fast", and one second is not
                    # a serious answer to that. GDELT asks in its own 429 body
                    # for one request per five seconds and sends no Retry-After,
                    # so retrying at 1s then 2s burned every attempt and
                    # reported a dead source that was merely being throttled.
                    wait = max(backoff, RATE_LIMIT_FLOOR)
                else:
                    wait = backoff
                time.sleep(wait)
                backoff = max(backoff * 2, wait * 2)
                continue

            ctype = (r.headers.get("content-type") or "").split(";")[0].strip()
            # Only decode to text when it plausibly is text. A PDF or an image
            # keeps its bytes and leaves `html` empty, so nothing downstream
            # mistakes a binary blob for an article.
            # Structured APIs commonly use registered vendor media types such
            # as GLEIF's ``application/vnd.api+json``. Treat every +json/+xml
            # type as text; otherwise a valid 200 response is kept only in
            # ``content`` while adapters receive an empty ``html`` string and
            # incorrectly report malformed JSON.
            textual = (not ctype
                       or ctype.startswith("text/")
                       or ctype.endswith("+json")
                       or ctype.endswith("+xml")
                       or ctype in ("application/json", "application/xml",
                                    "application/rss+xml", "application/atom+xml",
                                    "application/xhtml+xml", "application/javascript"))
            if r.status_code != 200:
                # Preserve structured/text error bodies so an API adapter can
                # surface an actionable provider message (for example a 402
                # credit balance) instead of only "HTTP 402". Binary error
                # pages remain undecoded.
                return FetchResult(
                    url, r.status_code,
                    html=r.text if textual else "",
                    content=r.content,
                    content_type=ctype,
                    error=f"HTTP {r.status_code}",
                )
            return FetchResult(url, 200,
                               html=r.text if textual else "",
                               content=r.content, content_type=ctype)

        return FetchResult(url, 0, error="exhausted retries")

    def post(self, url: str, data: dict | None = None,
             headers: dict | None = None, api: bool = False,
             json_body: dict | None = None) -> FetchResult:
        """Only for API auth handshakes (OAuth token exchange), which is why
        there's no retry loop: replaying a credential grant is not obviously
        safe, and a failed one should surface immediately rather than be
        attempted three times against someone's rate limit."""
        if not api and not self.allowed(url):
            return FetchResult(url, 0, error="blocked by robots.txt")
        self._throttle(urlparse(url).netloc)
        try:
            r = (self.client.post(url, json=json_body, headers=headers or None)
                 if json_body is not None
                 else self.client.post(url, data=data or {},
                                       headers=headers or None))
        except httpx.HTTPError as e:
            return FetchResult(url, 0, error=f"{type(e).__name__}: {e}")
        if r.status_code != 200:
            return FetchResult(url, r.status_code, error=f"HTTP {r.status_code}")
        return FetchResult(url, 200, html=r.text)

    def close(self) -> None:
        self.client.close()
