"""Keyword-searchable sources that need no API key and no scraping.

Every backend here takes a query string and returns list[Item]. All of them are
public APIs or published feeds, so there's no ToS grey area and nothing to
maintain when a site redesigns.

  gdelt          global news, all languages, 15-min lag, back to 2017
  google_news    broad news via the published RSS search endpoint
  wikipedia      entity background and disambiguation
  hackernews     via Algolia's public API; tech and fintech chatter
  reddit         official OAuth API   (REDDIT_CLIENT_ID/REDDIT_CLIENT_SECRET)
  x              X/Twitter recent search, official paid API (X_BEARER_TOKEN)
  socialcrawl    cross-platform public social search (SOCIALCRAWL_API_KEY)
  gleif          Legal Entity Identifiers, free, no key
  opencorporates company registries      (OPENCORPORATES_API_KEY)
  sec_edgar      US filings full-text, useful for company checks
  opensanctions  sanctions/PEP/watchlist matching (OPENSANCTIONS_API_KEY)

Scraped platforms are absent on purpose — see CLAUDE.md. X is here *only*
through its official paid API: a documented endpoint with a contract behind it
fails loudly, where a scraper returns an empty list and calls it coverage.
ICIJ Offshore Leaks is deliberately not here: it publishes no API, and the
only way in would be scraping the search UI.

Add a backend by writing one function with the same signature and registering
it in BACKENDS. Raise SourceError on failure and SourceSkipped when it isn't
configured — never return [] for either. Nothing else in the pipeline changes.
"""

from __future__ import annotations

import base64
import json
import os
import logging
import queue
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus, urlencode, urlsplit, urlunsplit

import feedparser

from core.fetch import Fetcher
from core.models import Item


class SourceError(Exception):
    """A source could not be searched: blocked, timed out, 404, bad payload.

    The distinction this exists to protect: "we searched and found nothing" and
    "we could not look" are different answers, and for screening work the
    difference is the whole point. A backend that swallows a 429 and returns []
    renders identically to a clean result, and a clean result that is really a
    failed fetch is a false negative someone signs off on.
    """


class SourceSkipped(Exception):
    """A source was never attempted — not configured, no credentials.

    Deliberately not a SourceError. Nothing is broken and nothing needs
    fixing, but the source still wasn't searched, so it must not be reported
    as a zero either. See CLAUDE.md on degrading without keys.
    """


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _fail(res) -> None:
    """Turn a failed FetchResult into a SourceError carrying the real reason."""
    raise SourceError(res.error or f"HTTP {res.status}")


def _strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html or "").replace("&nbsp;", " ").strip()


# ------------------------------------------------------------------ GDELT

def gdelt(query: str, fetcher: Fetcher, hours: int = 72,
          limit: int = 40) -> list[Item]:
    """Free, no key. Supports sourcecountry:, sourcelang:, domain: operators."""
    url = "https://api.gdeltproject.org/api/v2/doc/doc?" + urlencode({
        "query": query, "mode": "ArtList", "format": "json",
        "timespan": f"{hours}h", "maxrecords": min(limit, 250), "sort": "datedesc",
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        articles = json.loads(res.html).get("articles", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for a in articles:
        if not a.get("url"):
            continue
        out.append(Item(
            url=a["url"], source="gdelt", source_type="news",
            title=(a.get("title") or "").strip(),
            published_at=a.get("seendate", ""),
            lang=a.get("language", ""),
            raw_meta={"domain": a.get("domain", ""),
                      "country": a.get("sourcecountry", "")},
        ))
    return out


# ------------------------------------------------------------ Google News

def google_news(query: str, fetcher: Fetcher, hours: int = 72,
                limit: int = 30) -> list[Item]:
    """Published RSS search endpoint. Broader recall than GDELT on local outlets."""
    when = f"{max(1, hours // 24)}d" if hours >= 24 else f"{hours}h"
    url = (f"https://news.google.com/rss/search?q={quote_plus(query)}"
           f"+when:{when}&hl=en&gl=KE&ceid=KE:en")
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)

    out = []
    for e in feedparser.parse(res.html).entries[:limit]:
        if not e.get("link"):
            continue
        out.append(Item(
            url=e["link"], source="google_news", source_type="news",
            title=(e.get("title") or "").strip(),
            text=_strip_tags(e.get("summary", ""))[:1000],
            published_at=e.get("published", ""),
            raw_meta={"outlet": (e.get("source", {}) or {}).get("title", "")},
        ))
    return out


# -------------------------------------------------------------- Wikipedia

def wikipedia(query: str, fetcher: Fetcher, hours: int = 0,
              limit: int = 3) -> list[Item]:
    """Background context, not news. Answers 'who or what is this'."""
    url = "https://en.wikipedia.org/w/api.php?" + urlencode({
        "action": "query", "format": "json", "list": "search",
        "srsearch": query, "srlimit": limit,
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        hits = json.loads(res.html).get("query", {}).get("search", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for h in hits:
        title = h.get("title", "")
        out.append(Item(
            url=f"https://en.wikipedia.org/wiki/{quote_plus(title.replace(' ', '_'))}",
            source="wikipedia", source_type="reference",
            title=title,
            text=_strip_tags(h.get("snippet", "")),
            published_at=h.get("timestamp", ""),
        ))
    return out


# ------------------------------------------------------------ Hacker News

def hackernews(query: str, fetcher: Fetcher, hours: int = 72,
               limit: int = 20) -> list[Item]:
    since = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    url = "https://hn.algolia.com/api/v1/search_by_date?" + urlencode({
        "query": query, "hitsPerPage": limit,
        "numericFilters": f"created_at_i>{since}",
    })
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        hits = json.loads(res.html).get("hits", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for h in hits:
        link = h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        out.append(Item(
            url=link, source="hackernews", source_type="social",
            title=(h.get("title") or h.get("story_title") or "").strip(),
            text=_strip_tags(h.get("comment_text") or h.get("story_text") or "")[:2000],
            author=h.get("author", ""),
            published_at=h.get("created_at", ""),
            raw_meta={"points": h.get("points"), "comments": h.get("num_comments")},
        ))
    return out


# --------------------------------------------------------------- Mastodon

def mastodon(query: str, fetcher: Fetcher, hours: int = 72,
             limit: int = 20, instance: str = "mastodon.social") -> list[Item]:
    """Public post search. Open API, no key. Instances may rate-limit or opt out.

    This is the only genuinely open social network here. Instagram, TikTok,
    LinkedIn and X have no equivalent, which is why they're absent.
    """
    url = (f"https://{instance}/api/v2/search?"
           + urlencode({"q": query, "type": "statuses", "limit": min(limit, 40)}))
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        statuses = json.loads(res.html).get("statuses", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for s in statuses:
        acct = (s.get("account") or {}).get("acct", "")
        out.append(Item(
            url=s.get("url") or s.get("uri", ""), source=f"mastodon:{instance}",
            source_type="social",
            title=_strip_tags(s.get("content", ""))[:120],
            text=_strip_tags(s.get("content", "")),
            author=acct, published_at=s.get("created_at", ""),
            raw_meta={"reblogs": s.get("reblogs_count"),
                      "favourites": s.get("favourites_count")},
        ))
    return [i for i in out if i.url]


# ------------------------------------------------------ Free social index

SOCIAL_SITES = ("tiktok.com", "facebook.com", "instagram.com", "t.me",
                "x.com", "youtube.com", "wa.me")
# Seconds between index requests per worker. The index rate-limits bursts, and a
# throttled request looks exactly like an empty one, so we pace instead of racing.
SOCIAL_PACE = 0.5
# Hard ceiling for the whole backend. A DuckDuckGo request can hang past its own
# timeout; without this one stuck socket stalls the sweep forever.
SOCIAL_DEADLINE = 75.0


def _is_official_handle(path: str) -> bool:
    parts = [p for p in path.split("/") if p]
    from core.fraud_lexicon import OFFICIAL_HANDLES
    return bool(parts) and parts[0].lstrip("@").lower() in OFFICIAL_HANDLES


def _social_kind(host: str, path: str) -> tuple[str, str]:
    """(kind, account) for an indexed URL. Kind lets a reviewer skip platform-made
    topic pages (/discover/, /tag/) that the index returns but nobody posted."""
    parts = [p for p in path.split("/") if p]
    first = parts[0] if parts else ""
    if first in {"discover", "popular", "explore", "tag", "hashtag", "topic"}:
        return "topic_page", ""
    if host == "t.me":
        if first == "s" and len(parts) > 1:
            first = parts[1]
        if first.startswith("+") or first == "joinchat":
            return "invite_link", ""
        return "channel", first
    if host == "wa.me":
        return "contact", first
    if first.startswith("@"):
        return ("post" if len(parts) > 1 else "profile"), first.lstrip("@")
    if host in {"x.com", "instagram.com"} and first and first not in {"p", "reel", "tv", "i", "search"}:
        return ("post" if len(parts) > 1 else "profile"), first
    return "post", ""


_PLATFORM_CHROME = {"help", "docs", "developer", "developers", "business", "support", "about",
                    "transparency", "blog", "newsroom", "ads"}
_URL_IN_TEXT = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)


def _linked_urls(*texts: str) -> list[str]:
    """Off-platform links quoted in a title/snippet. A scam post's link is the pivot
    (the FulizaBoost page lived on vercel.app), so it is surfaced rather than buried."""
    found = []
    for t in texts:
        for m in _URL_IN_TEXT.findall(t or ""):
            u = m.rstrip(".,;:!?…")
            if not u.lower().startswith("http"):
                u = "https://" + u
            host = (urlsplit(u).hostname or "").lower()
            if host and not any(host == s_ or host.endswith("." + s_) for s_ in SOCIAL_SITES) and u not in found:
                found.append(u)
    return found[:5]


# Bait vocabulary: core/fraud_lexicon.py (1,000+ phrases in 19 families, EN/SW/Sheng) plus a few
# regex shapes a phrase list cannot express (numeric windows, throwaway-host domains). The shapes
# are mapped onto the lexicon's family names so "guaranteed" from either source is ONE signal:
# counting synonyms separately would let a single claim reach the two-signal threshold alone.
# Provenance is COMMON_PATTERN, not this repo's confirmed cases: a hit is a prompt to look, never
# a verdict. Advisories quote the bait verbatim, so any advisory marker suppresses the whole set
# (same reasoning as scamscan's counter_terms).
_BAIT_SHAPES = {
    "guarantee_claims": r"\b(?:guarantee[ds]?|100\s*%\s*(?:working|sure|legit))\b",
    "contact_funnel": r"\b(?:hit|dm|inbox|message|whatsapp)\s+(?:the\s+|our\s+|my\s+)?(?:admin|agent)\b",
    "advance_fee": r"\b(?:pre-?pay|upfront|ready with the charges)\b",
    "urgency_pressure": r"\b(?:slots?\s+(?:almost|are)\s+full|hurry|limited\s+(?:slots|time)|apply\s+now"
                        r"|within\s+\d+\s*(?:-\s*\d+\s*)?min(?:ute)?s?|1\s*[\u2013-]\s*2\s*minutes)\b",
    "link_hosting": r"\b[\w-]+\.(?:vercel\.app|netlify\.app|pages\.dev|blogspot\.com|weebly\.com|wixsite\.com)\b",
}
_ADVISORY = re.compile(r"\b(?:scam(?:s|mers?)?|fake|fraud(?:ulent|sters?)?|hoax|beware|warning|fact[- ]?check|"
                       r"don'?t (?:be )?(?:conned|fall)|safaricom (?:warns|says|clarif)|"
                       r"tahadhari|ulaghai|matapeli|walaghai)", re.I)
_BAIT_SHAPE_RE = {k: re.compile(v, re.I) for k, v in _BAIT_SHAPES.items()}


def _bait_signals(*texts: str) -> tuple[list[str], bool]:
    """(signals, advisory). Signals are empty for an advisory, which only quotes the bait."""
    signals, _terms, advisory = _bait_analysis(*texts)
    return signals, advisory


def _bait_analysis(*texts: str) -> tuple[list[str], dict[str, list[str]], bool]:
    """(families hit, phrases per family, advisory). The phrases are kept so a score can be defended."""
    from core.fraud_lexicon import match
    blob = " ".join(t for t in texts if t)
    if _ADVISORY.search(blob):
        return [], {}, True
    terms = match(blob)
    for family, rx in _BAIT_SHAPE_RE.items():
        hit = [m.group(0).lower() for m in rx.finditer(blob)]
        if hit:
            terms[family] = sorted(set(terms.get(family, [])) | set(hit))
    return sorted(terms), terms, False


def _social_url(parsed) -> str:
    """Canonical form so one account/post is one row. t.me/s/<name> is the public
    preview of t.me/<name>; ?before=N pages through the same channel."""
    host = parsed.netloc.lower()
    path, query = parsed.path, parsed.query
    if host == "t.me":
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2 and parts[0] == "s":
            path = "/" + "/".join(parts[1:])
        if len(parts) <= 2:
            query = ""
    return urlunsplit((parsed.scheme, host, path, query, ""))


def social_web_index(query: str, fetcher: Fetcher, hours: int = 72,
                     limit: int = 20) -> list[Item]:
    """Find public social URLs through an unauthenticated web index.

    This complements the authenticated/paid social APIs: it never bypasses a
    platform login or robots policy and is intentionally labelled as indexed
    leads. It is free, broad (TikTok, Instagram, Facebook, Telegram, WhatsApp,
    X and YouTube), and useful when platform APIs are unavailable.

    One request per platform and phrasing, not one giant OR. A single
    ``(site:a OR site:b ...)`` query comes back empty for most real topics
    (it returned nothing for "Fuliza limit increase" while per-site queries
    found Telegram "increment" channels and TikTok boost accounts), and an
    empty answer here reads as "nothing exists". Results are interleaved by
    platform so one chatty site cannot fill the page, and a failed request is
    never counted as a zero: every item carries ``requests_failed``, and no
    items with any failure raises.

    ``hours`` is ignored: the index has no date filter. Said here because the
    other backends honour it and a reader would assume this one does too.
    """
    import osint_discovery

    clean_query = " ".join(str(query or "").split())
    if len(clean_query) < 2:
        raise SourceError("social index query must contain at least 2 characters")

    bounded_limit = max(1, min(int(limit), 30))
    sites = SOCIAL_SITES
    # Exact phrase for precision; loose form because a throwaway scam account
    # rarely repeats an investigator's phrase verbatim. The loose form only runs
    # where the exact one came back thin: it halves the requests on a busy topic.
    multiword = " " in clean_query

    def one(site, q):
        last = None
        for attempt in range(2):
            time.sleep(SOCIAL_PACE * (1 + attempt))
            try:
                return site, q, osint_discovery.search_duckduckgo(q, max_results=10), None
            except Exception as exc:                       # noqa: BLE001 - reported, not hidden
                last = exc
        return site, q, [], last

    def run(site):
        out_ = [one(site, f'"{clean_query}" site:{site}')]
        if multiword and len(out_[0][2]) < 4:
            out_.append(one(site, f"{clean_query} site:{site}"))
        return out_

    jobs = list(sites)

    # Daemon threads, not ThreadPoolExecutor: its workers are joined at interpreter
    # exit, so one request stuck in a socket kept the whole process alive after the
    # sweep had printed its report. A daemon thread can simply be abandoned.
    pending_jobs = queue.Queue()
    for job in jobs:
        pending_jobs.put(job)
    finished: list = []
    lock = threading.Lock()
    stop = threading.Event()

    def worker():
        # `stop` is set at the deadline so an abandoned worker does not keep working
        # through the queue (and hitting the index) after the sweep has moved on.
        while not stop.is_set():
            try:
                job = pending_jobs.get_nowait()
            except queue.Empty:
                return
            res = run(job)
            with lock:
                finished.extend(res)

    # One worker on purpose. ddgs builds a primp client per request and primp logs
    # through Python's logging from Rust; with three threads doing that at once the
    # process deadlocked (stack dump: all three inside http_client.__init__ /
    # logging.emit). Pacing already dominates the latency, so parallelism bought little.
    logging.getLogger("primp").setLevel(logging.ERROR)
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(SOCIAL_DEADLINE)
    stop.set()
    with lock:
        results = list(finished)
    answered = {site for site, _, _, _ in results}
    # Queued-but-never-run platforms and stuck ones are both "could not look", not zeros.
    results += [(site, f'"{clean_query}" site:{site}', [], TimeoutError(f"no answer within {SOCIAL_DEADLINE:.0f}s"))
                for site in jobs if site not in answered]

    failures = [(q, exc) for _, q, _, exc in results if exc is not None]
    if len(failures) == len(results):
        raise SourceError(f"free social index search failed: {failures[0][1]}") from failures[0][1]

    tokens = [t for t in re.findall(r"[a-z0-9]+", clean_query.lower()) if len(t) >= 4]
    by_site: dict[str, list[Item]] = {site: [] for site in sites}
    seen = set()
    for _, q, rows, _exc in results:
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            parsed = urlsplit(str(row.get("url") or "").strip())
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            platform = next((s_ for s_ in sites if host == s_ or host.endswith("." + s_)), None)
            if platform is None:
                continue
            # help.x.com, docs.x.com and a bare instagram.com are the platform, not content.
            if parsed.path.strip("/") == "" or host.split(".")[0] in _PLATFORM_CHROME:
                continue
            url = _social_url(parsed)
            canon = urlsplit(url)
            identity = (canon.netloc.removeprefix("www."), canon.path.rstrip("/") or "/", canon.query)
            if identity in seen:
                continue
            seen.add(identity)
            title = _strip_tags(str(row.get("title") or ""))[:200]
            summary = _strip_tags(str(row.get("summary") or ""))[:2000]
            official = _is_official_handle(canon.path)
            bait, bait_terms, advisory = ([], {}, False) if official else _bait_analysis(title, summary)
            kind, account = _social_kind(canon.netloc.removeprefix("www."), canon.path)
            haystack = f"{title} {summary} {url}".lower()
            matched = sum(t in haystack for t in tokens)
            score = (matched / len(tokens)) if tokens else 1.0
            # Site-restricted queries still return unrelated rows (a wa.me seller
            # for "limit increase"); with no query term at all it is not a lead,
            # and wa.me needs half the terms because a number says nothing itself.
            if tokens and (matched == 0 or (platform == "wa.me" and score < 0.5)):
                continue
            by_site[platform].append(Item(
                url=url, source="social_web_index", source_type="social",
                title=title, text=summary,
                author=account,
                raw_meta={"platform": platform, "indexed": True, "kind": kind,
                          "account": account,
                          "term_match": matched > 0 or not tokens,
                          "term_score": round(score, 2),
                          "linked_urls": _linked_urls(title, summary),
                          "bait_signals": bait, "bait_terms": bait_terms, "advisory": advisory,
                          "official_account": official,
                          "discovery_method": "duckduckgo_web_index",
                          "indexed_query": q,
                          "requests_failed": len(failures),
                          "requests_total": len(results)},
            ))

    # Platform-made topic pages go last within their platform, and weaker term
    # matches below stronger ones; the ranker still sees all of them.
    for items in by_site.values():
        items.sort(key=lambda i: (i.raw_meta["kind"] == "topic_page", -i.raw_meta["term_score"]))

    out, depth = [], 0
    while len(out) < bounded_limit and any(depth < len(v) for v in by_site.values()):
        for site in sites:
            if depth < len(by_site[site]) and len(out) < bounded_limit:
                out.append(by_site[site][depth])
        depth += 1

    if not out and failures:
        raise SourceError(f"free social index search failed: {len(failures)} of "
                          f"{len(results)} requests failed ({failures[0][1]}) and the rest found nothing")
    return out


# -------------------------------------------------------------- SEC EDGAR

def sec_edgar(query: str, fetcher: Fetcher, hours: int = 0,
              limit: int = 15) -> list[Item]:
    """US filings full-text search. Free. Requires a real UA with contact info,
    which core/fetch.py already sends."""
    url = "https://efts.sec.gov/LATEST/search-index?" + urlencode(
        {"q": f'"{query}"', "forms": "", "hits": limit})
    res = fetcher.get(url, api=True)
    if not res.ok:
        url = "https://efts.sec.gov/LATEST/search-index?" + urlencode({"q": query})
        res = fetcher.get(url, api=True)
        if not res.ok:
            _fail(res)
    try:
        hits = json.loads(res.html).get("hits", {}).get("hits", [])
    except (json.JSONDecodeError, AttributeError):
        raise SourceError("200 but the response body was not the expected JSON")

    out = []
    for h in hits[:limit]:
        src = h.get("_source", {})
        cid = (h.get("_id") or "").split(":")[0].replace("-", "")
        out.append(Item(
            url=f"https://www.sec.gov/Archives/edgar/data/{cid}",
            source="sec_edgar", source_type="regulatory",
            title=" | ".join(filter(None, [src.get("display_names", [""])[0],
                                           src.get("file_type", "")])),
            published_at=src.get("file_date", ""),
            raw_meta={"form": src.get("root_form", "")},
        ))
    return out


# --------------------------------------------------------- OpenSanctions

def opensanctions(query: str, fetcher: Fetcher, hours: int = 0,
                  limit: int = 10) -> list[Item]:
    """Sanctions, PEP and watchlist matching. Needs a free OPENSANCTIONS_API_KEY.

    Without the key this raises SourceSkipped rather than returning [], so the
    sweep still completes but never reports an unsearched sanctions list as a
    clean one. That is the single most dangerous silent zero in the tool.
    """
    key = os.environ.get("OPENSANCTIONS_API_KEY")
    if not key:
        raise SourceSkipped("OPENSANCTIONS_API_KEY is not set")
    url = ("https://api.opensanctions.org/search/default?"
           + urlencode({"q": query, "limit": limit}))
    # Per request, not on the shared client: the fan-out is concurrent, so
    # assigning to fetcher.client.headers would put this key on whatever other
    # backend happened to be mid-flight.
    res = fetcher.get(url, api=True, headers={"Authorization": f"ApiKey {key}"})
    if not res.ok:
        _fail(res)
    try:
        results = json.loads(res.html).get("results", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for r in results:
        props = r.get("properties", {})
        topics = props.get("topics", [])
        out.append(Item(
            url=f"https://www.opensanctions.org/entities/{r.get('id', '')}/",
            source="opensanctions", source_type="watchlist",
            title=f"{r.get('caption', '')} ({r.get('schema', '')})",
            text=("Listed on: " + ", ".join(r.get("datasets", []))
                  + ". Topics: " + ", ".join(topics)
                  + ". Countries: " + ", ".join(props.get("country", []))),
            published_at=r.get("last_seen", ""),
            # A watchlist hit is never noise. Pre-scored so it can't be buried.
            relevance=95, enriched=True,
            raw_meta={"datasets": r.get("datasets", []), "topics": topics},
        ))
    return out


# ------------------------------------------------------------- web search

def web_search(query: str, fetcher: Fetcher, hours: int = 72,
               limit: int = 20) -> list[Item]:
    """The whole indexed web, via Brave's Search API.

    Every other backend here searches one silo. This one is what lets a sweep
    reach an arbitrary domain — a regulator's own site, a *.vercel.app app, a
    company blog — without writing a backend per host. Free tier is 2,000
    queries/month. Needs BRAVE_API_KEY.
    """
    key = os.environ.get("BRAVE_API_KEY")
    if not key:
        raise SourceSkipped("BRAVE_API_KEY is not set")
    freshness = {24: "pd", 168: "pw", 720: "pm"}.get(hours, "" if hours > 720 else "pw")
    params = {"q": query, "count": min(limit, 20)}
    if freshness:
        params["freshness"] = freshness
    url = "https://api.search.brave.com/res/v1/web/search?" + urlencode(params)
    res = fetcher.get(url, api=True, headers={
        "X-Subscription-Token": key, "Accept": "application/json"})
    if not res.ok:
        _fail(res)
    try:
        hits = json.loads(res.html).get("web", {}).get("results", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for h in hits[:limit]:
        if not h.get("url"):
            continue
        out.append(Item(
            url=h["url"], source="web_search", source_type="news",
            title=_strip_tags(h.get("title", "")),
            text=_strip_tags(h.get("description", "")),
            published_at=h.get("page_age", "") or h.get("age", ""),
            raw_meta={"domain": (h.get("meta_url", {}) or {}).get("hostname", "")},
        ))
    return out


# ------------------------------------------------------------------ GLEIF

def gleif(query: str, fetcher: Fetcher, hours: int = 0,
          limit: int = 10) -> list[Item]:
    """Legal Entity Identifiers. Free, no registration, no key.

    Answers "is this the same company?" — the name collision that produces the
    classic adverse-media false positive. An LEI is an unambiguous handle where
    a name is not.
    """
    url = "https://api.gleif.org/api/v1/lei-records?" + urlencode({
        "filter[fulltext]": query, "page[size]": min(limit, 50)})
    res = fetcher.get(url, api=True, headers={"Accept": "application/vnd.api+json"})
    if not res.ok:
        _fail(res)
    try:
        records = json.loads(res.html).get("data", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for r in records[:limit]:
        a = r.get("attributes", {}) or {}
        ent = a.get("entity", {}) or {}
        name = (ent.get("legalName", {}) or {}).get("name", "")
        addr = ent.get("legalAddress", {}) or {}
        country = addr.get("country", "")
        status = ent.get("status", "")
        lei = a.get("lei", r.get("id", ""))
        if not lei:
            continue
        out.append(Item(
            url=f"https://search.gleif.org/#/record/{lei}",
            source="gleif", source_type="dataset",
            title=f"{name} ({country})" if country else name,
            text=(f"LEI {lei}. Legal name: {name}. Country: {country}. "
                  f"Entity status: {status}. "
                  f"Registered: {', '.join(filter(None, addr.get('addressLines', []) or []))}"),
            published_at=(a.get("registration", {}) or {}).get("lastUpdateDate", ""),
            raw_meta={"lei": lei, "country": country, "status": status},
        ))
    return out


# ---------------------------------------------------------- OpenCorporates

def opencorporates(query: str, fetcher: Fetcher, hours: int = 0,
                   limit: int = 15) -> list[Item]:
    """Company registry data across 140+ jurisdictions. Needs
    OPENCORPORATES_API_KEY (free tier available on request)."""
    key = os.environ.get("OPENCORPORATES_API_KEY")
    if not key:
        raise SourceSkipped("OPENCORPORATES_API_KEY is not set")
    url = "https://api.opencorporates.com/v0.4/companies/search?" + urlencode(
        {"q": query, "per_page": min(limit, 30), "api_token": key})
    res = fetcher.get(url, api=True)
    if not res.ok:
        _fail(res)
    try:
        companies = (json.loads(res.html).get("results", {}) or {}).get("companies", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for entry in companies[:limit]:
        c = entry.get("company", {}) or {}
        if not c.get("opencorporates_url"):
            continue
        out.append(Item(
            url=c["opencorporates_url"], source="opencorporates",
            source_type="dataset",
            title=f"{c.get('name', '')} ({c.get('jurisdiction_code', '')})",
            text=(f"Company number {c.get('company_number', '')}. "
                  f"Status: {c.get('current_status', 'unknown')}. "
                  f"Incorporated: {c.get('incorporation_date', 'unknown')}. "
                  f"Type: {c.get('company_type', '')}"),
            published_at=c.get("updated_at", ""),
            raw_meta={"jurisdiction": c.get("jurisdiction_code", ""),
                      "status": c.get("current_status", "")},
        ))
    return out


# ---------------------------------------------------------------- Bluesky

def bluesky(query: str, fetcher: Fetcher, hours: int = 72,
            limit: int = 25) -> list[Item]:
    """Post search over the AT Protocol. Needs BLUESKY_HANDLE and
    BLUESKY_APP_PASSWORD (Settings -> App Passwords; free, revocable, and not
    your account password).

    Read endpoints like getProfile are open, but searchPosts is refused at the
    CDN without a session — diagnose.py caught this returning 403 for every
    user agent, which as a silent [] would have looked like "no posts found"
    forever. App passwords are Bluesky's supported mechanism for exactly this,
    so this stays an intended-consumer API call, not a scrape.
    """
    handle = os.environ.get("BLUESKY_HANDLE")
    app_password = os.environ.get("BLUESKY_APP_PASSWORD")
    if not (handle and app_password):
        raise SourceSkipped("BLUESKY_HANDLE / BLUESKY_APP_PASSWORD are not set")

    auth = fetcher.post(
        "https://bsky.social/xrpc/com.atproto.server.createSession",
        json_body={"identifier": handle, "password": app_password}, api=True)
    if not auth.ok:
        _fail(auth)
    try:
        jwt = json.loads(auth.html).get("accessJwt")
    except json.JSONDecodeError:
        raise SourceError("auth response was not valid JSON")
    if not jwt:
        raise SourceError("no session token returned — check handle/app password")

    url = "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts?" + urlencode(
        {"q": query, "limit": min(limit, 100), "sort": "latest"})
    res = fetcher.get(url, api=True, headers={"Authorization": f"Bearer {jwt}"})
    if not res.ok:
        _fail(res)
    try:
        posts = json.loads(res.html).get("posts", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for p in posts[:limit]:
        rec = p.get("record", {}) or {}
        handle = (p.get("author", {}) or {}).get("handle", "")
        rkey = (p.get("uri", "") or "").rsplit("/", 1)[-1]
        if not (handle and rkey):
            continue
        text = rec.get("text", "")
        out.append(Item(
            url=f"https://bsky.app/profile/{handle}/post/{rkey}",
            source="bluesky", source_type="social",
            title=text[:120], text=text, author=handle,
            published_at=rec.get("createdAt", ""),
            raw_meta={"likes": p.get("likeCount"), "reposts": p.get("repostCount")},
        ))
    return out


# ----------------------------------------------------------------- Reddit

def reddit(query: str, fetcher: Fetcher, hours: int = 72,
           limit: int = 25) -> list[Item]:
    """Official OAuth API. Needs REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET
    (free: create a 'script' app at reddit.com/prefs/apps).

    Reddit requires OAuth for automated access; the old unauthenticated .json
    endpoints are not a supported interface and are being closed off, so this
    deliberately does not fall back to them.
    """
    cid = os.environ.get("REDDIT_CLIENT_ID")
    secret = os.environ.get("REDDIT_CLIENT_SECRET")
    if not (cid and secret):
        raise SourceSkipped("REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET are not set")

    basic = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    token_res = fetcher.post(
        "https://www.reddit.com/api/v1/access_token",
        data={"grant_type": "client_credentials"},
        headers={"Authorization": f"Basic {basic}"}, api=True)
    if not token_res.ok:
        _fail(token_res)
    try:
        token = json.loads(token_res.html).get("access_token")
    except json.JSONDecodeError:
        raise SourceError("auth response was not valid JSON")
    if not token:
        raise SourceError("no access token returned — check the credentials")

    window = "day" if hours <= 24 else "week" if hours <= 168 else "month"
    url = "https://oauth.reddit.com/search?" + urlencode(
        {"q": query, "limit": min(limit, 100), "sort": "new", "t": window,
         "type": "link"})
    res = fetcher.get(url, api=True, headers={"Authorization": f"Bearer {token}"})
    if not res.ok:
        _fail(res)
    try:
        children = (json.loads(res.html).get("data", {}) or {}).get("children", [])
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    out = []
    for child in children[:limit]:
        d = child.get("data", {}) or {}
        if not d.get("permalink"):
            continue
        created = d.get("created_utc")
        out.append(Item(
            url=f"https://www.reddit.com{d['permalink']}",
            source="reddit", source_type="social",
            title=(d.get("title") or "").strip(),
            text=_strip_tags(d.get("selftext", ""))[:2000],
            author=d.get("author", ""),
            published_at=(_iso(datetime.fromtimestamp(created, timezone.utc))
                          if created else ""),
            raw_meta={"subreddit": d.get("subreddit", ""),
                      "score": d.get("score"), "comments": d.get("num_comments")},
        ))
    return out


# ---------------------------------------------------------------------- X

def x_twitter(query: str, fetcher: Fetcher, hours: int = 72,
              limit: int = 20) -> list[Item]:
    """X/Twitter recent search via the official paid API. Needs X_BEARER_TOKEN.

    This is the official documented endpoint on a paid tier, which is why it is
    here when scraping X is not: it's a supported interface with a real
    contract behind it, so it fails loudly rather than silently. Recent search
    only reaches back 7 days on most tiers — beyond that this returns nothing,
    which is a real limit of the product, not of the sweep.
    """
    token = os.environ.get("X_BEARER_TOKEN")
    if not token:
        raise SourceSkipped("X_BEARER_TOKEN is not set")
    url = "https://api.x.com/2/tweets/search/recent?" + urlencode({
        "query": f"{query} -is:retweet",
        "max_results": max(10, min(limit, 100)),
        "tweet.fields": "created_at,public_metrics,lang,author_id",
        "expansions": "author_id",
        "user.fields": "username",
    })
    res = fetcher.get(url, api=True, headers={"Authorization": f"Bearer {token}"})
    if not res.ok:
        _fail(res)
    try:
        payload = json.loads(res.html)
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")

    users = {u["id"]: u.get("username", "")
             for u in (payload.get("includes", {}) or {}).get("users", [])}
    out = []
    for t in payload.get("data", [])[:limit]:
        handle = users.get(t.get("author_id", ""), "i")
        text = t.get("text", "")
        out.append(Item(
            url=f"https://x.com/{handle}/status/{t.get('id', '')}",
            source="x", source_type="social",
            title=text[:120], text=text, author=handle,
            published_at=t.get("created_at", ""), lang=t.get("lang", ""),
            raw_meta=t.get("public_metrics", {}) or {},
        ))
    return out


# ------------------------------------------------------------- SocialCrawl

def _socialcrawl_items(payload: dict) -> list[dict]:
    """Accept the documented meta envelope and tolerate nested data wrappers."""
    data = payload.get("data") or {}
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    for key in ("items", "results", "posts"):
        rows = data.get(key) if isinstance(data, dict) else None
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _first(mapping: dict, *keys, default=""):
    for key in keys:
        value = mapping.get(key)
        if value is not None and value != "":
            return value
    return default


def _socialcrawl_error(res) -> str:
    """Return the provider's actionable error without exposing credentials."""
    try:
        payload = json.loads(res.html)
    except (json.JSONDecodeError, TypeError):
        return res.error or f"HTTP {res.status}"
    error = payload.get("error") or {}
    if isinstance(error, dict):
        kind = str(error.get("type") or "").replace("_", " ").lower()
        message = str(error.get("message") or "").strip()
    else:
        kind, message = "", str(error).strip()
    detail = message or kind or res.error or f"HTTP {res.status}"
    credits_used = payload.get("credits_used")
    if credits_used is not None:
        detail += f" (credits used: {credits_used})"
    return detail


def socialcrawl(query: str, fetcher: Fetcher, hours: int = 72,
                limit: int = 20) -> list[Item]:
    """Search public posts across SocialCrawl's Universal Search API.

    The endpoint costs credits, so this backend is opt-in rather than part of
    DEFAULT_BACKENDS. SocialCrawl supplies the public post data; Watchtower
    still applies its normal ranking, dedupe, provenance and retention rules.
    """
    key = os.environ.get("SOCIALCRAWL_API_KEY")
    if not key:
        raise SourceSkipped("SOCIALCRAWL_API_KEY is not set")

    clean_query = " ".join(str(query or "").split())
    if len(clean_query) < 2:
        raise SourceError("SocialCrawl query must contain at least 2 characters; no credits were charged")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise SourceError("SocialCrawl limit must be a positive integer; no credits were charged")
    bounded_limit = min(limit, 100)

    lookback_days = max(1, min(3650, (max(0, hours) + 23) // 24))
    url = "https://www.socialcrawl.dev/v1/search/everywhere?" + urlencode({
        "query": clean_query,
        "lookback_days": lookback_days,
    })
    # Universal Search is a paid, multi-source fan-out and can legitimately
    # take longer than an ordinary API call. Never retry it automatically: a
    # timed-out response may still have completed and settled credits upstream.
    res = fetcher.get(url, api=True, retries=0, timeout=120, headers={
        "x-api-key": key,
        "Accept": "application/json",
    })
    if not res.ok:
        raise SourceError(_socialcrawl_error(res))
    try:
        payload = json.loads(res.html)
    except json.JSONDecodeError:
        raise SourceError("200 but the response body was not valid JSON")
    if not isinstance(payload, dict):
        raise SourceError("200 but the response body was not a JSON object")
    if payload.get("success") is False:
        detail = payload.get("error") or payload.get("message") or "API reported failure"
        raise SourceError(str(detail))

    envelope_meta = {
        key: payload.get(key)
        for key in ("request_id", "credits_used", "credits_remaining", "cached")
        if payload.get(key) is not None
    }
    if isinstance(payload.get("pagination"), dict):
        envelope_meta["pagination"] = payload["pagination"]
    rows = _socialcrawl_items(payload)
    out = []
    for row in rows[:bounded_limit]:
        author = row.get("author") or {}
        engagement = row.get("engagement") or {}
        computed = row.get("computed") or row.get("metadata") or {}
        if not isinstance(author, dict):
            author = {"username": str(author)}
        platform = str(_first(row, "platform", "source", default="socialcrawl"))
        item_url = str(_first(row, "url", "permalink", "web_url"))
        post_id = str(_first(row, "id", "post_id"))
        handle = str(_first(author, "username", "handle", "name"))
        if not item_url and post_id:
            # Keep a stable identity without pretending to know a platform URL.
            item_url = f"socialcrawl://{platform}/{post_id}"
        if not item_url:
            continue
        text = str(_first(row, "text", "content", "description", "caption"))
        raw_meta = {
            **envelope_meta,
            "platform": platform,
            "post_id": post_id,
            "engagement": engagement if isinstance(engagement, dict) else {},
            "computed": computed if isinstance(computed, dict) else {},
        }
        out.append(Item(
            url=item_url,
            source=f"socialcrawl:{platform}",
            source_type="social",
            title=str(_first(row, "title", default=text[:160])),
            text=text[:10000],
            author=handle,
            published_at=str(_first(row, "published_at", "created_at", "timestamp")),
            lang=str(_first(computed, "language", default=_first(row, "language"))),
            raw_meta=raw_meta,
        ))
    if rows and not out:
        raise SourceError(
            f"SocialCrawl returned {len(rows)} result(s), but none had a usable URL"
        )
    return out


BACKENDS = {
    "gdelt": gdelt,
    "google_news": google_news,
    "web_search": web_search,
    "wikipedia": wikipedia,
    "hackernews": hackernews,
    "mastodon": mastodon,
    "social_web_index": social_web_index,
    "bluesky": bluesky,
    "reddit": reddit,
    "x": x_twitter,
    "socialcrawl": socialcrawl,
    "gleif": gleif,
    "opencorporates": opencorporates,
    "sec_edgar": sec_edgar,
    "opensanctions": opensanctions,
}

# Which backends need credentials, and the variable each one wants. One map,
# because there are three consumers — `run.py sources`, /api/sources for the
# chip gating, and diagnose.py — and when this lived in two of them the CLI
# went on claiming opensanctions was the only key-gated source long after five
# more had been added.
BACKEND_KEYS = {
    "opensanctions": "OPENSANCTIONS_API_KEY",
    "opencorporates": "OPENCORPORATES_API_KEY",
    "x": "X_BEARER_TOKEN",
    "reddit": "REDDIT_CLIENT_ID",
    "socialcrawl": "SOCIALCRAWL_API_KEY",
}

# Some official APIs require a credential pair. Keep this separate from the
# single display key above so the web UI and CLI cannot advertise a source as
# ready when its second credential is missing.
BACKEND_REQUIREMENTS = {
    "reddit": ("REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET"),
}


def has_credentials(name: str) -> bool:
    """True when this backend either needs no key or has the one it needs."""
    requirements = BACKEND_REQUIREMENTS.get(name)
    if requirements:
        return all(bool(os.environ.get(var)) for var in requirements)
    var = BACKEND_KEYS.get(name)
    return not var or bool(os.environ.get(var))


# These legacy adapters remain importable for stored-job compatibility, but are
# deliberately retired from defaults and the product UI. They are either
# metered (Brave) or unreliable for unauthenticated search (Mastodon/Bluesky).
# Keeping the names here lets old explicit jobs fail/upgrade predictably rather
# than silently changing their meaning.
RETIRED_BACKENDS = frozenset({"web_search", "mastodon", "bluesky"})

# social_web_index is in the defaults: it is the only default that reaches TikTok,
# Telegram, Facebook, Instagram and YouTube, and without it a CLI sweep of a scam
# topic is news-only. Free and keyless; bounded by SOCIAL_DEADLINE.
DEFAULT_BACKENDS = ["gdelt", "google_news", "wikipedia", "hackernews",
                    "social_web_index", "reddit", "x", "gleif", "opencorporates",
                    "opensanctions"]
