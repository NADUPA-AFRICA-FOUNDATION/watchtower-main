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
import copy
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
    "urgency_pressure": r"\b(?:slots?\s+(?:almost|are)\s+full|hurry|limited\s+(?:slots|time)|apply\s+now|don'?t be left out|do not be left out"
                        r"|within\s+\d+\s*(?:-\s*\d+\s*)?min(?:ute)?s?|1\s*[\u2013-]\s*2\s*minutes)\b",
    "link_hosting": r"\b[\w-]+\.(?:vercel\.app|netlify\.app|pages\.dev|blogspot\.com|weebly\.com|wixsite\.com)\b",
    # The payment always moves to a personal channel: a Kenyan mobile number, a WhatsApp link with a
    # number in it, or a Till/Paybill number. The real brand never asks customers to pay or message
    # a personal number, so next to the scam's subject this is enough by itself.
    "personal_contact": r"(?<![\d])(?:\+?254|0)[\s-]?[17]\d{2}[\s-]?\d{3}[\s-]?\d{3}(?!\d)"
                        r"|\bwa\.me/\+?\d{9,15}"
                        r"|\b(?:till|paybill|pay\s*bill|buy\s*goods)\s*(?:no\.?|number|#)?\s*:?\s*\d{5,7}\b"
                        r"|\b(?:call|text|sms|whatsapp)\s+(?:me|us)\s+on\b",
    # Offering the service to whoever wants it, without naming a fee: how a lure reads when its
    # author has learned which fee words get reported.
    "solicitation": r"\b(?:do you (?:need|want)|those who (?:want|need)|(?:any ?one|anybody) (?:who )?(?:wants?|needs?)"
                    r"|contact (?:me |us )?for|(?:dm|inbox|message|text|call|whatsapp) (?:me |us )?for"
                    r"|serious (?:clients|people|customers) only|strictly for"
                    r"|(?:boost|increment|increase|upgrade|loans?)\s+(?:is |are )?(?:now )?available"
                    r"|legit (?:service|agent|fuliza|loan|increment|boost)"
                    r"|provide (?:the |your )?(?:correct )?details|send (?:me )?your (?:details|number|id))\b",
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
    """(families hit, phrases per family, advisory). The phrases are kept so a score can be defended.

    Matching runs on the de-obfuscated text and its digit-decoded reading (core/deobfuscate.py),
    so "F.u.l.i.z.a" and "Fuliz@" are read as Fuliza; the union of both readings counts."""
    from core.deobfuscate import variants
    from core.fraud_lexicon import match
    readings = variants(" ".join(t for t in texts if t))
    if any(_ADVISORY.search(r) for r in readings):
        return [], {}, True
    terms: dict[str, set] = {}
    for blob in readings:
        for family, hits in match(blob).items():
            terms.setdefault(family, set()).update(hits)
        for family, rx in _BAIT_SHAPE_RE.items():
            hit = {m.group(0).lower().strip() for m in rx.finditer(blob)}
            if hit:
                terms.setdefault(family, set()).update(hit)
    out = {k: sorted(v) for k, v in terms.items()}
    return sorted(out), out, False


_TITLE_TAIL = re.compile(r"\s*(?:[-|\u2022\u2013]\s*(?:facebook|tiktok|instagram|telegram|youtube|x)\b.*"
                         r"|\(@[^)]*\).*|\u2022\s*follow.*|/\s*x\s*$|on (?:x|instagram|tiktok)\b.*)$", re.I)
_SNIPPET_ACCOUNT = re.compile(r"(?:comments?\s*-\s*([\w. ]{3,40}?)\s+on\s+[A-Z][a-z]+\s+\d"
                              r"|video from\s+([^(]{3,40}?)\s*\(@\s*([\w.]+)\s*\)"
                              # A Telegram invite page names the channel only in its text.
                              r"|invited to (?:the |join the )?(?:channel|group)\s+([^.\n]{3,60}?)(?:[.!\n]|\s+click\b)"
                              r"|view and join\s+(?!@)([^\n]{3,80}?)\s+right away)", re.I)
_POST_PATHS = {"posts", "videos", "video", "photo", "reel", "reels", "status", "watch", "permalink"}
_POST_ROOTS = {"p", "reel", "tv", "watch", "i", "story.php", "permalink.php", "photo.php", "share"}


def _lure_identity(platform: str, path: str, kind: str, title: str, text: str) -> str:
    """The account's own name, if that name is a protected brand plus a service word.

    Identity comes from the handle, the page slug and the account's display name only, never
    from what a post says: "How to increase your Fuliza limit" by @someone is a how-to video,
    while a page NAMED "Fuliza Limit Increase" is the thing Safaricom says cannot exist.
    Returns the matched identity ('' if none) so a reviewer can see why it fired.
    """
    from core.fraud_lexicon import (IDENTITY_AMOUNT, IDENTITY_BRANDS, IDENTITY_LEGIT_PAIRS, IDENTITY_OFFER_BIO,
                                    IDENTITY_SERVICES, OFFICIAL_HANDLES)
    if kind == "topic_page" or platform == "youtube.com":
        return ""
    parts = [p for p in path.split("/") if p]
    if not parts:
        return ""
    names = []
    first = parts[0].lstrip("@")
    if first.lower() in OFFICIAL_HANDLES:
        return ""
    # facebook.com/p/<name> is a page, but facebook.com/watch/?v=... and /story.php are posts.
    is_post = any(p in _POST_PATHS for p in parts[1:]) or (first in _POST_ROOTS and not (platform == "facebook.com" and first == "p"))
    if platform == "facebook.com":
        slug = parts[1] if first in {"p", "public", "people"} and len(parts) > 1 else first
        if first != "groups" and not slug.isdigit() and slug != "profile.php":
            names.append(re.sub(r"-\d{6,}$", "", slug))
    elif first not in {"p", "reel", "tv", "watch", "i", "s", "hashtag", "joinchat"} and not first.startswith("+"):
        names.append(first)
    # A profile/page/channel title is the display name; a post's title is the post.
    if not is_post:
        names.append(_TITLE_TAIL.sub("", title))
    m = _SNIPPET_ACCOUNT.search(text or "")
    if m:
        names.extend(g for g in m.groups() if g)
    from core.deobfuscate import squeeze, variants
    for name in names:
        for reading in variants(name):
            compact = re.sub(r"[^a-z0-9]", "", reading.lower())
            if compact in OFFICIAL_HANDLES or len(compact) > 60:
                break
            # Brand checked with repeated letters squeezed too ("fulizza", "mpessa"); service words
            # are not squeezed, because "boost" and "support" have doubled letters of their own.
            brands = [b for b in IDENTITY_BRANDS if b in compact or b in squeeze(compact)]
            if not brands:
                continue
            services = [sv for sv in IDENTITY_SERVICES if sv in compact
                        and not all((b, sv) in IDENTITY_LEGIT_PAIRS for b in brands)]
            if services or re.search(IDENTITY_AMOUNT, compact):
                return name.strip()[:80]
            # An account named for the brand whose own bio sells the service ("Click on the link
            # below to Apply", "Huster fund increment"). Accounts only: a post's text is not a bio.
            if not is_post and re.search(IDENTITY_OFFER_BIO, (text or "").lower()):
                return name.strip()[:80]
    return ""


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


# Seconds a complete answer is reused for the same query. Users re-run a sweep when it feels
# slow; without this every retry is another 60s+ of index requests. Only complete runs are
# cached, and a cached item says so (`cached_age_seconds`), so a stale answer is never silent.
SOCIAL_CACHE_TTL = 1800.0
# Ceiling for the follow-up reads (Telegram previews, link checks) after the search itself.
SOCIAL_ENRICH_BUDGET = 20.0
SOCIAL_PREVIEW_MAX = 5
SOCIAL_LINKS_MAX = 3
_SOCIAL_CACHE: dict = {}
_SOCIAL_CACHE_LOCK = threading.Lock()

# One short phrase per family, for people who will never read the lexicon.
_FAMILY_PLAIN = {
    "advance_fee": "asks for money upfront", "guarantee_claims": "promises a guaranteed result",
    "urgency_pressure": "pressures you to act fast", "credential_theft": "asks for a PIN, code or ID",
    "impersonation": "uses an official-sounding name", "investment_returns": "promises unrealistic returns",
    "crypto_forex_signals": "pushes trading signals", "job_offer": "offers a job for a fee",
    "prize_giveaway": "says you have won something", "reversal_wrong_transaction": "asks you to send money back",
    "contact_funnel": "moves you to a private chat", "fake_social_proof": "shows success stories that cannot be checked",
    "link_hosting": "links to a throwaway website", "swahili": "uses known scam wording (Kiswahili)",
    "sheng": "uses known scam wording (Sheng)", "betting_fixed_match": "sells 'sure' betting tips",
    "emotional_pretext": "uses an emergency story", "fake_support_charity": "asks for donations to a personal number",
    "personal_contact": "gives a personal phone, WhatsApp or Till number", "solicitation": "offers the service to anyone who wants it",
}
_TG_POST = re.compile(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.S)
_TG_SUBS = re.compile(r'<span class="counter_value">([^<]+)</span>\s*<span class="counter_type">subscribers?', re.I)


def behavioural_signals(meta: dict) -> list[str]:
    """Bait families that describe how a lure behaves; the subject of the search is not one."""
    from core.fraud_lexicon import SUBJECT_FAMILIES
    if meta.get("advisory"):
        return []
    return [b for b in (meta.get("bait_signals") or []) if b not in SUBJECT_FAMILIES]


# Signals that, next to the scam's own subject ("fuliza limit increase"), are enough on their own:
# a third party offering the service and asking for money, a code, a private chat or a personal
# number. Weaker signals (urgency, success stories, throwaway hosting) still need a second one.
STRONG_WITH_SUBJECT = frozenset({"personal_contact", "solicitation", "advance_fee", "credential_theft", "contact_funnel"})
# Families that real brand activity and news about it also produce: never a lure verdict together.
WEAK_FAMILIES = frozenset({"impersonation", "prize_giveaway", "urgency_pressure", "fake_social_proof", "swahili", "sheng"})


def is_likely_lure(meta: dict) -> bool:
    """The one rule behind `likely_lure`, the score boost and the verdict, so they cannot disagree.

    Any of: the account is named for the scam; two behavioural signals agree; or the scam's
    subject appears together with one strong signal. Warnings about scams never count."""
    from core.fraud_lexicon import SUBJECT_FAMILIES
    if meta.get("advisory"):
        return False
    behav = behavioural_signals(meta)
    subject = bool(set(meta.get("bait_signals") or []) & SUBJECT_FAMILIES)
    strong = set(behav) & STRONG_WITH_SUBJECT
    # Two weak signals agreeing is not enough on their own when both are things ordinary coverage
    # of a real promotion also says ("Safaricom promotion", "winner"). With the scam's subject
    # beside them ("boosted from KSh 500 to 50,000, apply now") they are.
    weak_pair_only = set(behav) <= WEAK_FAMILIES
    return bool(meta.get("lure_identity")) or (len(behav) >= 2 and (subject or not weak_pair_only)) or (subject and bool(strong))


def social_verdict(meta: dict) -> dict:
    """A plain-language reading of one indexed result: what it looks like, why, and what to do.

    Every field is derived from facts already in `meta`; nothing here is a new judgement. The
    wording stays honest about depth: most rows were read from a search snippet, not opened.
    """
    details = []
    preview = meta.get("preview") or {}
    if preview.get("status") == "read":
        subs = f"{preview['subscribers']} subscribers, " if preview.get("subscribers") else ""
        details.append(f"Channel opened and read: {subs}{preview.get('posts', 0)} recent posts")
    elif preview.get("status") == "no_public_preview":
        details.append("Channel could not be read (it has no public preview page); judged on the search snippet only")
    elif preview.get("status"):
        details.append(f"Channel could not be read ({preview.get('error') or 'unavailable'}); judged on the search snippet only")
    for link in meta.get("link_intel") or []:
        bits = []
        if link.get("first_archived"):
            bits.append(f"first archived {link['first_archived']}")
        if link.get("urlscan_scans"):
            bits.append(f"{link['urlscan_scans']} public scan(s)")
        if link.get("errors"):
            bits.append("some checks failed: " + ", ".join(link["errors"]))
        details.append(f"Linked site {link['domain']}: " + ("; ".join(bits) if bits else "no archive or scan history found"))

    def out(level, label, reason, action=""):
        return {"level": level, "label": label, "reason": reason, "action": action, "details": details}

    behav = behavioural_signals(meta)
    plain = [_FAMILY_PLAIN.get(b, b.replace("_", " ")) for b in behav]
    if meta.get("official_account"):
        return out("official", "Official account", "This is the real brand's own account.")
    if meta.get("advisory"):
        return out("advisory", "Warning about a scam",
                   "The text warns about a scam rather than running one.", "Read it for the accounts it names.")
    if meta.get("lure_identity"):
        why = f'The account is named "{meta["lure_identity"]}". A real brand does not offer this through third-party accounts.'
        if plain:
            why += " It also " + ", ".join(plain) + "."
        return out("lure", "Likely scam account", why, "Do not pay or share a PIN or code. Report it to the real company.")
    if len(behav) >= 2:
        return out("lure", "Likely scam offer", "It " + ", and ".join(plain) + ".",
                   "Do not pay or share a PIN or code. Report it to the real company.")
    if meta.get("kind") == "topic_page":
        return out("topic", "Platform topic page", "An automatic page listing posts on a topic, not a post or an account.")
    if behav:
        return out("check", "Needs a look", "One warning sign: it " + plain[0] + ".", "Open it before deciding.")
    return out("none", "No scam signs found",
               "Nothing in the account name or the search snippet matched a known scam pattern. The page itself was not opened.")


def _telegram_preview(fetcher, name: str) -> dict:
    """Read a channel's public preview page (t.me/s/<name>): the same page anyone sees logged out.

    A channel's snippet in a search index is one stale sentence; the preview carries the recent
    posts, which is where the fee and "message the admin" wording actually lives. Fetched as a
    page (robots applies), never through an account.
    """
    res = fetcher.get(f"https://t.me/s/{name}", retries=0, timeout=8)
    if not res.ok:
        return {"status": "unavailable", "error": res.error or f"HTTP {res.status}"}
    posts = [_strip_tags(p).strip() for p in _TG_POST.findall(res.html)]
    posts = [p for p in posts if p]
    if not posts:
        # Private channels, groups and plain user accounts have no preview; t.me serves the
        # contact page instead. That is "no public preview", not "an empty channel".
        return {"status": "no_public_preview"}
    subs = _TG_SUBS.search(res.html)
    return {"status": "read", "posts": len(posts), "subscribers": subs.group(1).strip() if subs else "",
            "excerpt": posts[-1][:300], "_texts": posts[-20:]}


def _link_intel(fetcher, domain: str) -> dict:
    """History for a site a post links to: first Wayback capture and public urlscan.io scans.

    Both are lookups in archives other people already made; the site itself is not contacted.
    A failed lookup is listed in `errors`, never folded into "no history".
    """
    out: dict = {"domain": domain, "errors": []}
    res = fetcher.get("https://web.archive.org/cdx/search/cdx?" + urlencode(
        {"url": domain, "output": "json", "limit": 1, "fl": "timestamp"}), api=True, retries=0, timeout=8)
    try:
        if not res.ok and res.status != 200:
            raise ValueError(res.error or f"HTTP {res.status}")
        rows = json.loads(res.html or "[]")
        if len(rows) > 1 and rows[1]:
            ts = str(rows[1][0])
            out["first_archived"] = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
            out["archive_url"] = f"https://web.archive.org/web/{ts}/{domain}"
    except (ValueError, IndexError, TypeError):
        out["errors"].append("archive lookup")
    res = fetcher.get("https://urlscan.io/api/v1/search/?" + urlencode({"q": f"domain:{domain}", "size": 3}),
                      api=True, retries=0, timeout=8)
    try:
        if not res.ok:
            raise ValueError(res.error or f"HTTP {res.status}")
        data = json.loads(res.html)
        results = data.get("results") or []
        out["urlscan_scans"] = int(data.get("total") or len(results))
        if results:
            out["urlscan_url"] = str(results[0].get("result") or "").replace("/api/v1/result/", "/result/")
            out["last_scanned"] = str((results[0].get("task") or {}).get("time") or "")[:10]
    except (ValueError, TypeError, AttributeError):
        out["errors"].append("scan lookup")
    return out


def _enrich_social(items: list[Item], fetcher) -> None:
    """Open the few results worth opening. Bounded by count and by SOCIAL_ENRICH_BUDGET."""
    from core.fraud_lexicon import match
    deadline = time.monotonic() + SOCIAL_ENRICH_BUDGET
    channels = [i for i in items if i.raw_meta["platform"] == "t.me" and i.raw_meta["kind"] == "channel"
                and i.raw_meta.get("account") and not i.raw_meta.get("official_account")][:SOCIAL_PREVIEW_MAX]
    for item in channels:
        meta = item.raw_meta
        if time.monotonic() > deadline:
            meta["preview"] = {"status": "unavailable", "error": "time budget reached"}
            continue
        try:
            preview = _telegram_preview(fetcher, meta["account"])
        except Exception as exc:                                    # noqa: BLE001 - recorded on the item
            preview = {"status": "unavailable", "error": f"{type(exc).__name__}"}
        texts = preview.pop("_texts", [])
        meta["preview"] = preview
        # Post by post, so one "beware of fake admins" notice (which lure channels post too)
        # silences only itself, while a news channel quoting a scam is silenced where it warns.
        terms = {k: set(v) for k, v in (meta.get("bait_terms") or {}).items()}
        for post in texts:
            if _ADVISORY.search(post):
                continue
            for family, hits in match(post).items():
                terms.setdefault(family, set()).update(hits)
            for family, rx in _BAIT_SHAPE_RE.items():
                found = {m.group(0).lower() for m in rx.finditer(post)}
                if found:
                    terms.setdefault(family, set()).update(found)
            for url in _linked_urls(post):
                if url not in meta["linked_urls"] and len(meta["linked_urls"]) < 5:
                    meta["linked_urls"].append(url)
        if texts and not meta.get("advisory"):
            meta["bait_terms"] = {k: sorted(v)[:8] for k, v in terms.items()}
            meta["bait_signals"] = sorted(terms)

    seen: dict[str, dict] = {}
    for item in items:
        if item.raw_meta.get("official_account"):
            continue
        for url in item.raw_meta.get("linked_urls") or []:
            domain = (urlsplit(url).hostname or "").lower().removeprefix("www.")
            if not domain:
                continue
            if domain not in seen:
                if len(seen) >= SOCIAL_LINKS_MAX or time.monotonic() > deadline:
                    continue
                try:
                    seen[domain] = _link_intel(fetcher, domain)
                except Exception:                                   # noqa: BLE001 - recorded on the item
                    seen[domain] = {"domain": domain, "errors": ["archive lookup", "scan lookup"]}
            item.raw_meta.setdefault("link_intel", []).append(seen[domain])


_SITE_ALIASES = {"x.com": ("twitter.com",), "facebook.com": ("fb.com",)}
_PREFERRED: dict = {}


def _preferred_search() -> list:
    """(adapter, client) for each better search source that is configured, best first.

    Exa (EXA_API_KEY) then SearXNG (SEARXNG_URL). DuckDuckGo is the fallback for whichever of
    them is missing or fails, not the default. The client caches answers in memory so a repeated
    Exa query in the same process is not paid for twice.
    """
    from social.adapters import exa, searxng
    wanted = [a for a in (exa, searxng) if a.enabled()]
    if not wanted:
        return []
    if "client" not in _PREFERRED:
        from social.net import PoliteClient
        from social.store import SQLiteStore
        _PREFERRED["client"] = PoliteClient(SQLiteStore())
    return [(a, _PREFERRED["client"]) for a in wanted]


def social_web_index(query: str, fetcher: Fetcher, hours: int = 72,
                     limit: int = 20, on_partial=None) -> list[Item]:
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

    ``on_partial(new_items, total_so_far)`` is called as each platform answers,
    so a caller can show results during the minute this takes instead of at
    the end. Those early items are not yet enriched or given a verdict.

    ``hours`` is ignored: the index has no date filter. Said here because the
    other backends honour it and a reader would assume this one does too.
    """
    import osint_discovery

    clean_query = " ".join(str(query or "").split())
    if len(clean_query) < 2:
        raise SourceError("social index query must contain at least 2 characters")

    bounded_limit = max(1, min(int(limit), 30))
    cache_key = (clean_query.lower(), bounded_limit)
    if SOCIAL_CACHE_TTL > 0:
        with _SOCIAL_CACHE_LOCK:
            hit = _SOCIAL_CACHE.get(cache_key)
        if hit and time.monotonic() - hit[0] < SOCIAL_CACHE_TTL:
            fresh = copy.deepcopy(hit[1])
            for item in fresh:
                item.raw_meta["cached_age_seconds"] = int(time.monotonic() - hit[0])
            return fresh

    sites = SOCIAL_SITES
    # Exact phrase for precision; loose form because a throwaway scam account
    # rarely repeats an investigator's phrase verbatim. The loose form only runs
    # where the exact one came back thin: it halves the requests on a busy topic.
    multiword = " " in clean_query

    # Set at the deadline. Checked before every request, not just between platforms:
    # an abandoned worker that wakes from a stuck call must not send its retry or
    # its loose-phrasing follow-up after the sweep has moved on.
    stop = threading.Event()

    def one(site, q):
        last = TimeoutError("abandoned at the deadline")
        for attempt in range(2):
            time.sleep(SOCIAL_PACE * (1 + attempt))
            if stop.is_set():
                break
            try:
                return site, q, osint_discovery.search_duckduckgo(q, max_results=10), None
            except Exception as exc:                       # noqa: BLE001 - reported, not hidden
                last = exc
        return site, q, [], last

    # Daemon thread, not ThreadPoolExecutor: its workers are joined at interpreter
    # exit, so one request stuck in a socket kept the whole process alive after the
    # sweep had printed its report. A daemon thread can simply be abandoned.
    # One worker on purpose. ddgs builds a primp client per request and primp logs
    # through Python's logging from Rust; with three threads doing that at once the
    # process deadlocked (stack dump: all three inside http_client.__init__ /
    # logging.emit). Pacing already dominates the latency, so parallelism bought little.
    finished: queue.Queue = queue.Queue()
    preferred = _preferred_search()

    def better(site):
        """Ask the configured better sources (Exa, then SearXNG) first. Returns a result tuple
        when one of them answered, else None so the DuckDuckGo path runs as the fallback."""
        for adapter, client in preferred:
            if stop.is_set():
                return None
            try:
                out = adapter.search(client, clean_query, site, aliases=_SITE_ALIASES.get(site, ()))
            except Exception:                              # noqa: BLE001 - fall through to the next source
                continue
            if out.answered:
                rows = [{"url": r["url"], "title": r["title"], "summary": r["snippet"]} for r in out.results]
                return site, f"{adapter.SOURCE}: {clean_query} on {site}", rows, None
        return None

    def worker():
        for site in sites:
            if stop.is_set():
                return
            answered = better(site) if preferred else None
            if answered is not None:
                finished.put(answered)
                continue
            first = one(site, f'"{clean_query}" site:{site}')
            finished.put(first)
            if multiword and len(first[2]) < 4 and not stop.is_set():
                finished.put(one(site, f"{clean_query} site:{site}"))

    logging.getLogger("primp").setLevel(logging.ERROR)
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    tokens = [t for t in re.findall(r"[a-z0-9]+", clean_query.lower()) if len(t) >= 4]
    by_site: dict[str, list[Item]] = {site: [] for site in sites}
    seen = set()

    def ingest(q, rows) -> list[Item]:
        new = []
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
            identity_key = (canon.netloc.removeprefix("www."), canon.path.rstrip("/") or "/", canon.query)
            if identity_key in seen:
                continue
            title = _strip_tags(str(row.get("title") or ""))[:200]
            summary = _strip_tags(str(row.get("summary") or ""))[:2000]
            haystack = f"{title} {summary} {url}".lower()
            matched = sum(t in haystack for t in tokens)
            score = (matched / len(tokens)) if tokens else 1.0
            # Site-restricted queries still return unrelated rows (a wa.me seller
            # for "limit increase"); with no query term at all it is not a lead,
            # and wa.me needs half the terms because a number says nothing itself.
            if tokens and (matched == 0 or (platform == "wa.me" and score < 0.5)):
                continue
            seen.add(identity_key)
            official = _is_official_handle(canon.path)
            bait, bait_terms, advisory = ([], {}, False) if official else _bait_analysis(title, summary)
            kind, account = _social_kind(canon.netloc.removeprefix("www."), canon.path)
            identity = "" if (official or advisory) else _lure_identity(
                platform, canon.path, kind, title, summary)
            item = Item(
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
                          "lure_identity": identity,
                          "discovery_method": (q.split(":", 1)[0] + "_search") if ": " in q else "duckduckgo_web_index",
                          "indexed_query": q},
            )
            by_site[platform].append(item)
            new.append(item)
        return new

    # Results are ingested here as they arrive, so a caller can be told about each platform
    # while the rest are still being asked.
    results = []
    deadline = time.monotonic() + SOCIAL_DEADLINE
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            res = finished.get(timeout=min(remaining, 0.25))
        except queue.Empty:
            if not thread.is_alive() and finished.empty():
                break
            continue
        results.append(res)
        new = ingest(res[1], res[2])
        if new and on_partial is not None:
            try:
                on_partial(new, sum(len(v) for v in by_site.values()))
            except Exception:                              # noqa: BLE001 - a display hook must not fail the search
                pass
    stop.set()

    answered = {site for site, _, _, _ in results}
    # Queued-but-never-run platforms and stuck ones are both "could not look", not zeros.
    results += [(site, f'"{clean_query}" site:{site}', [], TimeoutError(f"no answer within {SOCIAL_DEADLINE:.0f}s"))
                for site in sites if site not in answered]

    failures = [(q, exc) for _, q, _, exc in results if exc is not None]
    if len(failures) == len(results):
        raise SourceError(f"free social index search failed: {failures[0][1]}") from failures[0][1]

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

    if fetcher is not None:
        _enrich_social(out, fetcher)
    for item in out:
        item.raw_meta["requests_failed"] = len(failures)
        item.raw_meta["requests_total"] = len(results)
        item.raw_meta["verdict"] = social_verdict(item.raw_meta)

    # Only a complete answer is worth reusing; a partial one should be retried, not replayed.
    if SOCIAL_CACHE_TTL > 0 and not failures:
        with _SOCIAL_CACHE_LOCK:
            _SOCIAL_CACHE[cache_key] = (time.monotonic(), copy.deepcopy(out))
            for key in [k for k, v in _SOCIAL_CACHE.items() if time.monotonic() - v[0] >= SOCIAL_CACHE_TTL]:
                _SOCIAL_CACHE.pop(key, None)
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
