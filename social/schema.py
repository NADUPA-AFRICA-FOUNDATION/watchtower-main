"""The one hit shape every adapter returns, and the URL rules that make dedupe work.

Never invent, estimate or pad a value. A field the source did not give is None and is
named in `missing_fields`; a hit built from a search snippet alone is still a valid hit
(`snippet_only`) and says so.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# ok: every field present. partial: details fetched, some fields unavailable.
# snippet_only: only the search engine's title and snippet. The rest are non-hits.
STATUSES = ("ok", "partial", "snippet_only", "not_found", "blocked", "rate_limited", "error")
HIT_STATUSES = ("ok", "partial", "snippet_only")
REVIEW_STATUSES = ("new", "relevant", "dismissed", "escalated")

PLATFORMS: dict[str, tuple[str, ...]] = {
    "reddit": ("reddit.com",), "tiktok": ("tiktok.com",), "x": ("x.com", "twitter.com"),
    "facebook": ("facebook.com", "fb.com"), "instagram": ("instagram.com",),
}
_TRACKING = re.compile(r"^(utm_|fbclid$|gclid$|igshid$|igsh$|ref$|ref_src$|ref_url$|s$|t$|lang$|hl$|_rdc$|_rdr$|rdt$|share_id$|mibextid$)")
_SUBDOMAINS = ("www.", "m.", "mobile.", "old.", "new.", "web.", "mbasic.", "touch.", "en-gb.")

_FIELD_PATHS = [("author", f) for f in ("username", "display_name", "profile_url", "followers", "verified")] + \
               [("content", f) for f in ("text", "published_at", "media_urls")] + \
               [("engagement", f) for f in ("likes", "comments", "shares", "views")]


def platform_of(url: str) -> str | None:
    host = (urlsplit(url).hostname or "").lower()
    for name, domains in PLATFORMS.items():
        if any(host == d or host.endswith("." + d) for d in domains):
            return name
    return None


def canonical_url(url: str) -> str:
    """One spelling per post or profile, so the same thing found twice is one hit."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    for sub in _SUBDOMAINS:
        if host.startswith(sub):
            host = host[len(sub):]
            break
    if host == "twitter.com":
        host = "x.com"
    if host == "fb.com":
        host = "facebook.com"
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not _TRACKING.match(k.lower())])
    path = re.sub(r"/{2,}", "/", parts.path).rstrip("/") or "/"
    return urlunsplit(("https", host, path, query, ""))


def author_from_url(platform: str, url: str) -> str | None:
    """A handle that is literally in the URL. Not a guess: None when the path does not carry one."""
    parts = [p for p in urlsplit(url).path.split("/") if p]
    if not parts:
        return None
    first = parts[0]
    if platform == "tiktok":
        return first[1:] if first.startswith("@") and len(first) > 1 else None
    if platform == "x":
        return first if first.lower() not in {"i", "hashtag", "search", "home", "explore", "intent", "share"} else None
    if platform == "reddit":
        return parts[1] if first in {"user", "u"} and len(parts) > 1 else None
    if platform == "instagram":
        return first if first not in {"p", "reel", "reels", "tv", "explore", "popular", "stories", "accounts"} else None
    if platform == "facebook":
        skip = {"groups", "watch", "share", "photo", "photo.php", "story.php", "permalink.php", "profile.php", "public",
                "people", "p", "events", "marketplace", "hashtag", "login", "reel"}
        return first if first not in skip and not first.isdigit() else None
    return None


def new_hit(platform: str, url: str, source_method: str, status: str, fetched_at: int, *, username=None,
            display_name=None, profile_url=None, followers=None, verified=None, text=None, published_at=None,
            media_urls=None, likes=None, comments=None, shares=None, views=None, title=None, raw=None) -> dict:
    hit = {
        "platform": platform, "url": canonical_url(url), "status": status, "source_method": source_method,
        "fetched_at": fetched_at, "title": title,
        "author": {"username": username, "display_name": display_name, "profile_url": profile_url,
                   "followers": followers, "verified": verified},
        "content": {"text": text, "published_at": published_at, "media_urls": media_urls},
        "engagement": {"likes": likes, "comments": comments, "shares": shares, "views": views},
        "raw": raw or {},
    }
    hit["missing_fields"] = missing_fields(hit)
    return hit


def missing_fields(hit: dict) -> list[str]:
    return [f"{group}.{field}" for group, field in _FIELD_PATHS if hit.get(group, {}).get(field) is None]


def merge_hit(old: dict, new: dict) -> dict:
    """Keep what is known. A later, poorer sighting never erases a fetched field."""
    rank = {s: i for i, s in enumerate(("snippet_only", "partial", "ok"))}
    out = {**old}
    for group in ("author", "content", "engagement"):
        out[group] = {k: (new.get(group, {}).get(k) if new.get(group, {}).get(k) is not None else old.get(group, {}).get(k))
                      for k in {**old.get(group, {}), **new.get(group, {})}}
    better = rank.get(new.get("status"), -1) >= rank.get(old.get("status"), -1)
    out["status"] = new["status"] if better else old["status"]
    out["source_method"] = new["source_method"] if better else old["source_method"]
    out["title"] = new.get("title") or old.get("title")
    out["fetched_at"] = max(old.get("fetched_at") or 0, new.get("fetched_at") or 0)
    out["raw"] = {**(old.get("raw") or {}), **(new.get("raw") or {})}
    out["missing_fields"] = missing_fields(out)
    return out
