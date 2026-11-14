"""Post details from Reddit's public post JSON. Disabled by default; see reddit_json.yaml."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from social.adapters import Outcome, load_config

SOURCE = "reddit_json"


def applies(url: str, cfg: dict | None = None) -> bool:
    cfg = cfg or load_config(SOURCE)
    return bool(cfg.get("enabled", False) and re.match(cfg["url_pattern"], url))


def enrich(client, url: str, cfg: dict | None = None) -> Outcome:
    cfg = cfg or load_config(SOURCE)
    fetched = client.get(cfg["host"] + urlsplit(url).path.rstrip("/") + cfg["suffix"],
                         min_interval=cfg["min_interval_seconds"], ttl=cfg["cache_ttl_seconds"])
    if fetched.error:
        return Outcome(SOURCE, "error", fetched.error)
    if fetched.status in cfg["not_found_status"]:
        return Outcome(SOURCE, "not_found", "the post is deleted or removed")
    if fetched.status in cfg["rate_limited_status"]:
        return Outcome(SOURCE, "rate_limited", f"HTTP {fetched.status}")
    if fetched.status in cfg["blocked_status"] or "/login" in urlsplit(fetched.final_url).path:
        return Outcome(SOURCE, "blocked", f"HTTP {fetched.status} or a login wall")
    try:
        post = json.loads(fetched.body)[0]["data"]["children"][0]["data"]
    except (ValueError, KeyError, IndexError, TypeError):
        return Outcome(SOURCE, "error", "200 but the body was not a post listing")
    author = post.get("author")
    created = post.get("created_utc")
    text = " ".join(x for x in (post.get("title"), post.get("selftext")) if x).strip()
    return Outcome(SOURCE, "ok", "post JSON", [{
        "username": author if author and author != "[deleted]" else None,
        "profile_url": f"https://reddit.com/user/{author}" if author and author != "[deleted]" else None,
        "text": text or None,
        "published_at": datetime.fromtimestamp(created, timezone.utc).isoformat(timespec="seconds") if created else None,
        "likes": post.get("score"), "comments": post.get("num_comments")}])
