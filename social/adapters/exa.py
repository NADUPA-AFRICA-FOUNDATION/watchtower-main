"""Discovery through Exa's search API. Off unless EXA_API_KEY is set; see exa.yaml."""
from __future__ import annotations

import json
import os

from social.adapters import Outcome, load_config
from social.schema import canonical_url

SOURCE = "exa"


def enabled(cfg: dict | None = None) -> bool:
    cfg = cfg or load_config(SOURCE)
    return bool(os.environ.get(cfg["key_env"], "").strip())


def search(client, term: str, domain: str, *, last_success_at=None, now=None, rotation: int = 0,
           cfg: dict | None = None, aliases: tuple = ()) -> Outcome:
    cfg = cfg or load_config(SOURCE)
    key = os.environ.get(cfg["key_env"], "").strip()
    if not key:
        return Outcome(SOURCE, "disabled", f"{cfg['key_env']} is not set")
    payload = {
        "query": cfg["query_template"].format(term=term.replace('"', " ")),
        "type": "auto",
        "objective": " ".join(cfg["objective"].split()),
        "includeDomains": [domain, *aliases],
        "contents": {"highlights": True},
    }
    fetched = client.post_json(cfg["endpoint"], payload, {"x-api-key": key},
                               min_interval=cfg["min_interval_seconds"], ttl=cfg["cache_ttl_seconds"])
    if fetched.error:
        return Outcome(SOURCE, "error", fetched.error)
    if fetched.status in cfg["rate_limited_status"]:
        return Outcome(SOURCE, "rate_limited", f"HTTP {fetched.status}")
    if fetched.status in cfg["blocked_status"]:
        return Outcome(SOURCE, "blocked", f"HTTP {fetched.status}: the key was refused or has no credit")
    if fetched.status != 200:
        return Outcome(SOURCE, "error", f"HTTP {fetched.status}")
    try:
        rows = json.loads(fetched.body).get("results") or []
    except (ValueError, AttributeError):
        return Outcome(SOURCE, "error", "200 but the body was not Exa's JSON")
    results, seen = [], set()
    domains = (domain, *aliases)
    for r in rows:
        url = str(r.get("url") or "")
        host = url.split("/")[2].lower() if url.count("/") >= 2 else ""
        if not url.startswith("http") or not any(host == d or host.endswith("." + d) for d in domains):
            continue
        url = canonical_url(url)
        if url in seen:
            continue
        seen.add(url)
        highlights = [h for h in (r.get("highlights") or []) if isinstance(h, str) and h.strip()]
        published = str(r.get("publishedDate") or "")[:10] or None
        results.append({"url": url, "title": str(r.get("title") or "").strip(), "snippet": " … ".join(highlights)[:2000],
                        "published_at": published, "author": str(r.get("author") or "").strip() or None})
    via = " (cached)" if fetched.from_cache else ""
    if results:
        return Outcome(SOURCE, "ok", f"{len(results)} result(s){via}", results)
    return Outcome(SOURCE, "no_results", f"Exa answered{via} and found nothing on {domain}")
