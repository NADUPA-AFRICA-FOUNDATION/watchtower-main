"""Discovery through a self-hosted SearXNG instance's JSON API. See searxng.yaml."""
from __future__ import annotations

import json
import os
from urllib.parse import urlencode, urlsplit

from social.adapters import Outcome, load_config
from social.schema import canonical_url

SOURCE = "searxng"


def enabled(cfg: dict | None = None) -> bool:
    cfg = cfg or load_config(SOURCE)
    return bool(os.environ.get(cfg["url_env"], "").strip())


def search(client, term: str, domain: str, *, last_success_at=None, now=None, rotation: int = 0,
           cfg: dict | None = None, aliases: tuple = ()) -> Outcome:
    cfg = cfg or load_config(SOURCE)
    base = os.environ.get(cfg["url_env"], "").strip().rstrip("/")
    if not base:
        return Outcome(SOURCE, "disabled", f"{cfg['url_env']} is not set")
    q = cfg["query_template"].format(term=term.replace('"', " "), domain=domain)
    fetched = client.get(f"{base}{cfg['path']}?" + urlencode({"q": q, **cfg["params"]}),
                         min_interval=cfg["min_interval_seconds"], ttl=cfg["cache_ttl_seconds"])
    if fetched.error:
        return Outcome(SOURCE, "error", f"the SearXNG instance did not answer ({fetched.error})")
    if fetched.status == 429:
        return Outcome(SOURCE, "rate_limited", "HTTP 429 from the SearXNG instance (its limiter is on)")
    if fetched.status == 403:
        return Outcome(SOURCE, "blocked", "HTTP 403: JSON output is not enabled on the instance (search.formats)")
    if fetched.status != 200:
        return Outcome(SOURCE, "error", f"HTTP {fetched.status} from the SearXNG instance")
    try:
        data = json.loads(fetched.body)
        rows = data.get("results") or []
    except (ValueError, AttributeError):
        return Outcome(SOURCE, "error", "200 but not SearXNG's JSON")
    domains = (domain, *aliases)
    results, seen = [], set()
    for r in rows:
        url = str(r.get("url") or "")
        host = (urlsplit(url).hostname or "").lower()
        if not url.startswith("http") or not any(host == d or host.endswith("." + d) for d in domains):
            continue
        url = canonical_url(url)
        if url in seen:
            continue
        seen.add(url)
        results.append({"url": url, "title": str(r.get("title") or "").strip(),
                        "snippet": str(r.get("content") or "").strip()[:2000],
                        "published_at": (str(r.get("publishedDate") or "")[:10] or None), "author": None})
        if len(results) >= cfg["max_results"]:
            break
    failed = [e[0] if isinstance(e, list) and e else str(e) for e in data.get("unresponsive_engines") or []]
    via = " (cached)" if fetched.from_cache else ""
    if results:
        note = f"; engines that did not answer: {', '.join(failed)}" if failed else ""
        return Outcome(SOURCE, "ok", f"{len(results)} result(s){via}{note}", results)
    if failed and not rows:
        return Outcome(SOURCE, "blocked", f"no engine answered ({', '.join(failed)})")
    return Outcome(SOURCE, "no_results", f"SearXNG answered{via} and found nothing on {domain}")
