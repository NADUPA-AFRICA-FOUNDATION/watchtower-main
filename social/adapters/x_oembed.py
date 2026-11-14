"""Post details for a public X post from the documented oEmbed endpoint. See x_oembed.yaml."""
from __future__ import annotations

import html as _html
import json
import re
from datetime import datetime
from urllib.parse import urlencode

from social.adapters import Outcome, load_config

SOURCE = "x_oembed"


def applies(url: str, cfg: dict | None = None) -> bool:
    cfg = cfg or load_config(SOURCE)
    return bool(cfg.get("enabled", True) and re.match(cfg["url_pattern"], url))


def enrich(client, url: str, cfg: dict | None = None) -> Outcome:
    cfg = cfg or load_config(SOURCE)
    fetched = client.get(cfg["endpoint"] + "?" + urlencode({"url": url, **cfg["params"]}),
                         min_interval=cfg["min_interval_seconds"], ttl=cfg["cache_ttl_seconds"])
    if fetched.error:
        return Outcome(SOURCE, "error", fetched.error)
    if fetched.status in cfg["not_found_status"]:
        return Outcome(SOURCE, "not_found", "the post is deleted, private or was never public")
    if fetched.status in cfg["rate_limited_status"]:
        return Outcome(SOURCE, "rate_limited", f"HTTP {fetched.status}")
    if fetched.status in cfg["blocked_status"]:
        return Outcome(SOURCE, "blocked", f"HTTP {fetched.status}")
    if fetched.status != 200:
        return Outcome(SOURCE, "error", f"HTTP {fetched.status}")
    try:
        data = json.loads(fetched.body)
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except ValueError:
        return Outcome(SOURCE, "error", "200 but the body was not oEmbed JSON")
    block = str(data.get("html") or "")
    para = re.search(r"<p[^>]*>(.*?)</p>", block, re.S)
    text = re.sub(r"\s+", " ", _html.unescape(re.sub(r"<[^>]+>", " ", para.group(1)))).strip() if para else None
    published = None
    stamps = re.findall(r"<a[^>]*>([^<]+)</a>", block)
    for fmt in ("%B %d, %Y", "%b %d, %Y"):
        try:
            published = datetime.strptime(_html.unescape(stamps[-1]).strip(), fmt).date().isoformat() if stamps else None
            break
        except ValueError:
            continue
    fields = {"display_name": data.get("author_name") or None, "profile_url": data.get("author_url") or None,
              "text": text or None, "published_at": published}
    if not any(fields.values()):
        return Outcome(SOURCE, "error", "oEmbed answered without an author or any text")
    return Outcome(SOURCE, "ok", "author and text from oEmbed; it carries no engagement counts", [fields])
