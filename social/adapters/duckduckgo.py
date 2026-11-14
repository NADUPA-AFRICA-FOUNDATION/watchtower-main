"""Discovery through DuckDuckGo's HTML pages. See duckduckgo.yaml for everything tunable."""
from __future__ import annotations

import html as _html
import re
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from social.adapters import Outcome, load_config
from social.schema import canonical_url

SOURCE = "duckduckgo"


def _text(fragment: str) -> str:
    return re.sub(r"\s+", " ", _html.unescape(re.sub(r"<[^>]+>", " ", fragment or ""))).strip()


def _unwrap(href: str, param: str) -> str:
    href = href.replace("&amp;", "&")
    if href.startswith("//"):
        href = "https:" + href
    if "duckduckgo.com/l/" in href:
        return unquote((parse_qs(urlsplit(href).query).get(param) or [""])[0])
    return href


def _blocked(fetched, cfg) -> tuple[str, str] | None:
    if fetched.error:
        return "error", fetched.error
    if fetched.status in cfg["rate_limited_status"]:
        return "rate_limited", f"HTTP {fetched.status}"
    if fetched.status in cfg["blocked_status"]:
        return "blocked", f"HTTP {fetched.status} (challenge or refusal)"
    if fetched.status != 200:
        return "error", f"HTTP {fetched.status}"
    low = fetched.body[:200_000].lower()
    for marker in cfg["block_markers"]:
        if marker in low:
            return "blocked", f"challenge page ('{marker}')"
    return None


def parse_results(body: str, domains, cfg: dict) -> list[dict]:
    """Result links on any of `domains` (a platform's aliases: x.com and twitter.com are one
    place), each with the title and whatever snippet sits before the next link."""
    domains = (domains,) if isinstance(domains, str) else tuple(domains)
    links = [(m.start(), m.end(), _unwrap(m.group(1), cfg["redirect_param"]), _text(m.group(2)))
             for m in re.finditer(cfg["link_pattern"], body, re.S)]
    out, seen = [], {}
    for i, (_start, end, href, title) in enumerate(links):
        host = (urlsplit(href).hostname or "").lower()
        if not href.startswith("http") or not any(host == d or host.endswith("." + d) for d in domains):
            continue
        url = canonical_url(href)
        nxt = next((s for s, _e, h, _t in links[i + 1:] if canonical_url(h) != url and h.startswith("http")), len(body))
        m = re.search(cfg["snippet_pattern"], body[end:nxt], re.S)
        snippet = _text(m.group(1)) if m else ""
        if url in seen:
            # Engines repeat the link (title, then display URL). Keep the first, fill gaps from the rest.
            row = seen[url]
            row["snippet"] = row["snippet"] or snippet
            if not row["title"] or row["title"].lower().startswith(("http",) + domains):
                row["title"] = title or row["title"]
            continue
        published = None
        d = re.match(cfg["date_prefix_pattern"], snippet)
        if d:
            for fmt in ("%b %d, %Y", "%B %d, %Y"):
                try:
                    published = datetime.strptime(d.group(1), fmt).date().isoformat()
                    snippet = snippet[d.end():]
                    break
                except ValueError:
                    continue
        seen[url] = {"url": url, "title": title, "snippet": snippet, "published_at": published}
        out.append(seen[url])
    return out[: cfg["max_results"]]


def _request(client, cfg, query: str, start: int) -> tuple[object, str, tuple[str, str] | None]:
    """Try each host once, beginning at `start`. Returns (fetched, host name, block) for the last one tried."""
    hosts = cfg["hosts"][start % len(cfg["hosts"]):] + cfg["hosts"][: start % len(cfg["hosts"])]
    fetched = name = block = None
    for host in hosts:
        params = {host["param"]: query}
        if cfg["recency"].get("value"):
            params[cfg["recency"]["param"]] = cfg["recency"]["value"]
        fetched = client.get(host["url"] + "?" + urlencode(params), min_interval=cfg["min_interval_seconds"],
                             ttl=cfg["cache_ttl_seconds"])
        name, block = host["name"], _blocked(fetched, cfg)
        if block is None:
            break
    return fetched, name, block


def search(client, term: str, domain: str, *, last_success_at: int | None, now: int, rotation: int = 0,
           cfg: dict | None = None, aliases: tuple = ()) -> Outcome:
    cfg = cfg or load_config(SOURCE)
    if not cfg.get("enabled", True):
        return Outcome(SOURCE, "disabled", "disabled in duckduckgo.yaml")
    query = cfg["query_template"].format(term=term.replace('"', " "), domain=domain)
    fetched, host, block = _request(client, cfg, query, rotation)
    if block:
        return Outcome(SOURCE, block[0], f"{block[1]} on every DuckDuckGo page tried")
    results = parse_results(fetched.body, (domain, *aliases), cfg)
    via = f"{host} page" + (" (cached)" if fetched.from_cache else "")
    if results:
        return Outcome(SOURCE, "ok", f"{len(results)} result(s) via the {via}", results)
    # Nothing found. Believe it only if the engine demonstrably answers us; a soft block is also "nothing".
    control = cfg["control"]
    if last_success_at is None or now - last_success_at > control["trust_seconds"] * 1000:
        check, _h, cblock = _request(client, cfg, control["query"], rotation)
        if cblock or not parse_results(check.body, control["expect_host"], cfg):
            return Outcome(SOURCE, "blocked", "no results, and a control query that must have results also came back "
                                              "empty: the engine is not answering this client")
    return Outcome(SOURCE, "no_results", f"the engine answered via the {via} and found nothing")
