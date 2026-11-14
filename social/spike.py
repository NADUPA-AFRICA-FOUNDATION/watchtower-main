"""Phase 1 feasibility spike: which keyless sources answer from THIS machine?

Run it where the app will run. Platforms and search engines treat datacenter addresses
differently from home ones, so a pass on a laptop proves nothing about the server:

    python -m social.spike                 # print the matrix
    python -m social.spike --json          # raw results
    GET /api/admin/source-matrix           # same thing, on the deployed instance

What it does and does not do:

  * Sends an honest, identifying User-Agent. It does not pose as a browser, rotate identities,
    use a proxy, sign in or solve challenges. A source that only answers a disguised client is
    recorded as blocked, because that is what it is to us.
  * One request per probe, paced per host. No retries: a retry would hide a rate limit.
  * A 200 with no results is not a pass. Each search engine also gets a control query that
    must return results; if the control comes back empty the engine is soft-blocking and its
    empty answers are reported as blocked, not as "nothing found".
  * Facebook and Instagram pages, X syndication and embedded page JSON are not probed. They
    are excluded by policy (see CLAUDE.md, "Scraped platforms stay absent"), not by test.

Everything that can change on a provider's whim (URLs, parameters, block markers) is in the
tables at the top of this file.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from urllib import robotparser
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import httpx

USER_AGENT = "Mnara-SourceMatrix/0.1 (keyless feasibility test; +https://github.com/NADUPA-AFRICA-FOUNDATION/watchtower-main)"
TIMEOUT = 15.0
PACE = 2.5                      # seconds between requests to the same host
ENGINE_PACE = 5.0               # search engines throttle bursts within a handful of requests

PLATFORMS = {"reddit": "reddit.com", "tiktok": "tiktok.com", "x": "x.com",
             "facebook": "facebook.com", "instagram": "instagram.com"}

# Search-engine HTML endpoints. `recency` is added for the one recency probe per engine.
ENGINES = {
    "duckduckgo_html": {"url": "https://html.duckduckgo.com/html/", "q": "q", "extra": {}, "recency": {"df": "m"}},
    "duckduckgo_lite": {"url": "https://lite.duckduckgo.com/lite/", "q": "q", "extra": {}, "recency": {"df": "m"}},
    "bing": {"url": "https://www.bing.com/search", "q": "q", "extra": {"count": "20"}, "recency": {"filters": 'ex1:"ez3"'}},
    "mojeek": {"url": "https://www.mojeek.com/search", "q": "q", "extra": {}, "recency": {"since": "month"}},
}
CONTROL_QUERY, CONTROL_HOST = "wikipedia kenya", "wikipedia.org"

BLOCK_MARKERS = ("captcha", "unusual traffic", "anomaly", "are you a robot", "are you human", "verify you are human",
                 "challenge-form", "automated requests", "access denied", "request blocked", "too many requests",
                 "enable javascript and cookies", "bots use duckduckgo too")
LOGIN_MARKERS = ("log in to continue", "login to continue", "sign in to continue", "you must log in", "loginform")

REDDIT = {
    "search.json": "https://www.reddit.com/search.json?" + urlencode({"q": "{term}", "sort": "new", "limit": 5}),
    "subreddit new.json": "https://www.reddit.com/r/Kenya/new.json?limit=5",
    "search.rss": "https://www.reddit.com/search.rss?" + urlencode({"q": "{term}", "sort": "new", "limit": 5}),
    "subreddit new.rss": "https://www.reddit.com/r/Kenya/new/.rss?limit=5",
    "old.reddit search.json": "https://old.reddit.com/search.json?" + urlencode({"q": "{term}", "sort": "new", "limit": 5}),
}
REDDIT_FIELDS = ("title", "selftext", "author", "created_utc", "score", "num_comments", "permalink", "subreddit")

# Documented oEmbed endpoints, tried against a public post from the brand's own account.
OEMBED = {
    "tiktok oEmbed": "https://www.tiktok.com/oembed?" + urlencode({"url": "https://www.tiktok.com/@safaricomplc/video/7662041989755522324"}),
    "x publish oEmbed": "https://publish.twitter.com/oembed?" + urlencode({"url": "https://x.com/SafaricomPLC/status/2079525210290626567", "omit_script": "1"}),
}
OEMBED_FIELDS = ("author_name", "author_url", "title", "html", "thumbnail_url", "provider_name")

EXCLUDED = [
    ("facebook", "public page / post HTML, Page Plugin embed"),
    ("instagram", "public post / profile HTML, embedded JSON"),
    ("x", "syndication (embedded tweet/timeline) endpoints"),
    ("tiktok", "tag and search pages (embedded JSON state)"),
]


def _environment() -> dict:
    env = os.environ
    where = ("render" if env.get("RENDER") else "vercel" if env.get("VERCEL") else
             "railway" if env.get("RAILWAY_ENVIRONMENT") else "github-actions" if env.get("GITHUB_ACTIONS") else "local")
    return {"where": where, "service": env.get("RENDER_SERVICE_NAME") or env.get("VERCEL_URL") or "",
            "region": env.get("RENDER_REGION") or env.get("VERCEL_REGION") or "", "hostname": socket.gethostname()[:40]}


class _Client:
    """httpx with per-host pacing and no retries. Returns a dict, never raises."""

    def __init__(self, transport=None, pace: float = PACE, engine_pace: float = ENGINE_PACE):
        self.http = httpx.Client(timeout=TIMEOUT, follow_redirects=True, transport=transport,
                                 headers={"User-Agent": USER_AGENT, "Accept-Language": "en"})
        self.pace, self.engine_pace, self.last = pace, engine_pace, {}
        self.engine_hosts = {urlsplit(cfg["url"]).hostname for cfg in ENGINES.values()}

    def get(self, url: str) -> dict:
        host = urlsplit(url).hostname or ""
        pace = self.engine_pace if host in self.engine_hosts else self.pace
        wait = pace - (time.monotonic() - self.last.get(host, 0))
        if wait > 0:
            time.sleep(wait)
        t0 = time.monotonic()
        try:
            r = self.http.get(url)
            out = {"status": r.status_code, "body": r.text, "final_url": str(r.url),
                   "content_type": r.headers.get("content-type", ""), "error": ""}
        except Exception as exc:                                   # noqa: BLE001 - the error IS the result
            out = {"status": 0, "body": "", "final_url": url, "content_type": "", "error": f"{type(exc).__name__}: {exc}"[:160]}
        self.last[host] = time.monotonic()
        out["ms"] = int((time.monotonic() - t0) * 1000)
        return out

    def close(self):
        self.http.close()


def _blocked(res: dict) -> str:
    """'' if the response looks like content, else why it does not."""
    if res["error"]:
        return res["error"]
    low = res["body"][:200000].lower()
    if res["status"] in (401, 403):
        return f"HTTP {res['status']} (refused)"
    if res["status"] == 429:
        return "HTTP 429 (rate limited)"
    if res["status"] == 202:
        return "HTTP 202 (challenge page)"
    if res["status"] != 200:
        return f"HTTP {res['status']}"
    if re.search(r"/(?:login|signin|accounts/login)\b", urlsplit(res["final_url"]).path):
        return "redirected to a login page"
    for marker in BLOCK_MARKERS:
        if marker in low:
            return f"block marker: '{marker}'"
    for marker in LOGIN_MARKERS:
        if marker in low:
            return f"login wall: '{marker}'"
    return ""


def _result_links(html: str) -> list[str]:
    """Outbound result URLs in a results page, unwrapping the engines' redirect links."""
    links = []
    for raw in re.findall(r'href="([^"]+)"', html):
        href = raw.replace("&amp;", "&")
        if "duckduckgo.com/l/?" in href:
            href = unquote((parse_qs(urlsplit(href).query).get("uddg") or [""])[0])
        elif "bing.com/ck/a" in href:
            u = (parse_qs(urlsplit(href).query).get("u") or [""])[0]
            if u.startswith("a1"):
                try:
                    href = base64.urlsafe_b64decode(u[2:] + "=" * (-len(u[2:]) % 4)).decode("utf-8", "replace")
                except Exception:                                  # noqa: BLE001
                    continue
        if href.startswith("//"):
            href = "https:" + href
        if href.startswith("http"):
            links.append(href)
    return links


def _hits(html: str, domain: str) -> list[str]:
    out = []
    for link in _result_links(html):
        host = (urlsplit(link).hostname or "").lower()
        if (host == domain or host.endswith("." + domain)) and link not in out:
            out.append(link)
    return out


def _robots(client: _Client, url: str) -> str:
    parts = urlsplit(url)
    res = client.get(f"{parts.scheme}://{parts.netloc}/robots.txt")
    if res["status"] != 200:
        return f"no robots.txt (HTTP {res['status'] or 'error'})"
    rp = robotparser.RobotFileParser()
    rp.parse(res["body"].splitlines())
    return "allows" if rp.can_fetch(USER_AGENT, url) else "disallows"


def _row(group, source, target, res, verdict, fields="", note="", robots=""):
    return {"group": group, "source": source, "target": target, "http": res["status"] if res else None,
            "ms": res["ms"] if res else None, "verdict": verdict, "fields": fields, "note": note, "robots": robots}


def probe_engines(client: _Client, term: str) -> list[dict]:
    rows = []
    for name, cfg in ENGINES.items():
        def url(q, extra=None, cfg=cfg):
            return cfg["url"] + "?" + urlencode({cfg["q"]: q, **cfg["extra"], **(extra or {})})
        robots = _robots(client, url("x"))
        control = client.get(url(CONTROL_QUERY))
        why = _blocked(control)
        control_ok = not why and bool(_hits(control["body"], CONTROL_HOST))
        rows.append(_row("discovery", name, "control query", control, "ok" if control_ok else "blocked",
                         f"{len(_result_links(control['body']))} links" if not why else "",
                         why or ("" if control_ok else "200 but no results for a query that must have some: soft block"), robots))
        probes = [(p, f'"{term}" site:{d}', d, None) for p, d in PLATFORMS.items()]
        probes.append(("reddit + recency filter", f'"{term}" site:reddit.com', "reddit.com", cfg["recency"]))
        for target, q, domain, extra in probes:
            if not control_ok:
                # The engine is not answering us at all; five more requests would only add load.
                rows.append(_row("discovery", name, target, None, "blocked", note="engine control query failed; not sent", robots=robots))
                continue
            res = client.get(url(q, extra))
            why = _blocked(res)
            found = [] if why else _hits(res["body"], domain)
            verdict = "blocked" if why else ("ok" if found else "no_results")
            if verdict == "no_results" and re.search(r"there are no results|no results found", res["body"], re.I):
                why = "the engine itself says there are no results"
            rows.append(_row("discovery", name, target, res, verdict,
                             f"{len(found)} {domain} links" + (f", e.g. {found[0][:70]}" if found else ""), why, robots))
    return rows


def probe_ddgs_library(term: str) -> list[dict]:
    """The path the app uses today. It presents itself as a browser, which the direct probes do not."""
    rows = []
    try:
        from ddgs import DDGS
    except ImportError:
        return [_row("discovery", "ddgs library (current app path)", "all", None, "error", note="ddgs is not installed")]
    for platform, domain in PLATFORMS.items():
        t0 = time.monotonic()
        try:
            got = DDGS().text(f'"{term}" site:{domain}', max_results=10)
            found = [r for r in got if domain in (urlsplit(r.get("href", "")).hostname or "")]
            verdict, note = ("ok" if found else "no_results"), ""
            fields = f"{len(found)} links; title+snippet {'present' if found and found[0].get('body') else 'absent'}"
        except Exception as exc:                                   # noqa: BLE001
            verdict, note, fields = "blocked", f"{type(exc).__name__}: {exc}"[:140], ""
        rows.append({"group": "discovery", "source": "ddgs library (current app path)", "target": platform, "http": None,
                     "ms": int((time.monotonic() - t0) * 1000), "verdict": verdict, "fields": fields, "note": note,
                     "robots": "n/a (library, browser-like client)"})
        time.sleep(1.0)
    return rows


def probe_reddit(client: _Client, term: str) -> list[dict]:
    rows, permalink = [], ""
    for name, template in REDDIT.items():
        url = template.replace("%7Bterm%7D", term).replace("{term}", term)
        res = client.get(url)
        why = _blocked(res)
        fields, verdict = "", "blocked" if why else "error"
        if not why and "json" in name:
            try:
                children = json.loads(res["body"])["data"]["children"]
                if children:
                    first = children[0]["data"]
                    have = [f for f in REDDIT_FIELDS if first.get(f) not in (None, "")]
                    permalink = permalink or first.get("permalink", "")
                    fields, verdict = f"{len(children)} posts; fields: {', '.join(have)}", "ok"
                else:
                    verdict = "no_results"
            except (ValueError, KeyError, TypeError):
                why = "200 but the body was not the expected JSON listing"
        elif not why:
            entries = re.findall(r"<entry>(.*?)</entry>", res["body"], re.S)
            if entries:
                have = [t for t in ("title", "author", "updated", "link", "content") if f"<{t}" in entries[0]]
                fields, verdict = f"{len(entries)} entries; fields: {', '.join(have)}", "ok"
            elif "<feed" in res["body"]:
                verdict = "no_results"
            else:
                why = "200 but the body was not an Atom feed"
        rows.append(_row("discovery + enrichment", f"reddit {name}", term if "search" in name else "r/Kenya", res, verdict, fields, why))
    if permalink:
        res = client.get(f"https://www.reddit.com{permalink.rstrip('/')}.json?limit=1")
        why = _blocked(res)
        ok = False
        if not why:
            try:
                post = json.loads(res["body"])[0]["data"]["children"][0]["data"]
                have = [f for f in REDDIT_FIELDS if post.get(f) not in (None, "")]
                ok = True
            except (ValueError, KeyError, TypeError, IndexError):
                why = "200 but not a post listing"
        rows.append(_row("enrichment", "reddit permalink.json", "one post", res, "ok" if ok else "blocked",
                         f"fields: {', '.join(have)}" if ok else "", why))
    else:
        rows.append(_row("enrichment", "reddit permalink.json", "one post", None, "not_tested",
                         note="no listing endpoint returned a post to follow"))
    return rows


def probe_oembed(client: _Client) -> list[dict]:
    rows = []
    for name, url in OEMBED.items():
        res = client.get(url)
        why = _blocked(res)
        fields, verdict = "", "blocked"
        if not why:
            try:
                data = json.loads(res["body"])
                have = [f for f in OEMBED_FIELDS if data.get(f)]
                text = re.sub(r"<[^>]+>", " ", str(data.get("html") or "")).strip()
                # An embed with no author and no words is a player widget, not post details.
                useful = bool(data.get("author_name") or data.get("title") or len(text) > 40)
                fields = f"fields: {', '.join(have)}" + ("; post text is inside html" if len(text) > 40 else "")
                verdict = "ok" if useful else "partial"
                why = "" if useful else "answers, but with no author, title or text: only an embed player"
            except ValueError:
                why = "200 but not JSON"
        rows.append(_row("enrichment", name, "one public post", res, verdict, fields, why))
    return rows


def run_matrix(term: str = "Fuliza", transport=None, pace: float = PACE, library: bool = True,
               engine_pace: float = ENGINE_PACE) -> dict:
    started = datetime.now(timezone.utc)
    client = _Client(transport, pace, engine_pace)
    try:
        rows = probe_engines(client, term)
        rows += probe_ddgs_library(term) if library else []
        rows += probe_reddit(client, term)
        rows += probe_oembed(client)
    finally:
        client.close()
    return {"environment": _environment(), "term": term, "user_agent": USER_AGENT,
            "started_at": started.isoformat(timespec="seconds"),
            "seconds": int((datetime.now(timezone.utc) - started).total_seconds()),
            "rows": rows, "excluded": EXCLUDED}


def to_markdown(result: dict) -> str:
    env = result["environment"]
    lines = [f"### Run from: {env['where']}" + (f" ({env['service']} {env['region']})".rstrip(" ()") if env["service"] else ""), "",
             f"- When: {result['started_at']} ({result['seconds']}s)",
             f"- Test term: `{result['term']}`",
             f"- Client: `{result['user_agent']}` — honest identifier, no browser disguise, no proxy, no retries",
             "- Verdicts: `ok` real results came back; `no_results` answered but found nothing; "
             "`partial` answered without the fields that matter; `blocked` refused, challenged, walled, or "
             "silently empty; `not_tested` nothing to test with", ""]
    for group in dict.fromkeys(r["group"] for r in result["rows"]):
        lines += [f"#### {group.capitalize()}", "", "| Source | Target | HTTP | Verdict | What came back | Why / note | robots.txt |",
                  "|---|---|---|---|---|---|---|"]
        for r in (x for x in result["rows"] if x["group"] == group):
            lines.append("| " + " | ".join(str(v if v not in (None, "") else "—").replace("|", "\\|") for v in (
                r["source"], r["target"], r["http"], f"**{r['verdict']}**", r["fields"], r["note"], r["robots"])) + " |")
        lines.append("")
    lines += ["#### Not probed (excluded by policy, not by test)", ""]
    lines += [f"- **{platform}**: {what}" for platform, what in result["excluded"]]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--term", default="Fuliza")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = run_matrix(args.term)
    print(json.dumps(result, indent=1) if args.json else to_markdown(result))


if __name__ == "__main__":
    main()
