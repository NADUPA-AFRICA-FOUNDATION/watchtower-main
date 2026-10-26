"""End-to-end sweep test with mocked HTTP.

Runs the real sweep pipeline — every backend parser, dedupe, concurrent body
fetching, keyword ranking, diversification, both renderers — against realistic
canned responses injected through httpx's transport layer. Nothing is stubbed
out inside the code under test; only the network is replaced.

    python sweep_test.py
"""

import json
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent))

from core import report
from core.fetch import Fetcher
from core.sources import (SourceError, SourceSkipped, gdelt,
                          opensanctions, socialcrawl, wikipedia)
from core.sweep import _diversify, _keyword_score, _terms, sweep
from core.models import Item

QUERY = "beneficial ownership Kenya"

ARTICLE_HTML = """<html><head><title>Regulator tightens beneficial ownership rules</title></head>
<body><nav><a href="/">Home</a></nav><article><h1>Regulator tightens beneficial
ownership rules</h1><p>The Central Bank of Kenya has published revised guidance
requiring banks in Kenya to verify beneficial ownership of corporate customers
before onboarding. The guidance follows a review of correspondent banking
controls.</p><p>Institutions have ninety days to comply.</p></article>
<footer>Subscribe now!</footer></body></html>"""

IRRELEVANT_HTML = """<html><head><title>Nairobi derby ends level</title></head>
<body><article><p>The Nairobi derby finished one-all on Saturday after a late
equaliser.</p></article></body></html>"""

GDELT_JSON = {"articles": [
    {"url": "https://outlet-a.co.ke/story/1", "title": "Regulator tightens beneficial ownership rules",
     "seendate": "20260810T090000Z", "domain": "outlet-a.co.ke",
     "sourcecountry": "Kenya", "language": "English"},
    # Same story, different outlet — must collapse on content hash after fetch.
    {"url": "https://outlet-b.com/wire/9", "title": "Regulator tightens beneficial ownership rules",
     "seendate": "20260810T093000Z", "domain": "outlet-b.com",
     "sourcecountry": "United States", "language": "English"},
    {"url": "https://outlet-a.co.ke/sport/5", "title": "Nairobi derby ends level",
     "seendate": "20260810T100000Z", "domain": "outlet-a.co.ke",
     "sourcecountry": "Kenya", "language": "English"},
    {"url": "https://outlet-a.co.ke/story/2", "title": "Bank fined over ownership checks",
     "seendate": "20260809T080000Z", "domain": "outlet-a.co.ke",
     "sourcecountry": "Kenya", "language": "English"},
    {"url": "https://outlet-a.co.ke/story/3", "title": "Ownership registry consultation opens",
     "seendate": "20260809T070000Z", "domain": "outlet-a.co.ke",
     "sourcecountry": "Kenya", "language": "English"},
]}

GNEWS_RSS = """<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Kenya publishes beneficial ownership register rules</title>
<link>https://outlet-c.co.ke/news/44</link>
<pubDate>Mon, 10 Aug 2026 07:00:00 GMT</pubDate>
<description>&lt;p&gt;New rules require disclosure of beneficial ownership.&lt;/p&gt;</description>
</item></channel></rss>"""

WIKI_JSON = {"query": {"search": [
    {"title": "Beneficial ownership", "timestamp": "2026-06-01T00:00:00Z",
     "snippet": "A <span>beneficial owner</span> is the natural person who ultimately owns or controls a legal entity."}]}}

HN_JSON = {"hits": [
    {"objectID": "111", "title": "Ownership transparency tooling", "url": "https://hnlink.io/x",
     "author": "someone", "created_at": "2026-08-09T12:00:00Z", "points": 40,
     "num_comments": 12, "story_text": "Discussion of beneficial ownership registries."}]}

MASTODON_JSON = {"statuses": [
    {"url": "https://mastodon.social/@x/1", "uri": "https://mastodon.social/@x/1",
     "content": "<p>Kenya's beneficial ownership register just went live.</p>",
     "created_at": "2026-08-10T11:00:00Z", "reblogs_count": 3, "favourites_count": 9,
     "account": {"acct": "x"}}]}


BLUESKY_JSON = {"posts": [
    {"uri": "at://did:plc:abc/app.bsky.feed.post/3kxyz",
     "author": {"handle": "openkenya.bsky.social"},
     "record": {"text": "Kenya beneficial ownership register goes live",
                "createdAt": "2026-08-12T10:00:00Z"},
     "likeCount": 4, "repostCount": 2}]}

GLEIF_JSON = {"data": [
    {"id": "5493001KJTIIGC8Y1R12",
     "attributes": {"lei": "5493001KJTIIGC8Y1R12",
                    "entity": {"legalName": {"name": "EXAMPLE HOLDINGS PLC"},
                               "legalAddress": {"country": "KE",
                                                "addressLines": ["Nairobi"]},
                               "status": "ACTIVE"},
                    "registration": {"lastUpdateDate": "2026-07-01T00:00:00Z"}}}]}

BRAVE_JSON = {"web": {"results": [
    {"title": "Beneficial ownership register rules",
     "url": "https://regulator.example.vercel.app/rules",
     "description": "New disclosure thresholds for trusts.",
     "page_age": "2026-08-12", "meta_url": {"hostname": "regulator.example.vercel.app"}}]}}

SOCIALCRAWL_JSON = {
    "success": True, "credits_used": 20, "credits_remaining": 80,
    "request_id": "req_test", "cached": False,
    "data": {"items": [{
        "id": "post-1", "platform": "tiktok",
        "url": "https://www.tiktok.com/@fraudwatch/video/1",
        "text": "Beneficial ownership scam targeting Kenya businesses",
        "author": {"username": "fraudwatch"},
        "engagement": {"likes": 12, "comments": 3},
        "computed": {"language": "en"},
        "created_at": "2026-08-12T10:00:00Z",
    }]},
}


def handler(request: httpx.Request) -> httpx.Response:
    u = str(request.url)
    if "robots.txt" in u:
        return httpx.Response(200, text="User-agent: *\nAllow: /\n")
    if "gdeltproject.org" in u:
        return httpx.Response(200, json=GDELT_JSON)
    if "news.google.com" in u:
        return httpx.Response(200, text=GNEWS_RSS)
    if "wikipedia.org" in u:
        return httpx.Response(200, json=WIKI_JSON)
    if "hn.algolia.com" in u:
        return httpx.Response(200, json=HN_JSON)
    if "mastodon.social/api" in u:
        return httpx.Response(200, json=MASTODON_JSON)
    if "createSession" in u:
        return httpx.Response(200, json={"accessJwt": "test-jwt"})
    if "bsky.app" in u:
        return httpx.Response(200, json=BLUESKY_JSON)
    if "api.gleif.org" in u:
        # GLEIF uses the JSON:API vendor type in production. The fetch layer
        # must decode vendor +json media types, not mistake them for binary.
        return httpx.Response(
            200, json=GLEIF_JSON,
            headers={"Content-Type": "application/vnd.api+json"},
        )
    if "api.search.brave.com" in u:
        return httpx.Response(200, json=BRAVE_JSON)
    if "socialcrawl.dev/v1/search/everywhere" in u:
        return httpx.Response(200, json=SOCIALCRAWL_JSON)
    if "/sport/" in u:
        return httpx.Response(200, text=IRRELEVANT_HTML)
    if "outlet-b.com" in u or "outlet-a.co.ke" in u or "outlet-c.co.ke" in u:
        return httpx.Response(200, text=ARTICLE_HTML)
    if "unreachable" in u:
        return httpx.Response(503, text="")
    return httpx.Response(404, text="")


def check(label, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")
    return bool(cond)


def main():
    ok = True
    # fetch.py's retry backoff is real (5s then 10s on a 429) and several checks below drive a 429 on
    # purpose. Give the fetch module its own `time` so those waits cost nothing; the one check that
    # asserts what the wait *is* captures it explicitly, and the sweep-budget check below keeps the
    # real clock because it patches nothing here.
    import types as _types
    import core.fetch as _fm
    # social_web_index is a default backend but searches DuckDuckGo through its own client, which
    # httpx.MockTransport cannot intercept. Left alone, every default sweep here goes to the real
    # network and waits on real pacing. Its behaviour is covered offline in tests/test_socialcrawl.py.
    import core.sources as _src
    _src.BACKENDS["social_web_index"] = lambda query, fetcher, hours=72, limit=20: []
    _fm.time = _types.SimpleNamespace(sleep=lambda seconds: None, monotonic=time.monotonic, time=time.time)
    fetcher = Fetcher("watchtower-test/0.1 (test@example.com)", delay=0.0,
                      transport=httpx.MockTransport(handler))

    print("\nquery parsing")
    terms = _terms(QUERY)
    ok &= check("drops stopwords, keeps content words",
                terms == ["beneficial", "ownership", "kenya"])

    print("\nkeyword scoring")
    hit = Item(url="u", source="s", source_type="news",
               title="Beneficial ownership in Kenya",
               text="beneficial ownership rules in Kenya " * 3)
    miss = Item(url="u2", source="s", source_type="news",
                title="Football result", text="A match ended one all.")
    ok &= check("relevant scores high", _keyword_score(hit, terms) >= 60)
    ok &= check("irrelevant scores zero", _keyword_score(miss, terms) == 0)
    ok &= check("relevant outranks irrelevant",
                _keyword_score(hit, terms) > _keyword_score(miss, terms))

    print("\nscoring: corroboration, source tier, headline penalty")
    from core.sweep import _adjust, _headline_only

    def mk(stype, text="beneficial ownership Kenya rules " * 20, **meta):
        return Item(url="https://x.example/1", source="s", source_type=stype,
                    title="Beneficial ownership Kenya", text=text,
                    raw_meta={"corroboration": 1, **meta})

    news = mk("news")
    ok &= check("a lone news item is scored as-is",
                _adjust(50, news) == 50)
    ok &= check("five outlets carrying it outranks one",
                _adjust(50, mk("news", corroboration=5)) > _adjust(50, news))
    ok &= check("corroboration is capped, not unbounded",
                _adjust(50, mk("news", corroboration=99))
                == _adjust(50, mk("news", corroboration=4)))
    ok &= check("a regulator outranks a news item at equal relevance",
                _adjust(50, mk("regulatory")) > _adjust(50, news))
    ok &= check("a social post ranks below a news item",
                _adjust(50, mk("social")) < _adjust(50, news))
    ok &= check("a sanctions listing outranks everything at equal relevance",
                _adjust(50, mk("watchlist")) > _adjust(50, mk("regulatory")))

    bare = mk("news", text="short")
    ok &= check("a bodyless item is recognised as headline-only",
                _headline_only(bare))
    ok &= check("a headline alone cannot reach the HIGH band",
                _adjust(95, mk("news", text="short")) < 80)
    ok &= check("and is flagged for the UI",
                mk("news", text="short").raw_meta.get("corroboration") == 1
                and (_adjust(95, bare) or True)
                and bare.raw_meta.get("headline_only") is True)
    ok &= check("a read article is not penalised", not _headline_only(news))
    ok &= check("scores stay inside 0-100",
                0 <= _adjust(99, mk("watchlist", corroboration=9)) <= 100)

    print("\ndiversification")
    many = [Item(url=f"https://same.com/{i}", source="s", source_type="news",
                 raw_meta={"domain": "same.com"}) for i in range(5)]
    other = Item(url="https://other.com/1", source="s", source_type="news",
                 raw_meta={"domain": "other.com"})
    div = _diversify(many + [other], cap_per_domain=3)
    ok &= check("one domain can't hold more than the cap up top",
                div[3].raw_meta["domain"] == "other.com")
    ok &= check("nothing is discarded", len(div) == 6)

    print("\nfull sweep (mocked network, no API key)")
    res = sweep(QUERY, fetcher, hours=72, limit=20, fetch_bodies=True,
                backends=["gdelt", "google_news", "wikipedia", "hackernews",
                          "mastodon", "opensanctions"],
                enricher=None,
                progress=lambda e: (lambda l: print("   " + l) if l else None)(
                    report.progress_line(e)))

    ok &= check("every backend returned", len(res.per_source) == 6)
    ok &= check("gdelt parsed", res.per_source["gdelt"] == 5)
    ok &= check("google news parsed", res.per_source["google_news"] == 1)
    ok &= check("wikipedia parsed", res.per_source["wikipedia"] == 1)
    ok &= check("hackernews parsed", res.per_source["hackernews"] == 1)
    ok &= check("mastodon parsed", res.per_source["mastodon"] == 1)
    ok &= check("opensanctions skipped without key",
                res.per_source["opensanctions"] == 0)
    ok &= check("no errors", not res.errors)

    urls = [i.url for i in res.items]
    ok &= check("syndicated duplicate collapsed",
                not ("https://outlet-a.co.ke/story/1" in urls
                     and "https://outlet-b.com/wire/9" in urls))
    ok &= check("bodies were fetched and cleaned",
                any("ninety days to comply" in i.text for i in res.items))
    ok &= check("nav and footer stripped",
                all("Subscribe now" not in i.text for i in res.items))

    top = res.items[0]
    sport = next((i for i in res.items if "derby" in i.title.lower()), None)
    ok &= check("relevant result ranks first", top.relevance >= 60)
    ok &= check("irrelevant result ranks last",
                sport is not None and sport.relevance < top.relevance)
    ok &= check("results are sorted by score",
                all(res.items[i].relevance >= res.items[i + 1].relevance
                    for i in range(len(res.items) - 1)))
    ok &= check("enriched flag off without a key", res.enriched is False)

    print("\nrendering")
    term = report.terminal(res, top=5)
    ok &= check("terminal shows the query", QUERY in term)
    ok &= check("terminal flags keyword-only mode", "keyword ranking only" in term)
    ok &= check("bands render", "HIGH" in term or "MED" in term)

    md = report.markdown(res)
    ok &= check("markdown has a heading", md.startswith("# Sweep:"))
    ok &= check("markdown lists every finding",
                md.count("### ") >= len(res.items) - 1)
    ok &= check("markdown opens with an executive summary",
                "## Executive summary" in md)
    ok &= check("markdown carries a readable coverage table",
                "| Source | Status | Hits | Detail |" in md)
    ok &= check("markdown carries a priority findings table",
                "| Score | Finding | Source | Published |" in md)

    out = report.save(res, "out_test")
    ok &= check("report file written", out.exists() and out.stat().st_size > 400)
    out.unlink()
    out.with_suffix(".html").unlink(missing_ok=True)
    out.parent.rmdir()

    print("\nper-domain rate limiting under concurrency")
    # The parallel fan-out in sweep.py assumes _throttle holds under threads.
    # Assert it rather than trusting it: 8 threads onto one domain with a 50ms
    # delay must serialise to >=350ms of gaps, and no two hits may coincide.
    import threading as _th
    rl = Fetcher("watchtower-test/0.1", delay=0.05,
                 transport=httpx.MockTransport(handler))
    stamps, slock = [], _th.Lock()

    def hammer():
        rl._throttle("same-host.example")
        with slock:
            stamps.append(time.monotonic())

    threads = [_th.Thread(target=hammer) for _ in range(8)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    span = time.monotonic() - t0
    gaps = [b - a for a, b in zip(sorted(stamps), sorted(stamps)[1:])]
    ok &= check("concurrent hits on one domain are serialised", span >= 0.35)
    ok &= check("no two threads pass the throttle together",
                all(g >= 0.04 for g in gaps))
    rl.close()

    print("\nbacking off properly on 429")
    # GDELT states "one request every 5 seconds" in its 429 body and sends no
    # Retry-After. Retrying at 1s then 2s burned every attempt and reported a
    # throttled source as a dead one.
    from core.fetch import RATE_LIMIT_FLOOR
    waits = []
    real_sleep = time.sleep

    def capture(seconds):
        waits.append(seconds)          # record, don't actually wait

    attempts = {"n": 0}

    def throttler(request: httpx.Request) -> httpx.Response:
        if "robots.txt" in str(request.url):
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        attempts["n"] += 1
        if attempts["n"] < 3:
            return httpx.Response(429, text="Please limit requests to one every 5 seconds")
        return httpx.Response(200, json=GDELT_JSON)

    tf = Fetcher("watchtower-test/0.1", delay=0.0,
                 transport=httpx.MockTransport(throttler))
    import core.fetch as _fetchmod
    _fetchmod.time.sleep = capture
    try:
        got = tf.get("https://api.gdeltproject.org/api/v2/doc/doc?x=1", api=True)
    finally:
        _fetchmod.time.sleep = lambda seconds: None
    ok &= check("a throttled source is retried, not written off", got.ok)
    ok &= check("the first 429 waits at least as long as the host asked",
                waits and waits[0] >= RATE_LIMIT_FLOOR)
    ok &= check("and backs off further on the second", len(waits) > 1
                and waits[1] > waits[0])
    tf.close()

    print("\nAPI calls are not treated as crawling")
    # robots.txt for the Wikipedia API disallows /w/ — the endpoint Wikipedia
    # publishes for this purpose. Crawling must still obey it.
    blocking = httpx.MockTransport(lambda r: (
        httpx.Response(200, text="User-agent: *\nDisallow: /w/\nDisallow: /api/\n")
        if "robots.txt" in str(r.url)
        else httpx.Response(200, json=WIKI_JSON)))
    rf = Fetcher("watchtower-test/0.1", delay=0.0, transport=blocking)
    ok &= check("a declared API endpoint is fetched despite robots.txt",
                rf.get("https://en.wikipedia.org/w/api.php?x=1", api=True).ok)
    ok &= check("crawling the same path still obeys robots.txt",
                not rf.get("https://en.wikipedia.org/w/api.php?x=1").ok)
    ok &= check("and the refusal says why",
                "robots" in rf.get("https://en.wikipedia.org/w/index.php").error)
    ok &= check("wikipedia backend now returns hits through robots.txt",
                len(wikipedia(QUERY, rf, limit=3)) == 1)
    rf.close()

    print("\nblocked is not the same as empty")
    dead = httpx.MockTransport(lambda r: (
        httpx.Response(200, text="User-agent: *\nAllow: /\n")
        if "robots.txt" in str(r.url) else httpx.Response(429, text="slow down")))
    df = Fetcher("watchtower-test/0.1", delay=0.0, transport=dead)
    try:
        gdelt(QUERY, df, hours=24, limit=5)
        ok &= check("a rate-limited source raises instead of returning []", False)
    except SourceError as e:
        ok &= check("a rate-limited source raises instead of returning []", True)
        ok &= check("and carries the real reason", "429" in str(e))
    try:
        opensanctions(QUERY, df)
        ok &= check("an unconfigured source reports as unsearched", False)
    except SourceSkipped as e:
        ok &= check("an unconfigured source reports as unsearched",
                    "OPENSANCTIONS_API_KEY" in str(e))

    broke = sweep(QUERY, df, hours=24, backends=["gdelt", "opensanctions"],
                  fetch_bodies=False)
    ok &= check("sweep separates failure from a genuine zero",
                broke.failed and "gdelt" in broke.failed)
    ok &= check("sweep separates unsearched from a genuine zero",
                "opensanctions" in broke.skipped)
    ok &= check("an incomplete sweep knows it is incomplete", not broke.complete)
    ok &= check("the empty report refuses to claim nothing was found",
                "INCOMPLETE" in report.terminal(broke))
    df.close()

    print("\nsweep time budget (serverless hosts kill long requests)")
    import core.sweep as SW
    slow_backends = dict(SW.BACKENDS)

    def crawler(query, fetcher, hours=72, limit=40):
        time.sleep(2.0)
        return [Item(url="https://slow.example/1", source="slow",
                     source_type="news", title="too late")]

    def quick(query, fetcher, hours=72, limit=40):
        return [Item(url="https://quick.example/1", source="quick",
                     source_type="news", title="beneficial ownership Kenya")]

    SW.BACKENDS = {"quick": quick, "slow": crawler}
    try:
        t0 = time.monotonic()
        budgeted = sweep(QUERY, fetcher, backends=["quick", "slow"],
                         fetch_bodies=False, budget=0.5)
        elapsed = time.monotonic() - t0
        ok &= check("a sweep returns within its budget", elapsed < 1.5)
        ok &= check("the source that ran is kept",
                    budgeted.per_source.get("quick") == 1)
        ok &= check("the source that ran out of time is marked unsearched",
                    "slow" in budgeted.skipped)
        ok &= check("running out of time is not reported as a zero",
                    not budgeted.complete)
        ok &= check("no budget means no deadline",
                    sweep(QUERY, fetcher, backends=["quick"],
                          fetch_bodies=False).complete)
    finally:
        SW.BACKENDS = slow_backends

    print("\nscoring failure must not masquerade as a scored run")
    # Reproduces a real incident: a depleted Anthropic balance returns 400 on
    # every call. The old code retried it once per candidate and then set
    # enriched=True regardless, so a keyword ranking was presented as though
    # Claude had scored it.
    class Billing400(Exception):
        status_code = 400

        def __str__(self):
            return ("Error code: 400 - your credit balance is too low to "
                    "access the Anthropic API")

    class BrokeEnricher:
        def __init__(self):
            self.enabled = True
            self.escalate_above = 60
            self.calls = 0
            self.fatal_error = None

        def enrich(self, title, text, focus=""):
            self.calls += 1
            from core.enrich import _fatal_reason
            e = Billing400()
            reason = _fatal_reason(e)
            self.enabled = False
            self.fatal_error = reason
            return {"summary": "", "entities": [], "categories": [],
                    "relevance": 0, "skipped": reason, "fatal": True}

    broke_ai = BrokeEnricher()
    billed = sweep(QUERY, fetcher, hours=72, limit=20, fetch_bodies=False,
                   enricher=broke_ai, max_enrich=25)
    ok &= check("a doomed API call is not retried for every candidate",
                broke_ai.calls == 1)
    ok &= check("the run is not labelled as model-scored",
                billed.enriched is False)
    ok &= check("the real reason is recorded once",
                "credit balance" in billed.scoring_error.lower())
    ok &= check("and reported exactly once, not per item",
                sum("credit balance" in e.lower() for e in billed.errors) == 1)
    ok &= check("results still come back, ranked by keyword",
                len(billed.items) > 0)
    ok &= check("the terminal report names the real reason, not 'no API key'",
                "credit balance" in report.terminal(billed).lower())

    from core.enrich import _fatal_reason as _fr
    ok &= check("a rejected key is fatal too",
                _fr(type("E", (Exception,), {"status_code": 401})()) is not None)
    ok &= check("a rate limit is NOT fatal — worth continuing past",
                _fr(type("E", (Exception,), {"status_code": 429})()) is None)

    print("\nnew backends")
    from core.sources import (BACKENDS, DEFAULT_BACKENDS, bluesky as bsky_fn,
                              gleif as gleif_fn, opencorporates as oc_fn,
                              reddit as reddit_fn, web_search as ws_fn,
                              x_twitter as x_fn)

    _os_b = __import__("os")
    _os_b.environ["BLUESKY_HANDLE"] = "tester.bsky.social"
    _os_b.environ["BLUESKY_APP_PASSWORD"] = "test-app-password"
    try:
        posts = bsky_fn(QUERY, fetcher, limit=5)
    finally:
        _os_b.environ.pop("BLUESKY_HANDLE", None)
        _os_b.environ.pop("BLUESKY_APP_PASSWORD", None)
    ok &= check("bluesky parses public post search", len(posts) == 1)
    ok &= check("and builds a reachable post URL",
                posts[0].url ==
                "https://bsky.app/profile/openkenya.bsky.social/post/3kxyz")

    leis = gleif_fn(QUERY, fetcher, limit=5)
    ok &= check("gleif parses LEI records", len(leis) == 1)
    ok &= check("and carries the LEI itself",
                leis[0].raw_meta["lei"] == "5493001KJTIIGC8Y1R12")

    import os as _os
    _os.environ["BRAVE_API_KEY"] = "test-key"
    try:
        web = ws_fn(QUERY, fetcher, limit=5)
        ok &= check("web search reaches an arbitrary domain",
                    web[0].url.endswith("example.vercel.app/rules"))
    finally:
        _os.environ.pop("BRAVE_API_KEY", None)

    # Every key-gated backend must skip, never return a misleading zero.
    for fn, label in ((ws_fn, "web_search"), (oc_fn, "opencorporates"),
                      (reddit_fn, "reddit"), (x_fn, "x"), (bsky_fn, "bluesky")):
        try:
            fn(QUERY, fetcher, limit=5)
            ok &= check(f"{label} reports as unsearched without its key", False)
        except SourceSkipped:
            ok &= check(f"{label} reports as unsearched without its key", True)
        except Exception as e:
            ok &= check(f"{label} reports as unsearched without its key "
                        f"(got {type(e).__name__})", False)

    ok &= check("every registered backend is callable",
                all(callable(f) for f in BACKENDS.values()))
    ok &= check("every default is registered",
                all(b in BACKENDS for b in DEFAULT_BACKENDS))
    ok &= check("no scraped platform crept into the registry",
                not ({"tiktok", "instagram", "linkedin", "facebook", "threads"}
                     & set(BACKENDS)))
    ok &= check("X is present only as the official API",
                BACKENDS["x"].__doc__ and "official" in BACKENDS["x"].__doc__)

    print("\ncredentials must not leak between concurrent backends")
    seen_headers = []

    def spy(request: httpx.Request) -> httpx.Response:
        seen_headers.append((str(request.url), request.headers.get("authorization")))
        return handler(request)

    spy_fetcher = Fetcher("watchtower-test/0.1", delay=0.0,
                          transport=httpx.MockTransport(spy))
    _os.environ["OPENSANCTIONS_API_KEY"] = "secret-sanctions-key"
    try:
        sweep(QUERY, spy_fetcher, hours=72, fetch_bodies=False,
              backends=["opensanctions", "gdelt", "wikipedia", "bluesky"])
    finally:
        _os.environ.pop("OPENSANCTIONS_API_KEY", None)
    leaked = [u for u, auth in seen_headers
              if auth and "opensanctions.org" not in u]
    ok &= check("the sanctions key is sent to opensanctions only", not leaked)
    spy_fetcher.close()

    print("\nfailure handling")
    bad = sweep("nothing matches here", fetcher, hours=24,
                backends=["gdelt", "nonexistent_backend"], fetch_bodies=False)
    ok &= check("unknown backend recorded, doesn't crash",
                any("unknown backend" in e for e in bad.errors))
    ok &= check("empty result renders a helpful message",
                "Nothing found" in report.terminal(
                    type(bad)(query="zzz", items=[])))

    fetcher.close()
    print("\n" + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED"))

    if "--show" in sys.argv:
        print("\n" + "=" * 70)
        print("Sample output (from the mocked fixtures above):")
        print("=" * 70)
        print(term)
    else:
        print("\n(run with --show to see the rendered report)\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
