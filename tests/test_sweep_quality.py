"""Sweep hit quality: Google News attribution, social-index matching, default
sources, and keyword matching. Offline; MockTransport and a patched index."""
from __future__ import annotations

import httpx

from core.fetch import Fetcher
from core.models import Item
from core.sources import (BACKENDS, DEFAULT_BACKENDS, _required_terms, google_news,
                          is_google_news_link, social_web_index)
from core.sweep import _keyword_score, _terms, sweep

TOKEN = "CBMitAlBVV95cUxPcjhsb0hm"

# Shaped like a live response (checked 2026-11-10): the link is a redirect
# token, the description is the headline again plus the outlet, and <source>
# names the outlet's home page.
GNEWS_RSS = f"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>CBK warns of “M-Pesa” loan apps - The Star</title>
<link>https://news.google.com/rss/articles/{TOKEN}1?oc=5</link>
<pubDate>Mon, 09 Nov 2026 07:00:00 GMT</pubDate>
<description>&lt;a href="https://news.google.com/rss/articles/{TOKEN}1?oc=5"&gt;CBK warns of “M-Pesa” loan apps&lt;/a&gt;&amp;nbsp;&amp;nbsp;&lt;font color="#6f6f6f"&gt;The Star&lt;/font&gt;</description>
<source url="https://www.the-star.co.ke">The Star</source></item>
<item><title>Speaker takes plea in Sacco fraud case and two others appeared before the - Facebook</title>
<link>https://news.google.com/rss/articles/{TOKEN}2?oc=5</link>
<description>&lt;a href="x"&gt;Speaker takes plea in Sacco fraud case and two others&lt;/a&gt;&amp;nbsp;&amp;nbsp;&lt;font color="#6f6f6f"&gt;Facebook&lt;/font&gt;</description>
<source url="https://www.facebook.com">Facebook</source></item>
<item><title>M-Pesa fraud ring charged - Nation</title>
<link>https://news.google.com/rss/articles/{TOKEN}3?oc=5</link>
<description>&lt;ol&gt;&lt;li&gt;&lt;a href="a"&gt;One&lt;/a&gt;&lt;/li&gt;&lt;li&gt;&lt;a href="b"&gt;Two&lt;/a&gt;&lt;/li&gt;&lt;/ol&gt;</description>
<source url="https://nation.africa">Nation</source></item>
<item><title>Paybill scam warning - Business Daily</title>
<link>https://news.google.com/rss/articles/{TOKEN}4?oc=5</link>
<description>&lt;a href="x"&gt;Paybill scam warning&lt;/a&gt;&amp;nbsp;&amp;nbsp;&lt;font color="#6f6f6f"&gt;Business Daily&lt;/font&gt;</description>
<source url="https://www.businessdailyafrica.com">Business Daily</source></item>
</channel></rss>"""

# The same Star story under its real URL, with plain quotes instead of curly.
GDELT_JSON = {"articles": [
    {"url": "https://www.the-star.co.ke/news/2026-11-09-cbk-warns", "title": 'CBK warns of "M-Pesa" loan apps',
     "seendate": "20261109T070000Z", "domain": "the-star.co.ke", "language": "English",
     "sourcecountry": "Kenya"}]}

ARTICLE = ("<html><head><title>CBK warns</title></head><body><article><h1>CBK warns of M-Pesa loan apps</h1>"
           + "".join(f"<p>Paragraph {n}: the Central Bank of Kenya said unlicensed digital lenders are "
                     f"using M-Pesa paybills to collect fees from borrowers who never receive a loan, "
                     f"case {n * 17}.</p>" for n in range(1, 7))   # distinct: trafilatura drops repeats
           + "</article></body></html>")

GOOGLE_ROBOTS = "User-agent: *\nDisallow: /\nAllow: /$\nAllow: /topics/\n"


def _handler(seen: list):
    def handle(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        seen.append(u)
        if u.endswith("/robots.txt"):
            return httpx.Response(200, text=GOOGLE_ROBOTS if "news.google.com" in u else "User-agent: *\nAllow: /\n")
        if "news.google.com/rss/search" in u:
            return httpx.Response(200, text=GNEWS_RSS)
        if "gdeltproject.org" in u:
            return httpx.Response(200, json=GDELT_JSON)
        if "the-star.co.ke/news/" in u:
            return httpx.Response(200, text=ARTICLE)
        return httpx.Response(404)
    return handle


def _fetcher(seen=None) -> Fetcher:
    return Fetcher("watchtower-test/0.1", delay=0,
                   transport=httpx.MockTransport(_handler(seen if seen is not None else [])))


# ------------------------------------------------------------- Google News

def test_google_news_attributes_items_to_the_outlet_not_to_google():
    items = {i.raw_meta["outlet"]: i for i in google_news("M-Pesa fraud", _fetcher())}
    star = items["The Star"]
    assert star.title == "CBK warns of “M-Pesa” loan apps"          # " - The Star" stripped
    assert star.text == ""                                           # description was only the headline
    assert star.raw_meta["domain"] == "the-star.co.ke"
    assert star.raw_meta["link_unresolved"] is True
    assert star.source_type == "news"
    assert len({i.raw_meta["domain"] for i in items.values()}) == 4   # four outlets, not one google


def test_google_news_facebook_posts_are_social_and_clusters_are_not_body_text():
    items = {i.raw_meta["outlet"]: i for i in google_news("M-Pesa fraud", _fetcher())}
    fb = items["Facebook"]
    assert fb.source_type == "social" and fb.raw_meta["social_post"] is True
    assert fb.text == ""                                  # truncated headline is still the headline
    nation = items["Nation"]
    assert nation.text == "" and nation.raw_meta["related_headlines"] == 2


def test_google_news_keeps_a_description_that_adds_something():
    rss = """<?xml version="1.0"?><rss version="2.0"><channel><item><title>Rules published</title>
<link>https://outlet.co.ke/a</link><description>&lt;p&gt;New rules require disclosure.&lt;/p&gt;</description>
</item></channel></rss>"""
    f = Fetcher("t", delay=0, transport=httpx.MockTransport(lambda r: httpx.Response(200, text=rss)))
    [item] = google_news("rules", f)
    assert item.text == "New rules require disclosure."
    assert item.raw_meta["domain"] == "outlet.co.ke" and "link_unresolved" not in item.raw_meta


def test_is_google_news_link():
    assert is_google_news_link(f"https://news.google.com/rss/articles/{TOKEN}?oc=5")
    assert not is_google_news_link("https://www.the-star.co.ke/news/1")
    assert not is_google_news_link("https://evilnews.google.com.example/x")


def test_sweep_merges_google_news_with_gdelt_and_reads_the_real_article():
    seen: list = []
    res = sweep("M-Pesa loan apps", _fetcher(seen), backends=["gdelt", "google_news"], enricher=None)
    star = [i for i in res.items if "cbk warns" in i.title.lower()]
    assert len(star) == 1                                          # one story, despite the quote styles
    star = star[0]
    assert star.url == "https://www.the-star.co.ke/news/2026-11-09-cbk-warns"
    assert "unlicensed digital lenders" in star.text                # the body was actually read
    assert not star.raw_meta.get("headline_only")
    assert star.raw_meta["corroborating_sources"] == ["gdelt", "google_news"]
    assert star.raw_meta["corroboration"] == 1                     # same outlet twice is not corroboration
    # No Google News redirect link was ever requested, robots.txt or not.
    assert not any("/rss/articles/" in u for u in seen)


def test_unmatched_google_news_items_say_why_they_are_unread():
    res = sweep("paybill scam", _fetcher(), backends=["google_news"], enricher=None)
    item = next(i for i in res.items if i.raw_meta["outlet"] == "Business Daily")
    assert "does not give the publisher URL" in item.raw_meta["fetch_error"]
    assert item.raw_meta["headline_only"] is True


def test_google_news_link_is_not_fetched_even_with_robots_off():
    seen: list = []
    f = Fetcher("t", delay=0, obey_robots=False, transport=httpx.MockTransport(_handler(seen)))
    sweep("paybill scam", f, backends=["google_news"], enricher=None)
    assert not any("/rss/articles/" in u for u in seen)


# ------------------------------------------------------------ social index

def test_social_index_needs_the_phrase_or_most_of_the_words(monkeypatch):
    def search(query, max_results):
        if "site:tiktok.com" not in query:
            return []
        return [
            {"title": "Nairobi nightlife in Kenya", "url": "https://www.tiktok.com/@a/video/1", "summary": ""},
            {"title": "Kenya fraud update", "url": "https://www.tiktok.com/@b/video/2", "summary": ""},
            {"title": "New M-Pesa fraud Kenya warning", "url": "https://www.tiktok.com/@c/video/3",
             "summary": "watch out"},
        ]

    monkeypatch.setattr("osint_discovery.search_duckduckgo", search)
    items = social_web_index("M-Pesa fraud Kenya", _fetcher())
    by_url = {i.url: i for i in items}
    assert "https://www.tiktok.com/@a/video/1" not in by_url       # one word of three: dropped
    assert by_url["https://www.tiktok.com/@b/video/2"].raw_meta["match"] == "terms"
    assert by_url["https://www.tiktok.com/@c/video/3"].raw_meta["match"] == "phrase"
    assert [i.url for i in items][0] == "https://www.tiktok.com/@c/video/3"   # phrase ranks first


def test_required_terms():
    assert [_required_terms(n) for n in range(1, 7)] == [1, 2, 2, 3, 3, 4]


# --------------------------------------------------------- default sources

def test_hackernews_is_available_but_not_a_default():
    assert "hackernews" in BACKENDS
    assert "hackernews" not in DEFAULT_BACKENDS


# --------------------------------------------------------- keyword matching

def _score(query, title, text=""):
    return _keyword_score(Item(url="u", source="s", source_type="news", title=title, text=text), _terms(query))


def test_terms_keep_hyphenated_words_whole():
    assert _terms("M-Pesa fraud Kenya") == ["m-pesa", "fraud", "kenya"]
    assert _terms("beneficial ownership Kenya") == ["beneficial", "ownership", "kenya"]


def test_keyword_match_rejects_mid_word_hits():
    assert _score("otp", "Adoption rates rise") == 0
    assert _score("loan", "Sloane Square opens") == 0
    assert _score("m-pesa", "Kipesa app launched") == 0


def test_keyword_match_keeps_inflections_and_spellings():
    assert _score("fraud", "Fraudulent paybills") > 0
    assert _score("kenya", "Kenyan regulator acts") > 0
    for title in ("M-Pesa outage", "MPESA outage", "M Pesa outage", "m–pesa outage".replace("–", "-")):
        assert _score("m-pesa", title) > 0, title
