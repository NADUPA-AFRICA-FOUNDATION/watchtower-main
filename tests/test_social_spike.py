"""The spike's own judgement is what Phase 2 is built on, so it is tested offline from recorded shapes."""
import base64

import httpx

from social.spike import _blocked, _hits, _result_links, run_matrix, to_markdown

DDG = ('<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.reddit.com%2Fr%2FKenya%2Fcomments%2F1%2Fx%2F&amp;rut=1">t</a>'
       '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FKenya">w</a>')
BING_U = "a1" + base64.urlsafe_b64encode(b"https://www.tiktok.com/@someone").decode().rstrip("=")
BING = f'<li class="b_algo"><h2><a href="https://www.bing.com/ck/a?!&amp;&amp;p=1&amp;u={BING_U}&amp;ntb=1">t</a></h2></li>'
LISTING = {"data": {"children": [{"data": {"title": "T", "selftext": "", "author": "a", "created_utc": 1, "score": 2,
                                           "num_comments": 0, "permalink": "/r/Kenya/comments/1/t/", "subreddit": "Kenya"}}]}}
ATOM = "<feed><entry><title>t</title><author><name>a</name></author><updated>x</updated><link href='h'/></entry></feed>"


def test_redirect_wrapped_result_links_are_unwrapped():
    assert _result_links(DDG)[0] == "https://www.reddit.com/r/Kenya/comments/1/x/"
    assert _hits(DDG, "reddit.com") == ["https://www.reddit.com/r/Kenya/comments/1/x/"]
    assert _hits(BING, "tiktok.com") == ["https://www.tiktok.com/@someone"]
    assert _hits(DDG, "tiktok.com") == []                         # a wikipedia link is not a tiktok hit


def test_block_detection_covers_refusals_challenges_and_login_walls():
    r = lambda status, body="", url="https://x/": {"status": status, "body": body, "final_url": url, "error": ""}
    assert _blocked(r(200, "<html>results</html>")) == ""
    assert "403" in _blocked(r(403)) and "429" in _blocked(r(429)) and "challenge" in _blocked(r(202))
    assert "captcha" in _blocked(r(200, "Please solve this CAPTCHA"))
    assert "login" in _blocked(r(200, "ok", "https://old.reddit.com/login/?dest=x"))
    assert _blocked({"status": 0, "body": "", "final_url": "", "error": "ConnectTimeout: x"}).startswith("ConnectTimeout")


def _world(engine_ok=True, reddit_ok=True):
    def handler(request):
        host, path, q = request.url.host, request.url.path, request.url.params.get("q", "")
        if path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /search\n" if "bing" in host else "User-agent: *\nAllow: /\n")
        if "duckduckgo" in host:
            if not engine_ok:
                return httpx.Response(202, text="challenge")
            if "wikipedia" in q:
                return httpx.Response(200, text=DDG)
            return httpx.Response(200, text=DDG if "reddit.com" in q else "<html>nothing here</html>")
        if "bing" in host:
            return httpx.Response(200, text='<a href="https://en.wikipedia.org/wiki/Kenya">w</a>' if "wikipedia" in q
                                  else "<html>There are no results for this</html>")
        if "mojeek" in host:
            return httpx.Response(403)
        if "reddit.com" in host:
            if not reddit_ok:
                return httpx.Response(403)
            if path.endswith(".rss"):
                return httpx.Response(200, text=ATOM)
            if "comments" in path:
                return httpx.Response(200, json=[LISTING])
            return httpx.Response(200, json=LISTING)
        if host == "www.tiktok.com":
            return httpx.Response(200, json={"type": "video", "html": "<iframe></iframe>", "provider_name": "TikTok"})
        if host == "publish.twitter.com":
            return httpx.Response(200, json={"author_name": "Safaricom PLC", "author_url": "https://x.com/SafaricomPLC",
                                             "html": "<blockquote><p>CUSTOMER NOTICE. Be aware of fake websites pretending to be us.</p></blockquote>"})
        return httpx.Response(500)
    return httpx.MockTransport(handler)


def _verdicts(result):
    return {(r["source"], r["target"]): r for r in result["rows"]}


def test_matrix_separates_ok_no_results_blocked_and_partial():
    v = _verdicts(run_matrix("Fuliza", transport=_world(), pace=0, engine_pace=0, library=False))
    assert v[("duckduckgo_html", "control query")]["verdict"] == "ok"
    assert v[("duckduckgo_html", "reddit")]["verdict"] == "ok" and "1 reddit.com links" in v[("duckduckgo_html", "reddit")]["fields"]
    assert v[("duckduckgo_html", "tiktok")]["verdict"] == "no_results"
    assert v[("bing", "x")]["verdict"] == "no_results" and "itself says" in v[("bing", "x")]["note"]
    assert v[("bing", "x")]["robots"] == "disallows" and v[("duckduckgo_html", "x")]["robots"] == "allows"
    # a refused engine is blocked for every platform, and the remaining requests are not sent
    assert v[("mojeek", "control query")]["verdict"] == "blocked"
    assert v[("mojeek", "reddit")]["verdict"] == "blocked" and v[("mojeek", "reddit")]["http"] is None
    assert v[("reddit search.json", "Fuliza")]["verdict"] == "ok" and "permalink" in v[("reddit search.json", "Fuliza")]["fields"]
    assert v[("reddit search.rss", "Fuliza")]["verdict"] == "ok"
    assert v[("reddit permalink.json", "one post")]["verdict"] == "ok"
    assert v[("tiktok oEmbed", "one public post")]["verdict"] == "partial"          # a player widget is not post details
    assert v[("x publish oEmbed", "one public post")]["verdict"] == "ok"


def test_a_soft_blocked_engine_and_a_refused_reddit_never_read_as_empty():
    v = _verdicts(run_matrix("Fuliza", transport=_world(engine_ok=False, reddit_ok=False), pace=0, engine_pace=0, library=False))
    assert all(v[("duckduckgo_html", t)]["verdict"] == "blocked" for t in ("control query", "reddit", "tiktok", "x"))
    assert v[("reddit search.json", "Fuliza")]["verdict"] == "blocked"
    assert v[("reddit permalink.json", "one post")]["verdict"] == "not_tested"     # nothing to follow is not a pass


def test_markdown_names_where_it_ran_and_what_was_excluded():
    md = to_markdown(run_matrix("Fuliza", transport=_world(), pace=0, engine_pace=0, library=False))
    assert "Run from: local" in md and "| duckduckgo_html | reddit | 200 | **ok** |" in md
    assert "excluded by policy, not by test" in md and "**instagram**" in md


def test_endpoint_starts_one_run_reports_progress_then_serves_the_matrix(monkeypatch):
    import threading
    import time

    from fastapi.testclient import TestClient

    import social.spike as spike
    from web import app as webapp

    release, calls = threading.Event(), []

    def fake(term):
        calls.append(term)
        release.wait(5)
        return run_matrix(term, transport=_world(), pace=0, engine_pace=0, library=False)

    monkeypatch.setattr(spike, "run_matrix", fake)
    monkeypatch.setattr(webapp, "_MATRIX", {"state": "idle", "result": None, "error": "", "started": ""})
    client = TestClient(webapp.app)
    first = client.get("/api/admin/source-matrix?term=Fuliza")
    assert first.status_code == 202 and first.headers["refresh"] == "10" and "Running" in first.text
    assert client.get("/api/admin/source-matrix").status_code == 202 and calls == ["Fuliza"]      # no second run
    release.set()
    for _ in range(50):
        done = client.get("/api/admin/source-matrix")
        if done.status_code == 200:
            break
        time.sleep(0.05)
    assert done.status_code == 200 and "Run from:" in done.text and "duckduckgo_html" in done.text
    assert client.get("/api/admin/source-matrix?format=json").json()["term"] == "Fuliza"
