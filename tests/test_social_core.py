"""Social discovery core, offline: schema, scoring, store, adapters and the job pipeline."""
import json
import random
from pathlib import Path

import httpx
import pytest

from social.adapters import duckduckgo, load_config, reddit_json, x_oembed
from social.net import PoliteClient
from social.pipeline import Engine, classify_query
from social.schema import author_from_url, canonical_url, merge_hit, new_hit, platform_of
from social.scoring import score_hit
from social.store import DAY_MS, SQLiteStore

FX = Path(__file__).parent / "fixtures" / "social"
HTML_OK, LITE_OK, CHALLENGE = ((FX / n).read_text() for n in ("ddg_html_ok.html", "ddg_lite_ok.html", "ddg_challenge_202.html"))
OEMBED = {"author_name": "Safaricom PLC", "author_url": "https://twitter.com/SafaricomPLC",
          "html": '<blockquote class="twitter-tweet"><p lang="en" dir="ltr">CUSTOMER NOTICE. Be aware of fake websites '
                  'pretending to be Ziidi Trader.</p>&mdash; Safaricom PLC (@SafaricomPLC) '
                  '<a href="https://twitter.com/SafaricomPLC/status/2079525210290626567">July 21, 2026</a></blockquote>'}
T0 = 1_800_000_000_000


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def world(ddg="ok", oembed=200, calls=None):
    """ddg: ok | challenge | empty | soft (200 with nothing, control empty too)."""
    def handler(request):
        if calls is not None:
            calls.append(str(request.url))
        host, q = request.url.host, request.url.params.get("q", "")
        if "duckduckgo" in host:
            if ddg == "challenge":
                return httpx.Response(202, text=CHALLENGE)
            if ddg == "soft":
                return httpx.Response(200, text="<html><body>nothing</body></html>")
            if "wikipedia" in q:
                return httpx.Response(200, text=HTML_OK)
            if ddg == "empty":
                return httpx.Response(200, text="<html><body>No results.</body></html>")
            if "tiktok.com" in q:
                return httpx.Response(200, text=LITE_OK)
            return httpx.Response(200, text=HTML_OK if "x.com" in q else "<html>No results.</html>")
        if host.startswith("publish."):
            return httpx.Response(oembed, json=OEMBED) if oembed == 200 else httpx.Response(oembed)
        return httpx.Response(500)
    return httpx.MockTransport(handler)


def engine(transport, clock=None, store=None):
    clock = clock or Clock()
    store = store or SQLiteStore()
    client = PoliteClient(store, transport=transport, clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + int(s * 1000)))
    return Engine(store, client, clock, random.Random(1)), store, clock


def drain(eng):
    n = 0
    while eng.work_once():
        n += 1
    return n


# ----------------------------------------------------------------------------- schema

def test_canonical_url_makes_one_spelling_per_post():
    a = canonical_url("http://mobile.twitter.com/SafaricomPLC/status/1/?s=20&utm_source=x#frag")
    assert a == canonical_url("https://www.x.com/SafaricomPLC/status/1") == "https://x.com/SafaricomPLC/status/1"
    assert canonical_url("https://old.reddit.com/r/Kenya/comments/abc/t/?ref=share") == "https://reddit.com/r/Kenya/comments/abc/t"
    assert canonical_url("https://www.facebook.com/profile.php?id=61567545292697") == "https://facebook.com/profile.php?id=61567545292697"
    assert platform_of("https://m.facebook.com/x") == "facebook" and platform_of("https://example.com/") is None


def test_handles_come_from_the_url_or_not_at_all():
    assert author_from_url("tiktok", "https://tiktok.com/@fulizaboost1/video/1") == "fulizaboost1"
    assert author_from_url("x", "https://x.com/SafaricomPLC/status/1") == "SafaricomPLC"
    assert author_from_url("x", "https://x.com/hashtag/Ziidi") is None
    assert author_from_url("instagram", "https://instagram.com/p/Abc") is None            # a post URL names no account
    assert author_from_url("reddit", "https://reddit.com/r/Kenya/comments/1/t") is None   # a subreddit is not an author
    assert author_from_url("facebook", "https://facebook.com/groups/123") is None


def test_unknown_fields_are_null_and_listed_never_padded():
    hit = new_hit("x", "https://x.com/a/status/1", "search_snippet:duckduckgo", "snippet_only", T0, username="a", text="hello")
    assert hit["author"]["followers"] is None and hit["engagement"] == {"likes": None, "comments": None, "shares": None, "views": None}
    assert "engagement.likes" in hit["missing_fields"] and "author.username" not in hit["missing_fields"]
    richer = new_hit("x", "https://x.com/a/status/1", "enrichment:x_oembed", "partial", T0 + 5, display_name="A", published_at="2026-07-21")
    merged = merge_hit(hit, richer)
    assert merged["status"] == "partial" and merged["content"]["text"] == "hello" and merged["author"]["display_name"] == "A"
    # a later, poorer sighting does not erase what enrichment fetched
    again = merge_hit(merged, new_hit("x", "https://x.com/a/status/1", "search_snippet:duckduckgo", "snippet_only", T0 + 9, text="hello"))
    assert again["status"] == "partial" and again["author"]["display_name"] == "A" and again["source_method"] == "enrichment:x_oembed"


# ---------------------------------------------------------------------------- scoring

def test_score_is_the_documented_sum_and_unknowns_score_zero():
    hit = new_hit("x", "https://x.com/a/status/1", "s", "snippet_only", T0, text="Get your Fuliza limit boost today", username="a")
    s = score_hit(hit, [{"term": "fuliza limit", "match_type": "exact"}], T0)
    assert s["score"] == 40 and s["matched_terms"] == ["fuliza limit"] and s["confidence"] == 0.5
    assert {r["signal"]: r["points"] for r in s["reasons"]} == {"term_match": 40, "recency": 0, "engagement": 0}
    assert any(r["basis"] == "published date unknown" for r in s["reasons"])
    hit["content"]["published_at"] = "2027-01-15"            # T0 is 2027-01-15 08:00 UTC
    hit["engagement"]["likes"], hit["engagement"]["views"] = 90, 909
    s = score_hit(hit, [{"term": "fuliza limit", "match_type": "exact"}, {"term": "boost fuliza", "match_type": "fuzzy"}], T0, lure=True)
    points = {r["signal"]: r["points"] for r in s["reasons"]}
    assert points == {"term_match": 40, "more_terms": 5, "recency": 20, "engagement": 8, "lure_wording": 15}
    assert s["score"] == sum(points.values()) == 88


def test_exact_terms_do_not_match_fuzzily_and_handles_match_run_together():
    hit = new_hit("tiktok", "https://tiktok.com/@fulizaboost1", "s", "snippet_only", T0, username="fulizaboost1", text="Apply now")
    assert score_hit(hit, [{"term": "fuliza boost", "match_type": "fuzzy"}], T0)["matched_terms"] == ["fuliza boost"]
    assert score_hit(hit, [{"term": "fuliza boost", "match_type": "exact"}], T0)["matched_terms"] == []
    assert score_hit(hit, [{"term": "ziidi", "match_type": "fuzzy"}], T0)["score"] == 0


# ------------------------------------------------------------------------------ store

def test_job_queue_claims_once_reclaims_stale_and_dedupes():
    s = SQLiteStore()
    a = s.job_enqueue("discover", {"term": "x"}, T0, dedupe_key="k")
    assert s.job_enqueue("discover", {"term": "x"}, T0, dedupe_key="k") is None
    later = s.job_enqueue("discover", {"term": "y"}, T0, run_after=T0 + 60_000)
    job = s.job_claim(T0)
    assert job["id"] == a and job["attempts"] == 1 and s.job_claim(T0) is None           # the later one is not due
    assert s.job_claim(T0 + 600_001)["id"] in {a, later}                                 # stale lock or newly due
    s.job_finish(a, True, None, T0)
    assert s.job_enqueue("discover", {"term": "x"}, T0, dedupe_key="k") is not None      # finished jobs do not block


def test_breaker_opens_after_three_failures_doubles_and_closes_on_success():
    s = SQLiteStore()
    assert s.source_event("ddg", False, "blocked", "202", T0)["breaker_until"] is None
    s.source_event("ddg", False, "blocked", "202", T0)
    third = s.source_event("ddg", False, "blocked", "202", T0)
    assert third["breaker_until"] == T0 + 1_800_000
    assert s.source_event("ddg", False, "blocked", "202", T0)["breaker_until"] == T0 + 3_600_000
    h = s.source_health(T0)[0]
    assert h["breaker"] == "open" and h["success_rate_7d"] == 0.0 and h["attempts_7d"] == 4
    s.source_event("ddg", True, "ok", "3 results", T0 + 10)
    h = s.source_health(T0 + 10)[0]
    assert h["breaker"] == "closed" and h["consecutive_failures"] == 0 and h["success_rate_7d"] == 0.2
    assert h["last_success_at"] == T0 + 10 and h["last_failure_at"] == T0


def test_cache_expires_and_purge_enforces_retention_but_keeps_escalated():
    s = SQLiteStore()
    s.cache_put("k", "body", 200, T0, 1000)
    assert s.cache_get("k", T0 + 999)["body"] == "body" and s.cache_get("k", T0 + 1001) is None
    ids = {}
    for name in ("old", "dismissed", "escalated", "fresh"):
        doc = new_hit("x", f"https://x.com/{name}/status/1", "s", "snippet_only", T0, username=name)
        doc.update(score=1, matched_terms=[], confidence=0.5)
        ids[name] = s.hit_put(doc, T0 if name != "fresh" else T0 + 95 * DAY_MS)["id"]
    s.hit_review(ids["dismissed"], "dismissed", "amina", T0)
    s.hit_review(ids["escalated"], "escalated", "amina", T0)
    counts = s.purge(T0 + 8 * DAY_MS, 90 * DAY_MS, 7 * DAY_MS)
    assert counts["dismissed_hits"] == 1 and s.hit_get(ids["dismissed"]) is None and s.hit_get(ids["old"]) is not None
    counts = s.purge(T0 + 100 * DAY_MS, 90 * DAY_MS, 7 * DAY_MS)
    assert counts["expired_hits"] == 1 and s.hit_get(ids["old"]) is None
    assert s.hit_get(ids["escalated"]) is not None and s.hit_get(ids["fresh"]) is not None


def test_hit_put_keeps_review_state_and_first_seen():
    s = SQLiteStore()
    doc = new_hit("x", "https://x.com/a/status/1", "s", "snippet_only", T0, username="a")
    doc.update(score=10, matched_terms=["a"], confidence=0.5)
    first = s.hit_put(doc, T0, run_id="r1")
    s.hit_review(first["id"], "relevant", "amina", T0 + 1)
    doc["score"] = 50
    second = s.hit_put(doc, T0 + 99, run_id="r2")
    got = s.hit_get(first["id"])
    assert second == {"id": first["id"], "created": False}
    assert got["review_status"] == "relevant" and got["first_seen"] == T0 and got["last_seen"] == T0 + 99 and got["score"] == 50
    assert [h["id"] for h in s.hits_list(run_id="r2")] == [first["id"]] and s.hits_list(review_status="new") == []


# --------------------------------------------------------------------------- adapters

def test_duckduckgo_parses_both_page_shapes_and_filters_to_the_platform():
    cfg = load_config("duckduckgo")
    rows = duckduckgo.parse_results(HTML_OK, ("x.com", "twitter.com"), cfg)
    assert [r["url"] for r in rows] == ["https://x.com/SafaricomPLC/status/2079525210290626567", "https://x.com/Safaricom_Care"]
    assert rows[0]["title"].startswith("Safaricom PLC on X") and rows[0]["published_at"] == "2026-07-21"
    assert rows[0]["snippet"].startswith("CUSTOMER NOTICE") and "fake websites" in rows[0]["snippet"]
    assert rows[1]["published_at"] is None                                               # no date in the snippet: not guessed
    lite = duckduckgo.parse_results(LITE_OK, "tiktok.com", cfg)
    assert lite == [{"url": "https://tiktok.com/@safaricomplc", "title": "Safaricom PLC (@safaricomplc) | TikTok",
                     "snippet": "Safaricom PLC on TikTok. Twende Tukiuke.", "published_at": None}]
    assert duckduckgo.parse_results(HTML_OK, "instagram.com", cfg) == []


@pytest.mark.parametrize("mode,status", [("challenge", "blocked"), ("soft", "blocked"), ("empty", "no_results"), ("ok", "ok")])
def test_duckduckgo_never_reports_a_block_as_no_results(mode, status):
    calls = []
    eng, store, clock = engine(world(mode, calls=calls))
    out = duckduckgo.search(eng.client, "Safaricom", "x.com", last_success_at=None, now=clock())
    assert out.status == status
    if mode == "challenge":
        assert len(calls) == 2 and {httpx.URL(c).host for c in calls} == {"html.duckduckgo.com", "lite.duckduckgo.com"}
    if mode == "empty":
        assert any("wikipedia" in c for c in calls)                                      # the control query was needed
        calls.clear()
        again = duckduckgo.search(eng.client, "Other", "x.com", last_success_at=clock(), now=clock())
        assert again.status == "no_results" and not any("wikipedia" in c for c in calls)  # trusted while recently answering


def test_x_oembed_maps_fields_and_reports_missing_and_blocked_honestly():
    eng, _, _ = engine(world())
    assert x_oembed.applies("https://x.com/SafaricomPLC/status/2079525210290626567")
    assert not x_oembed.applies("https://x.com/SafaricomPLC") and not x_oembed.applies("https://tiktok.com/@a/video/1")
    out = x_oembed.enrich(eng.client, "https://x.com/SafaricomPLC/status/2079525210290626567")
    assert out.status == "ok" and out.results[0] == {
        "display_name": "Safaricom PLC", "profile_url": "https://twitter.com/SafaricomPLC",
        "text": "CUSTOMER NOTICE. Be aware of fake websites pretending to be Ziidi Trader.", "published_at": "2026-07-21"}
    for code, status in ((404, "not_found"), (403, "blocked"), (429, "rate_limited"), (500, "error")):
        e, _, _ = engine(world(oembed=code))
        assert x_oembed.enrich(e.client, "https://x.com/a/status/1").status == status


def test_reddit_enrichment_is_off_by_default_but_works_from_a_recorded_listing():
    assert load_config("reddit_json")["enabled"] is False
    assert not reddit_json.applies("https://reddit.com/r/Kenya/comments/abc/title")
    listing = [{"data": {"children": [{"data": {"title": "Fuliza", "selftext": "limit", "author": "someone",
                                                "created_utc": 1767225600, "score": 12, "num_comments": 3}}]}}]
    cfg = {**load_config("reddit_json"), "enabled": True}
    eng, _, _ = engine(httpx.MockTransport(lambda r: httpx.Response(200, json=listing)))
    assert reddit_json.applies("https://reddit.com/r/Kenya/comments/abc/title", cfg)
    row = reddit_json.enrich(eng.client, "https://reddit.com/r/Kenya/comments/abc/title", cfg).results[0]
    assert row["username"] == "someone" and row["text"] == "Fuliza limit" and row["likes"] == 12 and row["comments"] == 3
    assert row["published_at"] == "2026-01-01T00:00:00+00:00"
    eng, _, _ = engine(httpx.MockTransport(lambda r: httpx.Response(403)))
    assert reddit_json.enrich(eng.client, "https://reddit.com/r/Kenya/comments/abc/title", cfg).status == "blocked"


def test_client_caches_only_good_answers_and_paces_per_host():
    calls, clock, store = [], Clock(), SQLiteStore()
    slept = []
    c = PoliteClient(store, transport=httpx.MockTransport(lambda r: (calls.append(1), httpx.Response(200 if len(calls) > 1 else 202, text="x"))[1]),
                     clock=clock, sleep=lambda s: (slept.append(s), setattr(clock, "t", clock.t + int(s * 1000))))
    assert c.get("https://a.example/1", min_interval=5, ttl=60).status == 202            # a block is never cached
    assert c.get("https://a.example/1", min_interval=5, ttl=60).status == 200 and slept == [5.0]
    assert c.get("https://a.example/1", min_interval=5, ttl=60).from_cache and len(calls) == 2


# --------------------------------------------------------------------------- pipeline

def test_input_is_classified_by_shape():
    assert classify_query("https://twitter.com/SafaricomPLC/status/1?s=20") == {
        "kind": "url", "term": "https://x.com/SafaricomPLC/status/1", "platform": "x"}
    assert classify_query("@fulizaboost1")["kind"] == "handle" and classify_query("@fulizaboost1")["term"] == "fulizaboost1"
    assert classify_query("  Fuliza   limit ") == {"kind": "keyword", "term": "Fuliza limit", "platform": None}


def test_a_search_needs_a_purpose_and_is_audited():
    eng, store, _ = engine(world())
    with pytest.raises(ValueError, match="purpose"):
        eng.submit_search("Safaricom", "", "amina")
    with pytest.raises(ValueError, match="not on Reddit"):
        eng.submit_search("https://example.com/x", "checking a report", "amina")
    eng.submit_search("Safaricom", "checking a customer report", "amina", ["x"])
    log = store.audit_list()[0]
    assert log["user"] == "amina" and log["action"] == "search:keyword" and log["query"] == "Safaricom"
    assert log["purpose"] == "checking a customer report" and log["sources_used"] == ["duckduckgo"]


def test_keyword_search_end_to_end_discovers_dedupes_enriches_and_scores():
    eng, store, _ = engine(world())
    store.watchlist_add("Ziidi Trader", "exact", ["x"], "amina", T0)
    run_id = eng.submit_search("Safaricom", "checking a customer report", "amina", ["x", "tiktok", "instagram"])
    assert store.run_get(run_id)["pending_jobs"] == 3                                    # nothing ran inside the request
    drain(eng)
    run = store.run_get(run_id)
    assert run["pending_jobs"] == 0
    by_platform = {o["platform"]: o for o in run["outcomes"]}
    assert by_platform["x"]["status"] == "ok" and by_platform["x"]["count"] == 2
    assert by_platform["tiktok"]["status"] == "ok" and "embed player" in by_platform["tiktok"]["detail"]
    assert by_platform["instagram"]["status"] == "no_results"                            # answered, found nothing: said so
    hits = {h["url"]: h for h in store.hits_list(run_id=run_id)}
    post = hits["https://x.com/SafaricomPLC/status/2079525210290626567"]
    assert post["status"] == "partial" and post["source_method"] == "enrichment:x_oembed"
    assert post["author"] == {"username": "SafaricomPLC", "display_name": "Safaricom PLC",
                              "profile_url": "https://twitter.com/SafaricomPLC", "followers": None, "verified": None}
    assert post["content"]["published_at"] == "2026-07-21" and post["engagement"]["likes"] is None
    assert "engagement.likes" in post["missing_fields"] and "author.followers" in post["missing_fields"]
    assert set(post["matched_terms"]) == {"Safaricom", "Ziidi Trader"} and post["confidence"] == 0.7
    assert post["score"] == sum(r["points"] for r in post["reasons"]) and post["verdict"]["level"] == "official"
    profile = hits["https://x.com/Safaricom_Care"]
    assert profile["status"] == "snippet_only" and profile["source_method"] == "search_snippet:duckduckgo"
    assert hits["https://tiktok.com/@safaricomplc"]["status"] == "snippet_only"
    # a second run finds the same things: no duplicates, and review state would survive
    eng2_run = eng.submit_search("Safaricom", "checking a customer report", "amina", ["x"])
    drain(eng)
    assert len(store.hits_list(limit=50)) == 3 and len(store.hits_list(run_id=eng2_run)) == 2


def test_a_blocked_engine_is_reported_retried_with_backoff_and_then_paused():
    eng, store, clock = engine(world("challenge"))
    run_id = eng.submit_search("Safaricom", "checking a customer report", "amina", ["x", "reddit", "tiktok", "facebook"])
    assert drain(eng) == 4
    run = store.run_get(run_id)
    assert {o["status"] for o in run["outcomes"]} == {"blocked"} and run["pending_jobs"] == 4   # queued to retry, not dropped
    assert store.hits_list() == []
    health = {h["source"]: h for h in store.source_health(clock())}["duckduckgo"]
    assert health["breaker"] == "open" and health["consecutive_failures"] == 3            # the 4th job was not even sent
    assert "paused" in run["outcomes"][-1]["detail"]
    assert store.job_claim(clock()) is None                                               # backoff: nothing due yet
    clock.t += 2 * 3600_000
    for _ in range(12):
        clock.t += 2 * 3600_000
        drain(eng)
    assert store.run_get(run_id)["pending_jobs"] == 0                                     # gave up after MAX_ATTEMPTS
    assert all(o["status"] == "blocked" for o in store.run_get(run_id)["outcomes"])


def test_url_lookup_uses_enrichment_when_the_engine_has_no_entry():
    eng, store, _ = engine(world("empty"))
    run_id = eng.submit_search("https://twitter.com/SafaricomPLC/status/2079525210290626567?s=20", "verifying a reported post", "amina")
    drain(eng)
    outcomes = {(o["source"], o["status"]) for o in store.run_get(run_id)["outcomes"]}
    assert ("duckduckgo", "no_results") in outcomes and ("x_oembed", "ok") in outcomes
    hit = store.hits_list(run_id=run_id)[0]
    assert hit["url"] == "https://x.com/SafaricomPLC/status/2079525210290626567" and hit["status"] == "partial"
    assert hit["content"]["text"].startswith("CUSTOMER NOTICE")


def test_watchlist_fans_out_once_per_term_and_platform_and_tick_schedules_it(monkeypatch):
    eng, store, clock = engine(world())
    store.watchlist_add("Safaricom", "exact", ["x", "tiktok"], "amina", T0)
    off = store.watchlist_add("Paused", "exact", ["x"], "amina", T0)
    store.watchlist_update(off["id"], False)
    assert eng.enqueue_watchlist() == 2 and eng.enqueue_watchlist() == 0                  # already queued: not duplicated
    drain(eng)
    assert len(store.hits_list()) == 3
    monkeypatch.setenv("SOCIAL_WATCH_INTERVAL_MINUTES", "60")
    store.kv_set("last_watchlist_at", str(clock()))
    eng.tick()
    assert store.jobs_pending() == 1 and store.kv_get("worker_heartbeat") == str(clock())  # only the daily purge
    drain(eng)
    clock.t += 61 * 60_000
    eng.tick()
    assert store.jobs_pending() == 2                                                      # the watchlist came due


def test_lure_wording_raises_the_score_and_carries_a_plain_verdict():
    page = HTML_OK.replace("SafaricomPLC%2Fstatus%2F2079525210290626567%3Fs%3D20", "fulizaboost1").replace(
        "Safaricom PLC on X: &quot;CUSTOMER NOTICE&quot;", "Fuliza Boost (@fulizaboost1)").replace(
        "Jul 21, 2026 · CUSTOMER NOTICE. Be aware of <b>fake</b> websites pretending to be Ziidi Trader.", "Apply now for a higher limit")
    eng, store, _ = engine(httpx.MockTransport(lambda r: httpx.Response(200, text=page)))
    eng.submit_search("fuliza boost", "watching for limit-increase lures", "amina", ["x"])
    drain(eng)
    hit = next(h for h in store.hits_list() if h["author"]["username"] == "fulizaboost1")
    assert hit["verdict"]["level"] == "lure" and any(r["signal"] == "lure_wording" for r in hit["reasons"])


# ------------------------------------------------------------------------------- exa

EXA_BODY = {"results": [
    {"url": "https://www.tiktok.com/@fulizaboost1/video/1?lang=en", "title": "Apply now | TikTok", "author": "Fuliza Boost",
     "publishedDate": "2026-10-02T00:00:00.000Z", "highlights": ["88 Likes, TikTok video from Fuliza Boost: Apply now"]},
    {"url": "https://en.wikipedia.org/wiki/Fuliza", "title": "Fuliza", "highlights": ["off platform"]}]}


def exa_world(status=200, calls=None):
    def handler(request):
        if request.url.host == "api.exa.ai":
            if calls is not None:
                calls.append((dict(request.headers), json.loads(request.content)))
            return httpx.Response(status, json=EXA_BODY if status == 200 else {"error": "x"})
        return world("challenge").handler(request)
    return httpx.MockTransport(handler)


def test_exa_is_off_without_a_key_and_the_pipeline_never_asks_it(monkeypatch):
    monkeypatch.delenv("EXA_API_KEY", raising=False)
    from social.pipeline import discovery_sources
    assert [a.SOURCE for a in discovery_sources()] == ["duckduckgo"]
    calls = []
    eng, store, _ = engine(exa_world(calls=calls))
    run_id = eng.submit_search("fuliza boost", "watching for limit-increase lures", "amina", ["tiktok"])
    drain(eng)
    assert calls == [] and {o["source"] for o in store.run_get(run_id)["outcomes"]} == {"duckduckgo"}


def test_exa_sends_the_recommended_request_and_maps_results(monkeypatch):
    monkeypatch.setenv("EXA_API_KEY", "exa_test_key")
    calls = []
    eng, store, _ = engine(exa_world(calls=calls))
    run_id = eng.submit_search("fuliza boost", "watching for limit-increase lures", "amina", ["tiktok"])
    drain(eng)
    headers, body = calls[0]
    assert headers["x-api-key"] == "exa_test_key"
    assert set(body) == {"query", "type", "objective", "includeDomains", "contents"}            # nothing decorative
    assert body["type"] == "auto" and body["contents"] == {"highlights": True} and body["includeDomains"] == ["tiktok.com"]
    assert body["query"] == '"fuliza boost"' and len(body["objective"]) > 40
    outcomes = {o["source"]: o for o in store.run_get(run_id)["outcomes"]}
    assert outcomes["exa"]["status"] == "ok" and outcomes["duckduckgo"]["status"] == "blocked"
    assert store.run_get(run_id)["pending_jobs"] == 0                       # one source answered: no retry needed
    hit = store.hits_list(run_id=run_id)[0]
    assert hit["url"] == "https://tiktok.com/@fulizaboost1/video/1" and hit["source_method"] == "search_snippet:exa"
    assert hit["author"]["username"] == "fulizaboost1" and hit["content"]["published_at"] == "2026-10-02"
    assert hit["content"]["text"].startswith("88 Likes") and len(store.hits_list()) == 1            # off-platform row dropped
    assert "exa_test_key" not in json.dumps(store.audit_list()) and store.audit_list()[0]["sources_used"] == ["duckduckgo", "exa"]
    # cached: the same paid query inside six hours is not paid for again
    eng.submit_search("fuliza boost", "watching for limit-increase lures", "amina", ["tiktok"])
    drain(eng)
    assert len(calls) == 1


def test_a_refused_exa_key_is_reported_and_never_stops_the_keyless_source(monkeypatch):
    monkeypatch.setenv("EXA_API_KEY", "exa_bad")
    eng, store, _ = engine(httpx.MockTransport(lambda r: httpx.Response(401) if r.url.host == "api.exa.ai"
                                               else world("ok").handler(r)))
    run_id = eng.submit_search("Safaricom", "checking a customer report", "amina", ["x"])
    drain(eng)
    outcomes = {o["source"]: o for o in store.run_get(run_id)["outcomes"] if o["source"] != "x_oembed"}
    assert outcomes["exa"]["status"] == "blocked" and "refused" in outcomes["exa"]["detail"]
    assert outcomes["duckduckgo"]["status"] == "ok" and len(store.hits_list(run_id=run_id)) == 2
