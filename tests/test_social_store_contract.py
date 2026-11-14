"""One contract, two stores. Runs against SQLite always, and against a real Convex deployment
when MNARA_TEST_CONVEX_URL and MNARA_TEST_CONVEX_KEY are set (CI sets neither; it never
touches the network).

    CONVEX_AGENT_MODE=anonymous npx convex dev --once           # throwaway local backend
    npx convex env set MNARA_SERVER_KEY test-key
    MNARA_TEST_CONVEX_URL=http://127.0.0.1:3210 MNARA_TEST_CONVEX_KEY=test-key pytest tests/test_social_store_contract.py

A Convex deployment keeps its rows between runs, so every test works in its own far-future time
window and with its own names, and first drains any job an earlier run left due.
"""
import itertools
import os
import random
import uuid

import pytest

from social.store import DAY_MS, SQLiteStore
from social.schema import new_hit

_WINDOW = itertools.count()
CONVEX_URL, CONVEX_KEY = os.environ.get("MNARA_TEST_CONVEX_URL"), os.environ.get("MNARA_TEST_CONVEX_KEY")


@pytest.fixture(params=["sqlite", "convex"])
def store(request):
    if request.param == "sqlite":
        s = SQLiteStore()
    else:
        if not (CONVEX_URL and CONVEX_KEY):
            pytest.skip("set MNARA_TEST_CONVEX_URL and MNARA_TEST_CONVEX_KEY to run against Convex")
        from social.convex_store import ConvexStore
        s = ConvexStore(CONVEX_URL, CONVEX_KEY)
    yield s
    s.close()


def window(store) -> int:
    """A fresh time window, with anything an earlier test left due drained out of the queue."""
    base = 4_000_000_000_000 + random.randrange(10**9) * 10**4 + next(_WINDOW) * 10**10
    while (job := store.job_claim(base + DAY_MS, lock_ms=0)) is not None:
        store.job_finish(job["id"], True, None, base)
    return base + 2 * DAY_MS


def tag() -> str:
    return uuid.uuid4().hex[:10]


def test_watchlist(store):
    t, now = f"term {tag()}", window(store)
    row = store.watchlist_add(t, "exact", ["x", "tiktok"], "amina", now)
    assert row["term"] == t and row["active"] is True and row["platforms"] == ["x", "tiktok"]
    assert any(w["id"] == row["id"] for w in store.watchlist_list(active_only=True))
    assert store.watchlist_update(row["id"], False) is True
    assert not any(w["id"] == row["id"] for w in store.watchlist_list(active_only=True))
    assert store.watchlist_delete(row["id"]) is True and store.watchlist_delete(row["id"]) is False
    assert store.watchlist_update("not-an-id", True) is False


def test_job_queue(store):
    now, key = window(store), f"k-{tag()}"
    run = f"run-{tag()}"
    a = store.job_enqueue("discover", {"term": "x", "run_id": run}, now, dedupe_key=key)
    assert a and store.job_enqueue("discover", {"term": "x"}, now, dedupe_key=key) is None
    store.job_enqueue("discover", {"term": "later", "run_id": run}, now, run_after=now + 60_000)
    assert store.jobs_pending(run) == 2
    job = store.job_claim(now)
    assert job["id"] == a and job["attempts"] == 1 and job["status"] == "running" and job["payload"]["term"] == "x"
    assert store.job_claim(now) is None                                   # the other is not due yet
    store.job_retry(a, now + 30_000, "blocked")
    again = store.job_claim(now + 30_000)
    assert again["id"] == a and again["attempts"] == 2
    stale = store.job_claim(now + 30_000 + 600_001)                      # a dead worker's lock is reclaimed
    assert stale["id"] == a and stale["attempts"] == 3
    store.job_finish(a, True, None, now)
    later = store.job_claim(now + 10**7)
    assert later["payload"]["term"] == "later"
    store.job_finish(later["id"], False, "gave up", now)
    assert store.jobs_pending(run) == 0 and store.job_claim(now + 10**8) is None
    assert store.job_enqueue("discover", {"term": "x"}, now, dedupe_key=key) is not None    # finished jobs do not block


def test_cache(store):
    now, k = window(store), f"c-{tag()}"
    store.cache_put(k, "body", 200, now, 1000)
    assert store.cache_get(k, now + 999) == {"body": "body", "status": 200, "fetched_at": now}
    assert store.cache_get(k, now + 1001) is None


def _hit(name, now):
    doc = new_hit("x", f"https://x.com/{name}/status/1", "search_snippet:duckduckgo", "snippet_only", now, username=name, text="hello")
    doc.update(score=10, matched_terms=["hello"], confidence=0.5, reasons=[{"signal": "term_match", "points": 10, "basis": "b"}])
    return doc


def test_hits_keep_review_state_and_first_seen(store):
    now, name, run = window(store), f"u{tag()}", f"run-{tag()}"
    first = store.hit_put(_hit(name, now), now, run)
    assert first["created"] is True
    store.hit_review(first["id"], "relevant", "amina", now + 1)
    doc = _hit(name, now)
    doc["score"] = 55
    second = store.hit_put(doc, now + 99, run)
    got = store.hit_get(first["id"])
    assert second == {"id": first["id"], "created": False}
    assert got["review_status"] == "relevant" and got["reviewed_by"] == "amina" and got["first_seen"] == now
    assert got["last_seen"] == now + 99 and got["score"] == 55 and got["author"]["username"] == name
    assert got["missing_fields"] and got["reasons"][0]["signal"] == "term_match"
    assert store.hit_get_by_url(f"https://x.com/{name}/status/1")["id"] == first["id"]
    assert [h["id"] for h in store.hits_list(run_id=run)] == [first["id"]]
    assert first["id"] in [h["id"] for h in store.hits_list(review_status="relevant", limit=500)]
    assert store.hit_review("missing", "dismissed", "amina", now) is False and store.hit_get("missing") is None


def test_breaker_and_health(store):
    now, src = window(store), f"src-{tag()}"
    for _ in range(2):
        assert store.source_event(src, False, "blocked", "202", now)["breaker_until"] is None
    assert store.source_event(src, False, "blocked", "202", now)["breaker_until"] == now + 1_800_000
    h = next(s for s in store.source_health(now) if s["source"] == src)
    assert h["breaker"] == "open" and h["success_rate_7d"] == 0.0 and h["attempts_7d"] == 3 and h["last_success_at"] is None
    store.source_event(src, True, "ok", "fine", now + 5)
    h = next(s for s in store.source_health(now + 5) if s["source"] == src)
    assert h["breaker"] == "closed" and h["consecutive_failures"] == 0 and h["success_rate_7d"] == 0.25
    assert h["last_failure_at"] == now and h["last_success_at"] == now + 5


def test_runs_audit_and_kv(store):
    now = window(store)
    rid = store.run_create("adhoc", f"q {tag()}", "a reason", "amina", ["x"], now)
    store.run_outcome(rid, "x", "duckduckgo", "ok", "2 result(s)", 2, now)
    run = store.run_get(rid)
    assert run["outcomes"] == [{"platform": "x", "source": "duckduckgo", "status": "ok", "detail": "2 result(s)", "count": 2, "at": now}]
    assert run["purpose"] == "a reason" and run["pending_jobs"] == 0 and store.run_get("missing") is None
    marker = f"audit {tag()}"
    store.audit("amina", "search:keyword", marker, ["duckduckgo"], "a reason", now)
    assert any(a["query"] == marker and a["purpose"] == "a reason" for a in store.audit_list(500))
    k = f"kv-{tag()}"
    assert store.kv_get(k) is None
    store.kv_set(k, "1")
    store.kv_set(k, "2")
    assert store.kv_get(k) == "2"


def test_purge_keeps_escalated(store):
    now = window(store)
    ids = {}
    for kind in ("old", "dismissed", "escalated"):
        ids[kind] = store.hit_put(_hit(f"{kind}{tag()}", now), now)["id"]
    store.hit_review(ids["dismissed"], "dismissed", "amina", now)
    store.hit_review(ids["escalated"], "escalated", "amina", now)
    store.purge(now + 8 * DAY_MS, 90 * DAY_MS, 7 * DAY_MS)
    assert store.hit_get(ids["dismissed"]) is None and store.hit_get(ids["old"]) is not None
    store.purge(now + 100 * DAY_MS, 90 * DAY_MS, 7 * DAY_MS)
    assert store.hit_get(ids["old"]) is None and store.hit_get(ids["escalated"]) is not None


def test_pipeline_end_to_end(store):
    from social.net import PoliteClient
    from social.pipeline import Engine
    from test_social_core import Clock, world
    clock = Clock()
    clock.t = window(store)
    client = PoliteClient(store, transport=world(), clock=clock, sleep=lambda s: setattr(clock, "t", clock.t + int(s * 1000)))
    eng = Engine(store, client, clock, random.Random(1))
    run_id = eng.submit_search("Safaricom", "contract test of the pipeline", "amina", ["x"])
    for _ in range(200):
        if not eng.work_once():
            break
    run = store.run_get(run_id)
    assert run["pending_jobs"] == 0 and {o["status"] for o in run["outcomes"] if o["source"] == "duckduckgo"} == {"ok"}
    hits = {h["url"]: h for h in store.hits_list(run_id=run_id)}
    post = hits["https://x.com/SafaricomPLC/status/2079525210290626567"]
    assert post["status"] == "partial" and post["author"]["display_name"] == "Safaricom PLC"
