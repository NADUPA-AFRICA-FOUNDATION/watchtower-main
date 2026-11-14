"""The social API: nothing waits on a crawl, an empty answer is explained, every action is audited."""
import random
import re
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from social.net import PoliteClient
from social.pipeline import Engine
from social.store import SQLiteStore
from test_social_core import T0, Clock, drain, world
from web.social_routes import build_router


def setup(mode="ok", authenticated=False):
    store, clock = SQLiteStore(), Clock()
    app = FastAPI()
    identity = (lambda request, claimed: ("watchtower", "authenticated")) if authenticated else \
               (lambda request, claimed: ((claimed or "").strip(), "self_asserted"))
    app.include_router(build_router(lambda: store, identity, clock))
    worker = Engine(store, PoliteClient(store, transport=world(mode), clock=clock,
                                        sleep=lambda s: setattr(clock, "t", clock.t + int(s * 1000))), clock, random.Random(1))
    return TestClient(app), store, clock, worker


def test_search_returns_a_run_id_at_once_and_the_run_explains_itself():
    client, store, clock, worker = setup()
    bad = client.post("/api/social/search", json={"query": "Safaricom", "purpose": "", "analyst": "Amina"})
    assert bad.status_code == 400 and "purpose" in bad.json()["detail"]
    assert client.post("/api/social/search", json={"query": "Safaricom", "purpose": "customer report"}).status_code == 400   # no name
    r = client.post("/api/social/search", json={"query": "Safaricom", "purpose": "customer report", "analyst": "Amina",
                                                "platforms": ["x", "instagram"]})
    assert r.status_code == 202 and r.json()["worker"]["running"] is False and "queued" in r.json()["worker"]["note"]
    run = client.get(r.json()["poll"]).json()
    assert run["state"] == "running" and run["hits"] == []
    assert {(o["platform"], o["status"]) for o in run["outcomes"]} == {("x", "queued"), ("instagram", "queued")}
    worker.tick()
    drain(worker)
    run = client.get(r.json()["poll"]).json()
    assert run["state"] == "finished" and run["worker"]["running"] is True
    by = {o["platform"]: o for o in run["outcomes"] if o["source"] == "duckduckgo"}
    assert by["x"]["status"] == "ok" and by["instagram"]["status"] == "no_results" and "found nothing" in by["instagram"]["detail"]
    assert len(run["hits"]) == 2 and run["hits"][0]["first_seen"].endswith("+00:00")                 # ISO at the boundary
    assert client.get("/api/social/search/nope").status_code == 404 and client.get("/api/social/search/a b").status_code == 400
    log = store.audit_list()[0]
    assert log["user"] == "Amina (self-asserted)" and log["purpose"] == "customer report"


def test_blocked_sources_show_as_blocked_in_the_run_and_in_health():
    client, store, clock, worker = setup("challenge")
    empty = client.get("/health/social").json()
    assert empty["sources"] == [] and "not a healthy reading" in empty["note"]
    r = client.post("/api/social/search", json={"query": "Safaricom", "purpose": "customer report", "analyst": "Amina", "platforms": ["x", "reddit", "tiktok"]})
    drain(worker)
    run = client.get(r.json()["poll"]).json()
    assert run["state"] == "running" and {o["status"] for o in run["outcomes"]} == {"blocked"} and run["hits"] == []
    health = client.get("/health/social").json()["sources"][0]
    assert health["source"] == "duckduckgo" and health["breaker"] == "open" and health["success_rate_7d"] == 0.0
    assert health["last_success_at"] is None and health["last_failure_at"].startswith("2027-") and health["breaker_until"]
    assert client.get("/api/social/health").json()["sources"] == client.get("/health/social").json()["sources"]
    inbox = client.get("/api/social/hits").json()
    assert inbox["hits"] == [] and inbox["sources"][0]["last_status"] == "blocked" and inbox["pending_jobs"] == 3


def test_review_actions_move_hits_and_are_audited_under_the_authenticated_account():
    client, store, clock, worker = setup(authenticated=True)
    r = client.post("/api/social/search", json={"query": "Safaricom", "purpose": "customer report", "platforms": ["x"]})
    drain(worker)
    hits = client.get("/api/social/hits?review=new").json()["hits"]
    assert len(hits) == 2
    hid = hits[0]["id"]
    assert client.post(f"/api/social/hits/{hid}/review", json={"action": "delete"}).status_code == 400
    assert client.post("/api/social/hits/unknown/review", json={"action": "dismiss"}).status_code == 404
    assert client.post(f"/api/social/hits/{hid}/review", json={"action": "escalate"}).json()["review_status"] == "escalated"
    assert [h["id"] for h in client.get("/api/social/hits?review=escalated").json()["hits"]] == [hid]
    assert len(client.get("/api/social/hits?review=new").json()["hits"]) == 1
    assert len(client.get("/api/social/hits?review=all").json()["hits"]) == 2
    assert client.get("/api/social/hits?review=bogus").status_code == 400
    log = store.audit_list()[0]
    assert log["user"] == "watchtower" and log["action"] == "review:escalated" and log["query"] == hits[0]["url"]


def test_watchlist_crud_run_and_validation():
    client, store, clock, worker = setup()
    assert client.post("/api/social/watchlist", json={"term": "x", "analyst": "Amina"}).status_code == 400
    assert client.post("/api/social/watchlist", json={"term": "Safaricom", "analyst": "Amina", "platforms": ["myspace"]}).status_code == 400
    made = client.post("/api/social/watchlist", json={"term": " Safaricom ", "match_type": "exact", "platforms": ["x", "tiktok"], "analyst": "Amina"})
    assert made.status_code == 201 and made.json()["term"] == "Safaricom" and made.json()["active"] is True
    assert client.post("/api/social/watchlist", json={"term": "safaricom", "analyst": "Amina"}).status_code == 409
    wid = made.json()["id"]
    ran = client.post("/api/social/watchlist/run", json={"analyst": "Amina"})
    assert ran.status_code == 202 and ran.json()["queued"] == 2
    assert client.post("/api/social/watchlist/run", json={"analyst": "Amina"}).json()["queued"] == 0   # already queued
    drain(worker)
    assert len(client.get("/api/social/hits").json()["hits"]) == 3
    assert client.patch(f"/api/social/watchlist/{wid}", json={"active": False, "analyst": "Amina"}).json()["active"] is False
    assert client.get("/api/social/watchlist").json()["watchlist"][0]["active"] is False
    assert client.post("/api/social/watchlist/run", json={"analyst": "Amina"}).json()["queued"] == 0   # paused
    assert client.delete(f"/api/social/watchlist/{wid}?analyst=Amina").json()["deleted"] is True
    assert client.get("/api/social/watchlist").json()["watchlist"] == []
    assert client.delete(f"/api/social/watchlist/{wid}?analyst=Amina").status_code == 404
    assert [a["action"] for a in store.audit_list()][:3] == ["watchlist:delete", "watchlist:pause", "watchlist_run"]


def test_status_states_what_each_platform_can_and_cannot_give():
    client, *_ = setup()
    s = client.get("/api/social/status").json()
    assert s["storage"] == "sqlite" and s["worker"]["running"] is False
    assert s["platforms"]["x"]["details"] == "x_oembed"
    assert s["platforms"]["reddit"]["details"] is None and "refuses" in s["platforms"]["reddit"]["note"]
    assert s["platforms"]["facebook"]["details"] is None and "excluded by policy" in s["platforms"]["facebook"]["note"]


def test_the_app_mounts_the_routes_and_the_page_wires_every_element_the_script_uses():
    from web import app as webapp
    paths = set(webapp.app.openapi()["paths"])
    assert {"/api/social/hits", "/api/social/search", "/api/social/watchlist", "/health/social", "/api/social/status"} <= paths
    static = Path(webapp.__file__).parent / "static"
    html, js, css, appjs = ((static / n).read_text() for n in ("index.html", "social.js", "social.css", "app.js"))
    assert "/social.js" in html and "/social.css" in html
    for el in set(re.findall(r'\$s\("#((?:sx|sw)-[\w-]+)', js)):
        assert f'id="{el}"' in html, el
    for view in ("social", "watchlist"):
        assert f'data-view="{view}" data-side="watchtower"' in html and f'id="view-{view}"' in html and f'"{view}"' in appjs
    assert "socialOnView" in appjs and "window.socialOnView" in js
    for cls in set(re.findall(r'class="(sx-[\w-]+)', js)):
        assert f".{cls}" in css or cls in {"sx-run-hits", "sx-hit-top"} or f".{cls}" in css, cls
    for status in ("ok", "partial", "snippet_only", "blocked", "rate_limited", "no_results", "not_found", "queued"):
        assert f".sx-{status}" in css, status
    assert "innerHTML" in js and js.count("esc(") > 40                                               # everything rendered is escaped
