import base64
import datetime as dt
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from hunter.config import load
from hunter.store import HuntStore
from test_hunter_campaigns import phishing_net
from test_hunter_enrich import NOW
from web.hunter_routes import build_router

CFG = load("hunter.yaml")


def make_client(path, *, who="", source="self_asserted", ephemeral=False):
    """A standalone app around the router: identity is injected exactly as web/app.py injects it."""
    app = FastAPI()

    def identity(request, claimed):
        return (who or (claimed or "").strip()[:100]), source
    app.include_router(build_router(lambda: path, lambda: CFG, identity, lambda: ephemeral, clock=lambda: NOW + dt.timedelta(hours=1)))
    return TestClient(app)


@pytest.fixture
def world(tmp_path):
    path = str(tmp_path / "hunter.db")
    h, (a, b) = phishing_net(path)
    return {"h": h, "a": a, "b": b, "path": path, "c": make_client(path)}


def body(r, code=200):
    assert r.status_code == code, (r.status_code, r.text[:300])
    return r.json()


def disp(c, cid, disposition="CONFIRMED_SCAM", analyst="analyst-1", reason="same kit as case 12", **extra):
    return c.post(f"/api/hunter/candidates/{cid}/disposition", json={"disposition": disposition, "analyst": analyst, "reason": reason, **extra})


# -- overview and feed ------------------------------------------------------------------------------------------------------------

def test_status_summarises_the_last_day_without_leaking_configuration(world):
    r = body(world["c"].get("/api/hunter/status"))
    m = r["metrics"]
    assert m["candidates_discovered"] >= 2 and m["new_campaigns"] == 1 and m["high_priority"] >= 2 and m["pending_review"] >= 2
    assert m["candidates_investigated"] >= 2 and m["new_indicators"] >= 1 and r["persistent_storage"] is True
    assert r["queue"]["total"] >= 5 and set(r["providers"]) == {"healthy", "degraded", "failing", "not_run", "disabled"}
    blob = json.dumps(r)
    assert world["path"] not in blob and "WATCHTOWER" not in blob and "hunter.yaml" not in blob


def test_candidate_feed_is_sorted_filtered_and_paginated(world):
    c = world["c"]
    feed = body(c.get("/api/hunter/candidates", params={"type": "domain"}))
    scores = [i["risk_score"] for i in feed["items"] if i["risk_score"] is not None]
    assert scores == sorted(scores, reverse=True) and feed["total"] == len(feed["items"])
    top = feed["items"][0]
    assert {"indicator", "type", "brand", "market", "source", "risk_score", "classification", "campaign", "status", "disposition"} <= set(top)
    assert top["campaign"].startswith("WT-CMP-") and top["market"] == "Kenya"
    assert all(i["classification"] == "HIGH_PRIORITY" for i in body(c.get("/api/hunter/candidates", params={"classification": "high_priority"}))["items"])
    assert body(c.get("/api/hunter/candidates", params={"q": "first"}))["items"][0]["indicator"] == "mpesa-first.com"
    page = body(c.get("/api/hunter/candidates", params={"limit": 2, "offset": 1}))
    assert len(page["items"]) == 2 and page["offset"] == 1 and page["total"] > 2
    camp = body(c.get("/api/hunter/campaigns"))["items"][0]["public_id"]
    assert {i["indicator"] for i in body(c.get("/api/hunter/candidates", params={"campaign": camp}))["items"]} >= {"mpesa-first.com", "mpesa-second.com"}
    assert body(c.get("/api/hunter/candidates", params={"campaign": "WT-CMP-1999-0001"}))["items"] == []
    assert all(i["disposition"] is None for i in body(c.get("/api/hunter/candidates", params={"disposition": "unreviewed", "type": "domain"}))["items"])


def test_filter_inputs_are_validated_and_treated_as_data(world):
    c = world["c"]
    assert c.get("/api/hunter/candidates", params={"classification": "nonsense"}).status_code == 400
    assert c.get("/api/hunter/candidates", params={"limit": 5000}).status_code == 422
    assert c.get("/api/hunter/candidates", params={"offset": -1}).status_code == 422
    assert c.get("/api/hunter/candidates", params={"q": "x" * 101}).status_code == 422
    assert body(c.get("/api/hunter/candidates", params={"q": "' OR 1=1 --"}))["items"] == []
    assert body(c.get("/api/hunter/candidates", params={"q": "%"}))["items"] == []                  # a literal percent sign, not a wildcard
    assert body(c.get("/api/hunter/candidates", params={"source": "x'; DROP TABLE hunt_candidates;--"}))["items"] == []
    assert body(c.get("/api/hunter/status"))["queue"]["total"] > 0                                  # the table survived


# -- the investigation page ----------------------------------------------------------------------------------------------------------

def test_investigation_view_answers_why_how_what_and_where(world):
    r = body(world["c"].get(f"/api/hunter/investigations/{world['a']}"))
    assert r["candidate"]["indicator"] == "mpesa-first.com" and r["score"]["classification"] == "HIGH_PRIORITY"
    why = {w["signal"]: w for w in r["why_flagged"]}
    assert why["pin_field"]["weight"] == 20 and why["pin_field"]["evidence_ids"] and "form asks for a PIN" in why["pin_field"]["evidence"]
    known = {e["id"] for e in r["evidence"]}
    assert set(why["pin_field"]["evidence_ids"]) <= known or world["h"].graph.conn.execute("SELECT 1 FROM evidence WHERE id=?", (why["pin_field"]["evidence_ids"][0],)).fetchone()
    assert r["how_found"][0]["canonical"] == "mpesa-first.com" and r["first_discovered"]["source"] == "certificate_transparency"
    assert {"WhatsApp", "IPs", "Nameservers"} <= set(r["indicators"])
    assert {x["relationship_type"] for x in r["relationships"]} >= {"uses_whatsapp", "resolves_to", "member_of_campaign"}
    assert all(isinstance(e["raw_metadata"], dict) for e in r["evidence"]) and r["score_history"][-1]["trigger"] in {"deep", "campaign_change"}
    assert r["campaign"]["public_id"].startswith("WT-CMP-") and r["campaign"]["theme"] == "Credential phishing"
    assert r["coverage"]["page"] == "assessed" and r["dispositions"] == [] and r["changes"] == []


def test_unknown_and_malformed_ids_are_rejected_without_leaking(world):
    c = world["c"]
    assert c.get("/api/hunter/investigations/domain:nope").status_code == 404
    for bad in ("..%2F..%2Fetc%2Fpasswd", "a b", "x;y", "%27%20OR%201%3D1", "a" * 200):
        assert c.get(f"/api/hunter/investigations/{bad}").status_code in {400, 404}
    r = c.get("/api/hunter/investigations/domain:nope")
    assert world["path"] not in r.text and "Traceback" not in r.text


def test_indicator_and_relationship_endpoints_carry_provenance(world):
    c = world["c"]
    wa = next(i for i in body(c.get("/api/hunter/candidates", params={"type": "whatsapp"}))["items"])
    ind = body(c.get(f"/api/hunter/indicators/{wa['id']}"))
    assert ind["entity"]["canonical_value"] == "+254700000001" and {u["domain"] for u in ind["used_by"]} == {"mpesa-first.com", "mpesa-second.com"}
    assert ind["campaigns"][0]["members_using"] == 2 and all(u["evidence_id"] for u in ind["used_by"])
    rels = body(c.get("/api/hunter/relationships", params={"entity": world["a"], "type": "uses_whatsapp"}))["items"]
    assert rels and rels[0]["target"] == "+254700000001" and rels[0]["evidence_id"] and rels[0]["evidence_source"] == "signals"
    assert c.get("/api/hunter/relationships", params={"limit": 9999}).status_code == 422
    assert c.get("/api/hunter/indicators/nope").status_code == 404


# -- operations ------------------------------------------------------------------------------------------------------------------------

def test_queue_monitor_counts_every_state_and_explains_deferrals(world):
    h = world["h"]
    cid = h.add("mpesa-wait.com")
    h.store.claim(1)
    h.store.defer(h.store.list("INVESTIGATING")[0]["id"], "daily deep-investigation budget reached (30/hour)", NOW + dt.timedelta(hours=3))
    r = body(world["c"].get("/api/hunter/queue"))
    assert set(r) >= {"queued", "running", "completed", "failed", "retrying", "deferred", "stored_only", "deferred_reasons", "recent_failures"}
    assert r["deferred"] == 1 and r["deferred_reasons"][0]["reason"].startswith("daily deep-investigation budget reached")
    assert r["completed"] >= 2 and r["running"] == 0 and cid


def test_provider_coverage_lists_working_failing_and_unsupported_sources(world):
    r = body(world["c"].get("/api/hunter/providers"))
    rows = {s["source"]: s for s in r["sources"]}
    assert rows["dns"]["status"] == "healthy" and rows["tls"]["status"] == "healthy" and rows["certificate_transparency"]["status"] == "not_run"
    assert rows["x"]["status"] == "unavailable" and "reason" in rows["x"] and isinstance(r["recent_runs"], list)


def test_alerts_list_and_acknowledge_once_by_a_named_analyst(world):
    from hunter.alerts import AlertEngine
    AlertEngine(world["h"].store, world["h"].graph, CFG, env={}).evaluate()
    c = world["c"]
    items = body(c.get("/api/hunter/alerts"))["items"]
    assert items and items[0]["kind"] and body(c.get("/api/hunter/alerts", params={"unacknowledged": True}))["items"]
    first = items[0]["id"]
    assert c.post(f"/api/hunter/alerts/{first}/ack", json={}).status_code == 400                 # no analyst name
    assert body(c.post(f"/api/hunter/alerts/{first}/ack", json={"analyst": "analyst-1"}))["identity_source"] == "self_asserted"
    assert c.post(f"/api/hunter/alerts/{first}/ack", json={"analyst": "analyst-2"}).status_code == 404
    assert all(a["id"] != first for a in body(c.get("/api/hunter/alerts", params={"unacknowledged": True}))["items"])


# -- campaigns -------------------------------------------------------------------------------------------------------------------------

def test_campaign_endpoints_give_the_overview_the_why_and_the_graph(world):
    c = world["c"]
    (item,) = body(c.get("/api/hunter/campaigns"))["items"]
    assert item["name"].endswith("Cluster #1") and item["infrastructure"]["Domains"] == 3 and "why_related" not in item
    full = body(c.get(f"/api/hunter/campaigns/{item['public_id']}"))
    assert {w["link"] for w in full["why_related"]} >= {"shares_phone", "shares_analytics_id"} and full["events"][-1]["event"] == "created"
    g = body(c.get(f"/api/hunter/campaigns/{item['id']}/graph"))
    assert {n["type"] for n in g["nodes"]} >= {"domain", "whatsapp"} and all(e["evidence_id"] for e in g["edges"])
    assert c.get("/api/hunter/campaigns/WT-CMP-1999-0001").status_code == 404
    assert c.get("/api/hunter/campaigns/nope/graph").status_code == 404


# -- dispositions ----------------------------------------------------------------------------------------------------------------------

def test_a_disposition_is_recorded_with_who_when_why_and_the_candidate_is_kept(world):
    c, a = world["c"], world["a"]
    r = body(disp(c, a, "FALSE_POSITIVE", reason="the operator's own security-awareness page", notes="checked with comms"))
    assert r["disposition"] == "FALSE_POSITIVE" and r["previous"] is None
    inv = body(c.get(f"/api/hunter/investigations/{a}"))
    (d,) = inv["dispositions"]
    assert (d["analyst"], d["identity_source"], d["reason"], d["notes"]) == ("analyst-1", "self_asserted", "the operator's own security-awareness page", "checked with comms")
    assert d["at"] and inv["candidate"]["disposition"] == "FALSE_POSITIVE" and inv["candidate"]["indicator"] == "mpesa-first.com"   # kept, never deleted
    body(disp(c, a, "MONITOR", reason="re-opened: page changed"))
    hist = body(c.get(f"/api/hunter/investigations/{a}"))["dispositions"]
    assert [x["disposition"] for x in hist] == ["FALSE_POSITIVE", "MONITOR"] and hist[1]["previous"] == "FALSE_POSITIVE"      # append-only chain
    assert [i["indicator"] for i in body(c.get("/api/hunter/candidates", params={"disposition": "monitor"}))["items"]] == ["mpesa-first.com"]


@pytest.mark.parametrize("payload,code", [
    ({"disposition": "NOPE", "analyst": "a", "reason": "x"}, 400),
    ({"disposition": "BENIGN", "analyst": "a", "reason": ""}, 400),
    ({"disposition": "BENIGN", "analyst": "", "reason": "x"}, 400),
    ({"analyst": "a", "reason": "x"}, 400),
])
def test_disposition_input_is_validated(world, payload, code):
    assert world["c"].post(f"/api/hunter/candidates/{world['a']}/disposition", json=payload).status_code == code
    assert body(world["c"].get(f"/api/hunter/investigations/{world['a']}"))["dispositions"] == []


def test_every_disposition_in_the_brief_is_accepted_and_unknown_candidates_404(world):
    for d in ("UNREVIEWED", "BENIGN", "FALSE_POSITIVE", "SUSPICIOUS", "CONFIRMED_IMPERSONATION", "CONFIRMED_SCAM", "MONITOR"):
        assert disp(world["c"], world["b"], d, reason="r").status_code == 200, d
    assert disp(world["c"], "domain:nope").status_code == 404


def test_confirming_a_domain_raises_the_score_of_domains_that_share_its_infrastructure(world):
    c, a, b = world["c"], world["a"], world["b"]
    before = body(c.get(f"/api/hunter/investigations/{b}"))["score"]
    assert "known_malicious_infrastructure" not in {r["signal"] for r in before["reasons"]}
    r = body(disp(c, a, "CONFIRMED_SCAM"))
    assert r["rescored"] >= 1
    after = body(c.get(f"/api/hunter/investigations/{b}"))
    reason = next(x for x in after["why_flagged"] if x["signal"] == "known_malicious_infrastructure")
    assert reason["weight"] == 25 and "mpesa-first.com" in reason["evidence"] and reason["evidence_ids"]
    assert after["score_history"][-1]["trigger"] == "analyst_verdict"
    # the same confirmation via the campaign
    camp = body(c.get("/api/hunter/campaigns"))["items"][0]["id"]
    assert body(c.post(f"/api/hunter/campaigns/{camp}/disposition", json={"disposition": "CONFIRMED_IMPERSONATION", "analyst": "analyst-2", "reason": "whole kit"}))["campaign_id"] == camp
    assert body(c.get(f"/api/hunter/campaigns/{camp}"))["dispositions"][0]["disposition"] == "CONFIRMED_IMPERSONATION"


def test_a_cleared_candidate_stops_raising_score_alerts_but_new_evidence_still_can(world):
    from hunter.alerts import AlertEngine
    h, c, a = world["h"], world["c"], world["a"]
    body(disp(c, a, "FALSE_POSITIVE", reason="reviewed"))
    out = AlertEngine(h.store, h.graph, CFG, env={}).evaluate()
    assert not [x for x in out["raised"] if x["key"] == f"high:{a}"]
    h.store.add_change(a, "page_turned_hostile", "page now shows: credential_form", meaningful=True, evidence_id="e-new")
    out2 = AlertEngine(h.store, h.graph, CFG, env={}).evaluate()
    assert any(x["key"] == f"change:{a}:page_turned_hostile" for x in out2["raised"])


def test_authenticated_identity_cannot_be_spoofed_by_the_payload(world):
    c = make_client(world["path"], who="shared-account", source="authenticated")
    body(disp(c, world["a"], "SUSPICIOUS", analyst="someone-else", reason="r"))
    (d,) = body(c.get(f"/api/hunter/investigations/{world['a']}"))["dispositions"]
    assert (d["analyst"], d["identity_source"]) == ("shared-account", "authenticated")


def test_writes_refuse_on_ephemeral_storage_but_reads_work(world):
    c = make_client(world["path"], ephemeral=True)
    assert disp(c, world["a"]).status_code == 409 and "durable storage" in disp(c, world["a"]).text
    assert c.post("/api/hunter/trusted-domains", json={"domain": "x.com", "analyst": "a", "reason": "r"}).status_code == 409
    assert c.post("/api/hunter/alerts/1/ack", json={"analyst": "a"}).status_code == 409
    assert c.get("/api/hunter/status").json()["persistent_storage"] is False and c.get("/api/hunter/candidates").status_code == 200


# -- feedback loop: surfaced, never applied --------------------------------------------------------------------------------------------

def seed_cases(world, n, disposition, prefix):
    h = world["h"]
    ids = []
    for i in range(n):
        cid = h.add(f"{prefix}{i}-site.com")
        h.store.record_score(cid, trigger="t", score=80, classification="HIGH_PRIORITY", assessment="complete", version="1", config_hash="x",
                             content_hash=f"{prefix}{i}", coverage={},
                             reasons=[{"signal": s, "weight": 10, "evidence": "e", "basis": "evidence", "evidence_ids": [], "family": None}
                                      for s in ("whatsapp_cta", "login_form", "recently_registered")])
        assert disp(world["c"], cid, disposition, reason="r").status_code == 200
        ids.append(cid)
    return ids


def test_patterns_in_confirmed_cases_are_surfaced_only_with_enough_support_and_change_no_weights(world):
    weights_before = dict(CFG.scoring.weights)
    seed_cases(world, 2, "CONFIRMED_SCAM", "kit")
    assert body(world["c"].get("/api/hunter/insights"))["patterns"] == []                        # 2 cases: below min_support
    seed_cases(world, 1, "CONFIRMED_SCAM", "kitb")
    ins = body(world["c"].get("/api/hunter/insights"))
    top = next(p for p in ins["patterns"] if p["signals"] == ["login_form", "recently_registered", "whatsapp_cta"])
    assert top["confirmed_cases"] >= 3 and top["false_positive_cases"] == 0 and "unchanged" in top["note"]
    assert CFG.scoring.weights == weights_before and ins["min_support"] == 3


def test_repeated_false_positives_suggest_a_trusted_domain_that_needs_approval_and_is_attributed(world):
    h, c = world["h"], world["c"]
    for sub in ("a", "b", "c"):
        cid = h.add(f"{sub}.newsroom.example.com")
        body(disp(c, cid, "FALSE_POSITIVE", reason="news coverage"))
    ins = body(c.get("/api/hunter/insights"))
    (sug,) = [s for s in ins["suggestions"] if s["value"] == "example.com"]
    assert sug["cases"] == 3 and sug["needs"] == "administrator approval" and ins["approved_trusted"] == []
    victim = h.add("mpesa.newsroom.example.com")
    from hunter.scoring import rescore
    h.store.record_score(victim, trigger="t", score=40, classification="WATCH", assessment="complete", version="1", config_hash="x", content_hash="v", reasons=[], coverage={})
    # nothing changes until an administrator approves
    assert "trusted_third_party" not in {r.signal for r in rescore(h.store, h.graph, CFG, h.ctx.brands, victim, "t")[0].reasons}
    assert c.post("/api/hunter/trusted-domains", json={"domain": "example.com", "analyst": "admin-1"}).status_code == 400     # reason required
    assert c.post("/api/hunter/trusted-domains", json={"domain": "not a domain", "analyst": "admin-1", "reason": "r"}).status_code == 400
    r = body(c.post("/api/hunter/trusted-domains", json={"domain": "https://news.example.com/x", "analyst": "admin-1", "reason": "three reviewed false positives"}))
    assert r["added"] and r["domain"] == "example.com" and r["rescored"] >= 1
    approved = body(c.get("/api/hunter/insights"))["approved_trusted"]
    assert approved[0]["by"] == "admin-1" and approved[0]["identity_source"] == "self_asserted" and approved[0]["reason"]
    assert not [s for s in body(c.get("/api/hunter/insights"))["suggestions"] if s["value"] == "example.com"]
    last = h.store.latest_score(victim)
    assert last["trigger"] == "config_change" and "trusted_third_party" in {x["signal"] for x in last["reasons"]}
    assert body(c.post("/api/hunter/trusted-domains", json={"domain": "example.com", "analyst": "admin-1", "reason": "again"}))["added"] is False
    assert body(c.delete("/api/hunter/trusted-domains/example.com"))["removed"] is True
    assert "trusted_third_party" not in {x["signal"] for x in h.store.latest_score(victim)["reasons"]}
    assert CFG.scoring.trusted_domains == []                                                      # the config file's list was never touched


def test_small_samples_never_suggest_anything(world):
    for sub in ("a", "b"):
        disp(world["c"], world["h"].add(f"{sub}.small-news.example.org"), "FALSE_POSITIVE", reason="r")
    assert body(world["c"].get("/api/hunter/insights"))["suggestions"] == []


# -- the app wiring ----------------------------------------------------------------------------------------------------------------------

def test_the_real_app_protects_the_hunter_api_with_the_same_auth_as_everything_else(tmp_path, monkeypatch):
    import web.app as webapp
    monkeypatch.setattr(webapp, "DATA_DIR", tmp_path)
    monkeypatch.setattr(webapp, "WT_PASSWORD", "s3cret")
    monkeypatch.setattr(webapp, "WT_USER", "watchtower")
    monkeypatch.setattr(webapp, "_request_requires_auth", lambda request: True)
    client = TestClient(webapp.app)
    assert client.get("/api/hunter/status").status_code == 401
    assert client.get("/api/hunter/candidates").status_code == 401
    assert client.post("/api/hunter/candidates/x/disposition", json={}).status_code == 401
    good = {"Authorization": "Basic " + base64.b64encode(b"watchtower:s3cret").decode()}
    r = client.get("/api/hunter/status", headers=good)
    assert r.status_code == 200 and r.json()["queue"]["total"] == 0
    monkeypatch.setattr(webapp, "_request_requires_auth", lambda request: False)
    local = TestClient(webapp.app)
    assert local.get("/api/hunter/status").status_code == 200 and local.get("/").status_code == 200
    assert webapp._analyst_identity.__name__ == "_analyst_identity"


def test_a_missing_config_is_a_visible_503_that_does_not_reveal_paths(tmp_path):
    from hunter.config import ConfigError
    app = FastAPI()

    def broken():
        raise ConfigError(f"hunter config not found: {tmp_path}/hunter.yaml")
    app.include_router(build_router(lambda: str(tmp_path / "x.db"), broken, lambda r, c: ("a", "self_asserted")))
    r = TestClient(app).get("/api/hunter/status")
    assert r.status_code == 503 and str(tmp_path) not in r.text and "missing" in r.json()["detail"]
    assert HuntStore is not None
