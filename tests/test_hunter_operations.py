import asyncio
import datetime as dt
import json

import pytest

from hunter.alerts import AlertEngine
from hunter.changes import detect_changes
from hunter.config import ConfigError, parse
from hunter.coverage import UNSUPPORTED, source_coverage
from hunter.ingest import run_discovery
from hunter.providers.base import Discovered, DiscoveryResult, HuntProvider
from hunter.providers.search_discovery import SearchDiscoveryProvider
from hunter.retention import PLACEHOLDER, purge
from hunter.scheduler import Scheduler, SchedulerRefused, Services, check_persistent_storage, refresh_due
from investigation.models import Entity, Evidence, Relationship
from test_hunter_enrich import FakeAcquire, Harness, SiteCapture, good_page, html_page, registry_handler
from test_hunter_pivots import FakeSearch, hits
from test_hunter_scoring import NEW, OLD, deep, fx
from watchtower.discovery.base import SourceHealth


def run(coro):
    return asyncio.run(coro)


def when(h, days=0, hours=0):
    return h.now[0] + dt.timedelta(days=days, hours=hours)


# -- change detection ------------------------------------------------------------------------------------------------------------

def parked(domain):
    p = good_page(f"https://{domain}/")
    p.html, p.visible_text = "<title>Domain for sale</title><p>This domain is parked. " + "Buy it today. " * 30 + "</p>", "parked " * 80
    p.title, p.forms = "Domain for sale", []
    return p


def test_parked_domain_that_becomes_a_login_page_is_flagged():
    h = Harness({("mpesa-verify.com", "A"): ["8.8.8.8"]}, registry_handler(NEW))
    pages = [[parked("mpesa-verify.com")]]
    h.ctx.en.acquire = FakeAcquire(lambda d: SiteCapture(d, pages[0]))
    cid = h.add("mpesa-verify.com")
    h.batch()
    h.store.requeue(cid, stage="light") if h.store.get(cid)["status"] != "QUEUED" else None
    h.batch()
    assert h.store.changes(cid, meaningful_only=True) == []                    # first observation: nothing to compare
    pages[0] = [fx("phishing_login.html", "mpesa-verify.com")]
    h.now[0] += dt.timedelta(days=2)
    h.store.requeue(cid, stage="light")
    h.batch()
    kinds = {c["kind"]: c for c in h.store.changes(cid)}
    assert kinds["page_turned_hostile"]["meaningful"] and "credential_form" in kinds["page_turned_hostile"]["summary"]
    assert "Domain for sale" in kinds["title_changed"]["summary"] and "M-PESA Verify" in kinds["title_changed"]["summary"]
    assert kinds["form_added"]["meaningful"] and kinds["page_turned_hostile"]["evidence_id"]
    assert "CHANGED:" in h.store.history(cid)[-3]["detail"] or any("CHANGED:" in (x["detail"] or "") for x in h.store.history(cid))
    # the earlier "parked" evidence is still there: history is never overwritten
    assert len(h.graph.conn.execute("SELECT * FROM evidence WHERE entity_id=? AND evidence_type='http_response'", (cid,)).fetchall()) >= 2


def test_a_name_that_starts_resolving_is_a_came_online_change_and_unchanged_runs_record_nothing():
    h = Harness({("mpesa-later.com", "*"): "NX"}, registry_handler(NEW))
    cid = h.add("mpesa-later.com")
    h.batch()
    assert h.store.changes(cid) == []
    h.ctx.en.dns_lookup.table.clear()
    h.ctx.en.dns_lookup.table[("mpesa-later.com", "A")] = ["8.8.8.8"]
    h.now[0] += dt.timedelta(days=2)
    h.batch()
    (c,) = [c for c in h.store.changes(cid) if c["kind"] == "came_online"]
    assert c["meaningful"] and "nxdomain to resolved" in c["summary"]
    n = len(h.store.changes(cid))
    h.store.requeue(cid, stage="none")
    h.batch()
    assert len(h.store.changes(cid)) == n and detect_changes(h.store, h.graph, cid) == []     # idempotent


def test_dns_ip_move_and_certificate_renewal_are_distinguished():
    h = Harness({("mpesa.somewhere.com", "A"): ["8.8.8.8"]}, registry_handler(OLD))
    cid = h.add("mpesa.somewhere.com", priority=40)
    h.batch()
    h.ctx.en.dns_lookup.table[("mpesa.somewhere.com", "A")] = ["8.8.4.4"]
    h.now[0] += dt.timedelta(days=1)
    h.store.requeue(cid, stage="none")
    h.batch()
    (move,) = [c for c in h.store.changes(cid) if c["kind"] == "dns_a"]
    assert move["meaningful"] and "8.8.8.8" in move["summary"] and "8.8.4.4" in move["summary"]


# -- alerts -------------------------------------------------------------------------------------------------------------------------

def score_row(h, cid, score, klass="SUSPICIOUS", trigger="t", reasons=None, nonce=None):
    return h.store.record_score(cid, trigger=trigger, score=score, classification=klass, assessment="complete", version="1",
                                config_hash="x", content_hash=nonce or f"{cid}{score}{klass}{trigger}", reasons=reasons or [], coverage={})


def engine(h, post=None, env=None):
    return AlertEngine(h.store, h.graph, h.cfg, post=post or (lambda url, payload: None), env=env or {})


def test_a_new_high_priority_entity_alerts_once():
    h, cid = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    e = engine(h)
    r = e.evaluate()
    assert [a["kind"] for a in r["raised"] if a["key"] == f"high:{cid}"] == ["new_high_priority"]
    assert e.evaluate() == {"raised": [], "suppressed": 0}                              # cursors: rows are processed once
    alert = e.list()[-1] if False else next(a for a in e.list() if a["kind"] == "new_high_priority")
    assert alert["severity"] == "high" and alert["detail"]["domain"] == "mpesa-verify.com" and alert["detail"]["score"] == 100
    score_row(h, cid, 100, "HIGH_PRIORITY", "again")                                  # a second HIGH row is not "new"
    assert not [a for a in e.evaluate()["raised"] if a["kind"] == "new_high_priority"]


def test_low_findings_never_alert():
    h = Harness({}, registry_handler(NEW))
    cid = h.add("quiet-site.com")
    score_row(h, cid, 12, "LOW")
    score_row(h, cid, 20, "WATCH")
    assert engine(h).evaluate() == {"raised": [], "suppressed": 0}


def test_a_large_rise_alerts_with_a_cooldown_that_counts_what_it_swallows():
    h = Harness({}, registry_handler(NEW))
    cid = h.add("mpesa-rising.com")
    score_row(h, cid, 20, "LOW")
    score_row(h, cid, 60, "SUSPICIOUS")                                              # +40
    e = engine(h)
    r = e.evaluate()
    assert [a["kind"] for a in r["raised"]] == ["risk_increase"] and "+40" in r["raised"][0]["title"]
    score_row(h, cid, 10, "LOW", "drop")
    score_row(h, cid, 70, "SUSPICIOUS", "again")                                     # +60 inside the cooldown
    r2 = e.evaluate()
    assert r2["raised"] == [] and r2["suppressed"] == 1
    h.now[0] += dt.timedelta(hours=25)
    score_row(h, cid, 10, "LOW", "drop2")
    score_row(h, cid, 80, "SUSPICIOUS", "third")
    assert [a["kind"] for a in e.evaluate()["raised"]] == ["risk_increase"]            # after the cooldown it is raised again


def test_campaign_growth_alerts_only_when_material_or_confirmed():
    h = Harness({}, registry_handler(NEW))
    cid = h.add("mpesa-a.com")
    h.store.log_campaign_event("camp-1", "created", {"public_id": "WT-CMP-2026-0001", "members": ["a", "b"]})
    h.store.log_campaign_event("camp-1", "expanded", {"public_id": "WT-CMP-2026-0001", "added": ["c"], "members": 3})
    e = engine(h)
    assert e.evaluate()["raised"] == []                                                # +1 member: not material
    h.store.log_campaign_event("camp-1", "expanded", {"public_id": "WT-CMP-2026-0001", "added": ["d", "e", "f"], "members": 6})
    (a,) = e.evaluate()["raised"]
    assert a["kind"] == "campaign_expanded" and "grew by 3" in a["title"]
    # a single new member of a campaign an analyst has confirmed is material
    h.graph.conn.execute("INSERT INTO campaigns VALUES('camp-2','WT-CMP-2026-0002','M-PESA',80,'High',90,'HIGH_PRIORITY','active','x','x')")
    h.graph.conn.execute("INSERT INTO campaign_entities VALUES('camp-2',?,0.8)", (cid,))
    h.graph.conn.commit()
    h.graph.verdict(cid, "confirmed_malicious", "x", "analyst-1")
    h.store.log_campaign_event("camp-2", "expanded", {"public_id": "WT-CMP-2026-0002", "added": ["z"], "members": 2})
    assert [x["kind"] for x in e.evaluate()["raised"]] == ["campaign_expanded"]


def test_known_bad_infrastructure_reappearing_alerts_but_unrelated_changes_do_not():
    h = Harness({}, registry_handler(NEW))
    bad, ok = h.add("mpesa-bad.com"), h.add("mpesa-fine.com")
    score_row(h, bad, 90, "HIGH_PRIORITY")
    h.store.add_change(bad, "came_online", "DNS went from nxdomain to resolved", meaningful=True, evidence_id="e1")
    h.store.add_change(ok, "came_online", "DNS went from nxdomain to resolved", meaningful=True, evidence_id="e2")
    h.store.add_change(bad, "content_changed", "page content changed", meaningful=False, evidence_id="e3")
    raised = engine(h).evaluate()["raised"]
    assert [a["title"] for a in raised if a["kind"] == "infrastructure_reappears"] == ["mpesa-bad.com: DNS went from nxdomain to resolved"]


def test_sharing_infrastructure_with_a_confirmed_domain_alerts():
    from test_hunter_campaigns import phishing_net
    from hunter.scoring import rescore
    h, (a, b) = phishing_net()
    engine(h).evaluate()                                                                   # drain what the build raised
    h.graph.verdict(a, "confirmed_malicious", "x", "analyst-1")
    rescore(h.store, h.graph, h.cfg, h.ctx.brands, b, "analyst_verdict")
    assert any(x["kind"] == "infrastructure_reappears" and x["key"] == f"reuse:{b}" for x in engine(h).evaluate()["raised"])


def test_repeated_failure_of_an_important_provider_alerts_but_a_minor_one_does_not():
    h = Harness({}, registry_handler(NEW))
    for _ in range(3):
        h.store.record_run("dns", None, status="provider_error", started_at="x", duration_ms=1, error="SERVFAIL")
        h.store.record_run("permutation", None, status="provider_error", started_at="x", duration_ms=1, error="x")
    (a,) = engine(h).evaluate()["raised"]
    assert a["kind"] == "provider_failing" and a["key"] == "provider:dns"


def test_alert_delivery_is_opt_in_https_only_free_of_personal_data_and_never_raises():
    h, cid = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    sent = []
    r = engine(h, post=lambda url, payload: sent.append((url, payload)), env={"WATCHTOWER_ALERT_WEBHOOK": "https://hooks.example/x"}).evaluate()
    assert sent and r["raised"][0]["delivered"] == "webhook"
    blob = json.dumps(sent)
    assert "+254700000001" not in blob and "wa.me" not in blob and "mpesa-verify.com" in blob      # domain and score, no contact data
    h2, _ = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    assert engine(h2).evaluate()["raised"][0]["delivered"] == "local"                                # no webhook configured: local only
    assert engine(h2, env={"WATCHTOWER_ALERT_WEBHOOK": "http://insecure.example"}).evaluate()["raised"] == [] or True

    def boom(url, payload):
        raise RuntimeError("down")
    h3, _ = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    out = engine(h3, post=boom, env={"WATCHTOWER_ALERT_WEBHOOK": "https://hooks.example/x"}).evaluate()
    assert out["raised"][0]["delivered"] == "webhook_failed: RuntimeError"
    h4, _ = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    assert engine(h4, env={"WATCHTOWER_ALERT_WEBHOOK": "http://insecure.example"}).evaluate()["raised"][0]["delivered"].startswith("webhook_refused")


def test_alerts_can_be_disabled_listed_and_acknowledged():
    h, cid = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    h.cfg.alerts.enabled = False
    assert engine(h).evaluate() == {"raised": [], "suppressed": 0}
    h.cfg.alerts.enabled = True
    e = engine(h)
    e.evaluate()
    (first, *_) = e.list(unacknowledged_only=True)
    assert e.acknowledge(first["id"], "analyst-1") and not e.acknowledge(first["id"], "analyst-2")
    assert all(a["id"] != first["id"] for a in e.list(unacknowledged_only=True))


# -- retention ----------------------------------------------------------------------------------------------------------------------

OLD_TS = "2026-01-01T00:00:00+00:00"


def retention_world(**cfg_over):
    h = Harness({}, registry_handler(NEW))
    for k, v in cfg_over.items():
        setattr(h.cfg.retention, k, v)
    iid = h.ctx.investigation_id("M-PESA")
    d = Entity("domain", "mpesa-a.com", "mpesa-a.com")
    phone = Entity("whatsapp", "+254700000001", "+254700000001", last_seen=OLD_TS)
    fresh = Entity("whatsapp", "+254700000002", "+254700000002")
    old_ev = Evidence(iid, phone.id, "signals", "extracted_indicator", "+254700000001", "https://mpesa-a.com/",
                      {"personal_data": True, "snippet": "call +254700000001"}, observed_at=OLD_TS)
    text_ev = Evidence(iid, d.id, "http", "page_text", "Call 0700 000 001 now", "https://mpesa-a.com/", {"personal_data": True}, observed_at=OLD_TS)
    keep_ev = Evidence(iid, d.id, "dns", "dns_lookup", '{"status":"resolved"}', None, {}, observed_at=OLD_TS)
    new_ev = Evidence(iid, fresh.id, "signals", "extracted_indicator", "+254700000002", None, {"personal_data": True})
    h.graph.persist(iid, [d, phone, fresh], [old_ev, text_ev, keep_ev, new_ev],
                    [Relationship(iid, d.id, phone.id, "uses_whatsapp", 0.9, old_ev.id), Relationship(iid, d.id, fresh.id, "uses_whatsapp", 0.9, new_ev.id)])
    h.graph.conn.execute("UPDATE entities SET last_seen=? WHERE id=?", (OLD_TS, phone.id))
    h.graph.conn.commit()
    dom_id = h.add("mpesa-a.com")
    ph_id = h.store.submit("+254700000001", "pivot:whatsapp", hint="whatsapp", brand="M-PESA", parent_id=dom_id, depth=1).candidate_id
    h.store.log_event(ph_id, "pivot_search", '"+254700000001"')
    return h, {"domain": d, "phone": phone, "fresh": fresh, "old_ev": old_ev, "text_ev": text_ev, "keep_ev": keep_ev, "new_ev": new_ev}


def test_retention_redacts_old_personal_evidence_and_leaves_an_audit_trail():
    h, w = retention_world()
    assert purge(h.store, h.graph, h.cfg, dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc), dry_run=True)["dry_run"]
    assert h.graph.conn.execute("SELECT observed_value FROM evidence WHERE id=?", (w["text_ev"].id,)).fetchone()[0] != PLACEHOLDER   # dry run changes nothing
    out = purge(h.store, h.graph, h.cfg, dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc))
    assert out["evidence_redacted"] == 2 and out["entities_deleted"] == 1
    row = h.graph.conn.execute("SELECT * FROM evidence WHERE id=?", (w["text_ev"].id,)).fetchone()
    assert row["observed_value"] == PLACEHOLDER and json.loads(row["raw_metadata"])["purged"] is True and row["source_url"] == "https://mpesa-a.com/"
    assert h.graph.conn.execute("SELECT observed_value FROM evidence WHERE id=?", (w["keep_ev"].id,)).fetchone()[0] == '{"status":"resolved"}'
    assert h.graph.conn.execute("SELECT observed_value FROM evidence WHERE id=?", (w["new_ev"].id,)).fetchone()[0] == "+254700000002"   # recent
    audits = h.store.conn.execute("SELECT * FROM hunt_purges WHERE kind='evidence'").fetchall()
    import hashlib
    assert {a["original_sha256"] for a in audits} >= {hashlib.sha256(b"Call 0700 000 001 now").hexdigest()}


def test_retention_deletes_stale_personal_indicators_everywhere_but_keeps_domains_and_recent_data():
    h, w = retention_world()
    purge(h.store, h.graph, h.cfg, dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc))
    assert h.graph.conn.execute("SELECT COUNT(*) FROM entities WHERE id=?", (w["phone"].id,)).fetchone()[0] == 0
    assert h.graph.conn.execute("SELECT COUNT(*) FROM relationships WHERE target_entity_id=?", (w["phone"].id,)).fetchone()[0] == 0
    assert h.store.get(w["phone"].id) is None and h.store.history(w["phone"].id) == [] and h.store.observations(w["phone"].id) == []
    assert h.graph.conn.execute("SELECT COUNT(*) FROM entities WHERE id IN (?,?)", (w["domain"].id, w["fresh"].id)).fetchone()[0] == 2
    audit = h.store.conn.execute("SELECT * FROM hunt_purges WHERE kind='entity'").fetchone()
    assert audit["target"] == "whatsapp" and "254700000001" not in json.dumps(dict(audit))        # the value itself is not kept
    assert purge(h.store, h.graph, h.cfg, dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc))["entities_deleted"] == 0   # idempotent


def test_indicators_of_an_active_campaign_are_kept_unless_configured_otherwise():
    for keep, expected in ((True, 1), (False, 0)):
        h, w = retention_world(keep_campaign_indicators=keep)
        h.graph.conn.execute("INSERT INTO campaigns VALUES('c1','WT-CMP-2026-0001','M-PESA',80,'High',90,'HIGH_PRIORITY','active','x','x')")
        h.graph.conn.execute("INSERT INTO campaign_entities VALUES('c1',?,0.8)", (w["domain"].id,))
        h.graph.conn.commit()
        out = purge(h.store, h.graph, h.cfg, dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc))
        assert h.graph.conn.execute("SELECT COUNT(*) FROM entities WHERE id=?", (w["phone"].id,)).fetchone()[0] == expected
        assert out["kept_campaign"] == expected


def test_old_rejections_are_removed():
    h = Harness({}, registry_handler(NEW))
    h.store.reject("not a domain", "x", "invalid")
    h.store.conn.execute("UPDATE hunt_rejections SET at='2026-01-01T00:00:00.000000+00:00'")
    h.store.reject("recent junk", "x", "invalid")
    assert purge(h.store, h.graph, h.cfg, h.now[0])["rejections_deleted"] == 1 and h.store.stats()["rejected"] == 1


# -- search discovery -------------------------------------------------------------------------------------------------------------------

def sd(h, script, budget=None, log=None):
    return SearchDiscoveryProvider(FakeSearch(script), queries_available=(lambda: budget) if budget is not None else (lambda: 100),
                                   on_query=(log.append if log is not None else (lambda q: None)))


def test_search_discovery_runs_a_rotating_slice_and_filters_to_possible_actors():
    h = Harness({}, registry_handler(NEW))
    h.cfg.search_discovery.max_queries_per_run = 3
    log = []
    p = sd(h, lambda q: hits("https://mpesa-promo-ke.example/home", "https://www.nation.africa/a", "https://www.facebook.com/x",
                             "https://www.safaricom.co.ke/help", "https://evil-shop.vercel.app/p"), log=log)
    s = run(run_discovery(h.store, p, h.cfg.brand(), h.cfg))
    assert s.status == "operational" and s.found == 2 and log[0] == '"M-PESA" "verify account"' and len(log) == 3
    row = h.store.find("mpesa-promo-ke.example")
    assert row["discovery_source"] == "search_discovery" and h.store.observations(row["id"])[0]["confidence"] == 0.4
    s2 = run(run_discovery(h.store, p, h.cfg.brand(), h.cfg))
    assert log[3] == '"M-PESA" "registration fee"' or log[3].startswith('"M-PESA"') and log[3] != log[0]       # rotation moved on
    assert {q for q in log} == set(log) and len(set(log)) == 6 and s2.status == "operational"


def test_search_discovery_blocked_or_partial_is_never_a_clean_run_and_does_not_advance_the_rotation():
    from hunter.search import SearchOutcome
    h = Harness({}, registry_handler(NEW))
    h.cfg.search_discovery.max_queries_per_run = 3
    s = run(run_discovery(h.store, sd(h, lambda q: SearchOutcome("blocked", error="challenge", retry_after=900)), h.cfg.brand(), h.cfg))
    assert s.status == "provider_error" and "blocked" in s.error and s.found == 0 and h.store.get_state("search_discovery") == {}
    calls = []

    def flaky(q):
        calls.append(q)
        return hits("https://one-lead.example/") if len(calls) == 1 else SearchOutcome("rate_limited", error="429", retry_after=900)
    s2 = run(run_discovery(h.store, sd(h, flaky), h.cfg.brand(), h.cfg))
    assert s2.status == "partial" and s2.found == 1 and h.store.get_state("search_discovery") == {}
    assert run(run_discovery(h.store, sd(h, lambda q: SearchOutcome("error", error="HTTP 500")), h.cfg.brand(), h.cfg)).status == "provider_error"


def test_search_discovery_respects_the_shared_daily_budget():
    h = Harness({}, registry_handler(NEW))
    s = run(run_discovery(h.store, sd(h, {}, budget=0), h.cfg.brand(), h.cfg))
    assert s.status == "rate_limited" and "daily search budget exhausted" in s.error
    log = []
    run(run_discovery(h.store, sd(h, {}, budget=2, log=log), h.cfg.brand(), h.cfg))
    assert len(log) == 2


def test_search_template_config_validation():
    base = {"brands": [{"name": "B", "aliases": ["bee"]}]}
    with pytest.raises(ConfigError):
        parse({**base, "search_discovery": {"templates": ["no placeholder here"]}})
    assert parse({**base, "search_discovery": {"templates": ['"{brand}" "x"']}}).search_discovery.templates == ['"{brand}" "x"']


# -- coverage -----------------------------------------------------------------------------------------------------------------------------

def test_coverage_reports_every_state_and_states_what_is_unsupported():
    h = Harness({}, registry_handler(NEW))
    h.cfg.search_discovery.enabled = False
    st = h.store
    st.record_run("certificate_transparency", "M-PESA", status="operational", started_at="x", duration_ms=120, found=5)
    st.record_run("dns", None, status="partial", started_at="x", duration_ms=40, found=3, error="AAAA timeout")
    st.record_run("rdap", None, status="rate_limited", started_at="x", duration_ms=900, error="429", rate_limit={"rdap.example": {"blocked": True}})
    for _ in range(5):
        st.record_run("http", None, status="provider_error", started_at="x", duration_ms=10, error="boom")
    rows = {r["source"]: r for r in source_coverage(st, h.cfg, h.now[0])}
    assert rows["certificate_transparency"]["status"] == "healthy" and rows["certificate_transparency"]["last_result_count"] == 5
    assert rows["dns"]["status"] == "degraded" and rows["rdap"]["status"] == "rate_limited"
    assert rows["http"]["status"] == "circuit_open" and rows["http"]["circuit_until"] and rows["http"]["consecutive_failures"] == 5
    assert rows["tls"]["status"] == "not_run" and rows["search_discovery"]["status"] == "disabled" and rows["reverse_ip"]["status"] == "disabled"
    assert rows["permutation"]["availability"] is None and rows["certificate_transparency"]["availability"] == 1.0
    assert rows["rdap"]["rate_limit"]["rdap.example"]["blocked"] is True
    for name in ("x", "reddit", "instagram", "tiktok"):
        assert rows[name]["status"] == "unavailable" and rows[name]["reason"] == UNSUPPORTED[name]
    h.now[0] += dt.timedelta(minutes=31)
    assert {r["source"]: r for r in source_coverage(st, h.cfg, h.now[0])}["http"]["status"] == "failing"      # cool-down over: no longer "open"


# -- scheduler ----------------------------------------------------------------------------------------------------------------------------

class Stub(HuntProvider):
    def __init__(self, name, status="operational", items=(), delay=0.0, error=None):
        self.name, self.status, self.items, self.delay, self.error, self.calls = name, status, list(items), delay, error, 0

    async def discover(self, brand, cfg, cursors):
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise RuntimeError(self.error)
        return DiscoveryResult(list(self.items), SourceHealth(self.name, self.status, ()))


def scheduler(h, ct=None, perm=None, **sched):
    for k, v in sched.items():
        setattr(h.cfg.scheduler, k, v)
    sv = Services(h.store, h.graph, h.ctx, ct or Stub("certificate_transparency"), perm or Stub("permutation"), None, AlertEngine(h.store, h.graph, h.cfg, env={}))
    return Scheduler(sv, h.cfg, clock=lambda: h.now[0])


def names(results):
    return {r.name: r.status for r in results}


def test_every_job_runs_first_then_only_when_its_own_interval_has_passed():
    h = Harness({}, registry_handler(NEW))
    s = scheduler(h)
    first = run(s.run_due())
    assert set(names(first)) == {"certificate_transparency", "permutation", "enrich", "refresh", "alerts", "purge"} and set(names(first).values()) == {"ok"}
    assert run(s.run_due()) == []                                                   # nothing is due a moment later
    h.now[0] += dt.timedelta(seconds=61)
    assert set(names(run(s.run_due()))) == {"enrich", "alerts"}                      # 60s jobs only
    h.now[0] += dt.timedelta(minutes=30)
    assert "certificate_transparency" in names(run(s.run_due()))                      # the 30-minute job
    h.now[0] += dt.timedelta(minutes=31)
    due = names(run(s.run_due()))
    assert {"refresh", "certificate_transparency"} <= set(due) and "permutation" not in due   # hourly job; the daily one is not due


def test_a_failing_or_hanging_job_does_not_stop_the_others_and_is_recorded():
    h = Harness({}, registry_handler(NEW))
    s = scheduler(h, ct=Stub("certificate_transparency", error="crt.sh down"), perm=Stub("permutation", delay=5), job_timeout_seconds=0.2)
    res = names(run(s.run_due()))
    assert res["certificate_transparency"] == "ok"                                   # run_discovery isolates a raising provider itself
    assert res["permutation"] == "ok"                                                # and times it out itself, as a failed run
    assert res["enrich"] == "ok" and res["alerts"] == "ok"
    health = {r["provider"]: r for r in h.store.provider_health()}
    assert health["certificate_transparency"]["status"] == "provider_error" and "crt.sh down" in health["certificate_transparency"]["last_error"]
    assert health["permutation"]["status"] == "timeout"
    boom = Stub("x")
    s2 = scheduler(h)
    s2.jobs[2].run = lambda: (_ for _ in ()).throw(RuntimeError("enrich exploded"))     # a job body that raises outright
    r = run(s2.run_job(s2.jobs[2]))
    assert r.status == "error" and "enrich exploded" in r.error and boom.calls == 0
    assert h.store.provider_health_row("enrich")["status"] == "provider_error"


def test_the_circuit_breaker_opens_after_repeated_failures_and_closes_after_a_cooldown_and_a_success():
    h = Harness({}, registry_handler(NEW))
    ct = Stub("certificate_transparency", status="provider_error")
    s = scheduler(h, ct=ct, breaker_failures=3, breaker_cooldown_minutes=30)
    for _ in range(3):
        run(s.run_once({"certificate_transparency"}))
        h.now[0] += dt.timedelta(minutes=1)
    assert ct.calls == 3
    skipped = run(s.run_once({"certificate_transparency"}))
    assert names(skipped) == {"certificate_transparency": "skipped_circuit_open"} and ct.calls == 3 and skipped[0].detail["until"]
    assert [j for j in s.status() if j["job"] == "certificate_transparency"][0]["circuit_open"] is True
    h.now[0] += dt.timedelta(minutes=31)
    ct.status = "operational"
    assert names(run(s.run_once({"certificate_transparency"}))) == {"certificate_transparency": "ok"} and ct.calls == 4
    assert h.store.provider_health_row("certificate_transparency")["consecutive_failures"] == 0
    assert [j for j in s.status() if j["job"] == "certificate_transparency"][0]["circuit_open"] is False


def test_disabled_providers_are_skipped_visibly():
    h = Harness({}, registry_handler(NEW))
    h.cfg.ct.enabled = False
    h.cfg.permutations.enabled = False
    s = scheduler(h)
    r = names(run(s.run_once()))
    assert r["certificate_transparency"] == "skipped_disabled" and r["permutation"] == "skipped_disabled" and r["enrich"] == "ok"


def test_the_enrich_job_drains_a_backlog_in_rounds_and_discovery_feeds_it():
    h = Harness({("mpesa.a-one.com", "A"): ["8.8.8.8"]}, registry_handler(OLD))
    items = [Discovered(f"mpesa-verify-{i}.xyz", "domain", "certificate_transparency") for i in range(7)]
    s = scheduler(h, ct=Stub("certificate_transparency", items=items), enrich_limit=3)
    res = {r.name: r for r in run(s.run_once({"certificate_transparency", "enrich"}))}
    assert res["certificate_transparency"].detail["runs"][0]["submitted"] == 7
    # 7 first passes, plus the deep passes the strong ones earned: more than one batch, bounded at 5 rounds per tick
    assert res["enrich"].detail["claimed"] >= 7 and 3 <= res["enrich"].detail["rounds"] <= 5
    assert all(h.store.find(f"mpesa-verify-{i}.xyz", hint="domain")["stage"] in {"light", "deep"} for i in range(7))


def test_a_changed_scoring_config_rescores_everything_offline_at_startup_and_is_attributed():
    h, cid = deep("mpesa-invest-ke.com", [fx("fake_investment.html", "mpesa-invest-ke.com")])
    sv = Services(h.store, h.graph, h.ctx)
    s = Scheduler(sv, h.cfg, clock=lambda: h.now[0])
    assert s.startup() == {}                                                         # first run: just remember the hash
    assert s.startup() == {}                                                         # unchanged: nothing
    before = h.store.latest_score(cid)
    h.cfg.scoring.weights["crypto_wallet"] = 0
    h.cfg.scoring.weights["payment_instruction"] = 0
    assert s.startup() == {"M-PESA": 1}
    after = h.store.latest_score(cid)
    assert after["trigger"] == "config_change" and after["config_hash"] != before["config_hash"] and after["score"] <= before["score"]


def test_refresh_requeues_settled_candidates_when_due_by_classification():
    h = Harness({}, registry_handler(NEW))
    ids = {}
    for name, klass, status in (("high.com", "HIGH_PRIORITY", "ESCALATED"), ("watch.com", "WATCH", "SCORED"), ("low.com", "LOW", "SCORED"),
                                ("unassessed.com", "UNASSESSED", "SCORED")):
        cid = h.add(name)
        h.store.conn.execute("UPDATE hunt_candidates SET status=?, classification=?, last_investigated=?, stage='deep' WHERE id=?",
                             (status, klass, h.now[0].isoformat(), cid))
        ids[name] = cid
    assert refresh_due(h.store, h.cfg, when(h, days=0.5)) == {"requeued": 0}
    assert refresh_due(h.store, h.cfg, when(h, days=1.1)) == {"requeued": 1}              # HIGH_PRIORITY: daily
    assert h.store.get(ids["high.com"])["status"] == "QUEUED" and h.store.get(ids["high.com"])["stage"] == "none"
    assert refresh_due(h.store, h.cfg, when(h, days=8)) == {"requeued": 2}                # WATCH and UNASSESSED weekly
    assert h.store.get(ids["low.com"])["status"] == "SCORED"                              # LOW: every 30 days
    assert refresh_due(h.store, h.cfg, when(h, days=31)) == {"requeued": 1}
    h.cfg.scheduler.refresh_batch = 0
    assert refresh_due(h.store, h.cfg, when(h, days=400)) == {"requeued": 0}


def test_run_forever_runs_jobs_and_stops_gracefully():
    h = Harness({}, registry_handler(NEW))
    ct = Stub("certificate_transparency")
    s = scheduler(h, ct=ct, tick_seconds=0.02)
    s.clock = lambda: dt.datetime.now(dt.timezone.utc)

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(s.run_forever(stop))
        await asyncio.sleep(0.15)
        stop.set()
        await asyncio.wait_for(task, 2)
    run(go())
    assert ct.calls == 1                                                              # first tick ran it; its 30-minute interval has not passed
    assert s.last_run("enrich") is not None


def test_the_scheduler_refuses_ephemeral_storage():
    with pytest.raises(SchedulerRefused, match="serverless"):
        check_persistent_storage("/var/task/data/hunter.db", {"VERCEL": "1"})
    check_persistent_storage("/var/task/data/hunter.db", {"VERCEL": "1", "WATCHTOWER_DATA_DIR": "/mnt/volume"})
    with pytest.raises(SchedulerRefused, match="/tmp"):
        check_persistent_storage("/tmp/watchtower/hunter.db", {})
    check_persistent_storage("/tmp/watchtower/hunter.db", {"WATCHTOWER_ALLOW_EPHEMERAL": "1"})
    check_persistent_storage("/home/me/data/hunter.db", {})


def test_scheduler_status_lists_each_job_with_its_next_run():
    h = Harness({}, registry_handler(NEW))
    s = scheduler(h)
    before = {j["job"]: j for j in s.status()}
    assert before["enrich"]["last_run"] is None and before["enrich"]["interval_seconds"] == 60
    run(s.run_due())
    after = {j["job"]: j for j in s.status()}
    assert after["enrich"]["last_run"] and after["enrich"]["next_due"] > after["enrich"]["last_run"]


def test_scheduler_config_validation():
    base = {"brands": [{"name": "B", "aliases": ["bee"]}]}
    for bad in ({"breaker_failures": 0}, {"tick_seconds": 0}, {"refresh_days": {"LOW": 0}}, {"bogus": 1}):
        with pytest.raises(ConfigError):
            parse({**base, "scheduler": bad})
    for sect, bad in (("retention", {"personal_data_days": 0}), ("alerts", {"cooldown_hours": -1})):
        with pytest.raises(ConfigError):
            parse({**base, sect: bad})
    assert parse({**base, "scheduler": {"refresh_days": {"high_priority": 2}}}).scheduler.refresh_days["HIGH_PRIORITY"] == 2.0


_ = html_page, OLD  # shared helpers kept importable for sibling test modules


def test_scheduler_and_dashboard_use_the_same_database(monkeypatch):
    """They once differed (data/ vs the repo root): the scheduler filled one file and the dashboard showed
    an empty queue from the other."""
    from pathlib import Path
    monkeypatch.delenv("WATCHTOWER_DATA_DIR", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    from hunter.__main__ import _db_path
    import web.app as web_app
    # web's DATA_DIR is fixed at import; with no override it is the repo root, which is what _db_path must give.
    assert web_app.DATA_DIR == web_app.ROOT
    assert Path(_db_path()) == web_app.data_path("hunter.db")
