import datetime as dt
import json

import pytest

from hunter.config import ConfigError, DEFAULT_RISK_WEIGHTS, NEGATIVE_WEIGHTS, parse
from hunter.scoring import config_hash, gather_inputs, rescore, score
from test_hunter_enrich import (  # shared offline harness
    FakeAcquire, Harness, SiteCapture, good_page, html_page, rdap_record, registry_handler,
)

OLD = rdap_record(events=[{"eventAction": "registration", "eventDate": "2012-01-01T00:00:00Z"}])
NEW = rdap_record(events=[{"eventAction": "registration", "eventDate": "2026-09-28T00:00:00Z"}])
SYNTHETIC = {"reasons_basis": {"domain_name", "config", "adjustment", "analyst"}}


def deep(domain, pages, rdap=NEW, dns_ips=("8.8.8.8",), scoring=None, **cfg_over):
    """Run one candidate through the real light pass and then the deep pass."""
    h = Harness({(domain, "A"): list(dns_ips)}, registry_handler(rdap), **cfg_over)
    for k, v in (scoring or {}).items():
        setattr(h.cfg.scoring, k, v)
    h.ctx.en.acquire = FakeAcquire(SiteCapture(domain, pages) if not callable(pages) else pages)
    cid = h.add(domain, priority=60)
    h.batch()                                                    # light: DNS + RDAP
    if h.store.get(cid)["status"] != "QUEUED":                   # weak candidates stop after light; force deep
        h.store.requeue(cid, stage="light", reason="test: force deep pass")
    h.batch()                                                    # deep: TLS + page + signals
    return h, cid


def benign(domain, html="<p>Welcome to our shop. We sell shoes and bags across the country.</p>"):
    page = good_page(f"https://{domain}/")
    page.html, page.visible_text = html, "Welcome to our shop. We sell shoes and bags across the country."
    page.forms = []
    return page


def latest(h, cid):
    return h.store.latest_score(cid)


def sigs(h, cid):
    return {r["signal"]: r["weight"] for r in latest(h, cid)["reasons"]}


def fx(name, domain):
    return html_page(name, f"https://{domain}/")


def assert_invariants(h, cid):
    """The properties that make a score defensible, checked on every scenario."""
    row = latest(h, cid)
    assert sum(r["weight"] for r in row["reasons"]) == pytest.approx(row["score"]), "weights must sum to the score"
    assert 0 <= row["score"] <= 100
    known = {r["id"] for r in h.graph.conn.execute("SELECT id FROM evidence")}
    for r in row["reasons"]:
        assert r["evidence"], r
        if r["basis"] == "evidence":
            assert r["evidence_ids"], f"{r['signal']} claims evidence but cites none"
            assert set(r["evidence_ids"]) <= known, f"{r['signal']} cites evidence that is not stored"
        else:
            assert r["basis"] in SYNTHETIC["reasons_basis"]
    return row


# -- the scenarios from the brief ---------------------------------------------------------------------------------

def test_phishing_imitation_is_high_priority_with_every_point_explained():
    h, cid = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    row = assert_invariants(h, cid)
    assert row["classification"] == "HIGH_PRIORITY" and row["score"] == 100 and row["assessment"] == "complete"
    s = {r["signal"] for r in row["reasons"]}
    assert {"brand_in_domain", "recently_registered", "login_form", "pin_field", "otp_field", "card_field",
            "cross_origin_credential_form", "whatsapp_cta", "credential_language", "urgency_language",
            "external_payment_domain", "multiple_signals", "score_clamp"} <= s
    cross = next(r for r in row["reasons"] if r["signal"] == "cross_origin_credential_form")
    assert "collector.example" in cross["evidence"]
    assert h.store.get(cid)["status"] == "ESCALATED"


def test_fake_investment_without_any_form_is_still_high_priority():
    h, cid = deep("mpesa-invest-ke.com", [fx("fake_investment.html", "mpesa-invest-ke.com")])
    row = assert_invariants(h, cid)
    s = sigs(h, cid)
    assert row["classification"] == "HIGH_PRIORITY" and "login_form" not in s
    assert {"payment_instruction", "fee_language", "guaranteed_returns", "crypto_wallet", "whatsapp_cta"} <= set(s)


def test_the_briefs_example_combination_scores_very_highly():
    html = ("<title>M-PESA</title><h1>M-PESA</h1><p>Please verify your account. Contact us on WhatsApp "
            '<a href="https://wa.me/254700000009">here</a>. Pay to Paybill 123456.</p>'
            '<form action="/x"><input name="otp" placeholder="Enter OTP"></form>')
    page = good_page("https://mpesa-secure-help.com/")
    page.html, page.visible_text = html, "M-PESA verify your account"
    h, cid = deep("mpesa-secure-help.com", [page])
    row = assert_invariants(h, cid)
    assert row["score"] >= 76 and row["classification"] == "HIGH_PRIORITY"


def test_news_article_mentioning_the_brand_is_low_not_unassessed():
    h, cid = deep("daily-nation-news.com", [fx("news_article.html", "daily-nation-news.com")], rdap=OLD)
    row = assert_invariants(h, cid)
    assert row["classification"] == "LOW" and row["score"] <= 10 and row["assessment"] == "complete"
    s = sigs(h, cid)
    assert s.get("advisory_context") == -15 and "pin_field" not in s and "credential_language" not in s


def test_cybersecurity_report_quoting_the_lures_is_low():
    h, cid = deep("threat-research-lab.com", [fx("security_report.html", "threat-research-lab.com")], rdap=OLD)
    row = assert_invariants(h, cid)
    assert row["classification"] == "LOW"
    s = sigs(h, cid)
    assert not ({"whatsapp_cta", "telegram_cta", "payment_instruction", "crypto_wallet"} & set(s))


def test_official_property_with_a_login_form_scores_zero_and_is_low():
    h, cid = deep("m-pesa.co.ke", [fx("official_mpesa.html", "m-pesa.co.ke")], rdap=OLD)
    row = assert_invariants(h, cid)
    assert row["score"] == 0 and row["classification"] == "LOW" and sigs(h, cid)["official_domain"] == -50
    assert h.store.get(cid)["status"] == "SCORED"


def test_brand_free_credential_phishing_is_capped_with_an_explicit_reason():
    html = ('<title>Bank Login</title><p>Verify your account urgently, within 24 hours.</p>'
            '<form action="https://other-collector.example/x"><input type="password" name="pin"><input name="otp"></form>')
    page = good_page("https://some-other-bank-login.com/")
    page.html, page.visible_text = html, "Bank Login verify your account"
    h, cid = deep("some-other-bank-login.com", [page], rdap=OLD)
    row = assert_invariants(h, cid)
    assert row["score"] == 40 and row["classification"] == "WATCH"
    cap = next(r for r in row["reasons"] if r["signal"] == "no_brand_relevance_cap")
    assert cap["weight"] < 0 and cap["basis"] == "adjustment" and "M-PESA" in cap["evidence"]


# -- unseen is not clean ----------------------------------------------------------------------------------------

def test_blocked_page_with_no_other_signals_is_unassessed_not_low():
    page = good_page("https://quiet-site.com/", status=403, analyzable=True, unassessed_reason="HTTP 403 (bot challenge)")
    page.html, page.visible_text = "<p>Access denied</p>", "Access denied"
    h, cid = deep("quiet-site.com", [page], rdap=OLD)
    row = assert_invariants(h, cid)
    assert row["classification"] == "UNASSESSED" and row["assessment"] == "partial"
    assert row["coverage"]["page"] == "unassessed" and "HTTP 403" in row["coverage"]["unassessed"][0]


def test_page_never_fetched_is_unassessed():
    h = Harness({("mpesa.somewhere.com", "A"): ["8.8.8.8"]}, registry_handler(OLD))
    cid = h.add("mpesa.somewhere.com", priority=40)
    h.batch()                                              # light pass only
    row = latest(h, cid)
    assert row["classification"] == "UNASSESSED" and row["coverage"]["page"] == "not_fetched"
    assert row["coverage"]["unassessed"] == ["page not fetched"]


def test_unreachable_site_is_unassessed_and_a_name_that_does_not_resolve_is_too():
    from hunter.acquire import Page
    dead = Page("https://quiet-site.com/", error="ConnectError: refused", error_kind="unreachable")
    h, cid = deep("quiet-site.com", [dead], rdap=OLD)
    assert latest(h, cid)["classification"] == "UNASSESSED" and "unreachable" in latest(h, cid)["coverage"]["unassessed"][0]
    h2 = Harness({})
    cid2 = h2.add("quiet-two.com")
    from hunter.enrich.pipeline import _Batch, _record_dns  # noqa: F401
    from hunter.enrich.dns import DnsResult
    from investigation.models import Entity
    b = _Batch(h2.ctx, h2.ctx.investigation_id("M-PESA"), Entity("domain", "quiet-two.com", "quiet-two.com"))
    _record_dns(b, DnsResult("quiet-two.com", "nxdomain"))
    b.save()
    res, _ = rescore(h2.store, h2.graph, h2.cfg, h2.ctx.brands, cid2, "test")
    assert res.classification == "UNASSESSED" and res.unassessed == ["name does not resolve"]


def test_real_signals_are_kept_when_the_page_is_blocked_and_the_result_stays_unassessed():
    page = good_page("https://mpesa-verify.com/", status=403, analyzable=True, unassessed_reason="HTTP 403")
    page.html, page.visible_text = "<p>no</p>", "no"
    h, cid = deep("mpesa-verify.com", [page])
    row = assert_invariants(h, cid)
    s = sigs(h, cid)
    assert {"brand_in_domain", "recently_registered"} <= set(s) and row["score"] == 30
    assert row["classification"] == "UNASSESSED" and row["assessment"] == "partial"     # 30 is not "low", it is "not seen"


def test_official_domain_stays_low_even_when_its_page_cannot_be_read():
    page = good_page("https://www.safaricom.co.ke/", status=403, analyzable=True, unassessed_reason="HTTP 403 (bot challenge)")
    page.html, page.visible_text = "<p>denied</p>", "denied"
    h, cid = deep("safaricom.co.ke", [page], rdap=OLD)
    assert latest(h, cid)["classification"] == "LOW"


def test_missing_registration_data_is_not_a_risk_factor():
    h, cid = deep("mpesa-verify.org", [fx("phishing_login.html", "mpesa-verify.org")])    # .org: no RDAP service in the fake bootstrap
    row = assert_invariants(h, cid)
    assert row["coverage"]["rdap"] == "unsupported" and "recently_registered" not in sigs(h, cid)


# -- discounts ----------------------------------------------------------------------------------------------------------------

def test_established_organization_discount_only_without_serious_signals():
    h, cid = deep("old-shop.com", [benign("old-shop.com")], rdap=OLD)
    assert "established_organization" in sigs(h, cid) and latest(h, cid)["classification"] == "LOW"
    h2, cid2 = deep("old-mpesa-shop.com", [fx("phishing_login.html", "old-mpesa-shop.com")], rdap=OLD)
    assert "established_organization" not in sigs(h2, cid2) and latest(h2, cid2)["score"] >= 76   # old domains get compromised too


def test_admin_trusted_domain_and_suffix_but_never_a_shared_hosting_subdomain():
    cfg_over = {}
    h, cid = deep("mpesa-news.com", [fx("news_article.html", "mpesa-news.com")], rdap=OLD)
    h.cfg.scoring.trusted_domains = ["mpesa-news.com"]
    res, _ = rescore(h.store, h.graph, h.cfg, h.ctx.brands, cid, "config_change")
    assert next(r for r in res.reasons if r.signal == "trusted_third_party").weight == -30 and cfg_over == {}
    h2, cid2 = deep("evil.vercel.app", [fx("phishing_login.html", "evil.vercel.app")], rdap=OLD)
    h2.cfg.scoring.trusted_domains = ["vercel.app"]
    res2, _ = rescore(h2.store, h2.graph, h2.cfg, h2.ctx.brands, cid2, "config_change")
    assert "trusted_third_party" not in {r.signal for r in res2.reasons}
    h3, cid3 = deep("ministry-health.go.ke", [fx("news_article.html", "ministry-health.go.ke")], rdap=OLD)
    assert sigs(h3, cid3).get("trusted_third_party") == -30


# -- known-bad infrastructure ----------------------------------------------------------------------------------------------------

def two_domains_sharing_a_whatsapp_number():
    pages = lambda d: SiteCapture(d, [fx("phishing_login.html", d)])  # noqa: E731
    h = Harness({("mpesa-first.com", "A"): ["8.8.8.8"], ("mpesa-second.com", "A"): ["8.8.4.4"]}, registry_handler(NEW))
    h.ctx.en.acquire = FakeAcquire(pages)
    ids = []
    for d in ("mpesa-first.com", "mpesa-second.com"):
        cid = h.add(d)
        h.store.conn.execute("UPDATE hunt_candidates SET stage='light' WHERE id=?", (cid,))
        ids.append(cid)
    h.batch(5)
    return h, ids


def test_sharing_infrastructure_with_an_analyst_confirmed_domain_adds_a_cited_reason():
    h, (a, b) = two_domains_sharing_a_whatsapp_number()
    assert "known_malicious_infrastructure" not in sigs(h, b)                 # nobody has confirmed anything yet
    before = latest(h, b)["score"]
    h.graph.verdict(a, "confirmed_malicious", "same kit", "analyst-1")
    res, rec = rescore(h.store, h.graph, h.cfg, h.ctx.brands, b, "analyst_verdict")
    reason = next(r for r in res.reasons if r.signal == "known_malicious_infrastructure")
    assert reason.weight == 25 and "mpesa-first.com" in reason.evidence and "confirmed_malicious" in reason.evidence
    assert reason.evidence_ids and rec["recorded"]
    assert_invariants(h, b)
    assert any(c["signal"] == "known_malicious_infrastructure" and c["change"] == "added" for c in rec["changes"])
    assert rec["previous_score"] == before


def test_a_number_is_one_identity_whether_found_as_phone_or_whatsapp():
    h, (a, b) = two_domains_sharing_a_whatsapp_number()
    from investigation.models import Entity, Evidence, Relationship
    iid = h.ctx.investigation_id("M-PESA")
    third = Entity("domain", "mpesa-third.com", "mpesa-third.com")
    num = Entity("phone_number", "+254700000001", "0700000001")            # same number, found as plain text
    ev = Evidence(iid, num.id, "signals", "extracted_indicator", num.canonical_value, "https://mpesa-third.com/")
    h.graph.persist(iid, [third, num], [ev], [Relationship(iid, third.id, num.id, "uses_phone", 0.9, ev.id)])
    h.graph.verdict(third.id, "confirmed_malicious", "x", "analyst-1")
    res, _ = rescore(h.store, h.graph, h.cfg, h.ctx.brands, a, "analyst_verdict")
    assert "known_malicious_infrastructure" in {r.signal for r in res.reasons}


def test_only_confirmed_verdicts_count_and_generic_nodes_are_ignored():
    h, (a, b) = two_domains_sharing_a_whatsapp_number()
    for v in ("suspicious", "monitor", "needs_review"):
        h.graph.verdict(a, v, "x", "analyst-1")
    res, _ = rescore(h.store, h.graph, h.cfg, h.ctx.brands, b, "t")
    assert "known_malicious_infrastructure" not in {r.signal for r in res.reasons}
    h.graph.verdict(a, "confirmed_malicious", "x", "analyst-1")
    h.cfg.scoring.shared_node_max_domains = 0                             # every shared node now counts as "used everywhere"
    res, _ = rescore(h.store, h.graph, h.cfg, h.ctx.brands, b, "t")
    assert "known_malicious_infrastructure" not in {r.signal for r in res.reasons}


# -- history and rescoring ---------------------------------------------------------------------------------------------------------------

def test_light_then_deep_builds_history_with_deltas_and_changes():
    h, cid = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    hist = h.store.score_history(cid)
    assert [x["trigger"] for x in hist] == ["light", "deep"]
    assert hist[0]["score"] < hist[1]["score"] and hist[1]["delta"] == hist[1]["score"] - hist[0]["score"]
    assert hist[0]["classification"] in {"WATCH", "UNASSESSED"} and hist[1]["classification"] == "HIGH_PRIORITY"
    added = {c["signal"] for c in hist[1]["changes"] if c["change"] == "added"}
    assert {"login_form", "pin_field", "otp_field", "whatsapp_cta"} <= added
    assert h.store.get(cid)["risk_score"] == hist[1]["score"] and h.store.get(cid)["classification"] == "HIGH_PRIORITY"


def test_rescoring_unchanged_evidence_adds_no_history_row():
    h, cid = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    n = len(h.store.score_history(cid))
    _, rec = rescore(h.store, h.graph, h.cfg, h.ctx.brands, cid, "manual")
    assert rec == {"recorded": False, "score": 100, "previous_score": 100, "delta": 0, "changes": []}
    assert len(h.store.score_history(cid)) == n


def test_editing_a_weight_rescores_offline_and_the_config_hash_attributes_the_change():
    h, cid = deep("mpesa-invest-ke.com", [fx("fake_investment.html", "mpesa-invest-ke.com")])
    h.cfg.scoring.weights["payment_instruction"] = 0
    h.cfg.scoring.weights["fee_language"] = 0
    h.cfg.scoring.weights["guaranteed_returns"] = 0
    res, rec = rescore(h.store, h.graph, h.cfg, h.ctx.brands, cid, "config_change")
    hist = h.store.score_history(cid)
    assert rec["recorded"] and hist[-1]["config_hash"] != hist[-2]["config_hash"] and hist[-1]["score"] < 100
    assert {c["signal"] for c in rec["changes"] if c["change"] == "reweighted"} >= {"payment_instruction", "fee_language"}
    assert_invariants(h, cid)


def test_time_alone_can_change_a_score_and_is_recorded():
    h, cid = deep("mpesa-verify.com", [benign("mpesa-verify.com")])
    assert "recently_registered" in sigs(h, cid)
    h.now[0] += dt.timedelta(days=60)
    _, rec = rescore(h.store, h.graph, h.cfg, h.ctx.brands, cid, "scheduled_review")
    assert rec["recorded"] and any(c["signal"] == "recently_registered" and c["change"] == "removed" for c in rec["changes"])


def test_scores_are_reproducible_from_stored_evidence_alone():
    h, cid = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    stored = latest(h, cid)
    brand = h.ctx.brands["M-PESA"]
    again = score(gather_inputs(h.graph, cid, "mpesa-verify.com", brand, h.cfg, h.now[0]), h.cfg, config_hash(h.cfg, brand))
    assert again.score == stored["score"] and again.content_hash() == h.store.conn.execute(
        "SELECT content_hash FROM hunt_scores WHERE candidate_id=? ORDER BY id DESC LIMIT 1", (cid,)).fetchone()[0]
    assert [r.signal for r in again.reasons] == [r["signal"] for r in stored["reasons"]]


def test_weights_in_config_change_the_score_by_exactly_that_weight():
    base, cid = deep("mpesa-invest-ke.com", [fx("fake_investment.html", "mpesa-invest-ke.com")], rdap=OLD)
    h2, cid2 = deep("mpesa-invest-ke.com", [fx("fake_investment.html", "mpesa-invest-ke.com")], rdap=OLD)
    brand = h2.ctx.brands["M-PESA"]
    inp = gather_inputs(h2.graph, cid2, "mpesa-invest-ke.com", brand, h2.cfg, h2.now[0])
    a = score(inp, h2.cfg).score
    h2.cfg.scoring.weights["crypto_wallet"] = 0
    assert a > score(inp, h2.cfg).score or a == 100


# -- escalation and config --------------------------------------------------------------------------------------------------------------

def test_escalation_threshold_is_configurable():
    html = ('<title>M-PESA</title><p>M-PESA customers</p><form action="/x"><input type="password" name="pin"></form>')

    def page(d):
        p = good_page(f"https://{d}/")
        p.html, p.visible_text = html, "M-PESA customers"
        return p
    h, cid = deep("mpesa-login-help.com", [page("mpesa-login-help.com")])
    assert latest(h, cid)["classification"] == "SUSPICIOUS" and h.store.get(cid)["status"] == "SCORED"
    h2, cid2 = deep("mpesa-login-help.com", [page("mpesa-login-help.com")], scoring={"escalate_at": "SUSPICIOUS"})
    assert h2.store.get(cid2)["status"] == "ESCALATED"


BASE = {"brands": [{"name": "B", "aliases": ["bee"]}]}


@pytest.mark.parametrize("scoring", [
    {"weights": {"pin_feild": 20}},                     # typo in a name
    {"weights": {"official_domain": 50}},               # a discount that adds risk
    {"weights": {"pin_field": -5}},                     # a risk factor that subtracts
    {"bands": {"watch_min": 60}},                       # out of order
    {"escalate_at": "WATCH"}, {"bogus": 1},
])
def test_scoring_config_errors_are_loud(scoring):
    with pytest.raises(ConfigError):
        parse({**BASE, "scoring": scoring})


def test_scoring_config_overrides_and_defaults():
    c = parse({**BASE, "scoring": {"weights": {"pin_field": 30}, "trusted_domains": ["News.Example"], "unbranded_cap": 25}})
    assert c.scoring.weights["pin_field"] == 30 and c.scoring.weights["otp_field"] == 20
    assert c.scoring.trusted_domains == ["news.example"] and c.scoring.unbranded_cap == 25
    assert {k for k, v in DEFAULT_RISK_WEIGHTS.items() if v < 0} == NEGATIVE_WEIGHTS


def test_briefs_initial_weights_are_the_defaults():
    brief = {"brand_in_domain": 15, "brand_typo": 15, "recently_registered": 10, "login_form": 10, "pin_field": 20,
             "otp_field": 20, "whatsapp_cta": 8, "telegram_cta": 8, "payment_instruction": 12, "fee_language": 12,
             "guaranteed_returns": 12, "external_payment_domain": 10, "multiple_signals": 10,
             "known_malicious_infrastructure": 25, "official_domain": -50, "trusted_third_party": -30,
             "established_organization": -25}
    assert all(DEFAULT_RISK_WEIGHTS[k] == v for k, v in brief.items())


# -- the analyst-facing view -------------------------------------------------------------------------------------------------------------------

def test_explain_command_prints_reasons_with_evidence_and_history(tmp_path, monkeypatch, capsys):
    h = Harness({("mpesa-verify.com", "A"): ["8.8.8.8"]}, registry_handler(NEW), path=str(tmp_path / "hunter.db"))
    h.ctx.en.acquire = FakeAcquire(SiteCapture("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")]))
    cid = h.add("mpesa-verify.com")
    h.batch()
    if h.store.get(cid)["status"] != "QUEUED":
        h.store.requeue(cid, stage="light")
    h.batch()
    monkeypatch.setenv("WATCHTOWER_DATA_DIR", str(tmp_path))
    import hunter.__main__ as cli
    from hunter.__main__ import main
    # The CLI opens its own store on the real clock; the fixtures' registration and certificate dates are
    # relative to the harness clock, so they would age past "recent" and make an unchanged rescore look changed.
    real_ctx = cli._graph_ctx

    def frozen_ctx(cfg):
        store, graph, brands = real_ctx(cfg)
        store.clock = h.store.clock
        return store, graph, brands
    monkeypatch.setattr(cli, "_graph_ctx", frozen_ctx)
    assert main(["explain", "MPESA-VERIFY.COM"]) == 0
    out = capsys.readouterr().out
    assert "100/100  HIGH_PRIORITY" in out and "+20  pin_field" in out and "[evidence:" in out
    assert "<- light" in out and "<- deep" in out
    assert main(["rescore", "mpesa-verify.com"]) == 0 and json.loads(capsys.readouterr().out) == {"rescored": 1, "changed": 0}
    assert main(["explain", "never-seen.com"]) == 1
