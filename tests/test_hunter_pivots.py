import asyncio
import datetime as dt
import json

import httpx
import pytest

from hunter.config import ConfigError, parse
from hunter.pivots import is_infra_host
from hunter.ratelimit import RateLimiter
from hunter.search import (
    DuckDuckGoHtml, HackerTargetReverseIp, ReverseIpBackend, ReverseIpOutcome, SearchBackend, SearchHit,
    SearchOutcome, is_common_infra_ip, parse_duckduckgo, search_queries,
)
from test_hunter_enrich import FakeAcquire, Harness, SiteCapture, good_page, registry_handler
from test_hunter_scoring import NEW, OLD, deep, fx


def run(coro):
    return asyncio.run(coro)


class FakeSearch(SearchBackend):
    name = "fake"

    def __init__(self, script=None):
        self.script, self.queries = script or {}, []

    async def search(self, query, limit=10):
        self.queries.append(query)
        out = self.script(query) if callable(self.script) else self.script.get(query, SearchOutcome("no_results"))
        out.query = query
        return out


class FakeReverse(ReverseIpBackend):
    def __init__(self, outcome):
        self.outcome, self.calls = outcome, []

    async def lookup(self, ip, max_domains):
        self.calls.append(ip)
        return self.outcome


def hits(*urls):
    return SearchOutcome("ok", [SearchHit(u, f"title {i}", f"snippet {i}") for i, u in enumerate(urls)])


def children(h, cid):
    return [r for r in h.store.list(limit=1000) if r["parent_id"] == cid]


def pivot_candidates(h):
    return {(r["indicator_type"], r["canonical"]): r for r in h.store.list(limit=1000) if r["depth"] > 0}


def phishing(domain="mpesa-verify.com", **kw):
    return deep(domain, [fx("phishing_login.html", domain)], **kw)


# -- what a page spawns ------------------------------------------------------------------------------------------

def test_a_phishing_page_spawns_ranked_pivots_with_provenance():
    h, a = phishing()
    got = pivot_candidates(h)
    assert {k for k in got} == {
        ("whatsapp", "+254700000001"), ("domain", "collector.example"), ("domain", "redirect-target.example"),
        ("domain", "pay-now.example"), ("domain", "frame-host.example"), ("analytics_id", "google_analytics:g-phish0001")}
    wa = got[("whatsapp", "+254700000001")]
    assert wa["parent_id"] == a and wa["depth"] == 1 and wa["status"] == "QUEUED" and wa["discovery_source"] == "pivot:whatsapp"
    assert wa["priority"] > got[("domain", "pay-now.example")]["priority"]                 # high before medium
    obs = h.store.observations(wa["id"])[0]
    meta = json.loads(obs["metadata"])
    assert meta["pivot_from"] == "mpesa-verify.com" and meta["where"] == "link" and meta["pivot_value"] == "high"
    ev = h.graph.conn.execute("SELECT * FROM evidence WHERE id=?", (meta["evidence_id"],)).fetchone()
    assert ev["observed_value"] == "+254700000001"                                       # "what indicator caused this pivot"
    assert "pivots:" in h.store.history(a)[-3]["detail"] or any(e["event"] == "pivots" for e in h.store.history(a))


def test_infrastructure_official_and_generic_links_are_not_pivots():
    h, a = phishing()
    got = pivot_candidates(h)
    assert not any(c == "google.com" or c.endswith("safaricom.co.ke") for (_, c) in got)
    assert is_infra_host("d1234.cloudfront.net") and is_infra_host("www.facebook.com") and not is_infra_host("evil-shop.vercel.app")
    html = ('<p>M-PESA promo</p><a href="https://some-random.example/">link</a><a href="https://cdn.cloudfront.net/x">c</a>'
            '<a href="mailto:me@mpesa-own-site.com">own</a><a href="mailto:scammer@gmail.com">them</a>'
            '<a href="https://chat.whatsapp.com/AbC123">group</a><a href="https://t.me/+AbCdEf123">invite</a>')
    page = good_page("https://mpesa-own-site.com/")
    page.html, page.visible_text = html, "M-PESA promo"
    h2, a2 = deep("mpesa-own-site.com", [page])
    got2 = pivot_candidates(h2)
    assert ("email", "scammer@gmail.com") in got2 and not any(t == "email" and "own-site" in c for t, c in got2)
    assert ("domain", "some-random.example") in got2 and got2[("domain", "some-random.example")]["status"] == "NEW"   # low: stored, not queued
    assert not any(t in {"whatsapp", "telegram"} for t, _ in got2)
    detail = next(e for e in h2.store.history(a2) if e["event"] == "pivots")["detail"]
    skipped = json.loads(detail)["skipped"]
    assert skipped.get("common_infrastructure") == 1 and skipped.get("own_domain_email") == 1
    assert skipped.get("not_a_number") == 1 and skipped.get("invite_code") == 1


def test_medium_and_low_queueing_is_configurable():
    h, a = deep("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")])
    assert pivot_candidates(h)[("domain", "pay-now.example")]["status"] == "QUEUED"
    h2 = Harness({("mpesa-verify.com", "A"): ["8.8.8.8"]}, registry_handler(NEW))
    h2.cfg.pivots.queue_medium, h2.cfg.pivots.queue_low = False, True
    h2.ctx.en.acquire = FakeAcquire(SiteCapture("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")]))
    h2.add("mpesa-verify.com")
    h2.batch(); h2.batch()
    got = pivot_candidates(h2)
    assert got[("domain", "pay-now.example")]["status"] == "NEW" and got[("whatsapp", "+254700000001")]["status"] == "QUEUED"


def test_advisory_pages_never_spawn_pivots():
    h, a = deep("threat-research-lab.com", [fx("security_report.html", "threat-research-lab.com")], rdap=OLD)
    assert pivot_candidates(h) == {}
    ev = next(e for e in h.store.history(a) if e["event"] == "pivot_suppressed")
    assert json.loads(ev["detail"])["advisory_suppressed"] is True and json.loads(ev["detail"])["skipped"]["advisory_page"] >= 3


def test_a_known_indicator_is_a_resighting_not_a_new_job():
    h, a = phishing("mpesa-first.com")
    wa = pivot_candidates(h)[("whatsapp", "+254700000001")]
    h.ctx.en.dns_lookup.table[("mpesa-second.com", "A")] = ["8.8.4.4"]
    b = h.add("mpesa-second.com")
    h.store.conn.execute("UPDATE hunt_candidates SET stage='light' WHERE id=?", (b,))
    h.ctx.en.acquire = FakeAcquire(SiteCapture("mpesa-second.com", [fx("phishing_login.html", "mpesa-second.com")]))
    h.batch()
    again = h.store.get(wa["id"])
    assert again["observation_count"] >= 2 and again["parent_id"] == a                    # first parent is kept
    assert len([r for r in h.store.list(limit=1000) if r["indicator_type"] == "whatsapp"]) == 1
    assert {o["parent_id"] for o in h.store.observations(wa["id"])} == {a, b}              # both sightings are on the record


# -- limits -------------------------------------------------------------------------------------------------------------

def spawn(**pivot_cfg):
    h = Harness({("mpesa-verify.com", "A"): ["8.8.8.8"]}, registry_handler(NEW))
    for k, v in pivot_cfg.items():
        setattr(h.cfg.pivots, k, v)
    h.ctx.en.acquire = FakeAcquire(SiteCapture("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")]))
    cid = h.add("mpesa-verify.com")
    h.batch(); h.batch()
    return h, cid


def skipped(h, cid):
    return json.loads(next(e for e in h.store.history(cid) if e["event"] == "pivots")["detail"])


def test_per_entity_cap_keeps_the_highest_value_pivots():
    h, a = spawn(max_pivots_per_entity=2)
    kept = {k for k in pivot_candidates(h)}
    assert len(kept) == 2 and ("whatsapp", "+254700000001") in kept                       # high value survives the cut
    assert skipped(h, a)["skipped"]["entity_cap"] == 4


def test_lineage_and_daily_caps():
    h, a = spawn(max_jobs_per_lineage=3)
    assert len(pivot_candidates(h)) == 2 and skipped(h, a)["skipped"]["lineage_cap"] == 4   # root + 2 pivots = 3 jobs
    h2, a2 = spawn(max_pivots_per_day=3)
    assert len(pivot_candidates(h2)) == 3 and skipped(h2, a2)["skipped"]["daily_cap"] == 3


def test_depth_limit_stops_pivots_and_is_counted():
    h, a = spawn(max_depth=0)
    assert pivot_candidates(h) == {} and skipped(h, a)["skipped"]["depth_limit"] == 6


def test_zero_pivot_budget_still_scores_and_records_the_page():
    h, a = spawn(max_pivots_per_entity=0)
    assert pivot_candidates(h) == {} and h.store.latest_score(a)["score"] > 0


def endless_world(max_depth):
    """Every phishing page posts to a brand-new domain: A -> B -> C -> D -> E -> ..."""
    class AnyA(dict):
        def get(self, k, d=None):
            return ["8.8.8.8"] if k[1] == "A" else super().get(k, d)

    def site(domain):
        import re
        m = re.search(r"hop(\d+)", domain)
        n = int(m.group(1)) if m else 0
        nxt = f"hop{n + 1}-mpesa.com"
        html = (f'<title>M-PESA</title><p>M-PESA verify your account</p>'
                f'<form action="https://{nxt}/post"><input type="password" name="pin"><input name="otp"></form>')
        page = good_page(f"https://{domain}/")
        page.html, page.visible_text = html, "M-PESA verify your account"
        return SiteCapture(domain, [page])
    h = Harness(AnyA(), registry_handler(NEW))
    h.cfg.pivots.max_depth = max_depth
    h.cfg.pivots.queue_medium = True
    h.ctx.en.acquire = FakeAcquire(site)
    h.add("mpesa-verify-hop0.xyz")
    return h


@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_a_chain_of_domains_cannot_recurse_past_max_depth(depth):
    h = endless_world(depth)
    for _ in range(40):                                              # far more rounds than the chain could ever need
        if h.batch(20).claimed == 0:
            break
    rows = h.store.list(limit=1000)
    assert max(r["depth"] for r in rows) == depth
    domains = [r for r in rows if r["indicator_type"] == "domain"]
    assert len(domains) == depth + 1                                  # A, B, C ... exactly depth+1 links, never endless
    assert not h.store.list("QUEUED") and not h.store.list("INVESTIGATING")


def test_a_to_b_to_c_works_within_the_limit_and_lineage_explains_it():
    h = endless_world(3)
    for _ in range(40):
        if h.batch(20).claimed == 0:
            break
    last = next(r for r in h.store.list(limit=1000) if r["canonical"] == "hop3-mpesa.com")
    chain = h.store.lineage(last["id"])
    assert [c["canonical"] for c in chain] == ["mpesa-verify-hop0.xyz", "hop1-mpesa.com", "hop2-mpesa.com", "hop3-mpesa.com"]
    assert chain[1]["via"]["where"] == "form_action" and chain[1]["source"] == "pivot:domain"
    assert h.store.get(last["id"])["status"] in {"SCORED", "ESCALATED"} and h.store.ancestor_risk(last["id"]) >= 56


# -- lineage decides who gets a deep pass ---------------------------------------------------------------------------------------

def test_a_weak_name_reached_from_a_suspicious_parent_earns_a_deep_pass():
    h = Harness({("quiet-shop.com", "A"): ["8.8.8.8"]}, registry_handler(OLD))
    h.ctx.en.acquire = FakeAcquire(SiteCapture("quiet-shop.com", [good_page("https://quiet-shop.com/")]))
    parent = h.add("mpesa-verify.com")
    h.store.conn.execute("UPDATE hunt_candidates SET risk_score=83, status='SCORED' WHERE id=?", (parent,))
    child = h.store.submit("quiet-shop.com", "pivot:whatsapp", brand="M-PESA", parent_id=parent, depth=1, priority=70).candidate_id
    assert h.batch().outcomes == {"queued_deep": 1} and h.store.get(child)["stage"] == "light"
    lone = h.store.submit("quiet-two.com", "search", brand="M-PESA", priority=70).candidate_id
    h.ctx.en.dns_lookup.table[("quiet-two.com", "A")] = ["8.8.4.4"]
    h.batch()
    assert h.store.get(lone)["stage"] == "light" and h.store.get(lone)["status"] == "SCORED"   # no suspicious ancestor: stays light


# -- searching for an indicator -----------------------------------------------------------------------------------------------------

def indicator_world(searcher=None, **pivot_cfg):
    h, a = phishing()
    h.ctx.en.searcher = searcher
    for k, v in pivot_cfg.items():
        setattr(h.cfg.pivots, k, v)
    wa = pivot_candidates(h)[("whatsapp", "+254700000001")]
    return h, a, wa


def process(h, cid):
    """Run exactly this candidate: put it first in the queue, then claim one."""
    h.store.conn.execute("UPDATE hunt_candidates SET status='QUEUED', next_attempt_at=NULL, priority=1000 WHERE id=?", (cid,))
    return h.batch(1)


def test_whatsapp_pivot_queries_the_number_and_queues_untrusted_hits_as_leads():
    s = FakeSearch({'"+254700000001"': hits("https://quick-loans-ke.example/home", "https://www.facebook.com/x", "https://www.nation.africa/a",
                                            "https://www.safaricom.co.ke/help", "https://evil-shop.vercel.app/p"),
                    '"0700000001"': hits("https://quick-loans-ke.example/other")})
    h, a, wa = indicator_world(s)
    s.queries.clear()                                   # the shared deep() helper never ran a search
    out = process(h, wa["id"])
    assert out.outcomes == {"pivot": 1} and s.queries == ['"+254700000001"', '"0700000001"', '"wa.me/254700000001"']
    leads = {r["canonical"]: r for r in h.store.list(limit=1000) if r["discovery_source"] == "pivot:search"}
    assert set(leads) == {"quick-loans-ke.example", "evil-shop.vercel.app"}                # news, social, official, infra filtered
    lead = leads["quick-loans-ke.example"]
    assert lead["parent_id"] == wa["id"] and lead["depth"] == 2 and lead["status"] == "QUEUED"
    assert json.loads(h.store.observations(lead["id"])[0]["confidence"] and "{}")["x"] if False else True
    assert h.store.observations(lead["id"])[0]["confidence"] == 0.3                       # a lead, not a finding
    row = h.store.get(wa["id"])
    assert row["status"] == "ENRICHED" and row["stage"] == "pivot"
    ev = json.loads(h.graph.conn.execute("SELECT observed_value FROM evidence WHERE evidence_type='pivot_search'").fetchone()[0])
    assert ev["status"] == "ok" and [q["status"] for q in ev["queries"]] == ["ok", "ok", "no_results"]


def test_graph_neighbours_are_pivoted_without_any_external_search():
    h, a, wa = indicator_world(None)
    other = h.add("mpesa-neighbour.com")
    from investigation.models import Entity, Evidence, Relationship
    iid = h.ctx.investigation_id("M-PESA")
    d = Entity("domain", "mpesa-neighbour.com", "mpesa-neighbour.com")
    num = Entity("phone_number", "+254700000001", "0700000001")
    e = Evidence(iid, num.id, "signals", "extracted_indicator", num.canonical_value, "https://mpesa-neighbour.com/")
    h.graph.persist(iid, [d, num], [e], [Relationship(iid, d.id, num.id, "uses_phone", 0.9, e.id)])
    process(h, wa["id"])
    row = h.store.get(other)
    assert row["observation_count"] >= 2 and any(o["source"] == "pivot:graph" for o in h.store.observations(other))
    note = h.store.history(wa["id"])[-1]["detail"]
    assert "internal_only" in note and "1 graph neighbours" in note and "1 queued" not in note


def test_a_blocked_search_defers_with_a_reason_and_is_never_reported_as_no_results():
    s = FakeSearch(lambda q: SearchOutcome("blocked", error="search engine returned a bot challenge", retry_after=900))
    h, a, wa = indicator_world(s)
    out = process(h, wa["id"])
    assert out.outcomes == {"deferred_search_blocked": 1} and len(s.queries) == 1       # stopped at the first refusal
    row = h.store.get(wa["id"])
    assert row["status"] == "QUEUED" and "search blocked" in row["deferred_reason"] and row["stage"] != "pivot"
    ev = json.loads(h.graph.conn.execute("SELECT observed_value FROM evidence WHERE evidence_type='pivot_search'").fetchone()[0])
    assert ev["status"] == "not_searched" and ev["queries"][0]["status"] == "blocked"


def test_a_search_error_retries_and_a_partial_search_says_so():
    h, a, wa = indicator_world(FakeSearch(lambda q: SearchOutcome("error", error="HTTP 500")))
    assert process(h, wa["id"]).outcomes == {"failed_retry": 1}
    assert "search failed: HTTP 500" in h.store.get(wa["id"])["error_state"]
    calls = []

    def flaky(q):
        calls.append(q)
        return SearchOutcome("no_results") if len(calls) == 1 else SearchOutcome("rate_limited", error="429", retry_after=900)
    h2, a2, wa2 = indicator_world(FakeSearch(flaky))
    out = process(h2, wa2["id"])
    assert out.outcomes == {"pivot_partial": 1}
    assert "PARTIAL" in h2.store.history(wa2["id"])[-1]["detail"] and "not a complete negative" in h2.store.history(wa2["id"])[-1]["detail"]


def test_a_searched_zero_is_recorded_as_such():
    h, a, wa = indicator_world(FakeSearch({}))
    process(h, wa["id"])
    ev = json.loads(h.graph.conn.execute("SELECT observed_value FROM evidence WHERE evidence_type='pivot_search'").fetchone()[0])
    assert ev["status"] == "no_results" and all(q["status"] == "no_results" for q in ev["queries"])


def test_daily_search_budget_defers_and_frees_after_a_day():
    s = FakeSearch({})
    h, a, wa = indicator_world(s, max_search_queries_per_day=4)
    process(h, wa["id"])                                                       # 3 queries used
    h.store.submit("someone", "x", hint="telegram", brand="M-PESA", parent_id=a, depth=1)
    tcand = next(r for r in h.store.list(limit=100) if r["indicator_type"] == "telegram")
    out = process(h, tcand["id"])                                              # needs 2 more: 5 > 4
    assert out.outcomes == {"deferred_search_budget": 1}
    assert "daily search budget reached (4/day)" in h.store.get(tcand["id"])["deferred_reason"]
    h.now[0] += dt.timedelta(days=1, minutes=1)
    assert process(h, tcand["id"]).outcomes == {"pivot": 1}


def test_search_can_be_switched_off():
    s = FakeSearch({})
    h, a, wa = indicator_world(s, search=False)
    process(h, wa["id"])
    assert s.queries == []


def test_ip_pivots_respect_cdn_ranges_shared_hosting_and_failures():
    assert is_common_infra_ip("104.21.5.5") and not is_common_infra_ip("8.8.8.8") and not is_common_infra_ip("junk")

    def ip_world(outcome):
        h = Harness({("mpesa-verify.com", "A"): ["8.8.8.8", "104.21.5.5"]}, registry_handler(NEW))
        h.cfg.pivots.reverse_ip = True
        rev = FakeReverse(outcome)
        h.ctx.en.reverse_ip = rev
        h.ctx.en.acquire = FakeAcquire(SiteCapture("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")]))
        h.add("mpesa-verify.com")
        h.batch(); h.batch()
        ips = [r for r in h.store.list(limit=100) if r["indicator_type"] == "ip_address"]
        return h, rev, ips
    h, rev, ips = ip_world(ReverseIpOutcome("ok", ["sibling-one.com", "d1.cloudfront.net"], total=2))
    assert [r["canonical"] for r in ips] == ["8.8.8.8"]                                     # the Cloudflare address is never queued
    process(h, ips[0]["id"])
    assert rev.calls == ["8.8.8.8"] and {r["canonical"] for r in h.store.list(limit=100) if r["discovery_source"] == "pivot:reverse_ip"} == {"sibling-one.com"}
    h, rev, ips = ip_world(ReverseIpOutcome("shared_hosting", total=300))
    assert "shared hosting, not a link" in (process(h, ips[0]["id"]) and h.store.history(ips[0]["id"])[-1]["detail"])
    h, rev, ips = ip_world(ReverseIpOutcome("rate_limited", error="daily API limit reached"))
    assert process(h, ips[0]["id"]).outcomes == {"deferred_search_blocked": 1}
    h, rev, ips = ip_world(ReverseIpOutcome("error", error="boom"))
    assert process(h, ips[0]["id"]).outcomes == {"failed_retry": 1}
    h2 = Harness({("mpesa-verify.com", "A"): ["8.8.8.8"]}, registry_handler(NEW))               # default config: no IP pivots at all
    h2.ctx.en.acquire = FakeAcquire(SiteCapture("mpesa-verify.com", [fx("phishing_login.html", "mpesa-verify.com")]))
    h2.add("mpesa-verify.com"); h2.batch(); h2.batch()
    assert not [r for r in h2.store.list(limit=100) if r["indicator_type"] == "ip_address"]


def test_time_budget_defers_unstarted_candidates_visibly():
    h = Harness({("mpesa.somewhere.com", "A"): ["8.8.8.8"]}, registry_handler(OLD), max_batch_seconds=-1)
    cid = h.add("mpesa.somewhere.com")
    assert h.batch().outcomes == {"deferred_time_budget": 1}
    row = h.store.get(cid)
    assert row["status"] == "QUEUED" and "batch time budget exhausted" in row["deferred_reason"] and row["attempts"] == 0


# -- search backends ----------------------------------------------------------------------------------------------------------------------

DDG_OK = '''<div class="results">
<div class="result"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fquick-loans-ke.example%2Fhome&amp;rut=abc">Quick <b>Loans</b> KE</a>
<a class="result__snippet" href="x">Call <b>+254700000001</b> now</a></div>
<div class="result"><a class="result__a" href="https://other-site.example/p">Other &amp; site</a><a class="result__snippet">snip two</a></div>
<div class="result"><a class="result__a" href="//duckduckgo.com/y.js?ad_provider=x">Ad</a></div>
</div>'''


def test_duckduckgo_parser_classifies_every_kind_of_page():
    ok = parse_duckduckgo(DDG_OK, 10)
    assert ok.status == "ok" and [h.url for h in ok.hits] == ["https://quick-loans-ke.example/home", "https://other-site.example/p"]
    assert ok.hits[0].title == "Quick Loans KE" and ok.hits[0].snippet == "Call +254700000001 now" and ok.hits[1].title == "Other & site"
    assert len(parse_duckduckgo(DDG_OK, 1).hits) == 1
    assert parse_duckduckgo("<html><body><div class='no-results'>No results.</div></body></html>", 10).status == "no_results"
    assert parse_duckduckgo("<html>Unfortunately, bots use DuckDuckGo too. anomaly-modal</html>", 10).status == "blocked"
    garbage = parse_duckduckgo("<html><body>something changed entirely</body></html>", 10)
    assert garbage.status == "error" and "could not be parsed" in garbage.error      # never "no results"
    assert parse_duckduckgo("", 10).status == "error"


def ddg(handler, **kw):
    return DuckDuckGoHtml(httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                          RateLimiter(0, sleep=lambda s: asyncio.sleep(0)), **kw)


def test_duckduckgo_backend_http_failures_are_explicit_and_cool_down():
    calls = []

    def blocked(request):
        calls.append(str(request.url))
        return httpx.Response(202, text="challenge")
    b = ddg(blocked)
    first = run(b.search('"+254700000001"'))
    assert first.status == "blocked" and first.retry_after == 900 and "q=%22%2B254700000001%22" in calls[0]
    second = run(b.search("again"))
    assert second.status == "rate_limited" and len(calls) == 1                      # no request while cooling down
    assert run(ddg(lambda r: httpx.Response(429)).search("x")).status == "rate_limited"
    assert run(ddg(lambda r: httpx.Response(500)).search("x")).status == "error"

    def boom(request):
        raise httpx.ConnectTimeout("slow")
    assert run(ddg(boom).search("x")).status == "error"
    assert run(ddg(lambda r: httpx.Response(200, text=DDG_OK)).search("x")).status == "ok"


NO_RESULTS = "<html><body><span class='no-results'><div class='no-results__message'><h1>No results found for x</h1></div></span></body></html>"


def routed(target_body, canary_body=DDG_OK, log=None):
    def handler(request):
        q = request.url.params["q"]
        if log is not None:
            log.append(q)
        return httpx.Response(200, text=canary_body if q == DuckDuckGoHtml.CANARY else target_body)
    return handler


def test_no_results_is_only_believed_after_a_control_query_succeeds():
    log = []
    b = ddg(routed(NO_RESULTS, log=log))
    out = run(b.search('"+254700000001"'))
    assert out.status == "no_results" and log == ['"+254700000001"', DuckDuckGoHtml.CANARY]
    run(b.search('"another"'))
    assert log.count(DuckDuckGoHtml.CANARY) == 1                         # the canary result is cached


def test_a_soft_blocked_engine_cannot_produce_a_searched_zero():
    b = ddg(routed(NO_RESULTS, canary_body=NO_RESULTS))                    # even the control query comes back empty
    out = run(b.search('"+254700000001"'))
    assert out.status == "blocked" and "not a searched zero" in out.error and out.retry_after == 900
    assert run(b.search("next")).status == "rate_limited"                  # and it backs off
    ticks = [0.0]
    ok = ddg(routed(NO_RESULTS), clock=lambda: ticks[0])
    run(ok.search("q"))
    log = []
    ok2 = ddg(routed(NO_RESULTS, log=log), clock=lambda: ticks[0])
    run(ok2.search("q")); ticks[0] += 1000; run(ok2.search("q"))
    assert log.count(DuckDuckGoHtml.CANARY) == 2                          # the canary expires and is re-checked


def test_real_results_never_need_the_control_query():
    log = []
    out = run(ddg(routed(DDG_OK, log=log)).search("x"))
    assert out.status == "ok" and log == ["x"]


def rev(text, status=200):
    return HackerTargetReverseIp(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(status, text=text))),
                                 RateLimiter(0, sleep=lambda s: asyncio.sleep(0)))


def test_reverse_ip_failures_arrive_as_200_text_and_are_not_empty_results():
    assert run(rev("a-site.com\nb-site.org\n").lookup("8.8.8.8", 50)).domains == ["a-site.com", "b-site.org"]
    assert run(rev("No DNS A records found for 8.8.8.8").lookup("8.8.8.8", 50)).status == "no_results"
    limited = rev("API count exceeded - Increase Quota with Membership")
    assert run(limited.lookup("8.8.8.8", 50)).status == "rate_limited" and run(limited.lookup("8.8.8.8", 50)).error == "cooling down"
    assert run(rev("error check your search parameter").lookup("8.8.8.8", 50)).status == "error"
    assert run(rev("<html>blocked</html>").lookup("8.8.8.8", 50)).status == "error"
    many = "\n".join(f"site{i}.com" for i in range(80))
    shared = run(rev(many).lookup("8.8.8.8", 50))
    assert shared.status == "shared_hosting" and shared.total == 80 and shared.domains == []


def test_search_query_shapes():
    assert search_queries("whatsapp", "+254700000001") == ['"+254700000001"', '"0700000001"', '"wa.me/254700000001"']
    assert search_queries("phone_number", "+255754000000") == ['"+255754000000"']
    assert search_queries("telegram", "some_handle") == ['"t.me/some_handle"', '"@some_handle"'] and search_queries("telegram", "invite:x") == []
    assert search_queries("payment_identifier", "paybill:123456") == ['"paybill 123456"', '"Paybill number 123456"']
    assert search_queries("crypto_wallet", "btc:bc1qxx") == ['"bc1qxx"'] and search_queries("analytics_id", "google_analytics:g-1") == []
    assert search_queries("social_account", "x:someone") == ['"someone" x']


# -- config -------------------------------------------------------------------------------------------------------------------------------------

def test_pivot_config_validation():
    base = {"brands": [{"name": "B", "aliases": ["bee"]}]}
    for bad in ({"max_depth": -1}, {"max_jobs_per_lineage": 0}, {"bogus": 1}):
        with pytest.raises(ConfigError):
            parse({**base, "pivots": bad})
    c = parse({**base, "pivots": {"max_depth": 5, "queue_low": True}})
    assert c.pivots.max_depth == 5 and c.pivots.queue_low is True and c.pivots.max_pivots_per_entity == 10
