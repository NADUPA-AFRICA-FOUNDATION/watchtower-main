"""The brief's definition of done, as one test.

A scheduler tick discovers `mpesa-secure-example.test` with no analyst input; the hunter normalizes and
deduplicates it, pre-scores it, collects DNS, RDAP, certificate and page evidence, extracts a WhatsApp
number and credential-form characteristics, scores it with reasons and evidence references, pivots on
the number, finds a second simulated domain connected to it, correlates the two into a campaign, and
shows all of it on the dashboard API, where an analyst can inspect the chain and record decisions.
Nothing touches the network: crt.sh, the sites and the registry are mock transports; DNS and TLS are fakes.
"""
import asyncio
import datetime as dt
import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from hunter.acquire import KEEP_HEADERS, NativeFetcher
from hunter.alerts import AlertEngine
from hunter.config import load
from hunter.enrich.pipeline import EnrichContext, Enrichers
from hunter.enrich.rdap import RdapClient
from hunter.providers.ct import CertificateTransparencyProvider
from hunter.providers.search_discovery import SearchDiscoveryProvider
from hunter.ratelimit import RateLimiter
from hunter.scheduler import Scheduler, Services
from hunter.store import HuntStore
from investigation.storage import InvestigationStore
from test_hunter_campaigns import per_domain_rdap
from test_hunter_enrich import NOW, FakeDns, FakeTls
from test_hunter_pivots import FakeSearch, hits
from watchtower.discovery.safe_fetch import SafeFetcher
from web.hunter_routes import build_router

SITE_A, SITE_B = "mpesa-secure-example.test", "mpesa-promo-second.test"
NUMBER = "+254700000001"            # clearly fake, per the brief
PAGE_A = f"""<!doctype html><title>M-PESA Account Verification</title>
<h1>M-PESA Account Verification</h1>
<p>Urgent verification required: your account will be suspended within 24 hours. Verify your account now.</p>
<form action="/verify" method="post"><input name="phone" type="tel"><input name="pin" type="password" placeholder="M-PESA PIN">
<input name="otp" placeholder="Enter OTP"></form>
<p>Pay the activation fee to Paybill number 123456 to unlock the account.</p>
<a href="https://wa.me/{NUMBER[1:]}">Customer Support on WhatsApp</a>"""
PAGE_B = f"""<!doctype html><title>M-PESA Promo: double your money</title>
<h1>M-PESA Promo</h1><p>Investment opportunity with guaranteed returns of 15% daily returns. Claim your reward today.</p>
<form action="/join" method="post"><input name="otp" placeholder="Enter OTP"><input name="tel" type="tel"></form>
<a href="https://wa.me/{NUMBER[1:]}">Join on WhatsApp</a>"""
SITES = {SITE_A: PAGE_A, SITE_B: PAGE_B}


def stamp(delta_days):
    return (NOW - dt.timedelta(days=delta_days)).strftime("%Y-%m-%dT%H:%M:%S.000")


def crt_sh(request):
    row = {"id": 99, "min_cert_id": 99, "name_value": f"{SITE_A}\n*.{SITE_A}", "issuer_name": "Fake CA",
           "entry_timestamp": stamp(1), "not_before": stamp(1)}
    return httpx.Response(200, json=[row] if request.url.params["q"] == "%mpesa%" else [])


def site_handler(request):
    host, path = request.url.host, request.url.path
    if host in SITES and path == "/":
        return httpx.Response(200, text=SITES[host], headers={"content-type": "text/html; charset=utf-8", "server": "nginx"})
    return httpx.Response(404, text="not found", headers={"content-type": "text/html"})


async def public(host):
    return ["8.8.8.8"] if host == SITE_A else ["8.8.4.4"]


async def nosleep(_):
    return None


class World:
    def __init__(self, path):
        self.cfg = load("hunter.yaml")
        c = self.cfg
        c.ct.min_interval_seconds = 0
        c.acquisition.page_delay_seconds = 0
        c.enrichment.concurrency = 1
        c.search_discovery.max_queries_per_run = 3
        self.now = [NOW]
        clock = lambda: self.now[0]                                   # noqa: E731
        self.store, self.graph = HuntStore(path, clock=clock), InvestigationStore(path)
        dns = FakeDns({(SITE_A, "A"): ["8.8.8.8"], (SITE_B, "A"): ["8.8.4.4"],
                       (SITE_A, "NS"): ["ns1.alpha-dns.example"], (SITE_B, "NS"): ["ns1.beta-dns.example"]})
        rdap = RdapClient(httpx.AsyncClient(transport=httpx.MockTransport(per_domain_rdap)), self.store, min_interval=0,
                          clock=clock, sleep=nosleep)
        fetcher = NativeFetcher(SafeFetcher(client=httpx.AsyncClient(transport=httpx.MockTransport(site_handler)), resolver=public,
                                            max_bytes=c.acquisition.max_bytes, keep_headers=KEEP_HEADERS), c.acquisition, sleep=nosleep)
        self.queries = []

        def script(q):
            self.queries.append(q)
            if "wa.me" in q or NUMBER in q or "0700000001" in q:
                return hits(f"https://{SITE_B}/home", "https://www.nation.africa/story")     # a lead, plus a trusted news site
            if q.startswith('"M-PESA" "verify account"'):
                return hits(f"https://{SITE_A.upper()}/")                                       # same domain, different spelling
            from hunter.search import SearchOutcome
            return SearchOutcome("no_results")
        self.searcher = FakeSearch(script)
        ctx = EnrichContext(self.store, self.graph, c, {b.name: b for b in c.brands},
                            Enrichers(dns, rdap, FakeTls(), fetcher, self.searcher), clock=clock)
        ct = CertificateTransparencyProvider(httpx.AsyncClient(transport=httpx.MockTransport(crt_sh)),
                                             RateLimiter(0, sleep=nosleep), clock=clock)
        sd = SearchDiscoveryProvider(self.searcher, queries_available=lambda: 100)
        self.services = Services(self.store, self.graph, ctx, ct, None, sd, AlertEngine(self.store, self.graph, c, env={}))
        self.scheduler = Scheduler(self.services, c, clock=clock)

    def tick(self, n=1):
        async def go():
            out = []
            for _ in range(n):
                out += await self.scheduler.run_due()
                self.now[0] += dt.timedelta(seconds=61)
            return out
        return asyncio.run(go())

    def api(self):
        app = FastAPI()
        app.include_router(build_router(lambda: self.store.path, lambda: self.cfg, lambda r, claimed: (claimed.strip(), "self_asserted"),
                                        clock=lambda: self.now[0]))
        return TestClient(app)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    w = World(str(tmp_path_factory.mktemp("e2e") / "hunter.db"))
    w.evidence_counts = []
    for _ in range(6):                                                   # the scheduler does everything; nobody submits a URL
        w.tick()
        w.evidence_counts.append(w.graph.conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0])
    return w


def cand(w, name):
    return w.store.find(name, hint="domain")


# -- steps 1-4: discovery, normalization, deduplication, pre-scoring ---------------------------------------------------------

def test_01_the_scheduler_ran_every_job_on_its_own_and_nothing_failed(world):
    ran = {j["job"]: j["last_run"] for j in world.scheduler.status()}
    assert all(ran[j] for j in ("certificate_transparency", "search_discovery", "enrich", "refresh", "alerts", "purge"))
    assert world.store.provider_health_row("certificate_transparency")["consecutive_failures"] == 0
    health = {h["provider"]: h["status"] for h in world.store.provider_health()}
    assert health["dns"] == "operational" and health["rdap"] == "operational" and health["http"] == "operational"


def test_02_a_provider_found_the_domain_and_two_spellings_became_one_entity(world):
    a = cand(world, SITE_A)
    assert a["discovery_source"] == "certificate_transparency" and a["depth"] == 0 and a["parent_id"] is None
    assert set(a["sources_seen"]) == {"certificate_transparency", "search_discovery"} and a["observation_count"] >= 2
    assert sum(1 for r in world.store.list(limit=1000) if r["indicator_type"] == "domain" and r["canonical"] == SITE_A) == 1
    assert cand(world, SITE_A.upper() + "/")["id"] == a["id"]                      # every spelling resolves to the same entity


def test_03_cheap_prescoring_flagged_brand_risk_before_any_enrichment(world):
    first = json.loads(world.store.observations(cand(world, SITE_A)["id"])[0]["metadata"])
    signals = {r["signal"] for r in first["prescore"]["reasons"]}
    assert {"brand_token", "credential_keyword", "combination", "new_certificate"} <= signals
    assert first["prescore"]["band"] in {"FULL", "HIGH"} and first["certificate_id"] == "99"


# -- steps 5-7: enrichment, extraction, scoring --------------------------------------------------------------------------------

def test_04_dns_rdap_certificate_and_website_evidence_were_collected(world):
    a = cand(world, SITE_A)["id"]
    types = {r[0] for r in world.graph.conn.execute("SELECT evidence_type FROM evidence WHERE entity_id=?", (a,))}
    assert {"dns_lookup", "rdap_lookup", "tls_lookup", "http_response", "page_text", "page_signals", "market_estimate"} <= types
    ev = world.graph.conn.execute("SELECT * FROM evidence WHERE entity_id=? AND evidence_type='http_response'", (a,)).fetchone()
    facts = json.loads(ev["observed_value"])
    assert facts["status"] == 200 and facts["title"] == "M-PESA Account Verification" and facts["technology"]["server"] == "nginx"
    assert ev["source"] == "http" and ev["observed_at"] and ev["source_url"].startswith(f"https://{SITE_A}")


def test_05_the_whatsapp_number_wording_and_credential_form_were_extracted(world):
    a = cand(world, SITE_A)["id"]
    flags = json.loads(world.graph.conn.execute("SELECT observed_value FROM evidence WHERE entity_id=? AND evidence_type='page_signals'", (a,)).fetchone()[0])["flags"]
    assert flags["whatsapp_cta"] and flags["credential_form"] and flags["solicits_pin"] and flags["solicits_otp"]
    assert flags["urgency_language"] and flags["credential_language"] and flags["fee_language"] and flags["payment_instruction"]
    wa = world.graph.conn.execute("SELECT * FROM entities WHERE entity_type='whatsapp'").fetchall()
    assert [w["canonical_value"] for w in wa] == [NUMBER]


def test_06_the_score_has_a_classification_reasons_and_evidence_references(world):
    row = world.store.latest_score(cand(world, SITE_A)["id"])
    assert row["classification"] == "HIGH_PRIORITY" and row["score"] >= 76 and row["assessment"] == "complete"
    assert sum(r["weight"] for r in row["reasons"]) == pytest.approx(row["score"])
    known = {r[0] for r in world.graph.conn.execute("SELECT id FROM evidence")}
    cited = [r for r in row["reasons"] if r["basis"] == "evidence"]
    assert cited and all(r["evidence_ids"] and set(r["evidence_ids"]) <= known for r in cited)
    assert {"brand_in_domain", "pin_field", "otp_field", "whatsapp_cta", "payment_instruction", "fee_language"} <= {r["signal"] for r in row["reasons"]}
    assert cand(world, SITE_A)["status"] == "ESCALATED"


# -- steps 8-11: pivot, second domain, correlation, campaign -------------------------------------------------------------------------

def test_07_the_whatsapp_number_became_a_pivot_with_its_provenance(world):
    wa = next(r for r in world.store.list(limit=1000) if r["indicator_type"] == "whatsapp")
    a = cand(world, SITE_A)
    assert wa["canonical"] == NUMBER and wa["parent_id"] == a["id"] and wa["depth"] == 1 and wa["discovery_source"] == "pivot:whatsapp"
    meta = json.loads(world.store.observations(wa["id"])[0]["metadata"])
    assert meta["pivot_from"] == SITE_A and meta["where"] == "link" and meta["pivot_value"] == "high"
    assert world.graph.conn.execute("SELECT observed_value FROM evidence WHERE id=?", (meta["evidence_id"],)).fetchone()[0] == NUMBER
    assert wa["status"] == "ENRICHED" and wa["stage"] == "pivot"


def test_08_searching_for_the_number_found_a_second_simulated_domain_and_ignored_a_news_site(world):
    b = cand(world, SITE_B)
    assert b is not None and b["discovery_source"] == "pivot:search" and b["depth"] == 2
    assert b["parent_id"] == next(r["id"] for r in world.store.list(limit=1000) if r["indicator_type"] == "whatsapp")
    assert world.store.observations(b["id"])[0]["confidence"] == 0.3                  # search ranking is a lead, not evidence
    assert not any("nation.africa" in r["canonical"] for r in world.store.list(limit=1000))
    assert any(NUMBER in q for q in world.searcher.queries)


def test_09_the_second_domain_was_investigated_and_carries_the_same_number_and_an_otp_form(world):
    b = cand(world, SITE_B)
    assert b["stage"] == "deep" and b["status"] in {"SCORED", "ESCALATED"}             # lineage earned it a deep pass
    flags = json.loads(world.graph.conn.execute("SELECT observed_value FROM evidence WHERE entity_id=? AND evidence_type='page_signals'", (b["id"],)).fetchone()[0])["flags"]
    assert flags["solicits_otp"] and flags["whatsapp_cta"] and flags["guaranteed_returns"]
    users = {r["domain"] for r in world.graph.conn.execute(
        "SELECT d.canonical_value AS domain FROM relationships r JOIN entities d ON d.id=r.source_entity_id "
        "JOIN entities n ON n.id=r.target_entity_id WHERE n.entity_type='whatsapp' AND r.relationship_type='uses_whatsapp'")}
    assert users == {SITE_A, SITE_B}


def test_10_the_two_domains_were_correlated_into_one_campaign_with_a_cited_reason(world):
    (camp,) = [dict(r) for r in world.graph.conn.execute("SELECT * FROM campaigns WHERE status='active'")]
    members = {r[0] for r in world.graph.conn.execute(
        "SELECT e.canonical_value FROM campaign_entities ce JOIN entities e ON e.id=ce.entity_id WHERE ce.campaign_id=?", (camp["id"],))}
    assert {SITE_A, SITE_B} <= members and camp["correlation_score"] >= 70
    rel = world.graph.conn.execute("SELECT * FROM relationships WHERE relationship_type='shares_phone'").fetchone()
    assert rel and world.graph.conn.execute("SELECT 1 FROM evidence WHERE id=? AND evidence_type='correlation'", (rel["evidence_id"],)).fetchone()
    assert all(cand(world, d)["campaign_id"] == camp["id"] for d in (SITE_A, SITE_B))
    assert any(e["event"] == "created" for e in world.store.campaign_events(camp["id"]))


# -- steps 12-14: dashboard, inspection, analyst decisions ---------------------------------------------------------------------------------

def test_11_the_dashboard_api_shows_the_campaign_and_the_numbers(world):
    c = world.api()
    status = c.get("/api/hunter/status").json()
    assert status["metrics"]["new_campaigns"] == 1 and status["metrics"]["high_priority"] >= 2 and status["metrics"]["pending_review"] >= 1
    (camp,) = c.get("/api/hunter/campaigns").json()["items"]
    assert camp["name"].startswith("M-PESA ") and camp["infrastructure"]["Domains"] == 2 and camp["infrastructure"]["WhatsApp"] == 1
    full = c.get(f"/api/hunter/campaigns/{camp['public_id']}").json()
    assert any(w["link"] == "shares_phone" for w in full["why_related"])


def test_12_an_analyst_can_inspect_the_discovery_chain_indicators_evidence_relationships_and_scoring(world):
    c = world.api()
    b = cand(world, SITE_B)["id"]
    r = c.get(f"/api/hunter/investigations/{b}").json()
    assert [s["canonical"] for s in r["how_found"]] == [SITE_A, NUMBER, SITE_B]                 # CT -> domain -> WhatsApp -> second domain
    assert [s["source"] for s in r["how_found"]] == ["certificate_transparency", "pivot:whatsapp", "pivot:search"]
    assert r["how_found"][1]["via"]["where"] == "link" and r["how_found"][2]["query"]
    assert {"WhatsApp", "IPs", "Nameservers"} <= set(r["indicators"]) and r["evidence"] and r["relationships"] and r["score"]["reasons"]
    assert r["campaign"]["public_id"].startswith("WT-CMP-") and r["coverage"]["page"] == "assessed"


def test_13_every_disposition_can_be_recorded_and_stays_on_the_record(world):
    c = world.api()
    b = cand(world, SITE_B)["id"]
    for d in ("BENIGN", "FALSE_POSITIVE", "SUSPICIOUS", "CONFIRMED_IMPERSONATION", "CONFIRMED_SCAM"):
        r = c.post(f"/api/hunter/candidates/{b}/disposition", json={"disposition": d, "analyst": "analyst-1", "reason": f"review: {d.lower()}"})
        assert r.status_code == 200, (d, r.text)
    hist = c.get(f"/api/hunter/investigations/{b}").json()["dispositions"]
    assert [h["disposition"] for h in hist] == ["BENIGN", "FALSE_POSITIVE", "SUSPICIOUS", "CONFIRMED_IMPERSONATION", "CONFIRMED_SCAM"]
    assert [h["previous"] for h in hist] == [None, "BENIGN", "FALSE_POSITIVE", "SUSPICIOUS", "CONFIRMED_IMPERSONATION"]
    assert all(h["analyst"] == "analyst-1" and h["identity_source"] == "self_asserted" and h["at"] and h["reason"] for h in hist)
    assert world.graph.conn.execute("SELECT COUNT(*) FROM analyst_verdicts WHERE entity_id=?", (b,)).fetchone()[0] == 5
    assert cand(world, SITE_B) is not None                                                        # nothing was deleted
    # a confirmation changes the other domain's score, with its reasons
    a = c.get(f"/api/hunter/investigations/{cand(world, SITE_A)['id']}").json()
    assert "known_malicious_infrastructure" in {x["signal"] for x in a["why_flagged"]} and a["score_history"][-1]["trigger"] == "analyst_verdict"


# -- step 15: auditability ---------------------------------------------------------------------------------------------------------------------

def test_14_every_autonomous_action_can_be_explained(world):
    s, g = world.store, world.graph
    a, b = cand(world, SITE_A), cand(world, SITE_B)
    wa = next(r for r in s.list(limit=1000) if r["indicator_type"] == "whatsapp")
    assert s.observations(b["id"])[0]["query"].startswith('"')                                    # why did Mnara search this: the query is recorded
    assert any(h["event"] == "pivot_search" for h in s.history(wa["id"]))
    assert s.history(a["id"])[0]["event"] == "discovered" and "certificate_transparency" in s.history(a["id"])[0]["detail"]   # where it came from
    assert wa["parent_id"] == a["id"] and b["parent_id"] == wa["id"]                                # which indicator caused each pivot
    assert all(r["reasons"] for r in s.score_history(a["id"])) and s.score_history(a["id"])[0]["scoring_version"] == "1"     # why this score, under which config
    sources = {r[0] for r in g.conn.execute("SELECT DISTINCT source FROM evidence")}
    assert {"dns", "rdap", "tls", "http", "signals", "correlation", "pivot"} <= sources           # which source produced which evidence
    assert all(r[0] for r in g.conn.execute("SELECT observed_at FROM evidence"))                    # when it was collected
    assert any(h["event"] == "scored" for h in s.history(a["id"])) and s.score_history(a["id"])[-1]["changes"] is not None   # what changed since last time


def test_15_evidence_only_ever_grew_across_the_run(world):
    counts = world.evidence_counts
    assert counts == sorted(counts) and counts[-1] > counts[0] > 0                                  # append-only: never overwritten or shrunk
